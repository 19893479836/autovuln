"""资产管理层 API：导入/去重、分组、标签、聚合、存活监测、变更追踪"""
from fastapi import APIRouter, Depends, HTTPException, Request
from sqlalchemy import func
from sqlalchemy.orm import Session

from ..core.audit import write_audit
from ..core.deps import get_current_user
from ..database import get_db
from ..models import (Asset, AssetGroup, AssetRecord, ScanTask, User,
                      Vulnerability, VulnStatusHistory)
from ..schemas import (AssetImportIn, AssetOut, AssetUpdateIn, GroupIn, GroupOut,
                       Msg, Page)
from ..services import asset_service
from ..utils.text import escape_like

router = APIRouter(prefix="/api/assets", tags=["资产管理"])


def _asset_out(db: Session, a: Asset) -> AssetOut:
    vc = db.query(func.count(Vulnerability.id)).filter_by(asset_id=a.id).scalar() or 0
    out = AssetOut.model_validate(a)
    out.vuln_count = vc
    out.has_cookie = bool(a.cookie)
    return out


# ---------------- 资产 CRUD ----------------
@router.get("", response_model=Page[AssetOut])
def list_assets(kind: str = "", status: str = "", group_id: int | None = None,
                keyword: str = "", importance: str = "",
                page: int = 1, page_size: int = 20,
                user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    q = db.query(Asset).filter_by(user_id=user.id)
    if kind:
        q = q.filter(Asset.kind == kind)
    if status:
        q = q.filter(Asset.status == status)
    if group_id:
        q = q.filter(Asset.group_id == group_id)
    if importance:
        q = q.filter(Asset.importance == importance)
    if keyword:
        q = q.filter(Asset.value.like(f"%{escape_like(keyword)}%", escape="\\"))
    total = q.count()
    assets = q.order_by(Asset.id.desc()).offset((page - 1) * page_size).limit(page_size).all()
    return Page(total=total, items=[_asset_out(db, a) for a in assets])


@router.get("/{asset_id}", response_model=AssetOut)
def get_asset(asset_id: int, user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    asset = db.query(Asset).filter_by(id=asset_id, user_id=user.id).first()
    if not asset:
        raise HTTPException(404, "资产不存在")
    return _asset_out(db, asset)


@router.post("/import", response_model=dict)
def import_assets(data: AssetImportIn, request: Request,
                  user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    result = asset_service.import_assets(
        db, user.id, data.targets, data.group_id, data.tags, data.importance,
        cookie=data.cookie,
    )
    write_audit(db, user.id, user.username, "asset.import", "asset", None,
                {"result": result}, request)
    return result


@router.put("/{asset_id}", response_model=AssetOut)
def update_asset(asset_id: int, data: AssetUpdateIn, request: Request,
                 user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    asset = db.query(Asset).filter_by(id=asset_id, user_id=user.id).first()
    if not asset:
        raise HTTPException(404, "资产不存在")
    if data.group_id is not None:
        g = db.query(AssetGroup).filter_by(id=data.group_id, user_id=user.id).first()
        if not g:
            raise HTTPException(400, "分组不存在")
        asset.group_id = data.group_id
    if data.tags is not None:
        asset.tags = data.tags
    if data.importance is not None:
        asset.importance = data.importance
    if data.description is not None:
        asset.description = data.description
    if data.cookie is not None:
        asset.cookie = data.cookie.strip() or None
    db.commit()
    write_audit(db, user.id, user.username, "asset.update", "asset", asset.id, {}, request)
    return _asset_out(db, asset)


@router.delete("/{asset_id}", response_model=Msg)
def delete_asset(asset_id: int, request: Request,
                 user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    asset = db.query(Asset).filter_by(id=asset_id, user_id=user.id).first()
    if not asset:
        raise HTTPException(404, "资产不存在")
    # 级联清理：状态流转历史 → 漏洞 → 扫描任务 → 聚合记录 → 资产
    vuln_ids = [v.id for v in db.query(Vulnerability.id).filter_by(asset_id=asset.id).all()]
    if vuln_ids:
        db.query(VulnStatusHistory).filter(
            VulnStatusHistory.vuln_id.in_(vuln_ids),
        ).delete(synchronize_session=False)
        db.query(Vulnerability).filter_by(asset_id=asset.id).delete(synchronize_session=False)
    db.query(ScanTask).filter_by(asset_id=asset.id).delete(synchronize_session=False)
    db.query(AssetRecord).filter_by(asset_id=asset.id).delete(synchronize_session=False)
    db.delete(asset)
    db.commit()
    write_audit(db, user.id, user.username, "asset.delete", "asset", asset_id,
                {"cleaned_vulns": len(vuln_ids)}, request)
    return Msg(msg="已删除")


# ---------------- 聚合信息 ----------------
@router.get("/{asset_id}/records")
def asset_records(asset_id: int, kind: str = "",
                  user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    asset = db.query(Asset).filter_by(id=asset_id, user_id=user.id).first()
    if not asset:
        raise HTTPException(404, "资产不存在")
    q = db.query(AssetRecord).filter_by(asset_id=asset.id)
    if kind:
        q = q.filter(AssetRecord.kind == kind)
    rows = q.order_by(AssetRecord.kind, AssetRecord.id).limit(500).all()
    return [{"id": r.id, "kind": r.kind, "key": r.key, "value": r.value,
             "detail": r.detail, "source": r.source,
             "discovered_at": r.discovered_at} for r in rows]


# ---------------- 分组 ----------------
@router.get("/groups/all", response_model=list[GroupOut])
def list_groups(user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    groups = db.query(AssetGroup).filter_by(user_id=user.id).all()
    result = []
    for g in groups:
        cnt = db.query(func.count(Asset.id)).filter_by(group_id=g.id).scalar() or 0
        out = GroupOut.model_validate(g)
        out.asset_count = cnt
        result.append(out)
    return result


@router.post("/groups/create", response_model=GroupOut)
def create_group(data: GroupIn, request: Request,
                 user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    g = AssetGroup(user_id=user.id, name=data.name, description=data.description,
                   importance=data.importance)
    db.add(g)
    db.commit()
    db.refresh(g)
    write_audit(db, user.id, user.username, "asset.group_create", "asset_group", g.id, {}, request)
    return g


# ---------------- 存活监测 ----------------
@router.post("/alive-check", response_model=dict)
def alive_check(request: Request,
                user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    stats = asset_service.run_alive_check(db, user.id)
    write_audit(db, user.id, user.username, "asset.alive_check", "asset", None, stats, request)
    return stats


# ---------------- 变更追踪 ----------------
@router.get("/changes/timeline")
def asset_changes(user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    """近 7 天新增/下线的资产变更记录"""
    from datetime import datetime, timedelta
    from ..models import AuditLog
    since = datetime.utcnow() - timedelta(days=7)
    logs = db.query(AuditLog).filter(
        AuditLog.user_id == user.id,
        AuditLog.action.in_(("asset.import", "asset.delete")),
        AuditLog.created_at >= since,
    ).order_by(AuditLog.created_at.desc()).limit(100).all()
    return [{"id": l.id, "action": l.action, "detail": l.detail,
             "created_at": l.created_at} for l in logs]
