"""漏洞运营 API：列表 / 详情 / 状态机 / 批量操作 / 轮次对比 / 误报反馈"""
import json

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from sqlalchemy.orm import Session

from ..core.audit import write_audit
from ..core.deps import get_current_user
from ..database import get_db
from ..models import Asset, Rule, User, Vulnerability, VulnStatusHistory
from ..schemas import BatchActionIn, Msg, Page, RoundCompareIn, VulnOut, VulnTransitionIn
from ..services import vuln_service
from ..utils.text import escape_like

router = APIRouter(prefix="/api/vulns", tags=["漏洞运营"])


def _to_out(db: Session, v: Vulnerability) -> VulnOut:
    asset = db.get(Asset, v.asset_id)
    data = {
        "id": v.id, "asset_id": v.asset_id, "title": v.title, "vuln_type": v.vuln_type,
        "severity": v.severity, "cvss_score": v.cvss_score, "confidence": v.confidence,
        "state": v.state, "url": v.url, "param": v.param, "description": v.description,
        "payload": v.payload, "cve_id": v.cve_id, "cnvd_id": v.cnvd_id,
        "assignee": v.assignee, "due_date": v.due_date, "fix_suggestion": v.fix_suggestion,
        "request_raw": v.request_raw, "response_raw": v.response_raw,
        "first_seen_at": v.first_seen_at, "last_seen_at": v.last_seen_at,
        "resolved_at": v.resolved_at, "asset_value": asset.value if asset else "",
        "reference": _load_json_list(v.reference),
        "evidence_files": _load_json_list(v.evidence_files),
    }
    return VulnOut.model_validate(data)


def _load_json_list(s: str | None) -> list:
    if not s:
        return []
    try:
        v = json.loads(s)
        return v if isinstance(v, list) else []
    except Exception:
        return []


@router.get("", response_model=Page[VulnOut])
def list_vulns(severity: str = "", state: str = "", vuln_type: str = "",
               asset_id: int | None = None, keyword: str = "",
               page: int = 1, page_size: int = 20,
               user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    q = db.query(Vulnerability).filter_by(user_id=user.id)
    if severity:
        q = q.filter(Vulnerability.severity == severity)
    if state:
        q = q.filter(Vulnerability.state == state)
    if vuln_type:
        q = q.filter(Vulnerability.vuln_type == vuln_type)
    if asset_id:
        q = q.filter(Vulnerability.asset_id == asset_id)
    if keyword:
        q = q.filter(
            (Vulnerability.title.like(f"%{escape_like(keyword)}%", escape="\\")) |
            (Vulnerability.url.like(f"%{escape_like(keyword)}%", escape="\\")) |
            (Vulnerability.cve_id.like(f"%{escape_like(keyword)}%", escape="\\"))
        )
    total = q.count()
    vulns = q.order_by(Vulnerability.severity.desc(), Vulnerability.id.desc()) \
        .offset((page - 1) * page_size).limit(page_size).all()
    return Page(total=total, items=[_to_out(db, v) for v in vulns])


@router.get("/{vuln_id}", response_model=VulnOut)
def get_vuln(vuln_id: int, user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    v = db.query(Vulnerability).filter_by(id=vuln_id, user_id=user.id).first()
    if not v:
        raise HTTPException(404, "漏洞不存在")
    return _to_out(db, v)


@router.get("/{vuln_id}/history")
def vuln_history(vuln_id: int, user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    v = db.query(Vulnerability).filter_by(id=vuln_id, user_id=user.id).first()
    if not v:
        raise HTTPException(404, "漏洞不存在")
    rows = db.query(VulnStatusHistory).filter_by(vuln_id=vuln_id) \
        .order_by(VulnStatusHistory.created_at).all()
    return [{"from": r.from_state, "to": r.to_state, "operator": r.operator,
             "comment": r.comment, "time": r.created_at} for r in rows]


@router.post("/{vuln_id}/transition", response_model=dict)
def transition(vuln_id: int, data: VulnTransitionIn, request: Request,
               user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    ok, msg = vuln_service.transition(db, user.id, vuln_id, data.to_state,
                                      user.username, data.comment or None)
    if not ok:
        raise HTTPException(400, msg)
    write_audit(db, user.id, user.username, "vuln.transition", "vuln", vuln_id,
                {"to_state": data.to_state, "comment": data.comment}, request)
    return {"ok": True, "msg": "状态已更新"}


@router.post("/batch/action", response_model=dict)
def batch_action(data: BatchActionIn, request: Request,
                 user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    result = vuln_service.batch_action(db, user.id, data.action, data.vuln_ids,
                                       user.username, data.assignee, data.comment)
    write_audit(db, user.id, user.username, f"vuln.batch_{data.action}", "vuln", None,
                {"ids": data.vuln_ids[:100], "result": result}, request)
    return result


@router.post("/round-compare", response_model=dict)
def round_compare(data: RoundCompareIn, asset_id: int = Query(...),
                  user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    """轮次对比：round_a → round_b，识别新增/已修复/复发"""
    asset = db.query(Asset).filter_by(id=asset_id, user_id=user.id).first()
    if not asset:
        raise HTTPException(404, "资产不存在")
    return vuln_service.round_compare(db, user.id, asset_id, data.round_a, data.round_b)


@router.post("/{vuln_id}/false-positive-feedback", response_model=dict)
def fp_feedback(vuln_id: int, request: Request,
                user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    """误报反馈闭环：标记误报并反哺规则库（fp_count + 1，达到阈值自动抑制）"""
    v = db.query(Vulnerability).filter_by(id=vuln_id, user_id=user.id).first()
    if not v:
        raise HTTPException(404, "漏洞不存在")
    ok, msg = vuln_service.transition(db, user.id, vuln_id, "false_positive",
                                      user.username, "用户标记误报")
    # 反哺规则库
    rule = db.query(Rule).filter_by(name=v.title).first()
    feedback = {}
    if rule:
        rule.fp_count += 1
        if rule.fp_count >= 3:
            rule.fp_suppress = True
        db.commit()
        feedback = {"rule_id": rule.id, "fp_count": rule.fp_count,
                    "suppressed": rule.fp_suppress}
    write_audit(db, user.id, user.username, "vuln.fp_feedback", "vuln", vuln_id,
                {"feedback": feedback}, request)
    return {"ok": ok, "msg": msg, "feedback": feedback}
