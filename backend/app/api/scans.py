"""扫描任务 API：创建 / 列表 / 控制（暂停·恢复·取消）/ 轮次"""
import json
from datetime import datetime

from fastapi import APIRouter, Depends, HTTPException, Request
from sqlalchemy.orm import Session

from ..core.audit import write_audit
from ..core.deps import get_current_user
from ..config import settings
from ..database import get_db
from ..models import Asset, ScanTask, User
from ..scanners.base import task_manager
from ..scanners.scheduler import scheduler
from ..schemas import Msg, Page, ScanCreate, ScanOut

router = APIRouter(prefix="/api/scans", tags=["扫描任务"])


def _to_out(db: Session, t: ScanTask) -> ScanOut:
    asset = db.get(Asset, t.asset_id)
    out = ScanOut.model_validate(t)
    out.asset_value = asset.value if asset else ""
    return out


@router.post("", response_model=ScanOut)
def create_scan(data: ScanCreate, request: Request,
                user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    asset = db.query(Asset).filter_by(id=data.asset_id, user_id=user.id).first()
    if not asset:
        raise HTTPException(404, "资产不存在")
    # 轮次：同资产同类型最近任务的 round_no + 1
    last = db.query(ScanTask).filter_by(
        user_id=user.id, asset_id=asset.id, task_type=data.task_type,
    ).order_by(ScanTask.round_no.desc()).first()
    round_no = (last.round_no + 1) if last else 1
    # 未指定限速间隔时使用全局默认（秒 → 毫秒）
    rate_limit = data.rate_limit or int(settings.DEFAULT_RATE_LIMIT * 1000)
    task = ScanTask(
        user_id=user.id, asset_id=asset.id, task_type=data.task_type,
        name=data.name or f"{data.task_type} - {asset.value}",
        state="pending", round_no=round_no, rate_limit=rate_limit,
        params=json.dumps(data.params, ensure_ascii=False),
        scheduled_for=data.scheduled_for, triggered_by="manual",
    )
    db.add(task)
    db.commit()
    db.refresh(task)
    write_audit(db, user.id, user.username, "scan.create", "scan_task", task.id,
                {"asset": asset.value, "type": data.task_type, "round": round_no}, request)
    return _to_out(db, task)


@router.get("", response_model=Page[ScanOut])
def list_scans(asset_id: int | None = None, state: str = "", task_type: str = "",
               page: int = 1, page_size: int = 20,
               user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    q = db.query(ScanTask).filter_by(user_id=user.id)
    if asset_id:
        q = q.filter(ScanTask.asset_id == asset_id)
    if state:
        q = q.filter(ScanTask.state == state)
    if task_type:
        q = q.filter(ScanTask.task_type == task_type)
    total = q.count()
    tasks = q.order_by(ScanTask.id.desc()).offset((page - 1) * page_size).limit(page_size).all()
    return Page(total=total, items=[_to_out(db, t) for t in tasks])


@router.get("/{task_id}", response_model=ScanOut)
def get_scan(task_id: int, user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    task = db.query(ScanTask).filter_by(id=task_id, user_id=user.id).first()
    if not task:
        raise HTTPException(404, "任务不存在")
    return _to_out(db, task)


@router.post("/{task_id}/pause", response_model=Msg)
def pause_scan(task_id: int, request: Request,
               user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    task = db.query(ScanTask).filter_by(id=task_id, user_id=user.id).first()
    if not task:
        raise HTTPException(404, "任务不存在")
    if task.state == "running":
        db.commit()
        scheduler.pause(task_id)
        write_audit(db, user.id, user.username, "scan.pause", "scan_task", task_id, {}, request)
        return Msg(msg="已暂停")
    raise HTTPException(400, f"任务当前状态 {task.state} 不可暂停")


@router.post("/{task_id}/resume", response_model=Msg)
def resume_scan(task_id: int, request: Request,
                user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    task = db.query(ScanTask).filter_by(id=task_id, user_id=user.id).first()
    if not task:
        raise HTTPException(404, "任务不存在")
    if task.state == "paused":
        db.commit()
        scheduler.resume(task_id)
        write_audit(db, user.id, user.username, "scan.resume", "scan_task", task_id, {}, request)
        return Msg(msg="已恢复")
    raise HTTPException(400, f"任务当前状态 {task.state} 不可恢复")


@router.post("/{task_id}/cancel", response_model=Msg)
def cancel_scan(task_id: int, request: Request,
                user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    task = db.query(ScanTask).filter_by(id=task_id, user_id=user.id).first()
    if not task:
        raise HTTPException(404, "任务不存在")
    if task.state in ("completed", "cancelled", "failed"):
        raise HTTPException(400, f"任务已处于 {task.state} 状态")
    if task.state == "pending" and task.id not in (task_manager.running_tasks()):
        task.state = "cancelled"
        db.commit()
    else:
        scheduler.cancel(task_id)
    write_audit(db, user.id, user.username, "scan.cancel", "scan_task", task_id, {}, request)
    return Msg(msg="已取消")


@router.get("/rounds/{asset_id}")
def list_rounds(asset_id: int, user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    """某资产的扫描轮次（用于轮次对比选择）"""
    asset = db.query(Asset).filter_by(id=asset_id, user_id=user.id).first()
    if not asset:
        raise HTTPException(404, "资产不存在")
    rounds = db.query(ScanTask.round_no, ScanTask.task_type).filter_by(
        user_id=user.id, asset_id=asset_id,
    ).order_by(ScanTask.round_no.desc()).all()
    seen = {}
    for r_no, t_type in rounds:
        seen.setdefault(r_no, set()).add(t_type)
    return [{"round_no": r, "types": sorted(ts)} for r, ts in sorted(seen.items(), reverse=True)]
