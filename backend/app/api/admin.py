"""平台支撑 API：用户管理 / 审计日志 / 通知配置"""
from fastapi import APIRouter, Depends, HTTPException, Request
from sqlalchemy.orm import Session

from ..core.audit import write_audit
from ..core.deps import get_current_user, require_admin
from ..database import get_db
from ..models import AuditLog, Notification, User
from ..schemas import AuditOut, NotifyConfigIn, Page, UserOut

router = APIRouter(prefix="/api", tags=["平台支撑"])


# ---------------- 用户管理 ----------------
@router.get("/admin/users", response_model=list[UserOut])
def list_users(user: User = Depends(require_admin), db: Session = Depends(get_db)):
    rows = db.query(User).order_by(User.id).all()
    return [UserOut.model_validate(u) for u in rows]


@router.post("/admin/users/{user_id}/toggle-active")
def toggle_active(user_id: int, request: Request,
                  user: User = Depends(require_admin), db: Session = Depends(get_db)):
    if user_id == user.id:
        raise HTTPException(400, "不能停用自己的账号")
    target = db.get(User, user_id)
    if not target:
        raise HTTPException(404, "用户不存在")
    target.is_active = not target.is_active
    db.commit()
    write_audit(db, user.id, user.username, "admin.user_toggle", "user", user_id,
                {"active": target.is_active}, request)
    return {"ok": True, "active": target.is_active}


@router.post("/admin/users/{user_id}/set-role")
def set_role(user_id: int, role: str, request: Request,
             user: User = Depends(require_admin), db: Session = Depends(get_db)):
    if role not in ("admin", "user"):
        raise HTTPException(400, "非法角色")
    target = db.get(User, user_id)
    if not target:
        raise HTTPException(404, "用户不存在")
    target.role = role
    db.commit()
    write_audit(db, user.id, user.username, "admin.user_role", "user", user_id,
                {"role": role}, request)
    return {"ok": True, "role": role}


# ---------------- 审计日志 ----------------
@router.get("/audit-logs", response_model=Page[AuditOut])
def list_audit(action: str = "", page: int = 1, page_size: int = 20,
               user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    q = db.query(AuditLog)
    if user.role != "admin":
        q = q.filter(AuditLog.user_id == user.id)
    if action:
        q = q.filter(AuditLog.action == action)
    total = q.count()
    rows = q.order_by(AuditLog.id.desc()).offset((page - 1) * page_size).limit(page_size).all()
    return Page(total=total, items=[AuditOut.model_validate(r) for r in rows])


# ---------------- 通知 ----------------
@router.get("/notifications")
def list_notifications(user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    rows = db.query(Notification).filter_by(user_id=user.id) \
        .order_by(Notification.id.desc()).limit(100).all()
    return [{"id": n.id, "channel": n.channel, "event": n.event, "payload": n.payload,
             "status": n.status, "error_msg": n.error_msg, "created_at": n.created_at}
            for n in rows]


@router.post("/notify-config", response_model=dict)
def save_notify_config(data: NotifyConfigIn, request: Request,
                       user: User = Depends(require_admin), db: Session = Depends(get_db)):
    """通知配置写入本地配置（运行时生效；也可持久化到 settings 环境变量）"""
    from ..config import settings
    if data.webhook_url:
        settings.WEBHOOK_URL = data.webhook_url
    write_audit(db, user.id, user.username, "notify.config", "notify", None,
                {"channels": data.channels, "threshold": data.threshold}, request)
    return {"ok": True, "channels": data.channels}


@router.get("/notify-config")
def get_notify_config(user: User = Depends(get_current_user)):
    from ..config import settings
    return {"webhook_url": settings.WEBHOOK_URL,
            "smtp_host": settings.SMTP_HOST or "",
            "channels": [c for c, ok in [("webhook", bool(settings.WEBHOOK_URL)),
                                         ("email", bool(settings.SMTP_HOST)),
                                         ("im", False)] if ok]}
