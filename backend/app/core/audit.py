"""审计日志服务"""
import json

from fastapi import Request
from sqlalchemy.orm import Session

from ..models import AuditLog


def write_audit(
    db: Session,
    user_id: int,
    username: str,
    action: str,
    target_type: str | None = None,
    target_id: int | None = None,
    detail: dict | None = None,
    request: Request | None = None,
) -> None:
    ip = None
    if request is not None:
        ip = request.client.host if request.client else None
        # 兼容反向代理
        fwd = request.headers.get("x-forwarded-for")
        if fwd:
            ip = fwd.split(",")[0].strip()
    db.add(AuditLog(
        user_id=user_id,
        username=username,
        action=action,
        target_type=target_type,
        target_id=target_id,
        detail=json.dumps(detail, ensure_ascii=False, default=str) if detail else None,
        ip=ip,
    ))
    # 审计日志独立提交：确保全操作留痕不随业务事务丢失
    db.commit()
