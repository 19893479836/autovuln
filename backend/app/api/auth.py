"""认证 API：注册 / 登录 / 当前用户"""
from datetime import datetime

from fastapi import APIRouter, Depends, HTTPException, Request
from sqlalchemy.orm import Session

from ..core.audit import write_audit
from ..core.deps import get_current_user
from ..core.security import create_access_token, hash_password, verify_password
from ..config import settings
from ..database import get_db
from ..models import User
from ..schemas import LoginIn, RegisterIn, TokenOut, UserOut

router = APIRouter(prefix="/api/auth", tags=["认证"])


@router.post("/register", response_model=TokenOut)
def register(data: RegisterIn, request: Request, db: Session = Depends(get_db)):
    if db.query(User).filter(User.username == data.username).first():
        raise HTTPException(400, "用户名已存在")
    if db.query(User).filter(User.email == data.email).first():
        raise HTTPException(400, "邮箱已被注册")
    if not data.invite_code or data.invite_code != settings.INVITE_CODE:
        raise HTTPException(400, "邀请码无效")
    user = User(
        username=data.username, email=data.email,
        password_hash=hash_password(data.password),
        role="admin" if not db.query(User).count() else "user",  # 首个用户为管理员
    )
    db.add(user)
    db.commit()
    db.refresh(user)
    token = create_access_token(user.id, user.username, user.role)
    write_audit(db, user.id, user.username, "auth.register", "user", user.id,
                {"username": user.username}, request)
    return TokenOut(access_token=token, user=UserOut.model_validate(user))


@router.post("/login", response_model=TokenOut)
def login(data: LoginIn, request: Request, db: Session = Depends(get_db)):
    user = db.query(User).filter(User.username == data.username).first()
    if not user or not verify_password(data.password, user.password_hash):
        write_audit(db, 0, data.username, "auth.login_failed", detail={}, request=request)
        raise HTTPException(401, "用户名或密码错误")
    if not user.is_active:
        raise HTTPException(403, "账号已停用")
    user.last_login_at = datetime.utcnow()
    db.commit()
    token = create_access_token(user.id, user.username, user.role)
    write_audit(db, user.id, user.username, "auth.login", "user", user.id, {}, request)
    return TokenOut(access_token=token, user=UserOut.model_validate(user))


@router.get("/me", response_model=UserOut)
def me(user: User = Depends(get_current_user)):
    return user
