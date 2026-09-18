"""OAST 带外回调 API

- /api/oast/callback[/{path:path}]：公开回调端点（被扫描目标服务器访问），
  记录带 token 的请求。安全性依赖随机 token。
- 不提供查询 API（扫描器服务内部直接调用 oast.poll），避免泄露命中记录。
"""
from fastapi import APIRouter, Request

from ..services.oast import record_hit

router = APIRouter(prefix="/api/oast", tags=["OAST"])


@router.get("/callback")
@router.get("/callback/{path:path}")
async def oast_callback(request: Request, path: str = ""):
    token = request.query_params.get("token", "")
    if not token:
        return {"ok": False}
    record_hit(
        token,
        remote_ip=request.client.host if request.client else "",
        path=request.url.path,
        ua=request.headers.get("user-agent", ""),
    )
    return {"ok": True}
