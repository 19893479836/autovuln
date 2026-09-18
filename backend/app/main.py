"""AutoVuln 自动化漏洞挖掘平台 - FastAPI 入口"""
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from .config import BASE_DIR, settings
from .database import init_db


@asynccontextmanager
async def lifespan(app: FastAPI):
    init_db()
    # 首次启动种子规则
    from .services.seed import ensure_seed_data
    ensure_seed_data()
    # 启动任务调度器
    from .scanners.scheduler import scheduler
    scheduler.start()
    yield
    scheduler.shutdown()


app = FastAPI(
    title=settings.APP_NAME,
    version=settings.APP_VERSION,
    description="七层流水线自动化漏洞挖掘平台：资产 → 信息收集 → 漏洞发现 → 验证 → 运营 → 分析输出 → 平台支撑",
    docs_url="/api/docs",
    redoc_url="/api/redoc",
    openapi_url="/api/openapi.json",
    lifespan=lifespan,
)

# CORS（前端开发服务器 / 生产可通过 CORS_ORIGINS 环境变量收紧）
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.CORS_ORIGINS,
    allow_credentials=False,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ---------------- 路由注册 ----------------
from .api import admin, assets, auth, oast, reports, rules, scans, vulns  # noqa: E402

app.include_router(auth.router)
app.include_router(assets.router)
app.include_router(scans.router)
app.include_router(vulns.router)
app.include_router(reports.router)
app.include_router(oast.router)
app.include_router(rules.router)
app.include_router(admin.router)


@app.get("/api/health")
def health():
    return {"status": "ok", "app": settings.APP_NAME, "version": settings.APP_VERSION}


@app.get("/", include_in_schema=False)
def root():
    # 生产模式：根路径直接托管前端
    if _frontend_dist.exists():
        from fastapi.responses import FileResponse
        return FileResponse(str(_frontend_dist / "index.html"))
    return {"name": settings.APP_NAME, "docs": "/api/docs", "health": "/api/health"}


# ---------------- 生产模式：托管前端静态文件 ----------------
_frontend_dist = BASE_DIR.parent / "frontend" / "dist"
if _frontend_dist.exists():
    from fastapi.staticfiles import StaticFiles

    app.mount("/assets", StaticFiles(directory=_frontend_dist / "assets"), name="assets")

    @app.get("/{full_path:path}", include_in_schema=False)
    async def spa(full_path: str):
        """Vue SPA 兜底：非 API 路径返回 index.html。
        /api/* 一律交还 API 路由，未命中时返回标准 404，避免吞掉 API 错误。"""
        from fastapi import HTTPException
        from fastapi.responses import FileResponse

        if full_path.startswith("api/") or full_path == "api":
            raise HTTPException(404, "Not Found")
        candidate = _frontend_dist / full_path
        if full_path and candidate.is_file():
            return FileResponse(str(candidate))
        return FileResponse(str(_frontend_dist / "index.html"))
