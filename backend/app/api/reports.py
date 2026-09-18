"""分析输出 API：报告生成/列表/下载 + Dashboard 态势"""
import json

from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import FileResponse
from sqlalchemy.orm import Session

from ..core.audit import write_audit
from ..core.deps import get_current_user
from ..config import settings
from ..database import get_db
from ..models import Report, User
from ..schemas import ReportCreateIn, ReportOut
from ..services import report as report_svc
from ..services.dashboard import dashboard

router = APIRouter(prefix="/api", tags=["分析与输出"])


@router.post("/reports/generate", response_model=ReportOut)
def generate_report(data: ReportCreateIn, request: Request,
                    user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    try:
        r = report_svc.generate_report(db, user.id, data.fmt, data.title, data.asset_ids)
    except ValueError as e:
        raise HTTPException(400, str(e))
    write_audit(db, user.id, user.username, "report.generate", "report", r.id,
                {"fmt": data.fmt, "title": data.title, "assets": data.asset_ids}, request)
    return _to_out(r)


def _to_out(r: Report) -> ReportOut:
    try:
        stats = json.loads(r.stats_json or "{}")
    except Exception:
        stats = {}
    return ReportOut(
        id=r.id, title=r.title, fmt=r.fmt, file_path=r.file_path,
        scope_desc=r.scope_desc, stats=stats, created_at=r.created_at,
    )


@router.get("/reports", response_model=list[ReportOut])
def list_reports(user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    rows = db.query(Report).filter_by(user_id=user.id).order_by(Report.id.desc()).limit(100).all()
    return [_to_out(r) for r in rows]


@router.get("/reports/{report_id}/download")
def download_report(report_id: int, user: User = Depends(get_current_user),
                    db: Session = Depends(get_db)):
    r = db.query(Report).filter_by(id=report_id, user_id=user.id).first()
    if not r:
        raise HTTPException(404, "报告不存在")
    from pathlib import Path
    # 兼容相对路径（当前格式）与旧绝对路径记录
    cand = Path(r.file_path)
    if not cand.is_absolute():
        cand = settings.EXPORT_DIR / r.file_path
    # 路径穿越防护：解析后必须位于导出目录内
    try:
        resolved = cand.resolve()
    except Exception:
        resolved = cand
    export_root = settings.EXPORT_DIR.resolve()
    if export_root not in resolved.parents and resolved != export_root:
        raise HTTPException(403, "非法文件路径")
    if not resolved.exists() or not resolved.is_file():
        raise HTTPException(404, "报告文件已丢失")
    media = {"html": "text/html", "pdf": "application/pdf", "json": "application/json",
             "excel": "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"}
    return FileResponse(str(resolved), media_type=media.get(r.fmt, "application/octet-stream"),
                        filename=resolved.name)


@router.get("/dashboard")
def get_dashboard(user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    return dashboard(db, user.id)
