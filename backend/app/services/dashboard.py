"""态势统计服务：Dashboard 数据聚合（严格按 user_id 租户隔离）"""
from datetime import datetime, timedelta

from sqlalchemy import func
from sqlalchemy.orm import Session

from ..models import Asset, ScanTask, Vulnerability


def dashboard(db: Session, user_id: int) -> dict:
    vuln_total = db.query(func.count(Vulnerability.id)).filter_by(user_id=user_id).scalar() or 0
    asset_total = db.query(func.count(Asset.id)).filter_by(user_id=user_id).scalar() or 0
    task_running = db.query(func.count(ScanTask.id)).filter(
        ScanTask.user_id == user_id, ScanTask.state == "running",
    ).scalar() or 0
    open_vulns = db.query(func.count(Vulnerability.id)).filter(
        Vulnerability.user_id == user_id,
        Vulnerability.state.in_(("pending", "confirmed", "fixing")),
    ).scalar() or 0

    # 等级分布
    sev_rows = db.query(Vulnerability.severity, func.count(Vulnerability.id)).filter_by(
        user_id=user_id).group_by(Vulnerability.severity).all()
    severity = {s: 0 for s in ("critical", "high", "medium", "low", "info")}
    for s, c in sev_rows:
        severity[s] = c

    # 状态分布
    state_rows = db.query(Vulnerability.state, func.count(Vulnerability.id)).filter_by(
        user_id=user_id).group_by(Vulnerability.state).all()
    states = {s: 0 for s in ("pending", "confirmed", "fixing", "fixed", "verified",
                             "false_positive", "ignored")}
    for s, c in state_rows:
        states[s] = c

    # 近 14 天趋势
    since = datetime.utcnow() - timedelta(days=13)
    trend_rows = db.query(
        func.date(Vulnerability.first_seen_at), func.count(Vulnerability.id),
    ).filter(
        Vulnerability.user_id == user_id,
        Vulnerability.first_seen_at >= since,
    ).group_by(func.date(Vulnerability.first_seen_at)).all()
    trend = {}
    for i in range(14):
        d = (datetime.utcnow() - timedelta(days=13 - i)).strftime("%Y-%m-%d")
        trend[d] = 0
    for d, c in trend_rows:
        # SQLite 的 func.date 返回字符串 "YYYY-MM-DD"
        if isinstance(d, str):
            trend[d] = c
        else:
            trend[d.strftime("%Y-%m-%d")] = c

    # 类型 Top
    type_rows = db.query(Vulnerability.vuln_type, func.count(Vulnerability.id)).filter_by(
        user_id=user_id).group_by(Vulnerability.vuln_type).order_by(func.count(Vulnerability.id).desc()).limit(10).all()

    # 高危 Top 资产
    high_assets = db.query(Asset.value, func.count(Vulnerability.id)).join(
        Vulnerability, Vulnerability.asset_id == Asset.id,
    ).filter(
        Asset.user_id == user_id,
        Vulnerability.severity.in_(("critical", "high")),
        Vulnerability.state.in_(("pending", "confirmed", "fixing")),
    ).group_by(Asset.value).order_by(func.count(Vulnerability.id).desc()).limit(8).all()

    return {
        "vuln_total": vuln_total,
        "asset_total": asset_total,
        "task_running": task_running,
        "open_vulns": open_vulns,
        "severity": severity,
        "states": states,
        "trend": trend,
        "top_types": [{"type": t, "count": c} for t, c in type_rows],
        "top_assets": [{"asset": a, "count": c} for a, c in high_assets],
    }
