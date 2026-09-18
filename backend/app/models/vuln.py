"""漏洞运营模型：漏洞 / 状态流转历史 / 通知 / 报告"""
import json
from datetime import datetime

from sqlalchemy import DateTime, Float, ForeignKey, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship

from ..database import Base

# 漏洞状态机：发现 → 确认 → 修复中 → 已修复 → 复测通过
VULN_STATES = ("pending", "confirmed", "fixing", "fixed", "verified", "false_positive", "ignored")
STATE_FLOW = {
    "pending": ("confirmed", "false_positive", "ignored"),
    "confirmed": ("fixing", "fixed", "false_positive", "ignored"),
    "fixing": ("fixed", "confirmed", "false_positive"),
    "fixed": ("verified", "fixing", "false_positive"),
    "verified": ("fixing",),
    "false_positive": ("pending", "confirmed", "ignored"),
    "ignored": ("pending", "confirmed"),
}

# 置信度
CONFIDENCE = ("high", "medium", "low")


class Vulnerability(Base):
    """漏洞实体：定级 / 置信度 / 证据 / 状态机 / 工单字段"""

    __tablename__ = "vulnerabilities"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    user_id: Mapped[int] = mapped_column(ForeignKey("users.id"), index=True, nullable=False)
    asset_id: Mapped[int] = mapped_column(ForeignKey("assets.id"), index=True, nullable=False)
    task_id: Mapped[int | None] = mapped_column(ForeignKey("scan_tasks.id"), index=True, nullable=True)
    # 唯一键（同一资产同类型同位置视为同漏洞）
    vuln_key: Mapped[str] = mapped_column(String(256), index=True, nullable=False)
    title: Mapped[str] = mapped_column(String(256), nullable=False)
    vuln_type: Mapped[str] = mapped_column(String(64), index=True, nullable=False)  # 如 sqli/xss/ssrf/cve
    severity: Mapped[str] = mapped_column(String(16), index=True, default="medium")  # critical/high/medium/low/info
    cvss_score: Mapped[float] = mapped_column(Float, default=0.0)
    confidence: Mapped[str] = mapped_column(String(16), default="medium")
    state: Mapped[str] = mapped_column(String(16), default="pending", index=True)
    # 详情
    url: Mapped[str | None] = mapped_column(Text, nullable=True)
    param: Mapped[str | None] = mapped_column(String(128), nullable=True)
    description: Mapped[str | None] = mapped_column(Text, nullable=True)
    payload: Mapped[str | None] = mapped_column(Text, nullable=True)
    # 证据
    request_raw: Mapped[str | None] = mapped_column(Text, nullable=True)
    response_raw: Mapped[str | None] = mapped_column(Text, nullable=True)
    evidence_files: Mapped[str] = mapped_column(Text, default="[]")  # JSON: 截图/文件路径
    # 关联
    cve_id: Mapped[str | None] = mapped_column(String(32), nullable=True, index=True)
    cnvd_id: Mapped[str | None] = mapped_column(String(32), nullable=True)
    reference: Mapped[str | None] = mapped_column(Text, nullable=True)  # 参考链接(JSON 数组)
    # 工单
    assignee: Mapped[str | None] = mapped_column(String(64), nullable=True)
    due_date: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    # 修复
    fix_suggestion: Mapped[str | None] = mapped_column(Text, nullable=True)
    # 时间
    first_seen_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
    last_seen_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
    resolved_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    confirmed_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)

    asset: Mapped["Asset"] = relationship()  # noqa: F821


class VulnStatusHistory(Base):
    """漏洞状态流转记录（可追溯）"""

    __tablename__ = "vuln_status_history"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    vuln_id: Mapped[int] = mapped_column(ForeignKey("vulnerabilities.id"), index=True, nullable=False)
    from_state: Mapped[str | None] = mapped_column(String(16), nullable=True)
    to_state: Mapped[str] = mapped_column(String(16), nullable=False)
    operator: Mapped[str] = mapped_column(String(64), default="system")  # 操作人/扫描器
    comment: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)


class Notification(Base):
    """通知记录：高危漏洞触发邮件/IM/Webhook"""

    __tablename__ = "notifications"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    user_id: Mapped[int] = mapped_column(ForeignKey("users.id"), index=True, nullable=False)
    channel: Mapped[str] = mapped_column(String(16), nullable=False)  # webhook/email/im
    target: Mapped[str | None] = mapped_column(String(256), nullable=True)
    event: Mapped[str] = mapped_column(String(64), default="vuln_found")
    payload: Mapped[str] = mapped_column(Text, default="{}")
    status: Mapped[str] = mapped_column(String(16), default="success")  # success/failed
    error_msg: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)


class Report(Base):
    """生成的报告记录"""

    __tablename__ = "reports"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    user_id: Mapped[int] = mapped_column(ForeignKey("users.id"), index=True, nullable=False)
    title: Mapped[str] = mapped_column(String(256), nullable=False)
    fmt: Mapped[str] = mapped_column(String(16), default="html")  # html/pdf/json/excel
    file_path: Mapped[str] = mapped_column(String(512), nullable=False)
    scope_desc: Mapped[str | None] = mapped_column(Text, nullable=True)  # 统计范围
    stats_json: Mapped[str] = mapped_column(Text, default="{}")
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)

    @property
    def stats(self) -> dict:
        try:
            return json.loads(self.stats_json)
        except Exception:
            return {}
