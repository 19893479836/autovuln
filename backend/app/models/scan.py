"""扫描任务模型：任务 / 轮次 / 进度 / 控制状态"""
from datetime import datetime

from sqlalchemy import DateTime, ForeignKey, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from ..database import Base

# 任务类型
SCAN_TYPES = (
    "recon_subdomain",    # 子域名枚举
    "recon_port",         # 端口与服务识别
    "recon_fingerprint",  # 指纹识别
    "recon_jsapi",        # JS/API 接口提取
    "recon_path",         # 目录爆破
    "vuln_web",           # Web 漏洞扫描
    "vuln_cve",           # 组件 CVE 检测
    "vuln_poc",           # POC 验证
    "vuln_weakpass",      # 弱口令/未授权
    "full",               # 全流程
)

# 任务状态
TASK_STATES = ("pending", "running", "paused", "cancelled", "completed", "failed")


class ScanTask(Base):
    """一次扫描任务。task_type 决定执行哪些扫描器；round_no 标识扫描轮次（用于轮次对比）。"""

    __tablename__ = "scan_tasks"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    user_id: Mapped[int] = mapped_column(ForeignKey("users.id"), index=True, nullable=False)
    asset_id: Mapped[int] = mapped_column(ForeignKey("assets.id"), index=True, nullable=False)
    task_type: Mapped[str] = mapped_column(String(32), index=True, nullable=False)
    name: Mapped[str] = mapped_column(String(128), default="")
    state: Mapped[str] = mapped_column(String(16), default="pending", index=True)
    round_no: Mapped[int] = mapped_column(Integer, default=1, index=True)   # 扫描轮次
    # 进度
    progress: Mapped[int] = mapped_column(Integer, default=0)               # 0-100
    stage: Mapped[str] = mapped_column(String(128), default="pending")      # 当前阶段描述
    total_items: Mapped[int] = mapped_column(Integer, default=0)
    done_items: Mapped[int] = mapped_column(Integer, default=0)
    # 控制
    rate_limit: Mapped[float] = mapped_column(Integer, default=300)         # 毫秒/请求
    paused_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    # 结果统计
    vuln_count: Mapped[int] = mapped_column(Integer, default=0)
    error_msg: Mapped[str | None] = mapped_column(Text, nullable=True)
    # 本轮发现的 vuln_key 快照（JSON 数组，用于轮次对比）
    found_keys: Mapped[str] = mapped_column(Text, default="[]")
    # 参数 JSON（如扫描字典、端口范围、Cookie）
    params: Mapped[str | None] = mapped_column(Text, nullable=True)
    # 调度
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
    started_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    finished_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    scheduled_for: Mapped[datetime | None] = mapped_column(DateTime, nullable=True, index=True)
    triggered_by: Mapped[str] = mapped_column(String(16), default="manual")  # manual/cron/api
