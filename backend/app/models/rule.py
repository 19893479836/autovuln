"""规则库模型：漏洞规则 / 指纹规则 / POC 脚本"""
from datetime import datetime

from sqlalchemy import Boolean, DateTime, Float, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from ..database import Base


class Rule(Base):
    """漏洞检测规则（可在线更新/手动导入，禁止写死）"""

    __tablename__ = "rules"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    rule_key: Mapped[str] = mapped_column(String(128), unique=True, index=True, nullable=False)
    name: Mapped[str] = mapped_column(String(256), nullable=False)
    vuln_type: Mapped[str] = mapped_column(String(64), index=True, nullable=False)
    severity: Mapped[str] = mapped_column(String(16), default="medium")
    cvss_score: Mapped[float] = mapped_column(Float, default=0.0)
    # 匹配逻辑
    method: Mapped[str] = mapped_column(String(8), default="GET")
    path: Mapped[str] = mapped_column(String(256), default="/")
    headers: Mapped[str] = mapped_column(Text, default="{}")   # JSON
    body: Mapped[str | None] = mapped_column(Text, nullable=True)
    params: Mapped[str] = mapped_column(Text, default="[]")    # JSON
    # 响应匹配
    match_regex: Mapped[str | None] = mapped_column(Text, nullable=True)   # 响应体正则
    match_header: Mapped[str | None] = mapped_column(Text, nullable=True)  # 响应头键:值正则
    match_status: Mapped[str | None] = mapped_column(String(64), nullable=True)  # 逗号分隔 200,302
    # 指纹条件（可选：命中某指纹才检测）
    fingerprint_hint: Mapped[str | None] = mapped_column(String(128), nullable=True)
    # 描述与修复
    description: Mapped[str | None] = mapped_column(Text, nullable=True)
    fix_suggestion: Mapped[str | None] = mapped_column(Text, nullable=True)
    reference: Mapped[str | None] = mapped_column(Text, nullable=True)
    # 误报反馈：被标记误报次数，用于反向抑制
    fp_count: Mapped[int] = mapped_column(Integer, default=0)
    fp_suppress: Mapped[bool] = mapped_column(Boolean, default=False)
    enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    source: Mapped[str] = mapped_column(String(32), default="builtin")  # builtin/import/remote
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)


class FingerprintRule(Base):
    """指纹规则：识别 CMS / 框架 / 中间件 / 组件版本"""

    __tablename__ = "fingerprint_rules"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    fp_key: Mapped[str] = mapped_column(String(128), unique=True, index=True, nullable=False)
    name: Mapped[str] = mapped_column(String(128), nullable=False)       # 如 nginx / wordpress
    category: Mapped[str] = mapped_column(String(32), default="server")  # cms/framework/middleware/component
    # 匹配特征（JSON 数组）：{type: header|body|title|icon, pattern: 正则, }
    rules: Mapped[str] = mapped_column(Text, default="[]")
    cpe: Mapped[str | None] = mapped_column(String(64), nullable=True)   # CPE 用于关联 CVE
    enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    source: Mapped[str] = mapped_column(String(32), default="builtin")
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)


class PocScript(Base):
    """POC 脚本：插件式验证引擎"""

    __tablename__ = "poc_scripts"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    poc_key: Mapped[str] = mapped_column(String(128), unique=True, index=True, nullable=False)
    name: Mapped[str] = mapped_column(String(256), nullable=False)
    vuln_type: Mapped[str] = mapped_column(String(64), index=True, nullable=False)
    severity: Mapped[str] = mapped_column(String(16), default="high")
    # 脚本类型: http(simple http check) / python(沙箱执行)
    script_type: Mapped[str] = mapped_column(String(16), default="http")
    # HTTP 型：method/path/headers/body/match
    script_data: Mapped[str] = mapped_column(Text, default="{}")
    # Python 型：源码（受限沙箱执行）
    script_source: Mapped[str | None] = mapped_column(Text, nullable=True)
    fingerprint_hint: Mapped[str | None] = mapped_column(String(128), nullable=True)
    enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    source: Mapped[str] = mapped_column(String(32), default="builtin")
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
