"""Pydantic 请求/响应模型（集中定义）"""
from datetime import datetime
from typing import Any, Generic, TypeVar

from pydantic import BaseModel, EmailStr, Field

T = TypeVar("T")


# ---------------- 通用 ----------------
class Page(BaseModel, Generic[T]):
    total: int
    items: list[T]


class Msg(BaseModel):
    msg: str


# ---------------- 认证 ----------------
class RegisterIn(BaseModel):
    username: str = Field(min_length=3, max_length=32)
    email: EmailStr
    password: str = Field(min_length=6, max_length=64)
    invite_code: str = ""


class LoginIn(BaseModel):
    username: str
    password: str


class UserOut(BaseModel):
    id: int
    username: str
    email: str
    role: str
    created_at: datetime | None = None

    class Config:
        from_attributes = True


class TokenOut(BaseModel):
    access_token: str
    token_type: str = "bearer"
    user: UserOut


# ---------------- 资产 ----------------
class AssetImportIn(BaseModel):
    targets: list[str] = Field(min_length=1)
    group_id: int | None = None
    tags: str = ""
    importance: str = "medium"
    # 认证态扫描：登录会话 Cookie（`k=v; k2=v2`），扫描时随请求携带
    cookie: str = ""


class AssetUpdateIn(BaseModel):
    group_id: int | None = None
    tags: str | None = None
    importance: str | None = None
    description: str | None = None
    cookie: str | None = None


class AssetOut(BaseModel):
    id: int
    kind: str
    value: str
    tags: str
    status: str
    importance: str
    group_id: int | None = None
    last_seen_at: datetime | None = None
    created_at: datetime | None = None
    vuln_count: int = 0
    has_cookie: bool = False  # 是否配置了认证 Cookie（不回传明文，防泄露）

    class Config:
        from_attributes = True


class GroupIn(BaseModel):
    name: str
    description: str = ""
    importance: str = "medium"


class GroupOut(BaseModel):
    id: int
    name: str
    description: str | None = None
    importance: str
    asset_count: int = 0

    class Config:
        from_attributes = True


# ---------------- 扫描 ----------------
class ScanCreate(BaseModel):
    asset_id: int
    task_type: str = Field(pattern="^(recon_subdomain|recon_port|recon_fingerprint|recon_jsapi|recon_crawler|recon_path|vuln_web|vuln_cve|vuln_poc|vuln_weakpass|full)$")
    name: str = ""
    rate_limit: int | None = Field(default=None, ge=50, le=60000)  # 毫秒，缺省用 DEFAULT_RATE_LIMIT 全局配置
    params: dict[str, Any] = Field(default_factory=dict)
    scheduled_for: datetime | None = None


class ScanOut(BaseModel):
    id: int
    asset_id: int
    asset_value: str = ""
    task_type: str
    name: str
    state: str
    round_no: int
    progress: int
    stage: str
    rate_limit: int
    vuln_count: int
    error_msg: str | None = None
    created_at: datetime | None = None
    started_at: datetime | None = None
    finished_at: datetime | None = None
    scheduled_for: datetime | None = None

    class Config:
        from_attributes = True


# ---------------- 漏洞 ----------------
class VulnOut(BaseModel):
    id: int
    asset_id: int
    asset_value: str = ""
    title: str
    vuln_type: str
    severity: str
    cvss_score: float = 0.0
    confidence: str
    state: str
    url: str | None = None
    param: str | None = None
    description: str | None = None
    payload: str | None = None
    cve_id: str | None = None
    cnvd_id: str | None = None
    reference: list[str] = []
    assignee: str | None = None
    due_date: datetime | None = None
    fix_suggestion: str | None = None
    request_raw: str | None = None
    response_raw: str | None = None
    evidence_files: list[str] = []
    first_seen_at: datetime | None = None
    last_seen_at: datetime | None = None
    resolved_at: datetime | None = None

    class Config:
        from_attributes = True


class VulnTransitionIn(BaseModel):
    to_state: str = Field(pattern="^(pending|confirmed|fixing|fixed|verified|false_positive|ignored)$")
    comment: str = ""


class BatchActionIn(BaseModel):
    action: str = Field(pattern="^(confirm|ignore|assign|mark_fixed)$")
    vuln_ids: list[int]
    assignee: str | None = None
    comment: str = ""


class RoundCompareIn(BaseModel):
    round_a: int
    round_b: int


class VulnQuery(BaseModel):
    severity: str = ""
    state: str = ""
    vuln_type: str = ""
    asset_id: int | None = None
    keyword: str = ""
    page: int = 1
    page_size: int = 20


# ---------------- 报告 ----------------
class ReportCreateIn(BaseModel):
    fmt: str = Field(pattern="^(html|pdf|json|excel)$")
    title: str
    asset_ids: list[int] | None = None


class ReportOut(BaseModel):
    id: int
    title: str
    fmt: str
    file_path: str
    scope_desc: str | None = None
    stats: dict = {}
    created_at: datetime | None = None

    class Config:
        from_attributes = True


# ---------------- 规则 ----------------
class RuleIn(BaseModel):
    name: str
    vuln_type: str
    severity: str = "medium"
    cvss_score: float = 0.0
    method: str = "GET"
    path: str = "/"
    headers: dict = {}
    body: str | None = None
    match_regex: str | None = None
    match_header: str | None = None
    match_status: str | None = None
    fingerprint_hint: str | None = None
    description: str | None = None
    fix_suggestion: str | None = None
    reference: str | None = None
    enabled: bool = True


class FingerprintRuleIn(BaseModel):
    name: str
    category: str = "server"
    rules: list[dict]
    cpe: str | None = None
    enabled: bool = True


class PocIn(BaseModel):
    name: str
    vuln_type: str
    severity: str = "high"
    script_type: str = "http"
    script_data: dict = {}
    script_source: str | None = None
    fingerprint_hint: str | None = None
    enabled: bool = True


# ---------------- 通知 / 管理 ----------------
class NotifyConfigIn(BaseModel):
    channels: list[str] = []
    webhook_url: str = ""
    threshold: str = "high"


class AuditOut(BaseModel):
    id: int
    username: str
    action: str
    target_type: str | None = None
    target_id: int | None = None
    detail: str | None = None
    ip: str | None = None
    created_at: datetime | None = None

    class Config:
        from_attributes = True
