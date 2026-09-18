"""扫描器基类与任务控制中心

设计要点：
- 限速 / 暂停 / 恢复 / 取消 / 进度上报 全部在基类统一实现
- 子类只需实现 run()，内部通过 self.checkpoint() 协作
- 所有扫描器访问 DB 均携带 user_id（多租户硬边界）
"""
import json
import threading
import time
import urllib.request
import ssl
from dataclasses import dataclass, field
from datetime import datetime
from typing import Callable

from sqlalchemy.orm import Session

from ..config import settings
from ..database import SessionLocal
from ..models import Asset, ScanTask, AssetRecord, Vulnerability, VulnStatusHistory

# ---------------- 任务控制中心 ----------------
@dataclass
class TaskControl:
    state: str = "pending"          # pending/running/paused/cancelled
    pause_event: threading.Event = field(default_factory=threading.Event)
    cancel_event: threading.Event = field(default_factory=threading.Event)

    def __post_init__(self):
        self.pause_event.set()  # 默认不暂停


class TaskManager:
    """全局任务控制中心：task_id → 控制句柄"""

    def __init__(self):
        self._controls: dict[int, TaskControl] = {}
        self._lock = threading.Lock()

    def register(self, task_id: int) -> TaskControl:
        with self._lock:
            c = TaskControl(state="pending")
            self._controls[task_id] = c
            return c

    def get(self, task_id: int) -> TaskControl | None:
        return self._controls.get(task_id)

    def remove(self, task_id: int):
        with self._lock:
            self._controls.pop(task_id, None)

    def set_state(self, task_id: int, state: str) -> bool:
        c = self.get(task_id)
        if not c:
            return False
        c.state = state
        if state == "paused":
            c.pause_event.clear()
        elif state in ("running", "pending"):
            c.pause_event.set()
        if state == "cancelled":
            c.cancel_event.set()
            c.pause_event.set()
        return True

    def running_tasks(self) -> list[int]:
        return [tid for tid, c in self._controls.items() if c.state in ("running", "pending")]


task_manager = TaskManager()


# ---------------- HTTP 工具 ----------------
def _no_verify_ssl() -> ssl.SSLContext:
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    return ctx


class _NoRedirectHandler(urllib.request.HTTPRedirectHandler):
    """不跟随重定向：遇到 3xx 直接返回响应对象"""
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def http_request(
    url: str,
    method: str = "GET",
    headers: dict | None = None,
    body: str | bytes | None = None,
    timeout: int | None = None,
    allow_redirects: bool = True,
) -> tuple[int, dict, str]:
    """标准库 HTTP 请求，返回 (状态码, 响应头dict, 响应体文本)。失败抛异常。"""
    req = urllib.request.Request(url, method=method)
    default_headers = {
        "User-Agent": "AutoVuln/1.0 (security research scanner)",
        "Accept": "*/*",
    }
    for k, v in {**default_headers, **(headers or {})}.items():
        req.add_header(k, v)
    data = None
    if body is not None:
        data = body.encode() if isinstance(body, str) else body
    ctx = _no_verify_ssl()
    if allow_redirects:
        opener = urllib.request.build_opener(urllib.request.HTTPSHandler(context=ctx))
    else:
        opener = urllib.request.build_opener(
            urllib.request.HTTPSHandler(context=ctx),
            _NoRedirectHandler(),
        )
    try:
        resp = opener.open(req, data=data, timeout=timeout or settings.SCAN_TIMEOUT)
    except urllib.error.HTTPError as e:
        # 3xx 在不跟随重定向时会以 HTTPError 形式返回
        if not allow_redirects and e.code in (301, 302, 303, 307, 308):
            status = e.code
            headers_dict = {k.lower(): v for k, v in e.headers.items()}
            return status, headers_dict, ""
        raise
    status = resp.status
    headers_dict = {k.lower(): v for k, v in resp.headers.items()}
    raw = resp.read()
    # 优先按 charset 解码，失败则 utf-8 容错
    try:
        body_text = raw.decode("utf-8", errors="replace")
    except Exception:
        body_text = raw.decode("latin-1", errors="replace")
    return status, headers_dict, body_text


# ---------------- 扫描器基类 ----------------
class BaseScanner:
    """所有扫描器基类。

    子类实现:
        name: 扫描器名
        run(self, ctx): 执行扫描
    ctx 提供:
        task, asset, db, log, checkpoint, find_vuln, add_record
    """

    name = "base"
    display_name = "基础扫描器"

    def __init__(self, task_id: int):
        self.task_id = task_id
        self.control = task_manager.get(task_id)
        self._last_req = 0.0
        self._rate_ms = 0
        self.as_subtask = False  # full 流水线内的子扫描器置 True，不覆盖主任务进度

    # ---- 控制 ----
    def checkpoint(self, pause_hint: str = ""):
        """协作点：检查暂停/取消。子类在每个循环迭代调用。"""
        c = self.control
        if c is None:
            return
        if c.cancel_event.is_set():
            raise TaskCancelled(self.task_id)
        if not c.pause_event.is_set():
            # 暂停中：更新 DB 状态
            with SessionLocal() as db:
                task = db.get(ScanTask, self.task_id)
                if task and task.state != "paused":
                    task.state = "paused"
                    task.paused_at = datetime.utcnow()
                    db.commit()
            c.pause_event.wait()  # 阻塞直至恢复
            with SessionLocal() as db:
                task = db.get(ScanTask, self.task_id)
                if task and task.state == "paused":
                    task.state = "running"
                    task.paused_at = None
                    db.commit()
        # 限速
        self._throttle()

    def _throttle(self):
        """按任务的 rate_limit(毫秒) 限速"""
        if self._rate_ms <= 0:
            with SessionLocal() as db:
                task = db.get(ScanTask, self.task_id)
                self._rate_ms = int(getattr(task, "rate_limit", 0) or 0) if task else 0
        if self._rate_ms > 0:
            elapsed = time.time() - self._last_req
            need = self._rate_ms / 1000.0
            if elapsed < need:
                time.sleep(need - elapsed)
        self._last_req = time.time()

    # ---- 进度 ----
    def set_progress(self, done: int, total: int, stage: str):
        with SessionLocal() as db:
            task = db.get(ScanTask, self.task_id)
            if task:
                task.done_items = done
                task.total_items = total
                # 子扫描器（full 流水线内）不覆盖主任务整体进度，由调度器按阶段折算
                if not self.as_subtask:
                    task.progress = min(100, int(done / total * 100)) if total else 0
                task.stage = stage[:128]
                db.commit()

    def log(self, msg: str):
        with SessionLocal() as db:
            task = db.get(ScanTask, self.task_id)
            if task:
                task.stage = msg[:128]
                db.commit()

    def mark_failed(self, err: str):
        with SessionLocal() as db:
            task = db.get(ScanTask, self.task_id)
            if task:
                task.state = "failed"
                task.error_msg = err[:500]
                task.finished_at = datetime.utcnow()
                db.commit()

    # ---- 写结果 ----
    def add_record(self, kind: str, key: str, value: str | None = None,
                   detail: dict | None = None, source: str = "scanner"):
        """写入资产聚合记录（自动去重）"""
        with SessionLocal() as db:
            task = db.get(ScanTask, self.task_id)
            asset = db.get(Asset, task.asset_id) if task else None
            if not asset:
                return
            exist = db.query(AssetRecord).filter_by(
                user_id=asset.user_id, asset_id=asset.id, kind=kind, key=key[:512],
            ).first()
            if exist:
                exist.source = source
                if value:
                    exist.value = value
                if detail:
                    exist.detail = json.dumps(detail, ensure_ascii=False)
                db.commit()
                return
            db.add(AssetRecord(
                user_id=asset.user_id, asset_id=asset.id, kind=kind, key=key[:512],
                value=value, detail=json.dumps(detail, ensure_ascii=False) if detail else None,
                source=source,
            ))
            db.commit()

    def find_vuln(self, title: str, vuln_type: str, severity: str,
                  url: str | None = None, param: str | None = None,
                  description: str | None = None, payload: str | None = None,
                  request_raw: str | None = None, response_raw: str | None = None,
                  confidence: str = "medium", cvss_score: float = 0.0,
                  cve_id: str | None = None, reference: list[str] | None = None,
                  fix_suggestion: str | None = None, vuln_key: str | None = None,
                  evidence_files: list[str] | None = None):
        """按 vuln_key 幂等写入漏洞：同资产同键则更新 last_seen，不重复建。"""
        with SessionLocal() as db:
            task = db.get(ScanTask, self.task_id)
            if not task:
                return
            asset = db.get(Asset, task.asset_id)
            key = vuln_key or f"{vuln_type}|{url or ''}|{param or ''}"
            # 记录到本轮任务快照（轮次对比用）
            try:
                keys = json.loads(task.found_keys or "[]")
                if key[:256] not in keys:
                    keys.append(key[:256])
                    task.found_keys = json.dumps(keys, ensure_ascii=False)
            except Exception:
                pass
            exist = db.query(Vulnerability).filter_by(
                user_id=task.user_id, asset_id=task.asset_id, vuln_key=key[:256],
            ).first()
            now = datetime.utcnow()
            if exist:
                exist.last_seen_at = now
                exist.title = title
                exist.severity = severity
                exist.confidence = confidence
                if request_raw:
                    exist.request_raw = request_raw
                if response_raw:
                    exist.response_raw = response_raw[:10000]
                db.commit()
                return exist.id
            vuln = Vulnerability(
                user_id=task.user_id, asset_id=task.asset_id, task_id=task.id,
                vuln_key=key[:256], title=title[:256], vuln_type=vuln_type,
                severity=severity, cvss_score=cvss_score, confidence=confidence,
                state="pending", url=url, param=param,
                description=description, payload=payload,
                request_raw=request_raw, response_raw=(response_raw or "")[:10000],
                evidence_files=json.dumps(evidence_files or [], ensure_ascii=False),
                cve_id=cve_id, reference=json.dumps(reference or [], ensure_ascii=False),
                fix_suggestion=fix_suggestion,
                first_seen_at=now, last_seen_at=now,
            )
            db.add(vuln)
            db.flush()
            db.add(VulnStatusHistory(
                vuln_id=vuln.id, from_state=None, to_state="pending",
                operator=f"scanner:{self.name}",
            ))
            task.vuln_count += 1
            db.commit()
            # 高危漏洞触发通知（不阻塞扫描）
            try:
                from ..services.notify import notify_vuln_found
                channels = []
                if settings.WEBHOOK_URL:
                    channels.append("webhook")
                if settings.SMTP_HOST:
                    channels.append("email")
                if channels:
                    notify_vuln_found(db, vuln, channels)
            except Exception:
                pass
            return vuln.id

    # ---- 主入口 ----
    def execute(self, as_subtask: bool = False):
        """由调度器调用：状态机 + 异常处理。
        as_subtask=True 时（full 流水线中的子扫描器），不修改整体任务的 state/finished_at，
        只更新进度和阶段描述。"""
        self.as_subtask = as_subtask
        with SessionLocal() as db:
            task = db.get(ScanTask, self.task_id)
            if task and not as_subtask:
                task.state = "running"
                task.started_at = datetime.utcnow()
                db.commit()
        try:
            self.run()
            if not as_subtask:
                with SessionLocal() as db:
                    task = db.get(ScanTask, self.task_id)
                    if task and task.state not in ("cancelled", "failed"):
                        task.state = "completed"
                        task.progress = 100
                        task.finished_at = datetime.utcnow()
                        db.commit()
        except TaskCancelled:
            if not as_subtask:
                with SessionLocal() as db:
                    task = db.get(ScanTask, self.task_id)
                    if task:
                        task.state = "cancelled"
                        task.finished_at = datetime.utcnow()
                        db.commit()
            raise
        except Exception as e:  # noqa: BLE001
            with SessionLocal() as db:
                task = db.get(ScanTask, self.task_id)
                if task:
                    task.state = "failed"
                    task.error_msg = str(e)[:500]
                    if not as_subtask:
                        task.finished_at = datetime.utcnow()
                    db.commit()
            self.log(f"扫描器异常: {e}")
            if as_subtask:
                raise


class TaskCancelled(Exception):
    def __init__(self, task_id: int):
        super().__init__(f"任务 {task_id} 已取消")
        self.task_id = task_id
