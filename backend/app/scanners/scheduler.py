"""任务调度器：线程池执行 + 全流程编排 + 定时任务

- 并发数由 SCAN_CONCURRENCY 控制
- full 类型按 L1→L4 流水线顺序编排
- 支持取消/暂停/恢复（通过 task_manager）
"""
import threading
import time
from datetime import datetime

from ..config import settings
from ..database import SessionLocal
from ..models import ScanTask
from .base import TaskCancelled, task_manager
from .subdomain import SubdomainScanner
from .portscan import PortScanScanner
from .fingerprint import FingerprintScanner
from .jsapi import JsApiScanner
from .pathscan import PathScanScanner
from .crawler import ReconCrawlerScanner
from .webscan import WebVulnScanner
from .cve import CveScanner
from .poc_engine import PocEngine
from .weakpass import WeakPassScanner

SCANNER_MAP = {
    "recon_subdomain": SubdomainScanner,
    "recon_port": PortScanScanner,
    "recon_fingerprint": FingerprintScanner,
    "recon_jsapi": JsApiScanner,
    "recon_path": PathScanScanner,
    "recon_crawler": ReconCrawlerScanner,
    "vuln_web": WebVulnScanner,
    "vuln_cve": CveScanner,
    "vuln_poc": PocEngine,
    "vuln_weakpass": WeakPassScanner,
}

# full 编排顺序（资产主体类型感知，运行时动态裁剪）
FULL_PIPELINE = [
    ("recon_subdomain", ["domain"]),
    ("recon_port", ["domain", "ip"]),
    ("recon_fingerprint", ["domain", "ip", "url"]),
    ("recon_jsapi", ["domain", "url"]),
    ("recon_crawler", ["domain", "ip", "url"]),
    ("recon_path", ["domain", "ip", "url"]),
    ("vuln_web", ["domain", "ip", "url"]),
    ("vuln_weakpass", ["domain", "ip", "url"]),
    ("vuln_cve", ["domain", "ip", "url"]),
    ("vuln_poc", ["domain", "ip", "url"]),
]


class Scheduler:
    """全局调度器单例"""

    def __init__(self):
        self._threads: dict[int, threading.Thread] = {}
        self._lock = threading.Lock()
        self._running = True
        self._worker = None

    def start(self):
        if self._worker and self._worker.is_alive():
            return
        self._worker = threading.Thread(target=self._loop, daemon=True, name="autovuln-scheduler")
        self._worker.start()

    def _loop(self):
        """后台循环：派发 pending 任务 + 检查定时任务"""
        while self._running:
            try:
                self._dispatch_pending()
            except Exception:
                pass
            time.sleep(1.0)

    def _dispatch_pending(self):
        with SessionLocal() as db:
            # 并发上限
            running = task_manager.running_tasks()
            quota = settings.SCAN_CONCURRENCY - len(running)
            if quota <= 0:
                return
            tasks = (
                db.query(ScanTask)
                .filter(ScanTask.state == "pending")
                .order_by(ScanTask.scheduled_for.asc().nullsfirst(), ScanTask.id.asc())
                .limit(quota)
                .all()
            )
            for t in tasks:
                # 定时任务未到时间跳过
                if t.scheduled_for and t.scheduled_for > datetime.utcnow():
                    continue
                self._spawn(t)

    def _spawn(self, task: ScanTask):
        task_id = task.id
        task_manager.register(task_id)
        task_manager.set_state(task_id, "running")
        thr = threading.Thread(target=self._run_task, args=(task_id,), daemon=True)
        with self._lock:
            self._threads[task_id] = thr
        thr.start()

    def _run_task(self, task_id: int):
        try:
            with SessionLocal() as db:
                task = db.get(ScanTask, task_id)
                task_type = task.task_type

            if task_type == "full":
                self._run_full(task_id)
            else:
                scanner_cls = SCANNER_MAP.get(task_type)
                if scanner_cls:
                    scanner_cls(task_id).execute()
        finally:
            task_manager.remove(task_id)
            with self._lock:
                self._threads.pop(task_id, None)

    def _run_full(self, task_id: int):
        """full 编排：按资产类型裁剪流水线，顺序执行各扫描器。
        子扫描器以 as_subtask=True 运行，不覆盖整体任务状态。"""
        from ..models import Asset
        with SessionLocal() as db:
            task = db.get(ScanTask, task_id)
            asset = db.get(Asset, task.asset_id)
            kind = asset.kind if asset else "domain"
            task.state = "running"
            task.started_at = datetime.utcnow()
            db.commit()

        try:
            # 本资产适用的流水线阶段数（用于折算整体进度）
            applicable = [st for st, kinds in FULL_PIPELINE if kind in kinds]
            total_stages = len(applicable) or 1
            done_stages = 0
            for scan_type, supported_kinds in FULL_PIPELINE:
                # 检查取消/暂停
                ctl = task_manager.get(task_id)
                if ctl and ctl.cancel_event.is_set():
                    raise TaskCancelled(task_id)
                if ctl and not ctl.pause_event.is_set():
                    ctl.pause_event.wait()
                if kind not in supported_kinds:
                    continue
                with SessionLocal() as db:
                    task = db.get(ScanTask, task_id)
                    if task:
                        task.stage = f"执行 {SCANNER_MAP[scan_type].display_name}"
                        db.commit()
                cls = SCANNER_MAP[scan_type]
                cls(task_id).execute(as_subtask=True)
                done_stages += 1
                # 子扫描器完成：按阶段折算主任务进度（保留 2% 空间给收尾）
                with SessionLocal() as db:
                    task = db.get(ScanTask, task_id)
                    if task:
                        task.progress = min(98, int(done_stages / total_stages * 100))
                        db.commit()
        except TaskCancelled:
            with SessionLocal() as db:
                task = db.get(ScanTask, task_id)
                if task:
                    task.state = "cancelled"
                    task.finished_at = datetime.utcnow()
                    db.commit()
            return
        except Exception as e:
            with SessionLocal() as db:
                task = db.get(ScanTask, task_id)
                if task:
                    task.state = "failed"
                    task.error_msg = str(e)[:500]
                    task.finished_at = datetime.utcnow()
                    db.commit()
            return

        # 全部子扫描器完成
        with SessionLocal() as db:
            task = db.get(ScanTask, task_id)
            if task and task.state not in ("cancelled", "failed"):
                task.state = "completed"
                task.progress = 100
                task.finished_at = datetime.utcnow()
                db.commit()

    # ---- 对外控制 API ----
    def pause(self, task_id: int) -> bool:
        return task_manager.set_state(task_id, "paused")

    def resume(self, task_id: int) -> bool:
        return task_manager.set_state(task_id, "running")

    def cancel(self, task_id: int) -> bool:
        return task_manager.set_state(task_id, "cancelled")

    def shutdown(self):
        self._running = False


scheduler = Scheduler()
