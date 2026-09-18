"""POC 检测引擎：批量加载并执行 POC 脚本验证

支持脚本类型：
- http：结构化 HTTP 探测（method/path/headers/body/match）
- python：安全策略下已禁用执行（仅跳过并记录原因）。
  历史原因：原 exec 受限沙箱可被对象子类链逃逸，构成服务器 RCE 风险；
  如需 Python 型 POC，请改为在隔离子进程/容器中运行，或改用 HTTP 型 POC。
"""
import json
import re

from ..database import SessionLocal
from ..models import Asset, PocScript, ScanTask
from .base import BaseScanner, http_request


class PocEngine(BaseScanner):
    name = "vuln_poc"
    display_name = "POC 验证引擎"

    def run(self):
        asset = self._get_asset()
        if not asset:
            return
        with SessionLocal() as db:
            pocs = db.query(PocScript).filter_by(enabled=True).all()
            pocs = [p for p in pocs]

        base = asset.value if asset.value.startswith(("http://", "https://")) else "http://" + asset.value
        self.log(f"POC 引擎: {base}，加载 {len(pocs)} 个 POC")
        total = len(pocs)
        done = 0
        for poc in pocs:
            self.checkpoint()
            try:
                if poc.script_type == "http":
                    self._run_http_poc(poc, base)
                elif poc.script_type == "python":
                    self._run_python_poc(poc, base)
            except Exception as e:
                self.log(f"POC {poc.name} 执行异常: {e}")
            done += 1
            self.set_progress(done, total, f"POC {done}/{total}: {poc.name}")
        self.log("POC 引擎执行完成")

    # ---- HTTP 型 ----
    def _run_http_poc(self, poc: PocScript, base: str):
        try:
            data = json.loads(poc.script_data or "{}")
        except Exception:
            return
        path = data.get("path", "/")
        url = base.rstrip("/") + "/" + path.lstrip("/")
        method = data.get("method", "GET")
        headers = data.get("headers", {})
        body = data.get("body")
        match = data.get("match", {})
        try:
            status, resp_headers, resp_body = http_request(
                url, method=method, headers=headers, body=body, timeout=12,
            )
        except Exception:
            return
        ok = True
        if match.get("status"):
            if int(match["status"]) != status:
                ok = False
        if ok and match.get("regex"):
            if not re.search(match["regex"], resp_body, re.I):
                ok = False
        if ok and match.get("header"):
            try:
                hk, hv = match["header"].split(":", 1)
                if not re.search(hv.strip(), resp_headers.get(hk.strip().lower(), ""), re.I):
                    ok = False
            except Exception:
                ok = False
        if ok:
            self.find_vuln(
                title=f"[POC] {poc.name}", vuln_type=poc.vuln_type,
                severity=poc.severity, url=url, confidence="high",
                description=f"POC 验证成功: {poc.name}",
                request_raw=f"{method} {url}", response_raw=resp_body[:2000],
                fix_suggestion="请升级受影响组件或按官方公告处置",
                vuln_key=f"poc|{poc.poc_key}|{base}",
            )

    # ---- Python 型（安全策略：禁用执行） ----
    def _run_python_poc(self, poc: PocScript, base: str):
        """Python 型 POC 已禁用：受限沙箱可逃逸，改为安全跳过并记录。"""
        self.log(f"POC {poc.name} 为 python 型，已被安全策略禁用（避免沙箱逃逸 RCE），请改用 http 型 POC")

    def _get_asset(self):
        with SessionLocal() as db:
            task = db.get(ScanTask, self.task_id)
            return db.get(Asset, task.asset_id) if task else None
