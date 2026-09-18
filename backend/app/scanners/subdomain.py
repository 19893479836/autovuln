"""子域名枚举扫描器：被动（证书透明日志 crt.sh）+ 主动（字典 DNS 爆破）双通道"""
import json
import re
import socket
import time
import urllib.request

from .base import BaseScanner


class SubdomainScanner(BaseScanner):
    name = "recon_subdomain"
    display_name = "子域名枚举"

    # 内置小字典（可被任务 params 覆盖，规则可更新）
    DEFAULT_WORDS = [
        "www", "mail", "web", "api", "app", "admin", "oa", "vpn", "portal", "test",
        "dev", "stage", "demo", "shop", "store", "m", "mobile", "img", "static",
        "cdn", "blog", "news", "bbs", "forum", "git", "svn", "jenkins", "ftp",
        "dns", "ns1", "ns2", "smtp", "pop", "imap", "mx", "db", "mysql", "redis",
        "grafana", "monitor", "zabbix", "jumpserver", "sso", "auth", "login", "pay",
    ]

    PASSIVE_SOURCES = ["crt.sh"]

    def run(self):
        import socket as _s
        asset = self._get_asset()
        if not asset:
            return
        domain = asset.value
        params = self._get_params()
        words = params.get("words") or self.DEFAULT_WORDS
        sources = params.get("sources") or self.PASSIVE_SOURCES

        found: set[str] = set()
        total = len(words) + 2
        done = 0

        # ---- 被动通道 ----
        if "crt.sh" in sources:
            self.log("被动收集：查询证书透明日志 crt.sh")
            try:
                url = f"https://crt.sh/?q=%25.{domain}&output=json"
                req = urllib.request.Request(url, headers={"User-Agent": "AutoVuln/1.0"})
                with urllib.request.urlopen(req, timeout=30) as resp:
                    data = json.loads(resp.read().decode())
                for row in data:
                    name = (row.get("name_value") or "").strip()
                    for n in re.split(r"\s+", name):
                        n = n.strip().lower()
                        if n.endswith("." + domain) and "*" not in n:
                            found.add(n)
            except Exception as e:
                self.log(f"crt.sh 查询失败: {e}")
            done += 1
            self.set_progress(done, total, "被动收集完成")

        # ---- 主动通道 ----
        self.checkpoint()
        self.log("主动爆破：字典 DNS 解析")
        for word in words:
            self.checkpoint()
            sub = f"{word}.{domain}"
            try:
                socket.getaddrinfo(sub, None)
                found.add(sub)
            except Exception:
                pass
            done += 1
            # DNS 查询限速：每 50ms 一个，对权威 DNS 友好
            time.sleep(0.05)
            if done % 5 == 0:
                self.set_progress(done, total, f"爆破中: {sub}")

        # ---- 聚合写库 ----
        self.set_progress(total, total, "写入结果")
        for sub in sorted(found):
            self.checkpoint()
            self.add_record("subdomain", sub, value=sub, detail={"domain": domain}, source="crt.sh+brute")
        self.log(f"子域名枚举完成，共发现 {len(found)} 个")

    def _get_asset(self):
        from ..database import SessionLocal
        from ..models import Asset, ScanTask
        with SessionLocal() as db:
            task = db.get(ScanTask, self.task_id)
            return db.get(Asset, task.asset_id) if task else None

    def _get_params(self) -> dict:
        import json as _json
        from ..database import SessionLocal
        from ..models import ScanTask
        with SessionLocal() as db:
            task = db.get(ScanTask, self.task_id)
            try:
                return _json.loads(task.params or "{}")
            except Exception:
                return {}
