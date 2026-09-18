"""目录/路径爆破扫描器：内置字典探测敏感目录与文件"""
from urllib.parse import urljoin

from .base import BaseScanner, http_request

DEFAULT_PATH_DICT = [
    "/admin", "/admin/", "/login", "/login.php", "/wp-admin", "/wp-login.php",
    "/administrator", "/manage", "/manager", "/console", "/api", "/api/",
    "/swagger", "/swagger-ui.html", "/v2/api-docs", "/v3/api-docs", "/actuator",
    "/actuator/health", "/actuator/env", "/actuator/beans", "/druid", "/druid/index.html",
    "/config", "/config.php", "/backup", "/backup.zip", "/backup.tar.gz", "/db",
    "/database.sql", "/dump.sql", "/.git/", "/.git/config", "/.svn/", "/.env",
    "/phpinfo.php", "/info.php", "/test.php", "/robots.txt", "/sitemap.xml",
    "/crossdomain.xml", "/web.config", "/WEB-INF/web.xml", "/.htaccess",
    "/server-status", "/phpmyadmin", "/pma", "/uploads/", "/upload/", "/files/",
    "/download/", "/tmp/", "/temp/", "/logs/", "/log/", "/error", "/404",
    "/jenkins", "/gitlab", "/grafana", "/kibana", "/zabbix", "/nacos", "/consul",
    "/dubbo", "/seata", "/xxl-job", "/xxl-job-admin", "/quartz", "/monitor",
]


class PathScanScanner(BaseScanner):
    name = "recon_path"
    display_name = "目录/路径爆破"

    def run(self):
        asset = self._get_asset()
        if not asset:
            return
        base = asset.value if asset.value.startswith(("http://", "https://")) else "http://" + asset.value
        params = self._get_params()
        paths = params.get("paths") or DEFAULT_PATH_DICT

        self.log(f"目录爆破: {base}")
        total = len(paths)
        done = 0
        found = []

        # 连通性预检：先请求首页，连不上直接放弃，不再逐个超时等待
        try:
            http_request(base, timeout=5)
        except Exception:
            self.set_progress(total, total, "目标不可达，已跳过")
            self.log(f"目录爆破跳过：无法连接 {base}")
            self.mark_failed(f"目标 {base} 无法连接（超时/拒绝），请检查网络或目标存活状态")
            return

        for p in paths:
            self.checkpoint()
            url = urljoin(base + "/", p.lstrip("/"))
            try:
                status, headers, body = http_request(url, timeout=5, allow_redirects=False)
            except Exception:
                done += 1
                continue
            # 记录有意义的响应（200/301/302/401/403 且非统一 404 页）
            if status in (200, 301, 302, 401, 403):
                size = len(body)
                if size > 0:
                    found.append((p, status, size, headers.get("server", "")))
            done += 1
            if done % 10 == 0:
                self.set_progress(done, total, f"爆破中 {done}/{total}")

        self.set_progress(total, total, "写入结果")
        for p, status, size, server in found:
            self.checkpoint()
            url = urljoin(base + "/", p.lstrip("/"))
            self.add_record("path", p, value=str(status),
                            detail={"status": status, "size": size, "server": server},
                            source="path-brute")
            if p in ("/.git/config", "/.env", "/backup.zip", "/backup.tar.gz",
                     "/database.sql", "/dump.sql", "/.htaccess", "/WEB-INF/web.xml"):
                self.find_vuln(
                    title=f"敏感文件泄露: {p}", vuln_type="info_leak",
                    severity="high" if p in ("/.git/config", "/.env", "/backup.zip") else "medium",
                    url=url, confidence="medium",
                    description=f"目录爆破发现敏感路径 {p}，返回 {status}，响应大小 {size} 字节",
                    fix_suggestion="删除或限制敏感文件/目录的外部访问",
                )
        self.log(f"目录爆破完成，发现 {len(found)} 个路径")

    def _get_asset(self):
        from ..database import SessionLocal
        from ..models import Asset, ScanTask
        with SessionLocal() as db:
            task = db.get(ScanTask, self.task_id)
            return db.get(Asset, task.asset_id) if task else None

    def _get_params(self) -> dict:
        import json
        from ..database import SessionLocal
        from ..models import ScanTask
        with SessionLocal() as db:
            task = db.get(ScanTask, self.task_id)
            try:
                return json.loads(task.params or "{}")
            except Exception:
                return {}
