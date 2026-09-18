"""弱口令/未授权检测扫描器：常见管理后台默认凭据 + 未授权接口"""
import base64

from ..database import SessionLocal
from ..models import Asset, ScanTask
from .base import BaseScanner, http_request

# 常见后台路径 + 默认凭据
WEAK_TARGETS = [
    ("/admin", "admin", "admin"),
    ("/admin", "admin", "123456"),
    ("/admin", "admin", "password"),
    ("/admin/login", "admin", "admin"),
    ("/login", "admin", "admin"),
    ("/manager/html", "tomcat", "tomcat"),       # Tomcat
    ("/druid/index.html", "admin", "admin"),     # Druid
    ("/phpmyadmin", "root", "root"),
]

# 未授权接口路径
UNAUTH_PATHS = [
    "/actuator/env",
    "/actuator/health",
    "/druid/index.html",
    "/swagger-ui.html",
    "/v2/api-docs",
    "/api/users",
    "/api/v1/users",
    "/debug/vars",       # pprof
    "/metrics",          # Prometheus
]


class WeakPassScanner(BaseScanner):
    name = "vuln_weakpass"
    display_name = "弱口令/未授权检测"

    def run(self):
        asset = self._get_asset()
        if not asset:
            return
        base = asset.value if asset.value.startswith(("http://", "https://")) else "http://" + asset.value
        self.log(f"弱口令检测: {base}")
        self.checkpoint()

        total = len(WEAK_TARGETS) + len(UNAUTH_PATHS)
        done = 0

        # 1. 未授权接口检测
        for path in UNAUTH_PATHS:
            self.checkpoint()
            url = base.rstrip("/") + path
            try:
                status, headers, body = http_request(url, timeout=5, allow_redirects=False)
            except Exception:
                done += 1
                continue
            if status == 200 and len(body) > 50:
                self.find_vuln(
                    title=f"未授权访问: {path}", vuln_type="unauthorized",
                    severity="medium" if path in ("/metrics", "/debug/vars") else "high",
                    url=url, confidence="high",
                    description=f"路径 {path} 返回 {status}，无需认证即可访问",
                    fix_suggestion="为该接口添加认证鉴权",
                    vuln_key=f"unauth|{path}|{base}",
                )
            done += 1
            if done % 3 == 0:
                self.set_progress(done, total, f"未授权检测 {done}/{total}")

        # 2. 常见后台弱口令（HTTP Basic Auth）
        for path, user, pwd in WEAK_TARGETS:
            self.checkpoint()
            url = base.rstrip("/") + path
            cred = base64.b64encode(f"{user}:{pwd}".encode()).decode()
            try:
                status, headers, body = http_request(
                    url, timeout=5, allow_redirects=False,
                    headers={"Authorization": f"Basic {cred}"},
                )
            except Exception:
                done += 1
                continue
            # 200 且不是登录页特征 → 弱口令
            if status == 200 and "login" not in body.lower()[:500] and len(body) > 100:
                self.find_vuln(
                    title=f"弱口令: {path} ({user}/{pwd})", vuln_type="weak_password",
                    severity="high", url=url, confidence="medium",
                    description=f"路径 {path} 使用默认凭据 {user}:{pwd} 可登录",
                    fix_suggestion="修改默认密码并启用强密码策略",
                    vuln_key=f"weakpass|{path}|{user}|{base}",
                )
            done += 1

        self.set_progress(total, total, "弱口令检测完成")
        self.log("弱口令检测完成")

    def _get_asset(self):
        with SessionLocal() as db:
            task = db.get(ScanTask, self.task_id)
            return db.get(Asset, task.asset_id) if task else None
