"""动态爬虫扫描器：Playwright 无头浏览器渲染 JS 页面，提取动态链接与接口

- 现代 SPA（Vue/React）的链接/接口由 JS 动态渲染，静态正则爬取拿不到
- 本扫描器用无头 Chromium 渲染页面，收集渲染后 DOM 链接 + XHR/fetch 网络请求
- 支持认证态：资产配置的 Cookie 注入浏览器会话
- 发现结果写入 AssetRecord（kind=path 页面 / jsapi 接口），供 Web 漏洞扫描复用
"""
import json
import time
from urllib.parse import urljoin, urlparse

from .base import BaseScanner

# 单次爬取上限（防失控）
CRAWL_LIMIT = 30
CRAWL_DEPTH = 2


class ReconCrawlerScanner(BaseScanner):
    name = "recon_crawler"
    display_name = "动态爬虫(Playwright)"

    def run(self):
        asset = self._get_asset()
        if not asset:
            return
        base = asset.value if asset.value.startswith(("http://", "https://")) else "http://" + asset.value
        cookie = (asset.cookie or "").strip() or None

        try:
            from playwright.sync_api import sync_playwright
        except ImportError:
            self.mark_failed("Playwright 未安装，请执行: pip install playwright && playwright install chromium")
            return

        self.log(f"动态爬虫: {base}" + ("(认证态)" if cookie else ""))
        try:
            self._crawl(base, cookie)
        except Exception as e:
            # 浏览器可用性问题（未装 chromium 等）标记失败，其余按进度继续
            msg = str(e)
            if "Executable doesn't exist" in msg or "browser_type" in msg.lower():
                self.mark_failed(f"Chromium 未安装，请执行: playwright install chromium ({msg[:120]})")
            else:
                self.log(f"爬虫异常: {msg[:200]}")

    # ---------- 核心 ----------
    def _crawl(self, base: str, cookie: str | None):
        from playwright.sync_api import sync_playwright

        host = urlparse(base).hostname
        seen: set[str] = set()
        found_paths: set[str] = set()
        found_apis: set[str] = set()
        queue = [(base, 0)]
        visited = 0

        with sync_playwright() as p:
            try:
                browser = p.chromium.launch(headless=True, args=["--no-sandbox"])
            except Exception as e:
                self.mark_failed(f"Chromium 启动失败: {str(e)[:200]}")
                return
            try:
                ctx = browser.new_context(
                    user_agent="AutoVuln/1.0 (dynamic crawler)",
                    ignore_https_errors=True,
                )
                if cookie:
                    for kv in cookie.split(";"):
                        if "=" not in kv:
                            continue
                        name, value = kv.strip().split("=", 1)
                        if name:
                            try:
                                ctx.add_cookies([{"name": name, "value": value, "url": base}])
                            except Exception:
                                pass
                page = ctx.new_page()
                page.set_default_timeout(10000)

                def on_request(req):
                    try:
                        rtype = req.resource_type
                        if rtype not in ("xhr", "fetch"):
                            return
                        u = req.url
                        if u.startswith(("http://", "https://")) and urlparse(u).hostname == host:
                            found_apis.add(u)
                    except Exception:
                        pass

                page.on("request", on_request)

                while queue and visited < CRAWL_LIMIT:
                    self.checkpoint()
                    url, depth = queue.pop(0)
                    if url in seen:
                        continue
                    seen.add(url)
                    try:
                        page.goto(url, wait_until="networkidle", timeout=12000)
                    except Exception:
                        # 渲染超时也尝试提取已渲染内容
                        try:
                            page.goto(url, wait_until="domcontentloaded", timeout=10000)
                        except Exception:
                            continue
                    visited += 1
                    self.set_progress(visited, CRAWL_LIMIT, f"渲染 {visited}/{CRAWL_LIMIT}: {url}")

                    # 渲染后 DOM 链接
                    try:
                        hrefs = page.evaluate(
                            "Array.from(document.querySelectorAll('a[href]')).map(a => a.href)"
                        )
                    except Exception:
                        hrefs = []
                    for h in hrefs or []:
                        if not isinstance(h, str) or not h.startswith(("http://", "https://")):
                            continue
                        if urlparse(h).hostname != host:
                            continue
                        path = urlparse(h).path
                        found_paths.add(h)
                        if depth < CRAWL_DEPTH and h not in seen:
                            queue.append((h, depth + 1))

                    time.sleep(0.05)  # 温和渲染间隔

            finally:
                try:
                    browser.close()
                except Exception:
                    pass

        # 写结果
        total = len(found_paths) + len(found_apis) + 1
        done = 1
        for u in sorted(found_paths)[:300]:
            self.checkpoint()
            self.add_record("path", u, value="dynamic-page",
                            detail={"depth": "crawled"}, source="playwright")
            done += 1
            if done % 20 == 0:
                self.set_progress(done, total, f"写入发现 {done}/{total}")
        for u in sorted(found_apis)[:300]:
            self.checkpoint()
            self.add_record("jsapi", u, value="api",
                            detail={"method": "xhr/fetch"}, source="playwright")
            done += 1
            if done % 20 == 0:
                self.set_progress(done, total, f"写入接口 {done}/{total}")
        self.set_progress(total, total, "爬虫完成")
        self.log(f"动态爬虫完成：页面 {len(found_paths)} 个，接口 {len(found_apis)} 个")

    def _get_asset(self):
        from ..database import SessionLocal
        from ..models import Asset, ScanTask
        with SessionLocal() as db:
            task = db.get(ScanTask, self.task_id)
            return db.get(Asset, task.asset_id) if task else None
