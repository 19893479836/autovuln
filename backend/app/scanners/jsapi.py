"""JS/API 接口提取扫描器：抓取页面 JS 文件，提取接口、参数、路径"""
import json
import re
from urllib.parse import urljoin, urlparse

from .base import BaseScanner, http_request


class JsApiScanner(BaseScanner):
    name = "recon_jsapi"
    display_name = "JS/API 接口提取"

    JS_URL_RE = re.compile(r'(?:src|href)\s*=\s*["\']([^"\']+\.js(?:\?[^"\']*)?)["\']', re.I)
    API_PATH_RE = re.compile(
        r'''["'`]((?:/api|/v\d+|/rest|/graphql|/admin|/manage)[a-zA-Z0-9_\-/{}:.]{2,120})["'`]'''
    )
    FETCH_RE = re.compile(r'''fetch\s*\(\s*["'`]([^"'`]{2,200})["'`]''')
    AJAX_URL_RE = re.compile(r'''url\s*:\s*["'`]([^"'`]{2,200})["'`]''')

    def run(self):
        asset = self._get_asset()
        if not asset:
            return
        base = asset.value if asset.value.startswith(("http://", "https://")) else "http://" + asset.value
        self.checkpoint()

        found_apis: set[str] = set()
        js_files: set[str] = set()

        # 1. 抓首页
        try:
            status, headers, body = http_request(base, timeout=5)
        except Exception:
            try:
                base = base.replace("http://", "https://")
                status, headers, body = http_request(base, timeout=5)
            except Exception as e:
                self.log(f"首页抓取失败: {e}")
                return

        found_apis.update(self._extract_from_body(base, body))
        for js in self.JS_URL_RE.findall(body):
            js_url = urljoin(base, js)
            js_files.add(js_url)

        # 2. 抓 JS 文件
        total = len(js_files) + 1
        done = 1
        for js_url in sorted(js_files)[:50]:
            self.checkpoint()
            try:
                _, _, js_body = http_request(js_url, timeout=5)
            except Exception:
                continue
            found_apis.update(self._extract_from_body(js_url, js_body))
            self.add_record("jsapi", f"js:{js_url}", value="js file", detail={"url": js_url},
                            source="js-extract")
            done += 1
            self.set_progress(done, total, f"解析 JS: {js_url}")

        # 3. 写结果
        self.set_progress(total, total, "写入接口")
        for api in sorted(found_apis)[:300]:
            self.checkpoint()
            self.add_record("jsapi", api, value="api",
                            detail={"method": "unknown"}, source="js-extract")
        self.log(f"接口提取完成：发现 {len(found_apis)} 个接口")

    def _extract_from_body(self, base_url: str, body: str) -> set[str]:
        results: set[str] = set()
        for pat in (self.API_PATH_RE, self.FETCH_RE, self.AJAX_URL_RE):
            for m in pat.findall(body):
                p = m.strip().strip("'\"")
                if not p or p.startswith(("http://", "https://", "//", "javascript:")):
                    if p.startswith("//"):
                        p = "https:" + p
                    else:
                        continue
                if p.startswith(("http://", "https://")):
                    results.add(p)
                elif p.startswith("/"):
                    results.add(urljoin(base_url, p))
                elif "." not in p.split("/")[-1]:
                    results.add(urljoin(base_url, "/" + p))
        return results

    def _get_asset(self):
        from ..database import SessionLocal
        from ..models import Asset, ScanTask
        with SessionLocal() as db:
            task = db.get(ScanTask, self.task_id)
            return db.get(Asset, task.asset_id) if task else None
