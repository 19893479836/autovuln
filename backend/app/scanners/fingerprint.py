"""指纹识别扫描器：HTTP 探测 + 指纹规则库匹配（CMS/框架/中间件/组件）"""
import json
import re
from urllib.parse import urljoin

from ..database import SessionLocal
from ..models import Asset, FingerprintRule, ScanTask
from .base import BaseScanner, http_request


class FingerprintScanner(BaseScanner):
    name = "recon_fingerprint"
    display_name = "指纹识别"

    def run(self):
        asset = self._get_asset()
        if not asset:
            return
        target = self._to_http(asset.value)
        self.log(f"指纹识别: {target}")
        self.checkpoint()

        try:
            status, headers, body = http_request(target, timeout=5)
        except Exception as e:
            self.log(f"HTTP 探测失败: {e}")
            # 尝试 https
            try:
                target = target.replace("http://", "https://")
                status, headers, body = http_request(target, timeout=5)
            except Exception as e2:
                self.log(f"HTTPS 探测失败: {e2}")
                return

        with SessionLocal() as db:
            rules = db.query(FingerprintRule).filter_by(enabled=True).all()
            rules = [r for r in rules]

        title = ""
        m = re.search(r"<title[^>]*>(.*?)</title>", body, re.S | re.I)
        if m:
            title = m.group(1).strip()[:128]

        hits: list[tuple[FingerprintRule, str]] = []
        for rule in rules:
            self.checkpoint()
            try:
                feats = json.loads(rule.rules)
            except Exception:
                continue
            for feat in feats:
                ftype = feat.get("type", "body")
                pattern = feat.get("pattern", "")
                if not pattern:
                    continue
                try:
                    if ftype == "header":
                        key = feat.get("key", "").lower()
                        val = headers.get(key, "")
                        if val and re.search(pattern, val, re.I):
                            hits.append((rule, f"header {key}: {val[:80]}"))
                            break
                    elif ftype == "title":
                        if title and re.search(pattern, title, re.I):
                            hits.append((rule, f"title: {title}"))
                            break
                    else:  # body
                        if re.search(pattern, body, re.I):
                            hits.append((rule, f"body pattern: {pattern[:60]}"))
                            break
                except re.error:
                    continue

        seen = set()
        for rule, evidence in hits:
            if rule.id in seen:
                continue
            seen.add(rule.id)
            self.add_record("fingerprint", rule.name,
                            value=rule.category,
                            detail={"evidence": evidence, "cpe": rule.cpe, "fp_key": rule.fp_key},
                            source="fingerprint")

        # 基础 Server/X-Powered-By
        for hkey in ("server", "x-powered-by", "x-aspnet-version"):
            if headers.get(hkey):
                self.add_record("fingerprint", f"{hkey}:{headers[hkey]}",
                                value=hkey, detail={"evidence": f"{hkey}: {headers[hkey]}"},
                                source="http-header")

        self.log(f"指纹识别完成，命中 {len(hits)} 条指纹")
        # 供 CVE 扫描使用：写入资产 detail 缓存
        self.add_record("http_baseline", target, value=f"{status}",
                        detail={"title": title, "status": status}, source="fingerprint")

    def _get_asset(self):
        with SessionLocal() as db:
            task = db.get(ScanTask, self.task_id)
            return db.get(Asset, task.asset_id) if task else None

    @staticmethod
    def _to_http(value: str) -> str:
        if value.startswith(("http://", "https://")):
            return value
        return "http://" + value
