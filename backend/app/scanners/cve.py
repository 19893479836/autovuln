"""组件漏洞检测扫描器：基于指纹规则匹配已知 CVE（漏洞库可更新）"""
import json
import re

from ..database import SessionLocal
from ..models import Asset, AssetRecord, Rule, ScanTask
from .base import BaseScanner


class CveScanner(BaseScanner):
    name = "vuln_cve"
    display_name = "组件漏洞检测"

    def run(self):
        asset = self._get_asset()
        if not asset:
            return
        with SessionLocal() as db:
            # 收集该资产指纹
            records = db.query(AssetRecord).filter_by(
                user_id=asset.user_id, asset_id=asset.id, kind="fingerprint",
            ).all()
            # 加载 CVE 规则
            rules = db.query(Rule).filter(
                Rule.enabled == True,  # noqa: E712
                Rule.vuln_type == "cve",
            ).all()

        self.log(f"CVE 检测: 资产指纹 {len(records)} 条，规则 {len(rules)} 条")
        self.checkpoint()

        matched = 0
        for rule in rules:
            self.checkpoint()
            # 规则通过 fingerprint_hint 关联组件指纹
            hint = rule.fingerprint_hint
            if hint:
                hit = any(
                    (r.key == hint or r.value == hint or hint in (r.detail or ""))
                    for r in records
                )
                if not hit:
                    continue
            self.find_vuln(
                title=rule.name, vuln_type="cve",
                severity=rule.severity, cvss_score=rule.cvss_score,
                url=asset.value, confidence="medium",
                description=rule.description,
                cve_id=self._extract_cve(rule.name, rule.rule_key),
                reference=self._loads(rule.reference) if rule.reference else None,
                fix_suggestion=rule.fix_suggestion,
                vuln_key=f"cve|{rule.rule_key}|{asset.id}",
            )
            matched += 1
        self.log(f"CVE 检测完成，命中 {matched} 条")

    @staticmethod
    def _extract_cve(*texts: str) -> str | None:
        for t in texts:
            m = re.search(r"CVE-\d{4}-\d{4,7}", t, re.I)
            if m:
                return m.group(0).upper()
        return None

    @staticmethod
    def _loads(s: str):
        try:
            v = json.loads(s or "[]")
            return v if isinstance(v, list) else []
        except Exception:
            return []

    def _get_asset(self):
        with SessionLocal() as db:
            task = db.get(ScanTask, self.task_id)
            return db.get(Asset, task.asset_id) if task else None
