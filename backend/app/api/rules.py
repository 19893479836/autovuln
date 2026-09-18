"""规则库 API：漏洞规则 / 指纹 / POC 的 CRUD + 导入 + 在线更新（不写死）"""
import hashlib
import json

import requests
from fastapi import APIRouter, Depends, HTTPException, Request, UploadFile
from sqlalchemy.orm import Session

from ..core.audit import write_audit
from ..core.deps import get_current_user, require_admin
from ..database import get_db
from ..models import FingerprintRule, PocScript, Rule, User
from ..schemas import FingerprintRuleIn, Msg, PocIn, RuleIn
from ..utils.net import validate_outbound_url

router = APIRouter(prefix="/api/rules", tags=["规则库"])


def _stable_key(seed: str, prefix: str) -> str:
    """确定性规则 key：基于内容哈希，跨进程/重启保持稳定（替代不稳定的 hash()）。"""
    digest = int(hashlib.sha256(seed.encode("utf-8")).hexdigest()[:8], 16) % 100000
    return f"{prefix}{digest}"


# ---------------- 漏洞规则 ----------------
@router.get("/web")
def list_rules(vuln_type: str = "", enabled: bool | None = None,
               user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    q = db.query(Rule)
    if vuln_type:
        q = q.filter(Rule.vuln_type == vuln_type)
    if enabled is not None:
        q = q.filter(Rule.enabled == enabled)
    rows = q.order_by(Rule.id).limit(500).all()
    return [{"id": r.id, "rule_key": r.rule_key, "name": r.name, "vuln_type": r.vuln_type,
             "severity": r.severity, "path": r.path, "match_regex": r.match_regex,
             "fp_count": r.fp_count, "fp_suppress": r.fp_suppress, "enabled": r.enabled,
             "source": r.source} for r in rows]


@router.post("/web", response_model=dict)
def create_rule(data: RuleIn, request: Request,
                user: User = Depends(require_admin), db: Session = Depends(get_db)):
    key = _stable_key(f"{data.vuln_type}-{data.name}", f"custom-{data.vuln_type}-")
    while db.query(Rule).filter_by(rule_key=key).first():
        key += "x"
    r = Rule(rule_key=key, name=data.name, vuln_type=data.vuln_type, severity=data.severity,
             cvss_score=data.cvss_score, method=data.method, path=data.path,
             headers=json.dumps(data.headers, ensure_ascii=False),
             body=data.body, params="[]", match_regex=data.match_regex,
             match_header=data.match_header, match_status=data.match_status,
             fingerprint_hint=data.fingerprint_hint, description=data.description,
             fix_suggestion=data.fix_suggestion, reference=data.reference,
             enabled=data.enabled, source="manual")
    db.add(r)
    db.commit()
    write_audit(db, user.id, user.username, "rule.create", "rule", r.id, {"key": key}, request)
    return {"id": r.id, "rule_key": key}


@router.put("/web/{rule_id}", response_model=Msg)
def update_rule(rule_id: int, data: RuleIn, request: Request,
                user: User = Depends(require_admin), db: Session = Depends(get_db)):
    r = db.get(Rule, rule_id)
    if not r:
        raise HTTPException(404, "规则不存在")
    for field, value in data.model_dump().items():
        if field == "headers":
            value = json.dumps(value, ensure_ascii=False)
        setattr(r, field, value)
    db.commit()
    write_audit(db, user.id, user.username, "rule.update", "rule", rule_id, {}, request)
    return Msg(msg="已更新")


@router.post("/web/{rule_id}/toggle", response_model=Msg)
def toggle_rule(rule_id: int, user: User = Depends(require_admin), db: Session = Depends(get_db)):
    r = db.get(Rule, rule_id)
    if not r:
        raise HTTPException(404, "规则不存在")
    r.enabled = not r.enabled
    db.commit()
    return Msg(msg="已切换" if r.enabled else "已停用")


# ---------------- 指纹规则 ----------------
@router.get("/fingerprint")
def list_fingerprints(category: str = "", user: User = Depends(get_current_user),
                      db: Session = Depends(get_db)):
    q = db.query(FingerprintRule)
    if category:
        q = q.filter(FingerprintRule.category == category)
    rows = q.order_by(FingerprintRule.id).limit(500).all()
    return [{"id": r.id, "fp_key": r.fp_key, "name": r.name, "category": r.category,
             "rules": r.rules, "cpe": r.cpe, "enabled": r.enabled, "source": r.source}
            for r in rows]


@router.post("/fingerprint", response_model=dict)
def create_fingerprint(data: FingerprintRuleIn, request: Request,
                       user: User = Depends(require_admin), db: Session = Depends(get_db)):
    key = _stable_key(data.name, "custom-")
    r = FingerprintRule(fp_key=key, name=data.name, category=data.category,
                        rules=json.dumps(data.rules, ensure_ascii=False),
                        cpe=data.cpe, enabled=data.enabled, source="manual")
    db.add(r)
    db.commit()
    write_audit(db, user.id, user.username, "rule.fp_create", "fp_rule", r.id, {}, request)
    return {"id": r.id, "fp_key": key}


# ---------------- POC ----------------
@router.get("/poc")
def list_pocs(user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    rows = db.query(PocScript).order_by(PocScript.id).limit(500).all()
    return [{"id": p.id, "poc_key": p.poc_key, "name": p.name, "vuln_type": p.vuln_type,
             "severity": p.severity, "script_type": p.script_type,
             "fingerprint_hint": p.fingerprint_hint, "enabled": p.enabled,
             "source": p.source} for p in rows]


@router.post("/poc", response_model=dict)
def create_poc(data: PocIn, request: Request,
               user: User = Depends(require_admin), db: Session = Depends(get_db)):
    key = _stable_key(data.name, "custom-")
    while db.query(PocScript).filter_by(poc_key=key).first():
        key += "x"
    p = PocScript(poc_key=key, name=data.name, vuln_type=data.vuln_type,
                  severity=data.severity, script_type=data.script_type,
                  script_data=json.dumps(data.script_data, ensure_ascii=False),
                  script_source=data.script_source, fingerprint_hint=data.fingerprint_hint,
                  enabled=data.enabled, source="manual")
    db.add(p)
    db.commit()
    write_audit(db, user.id, user.username, "rule.poc_create", "poc", p.id, {}, request)
    return {"id": p.id, "poc_key": key}


# ---------------- 导入 / 在线更新 ----------------
@router.post("/import", response_model=dict)
async def import_rules(file: UploadFile, request: Request,
                       user: User = Depends(require_admin), db: Session = Depends(get_db)):
    """导入规则包（JSON）：{web: [...], fingerprint: [...], poc: [...]}"""
    raw = await file.read()
    try:
        data = json.loads(raw.decode("utf-8"))
    except Exception:
        raise HTTPException(400, "JSON 解析失败")
    added = {"web": 0, "fingerprint": 0, "poc": 0}

    for item in data.get("web", []):
        key = item.get("rule_key") or _stable_key(item['name'], "import-")
        if db.query(Rule).filter_by(rule_key=key).first():
            continue
        db.add(Rule(rule_key=key, name=item["name"], vuln_type=item.get("vuln_type", "web"),
                    severity=item.get("severity", "medium"),
                    cvss_score=item.get("cvss_score", 0.0),
                    method=item.get("method", "GET"), path=item.get("path", "/"),
                    headers=json.dumps(item.get("headers", {}), ensure_ascii=False),
                    body=item.get("body"), params="[]",
                    match_regex=item.get("match_regex"), match_header=item.get("match_header"),
                    match_status=item.get("match_status"),
                    fingerprint_hint=item.get("fingerprint_hint"),
                    description=item.get("description"), fix_suggestion=item.get("fix_suggestion"),
                    reference=item.get("reference"), enabled=item.get("enabled", True),
                    source="import"))
        added["web"] += 1
    for item in data.get("fingerprint", []):
        key = item.get("fp_key") or f"import-{item['name']}"
        if db.query(FingerprintRule).filter_by(fp_key=key).first():
            continue
        db.add(FingerprintRule(fp_key=key, name=item["name"],
                               category=item.get("category", "server"),
                               rules=json.dumps(item.get("rules", []), ensure_ascii=False),
                               cpe=item.get("cpe"), enabled=item.get("enabled", True),
                               source="import"))
        added["fingerprint"] += 1
    for item in data.get("poc", []):
        key = item.get("poc_key") or f"import-{item['name']}"
        if db.query(PocScript).filter_by(poc_key=key).first():
            continue
        db.add(PocScript(poc_key=key, name=item["name"], vuln_type=item.get("vuln_type", "web"),
                         severity=item.get("severity", "high"),
                         script_type=item.get("script_type", "http"),
                         script_data=json.dumps(item.get("script_data", {}), ensure_ascii=False),
                         script_source=item.get("script_source"),
                         fingerprint_hint=item.get("fingerprint_hint"),
                         enabled=item.get("enabled", True), source="import"))
        added["poc"] += 1
    db.commit()
    write_audit(db, user.id, user.username, "rule.import", "rule", None, added, request)
    return {"msg": "导入完成", "added": added}


@router.post("/sync-remote", response_model=dict)
def sync_remote(user: User = Depends(require_admin), db: Session = Depends(get_db)):
    """在线拉取规则（配置 RULE_REMOTE_URLS 指向规则包 JSON）"""
    from ..config import settings
    if not settings.RULE_REMOTE_URLS:
        return {"msg": "未配置 RULE_REMOTE_URLS", "added": 0}
    total = 0
    for url in settings.RULE_REMOTE_URLS:
        if not validate_outbound_url(url):
            return {"msg": f"同步 {url} 失败: URL 指向内网/环回地址，已拦截（SSRF 防护）", "added": total}
        try:
            resp = requests.get(url, timeout=15)
            resp.raise_for_status()
            data = resp.json()
            for item in data.get("web", []):
                key = item.get("rule_key") or f"remote-{item['name']}"
                if db.query(Rule).filter_by(rule_key=key).first():
                    continue
                db.add(Rule(rule_key=key, name=item["name"],
                            vuln_type=item.get("vuln_type", "web"),
                            severity=item.get("severity", "medium"),
                            cvss_score=item.get("cvss_score", 0.0),
                            method=item.get("method", "GET"), path=item.get("path", "/"),
                            headers=json.dumps(item.get("headers", {}), ensure_ascii=False),
                            body=item.get("body"), params="[]",
                            match_regex=item.get("match_regex"),
                            match_header=item.get("match_header"),
                            match_status=item.get("match_status"),
                            fingerprint_hint=item.get("fingerprint_hint"),
                            description=item.get("description"),
                            fix_suggestion=item.get("fix_suggestion"),
                            reference=item.get("reference"),
                            enabled=item.get("enabled", True), source="remote"))
                total += 1
            db.commit()
        except Exception as e:
            return {"msg": f"同步 {url} 失败: {str(e)[:200]}", "added": total}
    return {"msg": "同步完成", "added": total}
