"""nuclei 规则导入器

将 ProjectDiscovery nuclei HTTP 模板（YAML）转换为平台规则（Rule），
使外部安全社区模板可直接复用。

用法:
  python import_nuclei.py <模板文件或目录> [--dry-run]

映射说明:
  id             -> rule_key（前缀 nuclei-，幂等更新）
  info.name      -> name
  info.severity  -> severity（critical/high/medium/low/info）
  info.description / reference -> description / reference
  http.method    -> method（GET/POST/...）
  http.path[0]   -> path（剥离 {{BaseURL}} 变量）
  http.headers   -> headers（JSON 序列化）
  http.body      -> body
  matchers       -> match_regex（word/dsl/regex 类取匹配词）与 match_status（status 类）
"""
import argparse
import json
import re
import sys
from pathlib import Path

import yaml

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from app.database import SessionLocal  # noqa: E402
from app.models import Rule  # noqa: E402

SEV_MAP = {"critical": "critical", "high": "high", "medium": "medium",
           "low": "low", "info": "info", "unknown": "medium"}
DEFAULT_TYPE = "generic"


def _sev(sev: str | None) -> str:
    return SEV_MAP.get((sev or "unknown").lower(), "medium")


def _clean_path(path: str) -> str:
    p = path.strip()
    if p.startswith("{{BaseURL}}"):
        p = p[len("{{BaseURL}}"):]
    elif p.startswith("{{RootURL}}"):
        p = p[len("{{RootURL}}"):]
    # 常见 nuclei 变量占位剥除
    p = re.sub(r"\{\{[^}]+\}\}", "", p)
    return p or "/"


def _matchers_to_rule(req: dict) -> tuple[str, str]:
    """matchers -> (match_regex, match_status)"""
    words: list[str] = []
    statuses: list[int] = []
    for m in req.get("matchers", []) or []:
        mtype = (m or {}).get("type", "word")
        if mtype == "status":
            for s in (m.get("status", []) or []):
                try:
                    statuses.append(int(s))
                except (TypeError, ValueError):
                    pass
        elif mtype in ("word", "regex", "dsl"):
            for w in (m.get("words", []) or m.get("regex", []) or []):
                if w and str(w).strip():
                    words.append(str(w))
    regex = "|".join(re.escape(w) if _looks_literal(w) else w for w in words[:20]) if words else ""
    status = ",".join(str(s) for s in sorted(set(statuses))) if statuses else ""
    return regex[:500], status


def _looks_literal(s: str) -> bool:
    return not any(c in s for c in "()[]{}.*+?|\\^$")


def parse_template(text: str) -> dict | None:
    try:
        data = yaml.safe_load(text)
    except Exception as e:
        print(f"  [跳过] YAML 解析失败: {e}")
        return None
    if not isinstance(data, dict) or "http" not in data:
        return None
    info = data.get("info", {}) or {}
    reqs = data.get("http", []) or []
    if not reqs:
        return None
    req = reqs[0] or {}
    path_list = req.get("path", []) or []
    if not path_list:
        return None
    regex, status = _matchers_to_rule(req)
    if not regex and not status:
        return None  # 无匹配条件，跳过
    return {
        "rule_key": f"nuclei-{data.get('id', '')}"[:128],
        "name": str(info.get("name", data.get("id", "nuclei")))[:256],
        "vuln_type": str(data.get("id", "")).split("-")[0][:64] or DEFAULT_TYPE,
        "severity": _sev(info.get("severity")),
        "method": str(req.get("method", "GET")).upper()[:8],
        "path": str(_clean_path(path_list[0]))[:256],
        "headers": json.dumps(req.get("headers", {}) or {}, ensure_ascii=False),
        "body": str(req.get("body", "") or "")[:2000],
        "match_regex": regex,
        "match_status": status,
        "description": str(info.get("description", "") or "")[:1000],
        "reference": json.dumps([str(x) for x in (info.get("reference") or [])], ensure_ascii=False),
        "source": "nuclei",
        "enabled": True,
    }


def import_file(path: Path, dry_run: bool) -> int:
    text = path.read_text(encoding="utf-8", errors="replace")
    rule = parse_template(text)
    if not rule:
        return 0
    if dry_run:
        print(f"  [预览] {rule['name']} | {rule['severity']} | {rule['method']} {rule['path']}"
              f" | regex={'有' if rule['match_regex'] else '无'} status={rule['match_status'] or '无'}")
        return 1
    with SessionLocal() as db:
        existing = db.query(Rule).filter_by(rule_key=rule["rule_key"]).first()
        if existing:
            for k, v in rule.items():
                setattr(existing, k, v)
            db.commit()
            print(f"  [更新] {rule['rule_key']} → {rule['name']}")
        else:
            db.add(Rule(**rule))
            db.commit()
            print(f"  [导入] {rule['rule_key']} → {rule['name']}")
    return 1


def main():
    ap = argparse.ArgumentParser(description="nuclei 模板导入器")
    ap.add_argument("target", help="nuclei YAML 模板文件或目录")
    ap.add_argument("--dry-run", action="store_true", help="仅预览不写库")
    args = ap.parse_args()

    target = Path(args.target)
    files = [target] if target.is_file() else sorted(target.glob("*.yaml")) + sorted(target.glob("*.yml"))
    if not files:
        print("未找到模板文件")
        return
    print(f"共发现 {len(files)} 个模板文件")
    ok = 0
    for f in files:
        try:
            ok += import_file(f, args.dry_run)
        except Exception as e:
            print(f"  [错误] {f.name}: {e}")
    print(f"完成：成功处理 {ok}/{len(files)} 个模板"
          + ("（预览模式，未写库）" if args.dry_run else ""))


if __name__ == "__main__":
    main()
