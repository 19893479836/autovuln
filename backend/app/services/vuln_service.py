"""漏洞运营服务：状态机 / 轮次对比 / 工单 / 批量操作"""
import json
from datetime import datetime

from sqlalchemy.orm import Session

from ..models import ScanTask, Vulnerability, VulnStatusHistory
from ..models.vuln import STATE_FLOW

ALLOWED_BATCH_ACTIONS = ("confirm", "ignore", "assign", "mark_fixed")


def _commit_state(db: Session, vuln: Vulnerability, to_state: str,
                  operator: str, comment: str | None = None) -> bool:
    """状态机流转：非法流转返回 False"""
    if vuln.state == to_state:
        return True
    allowed = STATE_FLOW.get(vuln.state, ())
    if to_state not in allowed:
        return False
    from_state = vuln.state
    vuln.state = to_state
    if to_state in ("fixed", "verified", "false_positive", "ignored"):
        vuln.resolved_at = datetime.utcnow()
    else:
        vuln.resolved_at = None
    if to_state == "confirmed":
        vuln.confirmed_at = datetime.utcnow()
    db.add(VulnStatusHistory(
        vuln_id=vuln.id, from_state=from_state, to_state=to_state,
        operator=operator, comment=comment,
    ))
    db.commit()
    return True


def transition(db: Session, user_id: int, vuln_id: int, to_state: str,
               operator: str, comment: str | None = None) -> tuple[bool, str]:
    """单漏洞状态流转（带租户校验）"""
    vuln = db.query(Vulnerability).filter_by(id=vuln_id, user_id=user_id).first()
    if not vuln:
        return False, "漏洞不存在或无权访问"
    ok = _commit_state(db, vuln, to_state, operator, comment)
    return (True, "ok") if ok else (False, f"非法状态流转: {vuln.state} → {to_state}")


def batch_action(db: Session, user_id: int, action: str, vuln_ids: list[int],
                 operator: str, assignee: str | None = None,
                 comment: str | None = None) -> dict:
    """批量确认/忽略/指派/标记修复"""
    if action not in ALLOWED_BATCH_ACTIONS:
        return {"ok": 0, "failed": 0, "msg": f"不支持的操作: {action}"}
    ok = failed = 0
    for vid in vuln_ids:
        vuln = db.query(Vulnerability).filter_by(id=vid, user_id=user_id).first()
        if not vuln:
            failed += 1
            continue
        if action == "confirm":
            if _commit_state(db, vuln, "confirmed", operator, comment or "批量确认"):
                ok += 1
            else:
                failed += 1
        elif action == "ignore":
            if _commit_state(db, vuln, "ignored", operator, comment or "批量忽略"):
                ok += 1
            else:
                failed += 1
        elif action == "mark_fixed":
            if _commit_state(db, vuln, "fixed", operator, comment or "批量标记修复"):
                ok += 1
            else:
                failed += 1
        elif action == "assign":
            vuln.assignee = assignee
            db.commit()
            ok += 1
    return {"ok": ok, "failed": failed, "msg": "完成"}


def round_compare(db: Session, user_id: int, asset_id: int,
                  round_a: int, round_b: int) -> dict:
    """跨扫描轮次对比：识别 新增 / 已修复 / 复发 漏洞。

    语义：以扫描任务记录的本轮发现快照(found_keys)为集合依据。
    - 在 B 发现、A 未发现 → 新增
    - 在 A 发现、B 未发现 → 已修复
    - A 已解决（fixed/verified/ignored/fp）但 B 又发现 → 复发
    """
    a_keys = _keys_in_round(db, user_id, asset_id, round_a)
    b_keys = _keys_in_round(db, user_id, asset_id, round_b)

    # 资产全部漏洞（当前视图）
    vulns = {v.vuln_key: v for v in db.query(Vulnerability).filter_by(
        user_id=user_id, asset_id=asset_id,
    ).all()}

    new = [_to_dict(vulns[k]) for k in sorted(b_keys - a_keys) if k in vulns]
    fixed = [_to_dict(vulns[k]) for k in sorted(a_keys - b_keys) if k in vulns]
    regressed = []
    for k in sorted(a_keys & b_keys):
        v = vulns.get(k)
        if v and v.state in ("fixed", "verified", "ignored", "false_positive"):
            regressed.append(_to_dict(v))
    return {
        "asset_id": asset_id, "round_a": round_a, "round_b": round_b,
        "added": new, "fixed": fixed, "regressed": regressed,
        "summary": {
            "added": len(new), "fixed": len(fixed), "regressed": len(regressed),
            "total_b": len(b_keys),
        },
    }


def _keys_in_round(db: Session, user_id: int, asset_id: int, round_no: int) -> set[str]:
    """某轮次全部任务的漏洞发现快照"""
    tasks = db.query(ScanTask).filter_by(
        user_id=user_id, asset_id=asset_id, round_no=round_no,
    ).all()
    keys: set[str] = set()
    for t in tasks:
        try:
            keys.update(json.loads(t.found_keys or "[]"))
        except Exception:
            continue
    return keys


def _to_dict(v: Vulnerability) -> dict:
    return {
        "id": v.id, "title": v.title, "vuln_type": v.vuln_type,
        "severity": v.severity, "state": v.state, "url": v.url,
        "cve_id": v.cve_id, "confidence": v.confidence,
        "first_seen_at": v.first_seen_at.isoformat() if v.first_seen_at else None,
        "last_seen_at": v.last_seen_at.isoformat() if v.last_seen_at else None,
    }
