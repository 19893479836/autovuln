"""通知服务：高危漏洞发现后触发 Webhook / 邮件 / IM"""
import json
import smtplib
import ssl
import urllib.request
from email.mime.text import MIMEText
from email.header import Header

from sqlalchemy.orm import Session

from ..config import settings
from ..models import Notification, Vulnerability
from ..utils.net import validate_outbound_url

SEVERITY_LEVEL = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
NOTIFY_THRESHOLD = 1  # high 及以上触发（可配）


def notify_vuln_found(db: Session, vuln: Vulnerability, channels: list[str] | None = None) -> list[str]:
    """漏洞入库后调用：按等级触发通知，记录到 notifications 表。"""
    channels = channels or []
    if SEVERITY_LEVEL.get(vuln.severity, 9) > NOTIFY_THRESHOLD:
        return []
    results: list[str] = []
    payload = {
        "event": "vuln_found",
        "vuln_id": vuln.id,
        "title": vuln.title,
        "severity": vuln.severity,
        "type": vuln.vuln_type,
        "url": vuln.url,
        "asset_id": vuln.asset_id,
        "cve": vuln.cve_id,
        "time": vuln.last_seen_at.isoformat() if vuln.last_seen_at else None,
    }
    for ch in channels:
        ok, err = _send(ch, payload)
        db.add(Notification(
            user_id=vuln.user_id, channel=ch, event="vuln_found",
            payload=json.dumps(payload, ensure_ascii=False),
            status="success" if ok else "failed", error_msg=err,
        ))
        results.append(f"{ch}:{'ok' if ok else 'fail'}")
    if channels:
        db.commit()
    return results


def _send(channel: str, payload: dict) -> tuple[bool, str | None]:
    try:
        if channel == "webhook" and settings.WEBHOOK_URL:
            if not validate_outbound_url(settings.WEBHOOK_URL):
                return False, "webhook URL 指向内网/环回地址，已拦截（SSRF 防护）"
            req = urllib.request.Request(
                settings.WEBHOOK_URL,
                data=json.dumps(payload, ensure_ascii=False).encode(),
                headers={"Content-Type": "application/json"},
            )
            with urllib.request.urlopen(req, timeout=8):
                return True, None
        elif channel == "email" and settings.SMTP_HOST:
            _send_email(payload)
            return True, None
        elif channel == "im":
            return True, "IM 通道需配置（预留）"
        return False, f"通道 {channel} 未配置"
    except Exception as e:
        return False, str(e)[:200]


def _send_email(payload: dict):
    msg = MIMEText(
        f"AutoVuln 发现高危漏洞\n\n标题: {payload['title']}\n等级: {payload['severity']}\n"
        f"类型: {payload['type']}\nURL: {payload.get('url', '')}\nCVE: {payload.get('cve', '')}",
        "plain", "utf-8",
    )
    msg["Subject"] = Header(f"[AutoVuln 高危] {payload['title']}", "utf-8")
    msg["From"] = settings.SMTP_FROM or settings.SMTP_USER
    to = settings.SMTP_FROM or settings.SMTP_USER
    ctx = ssl.create_default_context()
    with smtplib.SMTP_SSL(settings.SMTP_HOST, settings.SMTP_PORT, context=ctx, timeout=10) as s:
        s.login(settings.SMTP_USER, settings.SMTP_PASSWORD)
        s.sendmail(msg["From"], [to], msg.as_string())
