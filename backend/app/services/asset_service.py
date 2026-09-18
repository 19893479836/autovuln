"""资产服务：规范化、批量导入去重、存活监测"""
import re
import socket
from datetime import datetime
from urllib.parse import urlparse

from sqlalchemy.orm import Session

from ..models import Asset, AssetRecord


def normalize_asset(raw: str) -> tuple[str, str] | None:
    """规范化输入 → (kind, value)。不支持的类型返回 None。"""
    raw = (raw or "").strip().strip("/")
    if not raw:
        return None
    # URL
    if raw.startswith(("http://", "https://")):
        try:
            p = urlparse(raw)
            host = p.netloc  # 保留端口号
            if not host:
                return None
            path = p.path or "/"
            return "url", f"{p.scheme}://{host}{path}".rstrip("/") or f"{p.scheme}://{host}"
        except Exception:
            return None
    # IP
    ipv4 = re.match(r"^\d{1,3}(\.\d{1,3}){3}$", raw)
    if ipv4:
        parts = [int(x) for x in raw.split(".")]
        if all(0 <= x <= 255 for x in parts):
            return "ip", raw
        return None
    # 域名（含子域名）
    if re.match(r"^[a-zA-Z0-9]([a-zA-Z0-9\-\.]*[a-zA-Z0-9])?\.[a-zA-Z]{2,}$", raw):
        return "domain", raw.lower()
    return None


def import_assets(db: Session, user_id: int, raw_values: list[str],
                  group_id: int | None = None, tags: str = "",
                  importance: str = "medium", cookie: str = "") -> dict:
    """批量导入 + 自动去重合并。返回 {added, existed, invalid, skipped_ip_private}"""
    result = {"added": 0, "existed": 0, "invalid": 0, "skipped": 0, "total": len(raw_values)}
    seen: set[tuple[str, str]] = set()
    for raw in raw_values:
        norm = normalize_asset(raw)
        if not norm:
            result["invalid"] += 1
            continue
        kind, value = norm
        key = (kind, value)
        if key in seen:
            result["existed"] += 1
            continue
        seen.add(key)
        exist = db.query(Asset).filter_by(user_id=user_id, kind=kind, value=value).first()
        if exist:
            result["existed"] += 1
            # 合并标签
            if tags and tags not in (exist.tags or "").split(","):
                merged = [t for t in (exist.tags or "").split(",") if t] + [tags]
                exist.tags = ",".join(dict.fromkeys(merged))
                exist.importance = importance or exist.importance
                if group_id and not exist.group_id:
                    exist.group_id = group_id
            # 认证 Cookie：仅显式传入时更新
            if cookie:
                exist.cookie = cookie
            continue
        db.add(Asset(
            user_id=user_id, group_id=group_id, kind=kind, value=value,
            raw_value=raw, tags=tags, importance=importance, status="unknown",
            cookie=cookie or None,
        ))
        result["added"] += 1
    db.commit()
    return result


def probe_alive(db: Session, asset: Asset) -> str:
    """存活探测：IP 用 TCP 445/80/443 之一；域名/URL 用 HTTP(S) 请求。"""
    try:
        if asset.kind == "ip":
            for port in (80, 443, 445):
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(3)
                try:
                    if s.connect_ex((asset.value, port)) == 0:
                        return "active"
                finally:
                    s.close()
            return "offline"
        # 域名 / URL
        import urllib.request
        import ssl
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        candidates = [asset.value] if asset.value.startswith(("http://", "https://")) else \
            [f"http://{asset.value}", f"https://{asset.value}"]
        for url in candidates:
            try:
                req = urllib.request.Request(url, method="HEAD",
                                             headers={"User-Agent": "AutoVuln/1.0"})
                with urllib.request.urlopen(req, timeout=6, context=ctx) as resp:
                    return "active"
            except Exception:
                try:
                    req = urllib.request.Request(url, headers={"User-Agent": "AutoVuln/1.0"})
                    with urllib.request.urlopen(req, timeout=6, context=ctx) as resp:
                        return "active"
                except Exception:
                    continue
        return "offline"
    except Exception:
        return "offline"


def run_alive_check(db: Session, user_id: int) -> dict:
    """批量存活监测：更新全部资产状态与 last_seen"""
    assets = db.query(Asset).filter_by(user_id=user_id).all()
    stats = {"active": 0, "offline": 0, "total": len(assets)}
    for asset in assets:
        status = probe_alive(db, asset)
        asset.status = status
        if status == "active":
            asset.last_seen_at = datetime.utcnow()
            stats["active"] += 1
        else:
            stats["offline"] += 1
    db.commit()
    return stats
