"""OAST 带外检测：回调记录器

原理：向注入点注入带唯一 token 的回调 URL，若目标服务器主动请求该 URL
（SSRF / 命令注入 / XXE 外带等），回调端点记录命中，从而在"无回显"场景下
确认漏洞存在。

- 默认回调基址为本地（演示/内网靶场模式）；配置 OAST_BASE_URL 为公网地址后
  可用于真实渗透（目标需能访问该地址）
- 回调端点公开（目标服务器不会携带 JWT），安全性依赖不可猜测的随机 token
"""
import threading
import time

# token → [命中详情]
_hits: dict[str, list[dict]] = {}
_lock = threading.Lock()
_HIT_LIMIT_PER_TOKEN = 20   # 单 token 最多保留命中数（防刷）
_MAX_TOKENS = 5000          # 内存上限（防泄漏）

_TOKEN_RE = None


def _token_ok(token: str) -> bool:
    global _TOKEN_RE
    if _TOKEN_RE is None:
        import re
        _TOKEN_RE = re.compile(r"^[A-Za-z0-9\-_]{8,64}$")
    return bool(token and _TOKEN_RE.match(token))


def record_hit(token: str, remote_ip: str = "", path: str = "", ua: str = "") -> bool:
    """记录一次带外回调命中。token 不合法返回 False。"""
    if not _token_ok(token):
        return False
    hit = {
        "remote_ip": remote_ip or "",
        "path": path[:300] or "",
        "ua": ua[:200] or "",
        "ts": time.strftime("%Y-%m-%d %H:%M:%S"),
    }
    with _lock:
        if token not in _hits and len(_hits) >= _MAX_TOKENS:
            # 内存上限：清理最老的 token
            oldest = sorted(_hits.keys(), key=lambda k: _hits[k][0]["ts"])[:100]
            for k in oldest:
                _hits.pop(k, None)
        lst = _hits.setdefault(token, [])
        if len(lst) < _HIT_LIMIT_PER_TOKEN:
            lst.append(hit)
    return True


def poll(token: str) -> list[dict]:
    """查询某 token 的命中记录（供扫描器确认）"""
    if not _token_ok(token):
        return []
    with _lock:
        return list(_hits.get(token, []))


def drain(token: str) -> list[dict]:
    """查询并清除命中记录（扫描器用后即焚，避免内存持续占用）"""
    if not _token_ok(token):
        return []
    with _lock:
        return _hits.pop(token, [])
