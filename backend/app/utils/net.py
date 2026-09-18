"""出站请求安全校验：防止 SSRF（内网 / 环回 / 链路本地地址拒绝）"""
import ipaddress
import socket
from urllib.parse import urlparse

_PRIVATE_NETS = (
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("169.254.0.0/16"),
    ipaddress.ip_network("0.0.0.0/8"),
    ipaddress.ip_network("100.64.0.0/10"),
    ipaddress.ip_network("224.0.0.0/4"),
    ipaddress.ip_network("::1/128"),
    ipaddress.ip_network("fc00::/7"),
    ipaddress.ip_network("fe80::/10"),
)


def _is_unsafe_ip(ip_str: str) -> bool:
    """判定 IP 是否属于内网/环回/链路本地/保留/组播等不可信段。"""
    try:
        ip = ipaddress.ip_address(ip_str.split("%")[0])
    except ValueError:
        return True  # 解析失败视为不安全
    if (ip.is_private or ip.is_loopback or ip.is_link_local
            or ip.is_multicast or ip.is_reserved or ip.is_unspecified):
        return True
    return any(ip in net for net in _PRIVATE_NETS)


def validate_outbound_url(url: str) -> bool:
    """校验出站 URL：必须 http/https，主机能解析且所有地址均非内网。

    返回 True 表示允许出站；False 表示协议非法 / 无法解析 / 命中内网段。
    """
    try:
        p = urlparse(url)
        if p.scheme not in ("http", "https"):
            return False
        host = p.hostname
        if not host:
            return False
        # 直接 IP
        try:
            ipaddress.ip_address(host)
            return not _is_unsafe_ip(host)
        except ValueError:
            pass
        # 域名：解析全部地址，任一内网即拒绝（防 DNS 重绑定风险面）
        infos = socket.getaddrinfo(host, None, proto=socket.IPPROTO_TCP)
        for info in infos:
            if _is_unsafe_ip(info[4][0]):
                return False
        return True
    except Exception:
        return False
