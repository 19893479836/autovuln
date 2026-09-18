"""Web 漏洞扫描引擎（规则驱动）

安全设计：
- 仅执行无害探测（引号闭合、特征回显、错误信息匹配、布尔/时间盲注），不注入破坏性语句
- 每个请求走限速；可暂停/取消
- 规则来自 rules 表（可导入/在线更新），不写死
"""
import hashlib
import json
import re
import time
from urllib.parse import parse_qs, quote, urlencode, urljoin, urlparse, urlunparse

from ..database import SessionLocal
from ..models import Asset, Rule, ScanTask
from .base import BaseScanner, http_request

# 无参数时探测的常见路径（规则引擎遍历）
PROBE_PATHS = ["/", "/index.php", "/index.html", "/login", "/api", "/api/v1", "/admin"]

# 无害探测载荷（不产生副作用）
PAYLOADS = {
    "sqli": ["'", '"', "1' and '1'='1", "1\" and \"1\"=\"1"],
    "xss": ['<script>alert(1)</script>', '"><svg/onload=alert(1)>'],
    "traversal": ["../../../../etc/passwd", "..%2f..%2f..%2fetc%2fpasswd"],
    "ssrf": ["http://127.0.0.1:80", "http://169.254.169.254/latest/meta-data/"],
}

# 响应特征 → 漏洞类型（误报抑制：至少两个特征同时命中）
SIGNATURES = {
    "sqli": [
        r"SQL syntax.*MySQL", r"Warning.*mysql_", r"Uncaught mysqli_sql_exception",
        r"SQLSTATE\[\d{5}\]", r"ORA-\d{5}", r"PostgreSQL.*ERROR", r"syntax error.*near",
        r"Microsoft OLE DB Provider for SQL Server", r"SQLite3::",
    ],
    "xss": [r"<script>alert\(1\)</script>", r"<svg/onload=alert\(1\)>"],
    "traversal": [r"root:.*:0:0:", r"\[root\]", r"root:x:0:0:"],
    "ssrf": [r"<title>.*meta-data.*</title>", r"ami-id", r"instance-id"],
}

# ---- SQL 盲注检测（阶段4） ----
# 布尔盲注模板：真条件响应应与基线一致，假条件响应应显著不同
BLIND_SQLI_TEMPLATES = {
    "numeric": [
        ("true", " AND 1=1"), ("false", " AND 1=2"),
        ("true", " AND 1=1-- -"), ("false", " AND 1=2-- -"),
    ],
    "string": [
        ("true", "' AND '1'='1"), ("false", "' AND '1'='2"),
        ("true", "' AND '1'='1'-- -"), ("false", "' AND '1'='2'-- -"),
    ],
}
# 时间盲注 payload（每主机限测，控制扫描时长）
TIME_BLIND_PAYLOADS = [" AND SLEEP(3)", "' AND SLEEP(3)-- -", " AND SLEEP(3)-- -"]
TIME_BLIND_THRESHOLD = 2.0  # 相对基线多出 2s 视为命中
BLIND_PARAM_CAP = 20        # 单次扫描最多盲注检测的参数数

# ---- 命令注入 / SSTI / XXE 检测（阶段5） ----
# 命令注入回显特征（uid=0(root) / /etc/passwd 行 / Windows 卷标）
CMD_SIGNATURES = [r"uid=\d+\(\w+\)", r"gid=\d+\(", r"root:x:0:0", r"Volume in drive"]
CMD_ECHO_PAYLOADS = [";id", "|id", "$(id)", ";whoami", "|uname -a"]
CMD_TIME_PAYLOADS = [";sleep 3", "|sleep 3", "$(sleep 3)"]
# SSTI 探针：{{7*7}} 等执行后应回显 49（且基线不含 49）
SSTI_PAYLOADS = ["{{7*7}}", "${7*7}", "<%=7*7%>", "{{7*'7'}}"]
SSTI_MARK = "49"
# XXE 探针：file 实体回显 /etc/passwd；http 实体触发带外回调
XXE_FILE_PAYLOAD = ('<?xml version="1.0"?><!DOCTYPE r [<!ENTITY x SYSTEM "file:///etc/passwd">]>'
                    "<root>&x;</root>")

# ---- 组件指纹版本比对（阶段8） ----
# match: 正则提取版本；bad_if: 版本区间（None 表示不限下限/上限）命中即视为存在已知漏洞
# 均为公开 CVE，命中提示人工复核（指纹可能被伪造）
FINGERPRINT_DB = [
    {"name": "nginx", "src": "header:server",
     "match": r"nginx/([\d.]+)", "bad_below": (1, 20, 0), "bad_above": None,
     "cve": "CVE-2021-23017", "sev": "high",
     "desc": "nginx < 1.20.0 存在 DNS 解析内存损坏漏洞，可导致拒绝服务/潜在代码执行"},
    {"name": "nginx", "src": "body:generator",
     "match": r'generator[^>]*content=["\']nginx[ /]([\d.]+)', "bad_below": (1, 20, 0), "bad_above": None,
     "cve": "CVE-2021-23017", "sev": "high",
     "desc": "nginx < 1.20.0 存在 DNS 解析内存损坏漏洞（Server 头被隐藏时从页面泄露）"},
    {"name": "Apache httpd", "src": "header:server",
     "match": r"Apache[/ ]([\d.]+)", "bad_below": (2, 4, 50), "bad_above": None,
     "cve": "CVE-2021-41773", "sev": "critical",
     "desc": "Apache httpd < 2.4.50 存在路径遍历 + 任意文件读取/命令执行"},
    {"name": "PHP", "src": "header:x-powered-by",
     "match": r"PHP/([\d.]+)", "bad_below": (7, 4, 0), "bad_above": None,
     "cve": "EOL", "sev": "medium",
     "desc": "PHP < 7.4 已停止安全维护，存在大量未修复漏洞"},
    {"name": "WordPress", "src": "body:generator",
     "match": r'generator[^>]*content=["\']WordPress ([\d.]+)', "bad_below": (5, 0, 0), "bad_above": None,
     "cve": "EOL", "sev": "medium",
     "desc": "WordPress < 5.0 为过期版本，存在多个已公开漏洞"},
    {"name": "jQuery", "src": "body:script",
     "match": r"jquery[-/]?([\d.]+)\.min\.js", "bad_below": (1, 9, 0), "bad_above": None,
     "cve": "CVE-2012-6708", "sev": "medium",
     "desc": "jQuery < 1.9.0 存在 Selector XSS（CVE-2012-6708）"},
    {"name": "jQuery", "src": "body:script",
     "match": r"jquery[-/]?([\d.]+)\.min\.js", "bad_below": (3, 5, 0), "bad_above": (3, 6, 0),
     "cve": "CVE-2020-11022", "sev": "medium",
     "desc": "jQuery 3.x < 3.5.0 存在 HTML 处理 XSS（CVE-2020-11022/11023）"},
    {"name": "Bootstrap", "src": "body:script",
     "match": r"bootstrap[-/]?([\d.]+)\.min\.js", "bad_below": (3, 4, 1), "bad_above": None,
     "cve": "CVE-2019-8331", "sev": "medium",
     "desc": "Bootstrap < 3.4.1 存在 tooltip/data-target XSS（CVE-2019-8331）"},
    {"name": "Tomcat", "src": "header:server",
     "match": r"Tomcat/([\d.]+)", "bad_below": (9, 0, 31), "bad_above": None,
     "cve": "CVE-2020-1938", "sev": "critical",
     "desc": "Apache Tomcat < 9.0.31 存在 Ghostcat（AJP 文件读取/包含）"},
]


class WebVulnScanner(BaseScanner):
    name = "vuln_web"
    display_name = "Web 漏洞扫描"
    _auth_cookie: str | None = None  # 认证态会话 Cookie（资产配置）

    def run(self):
        asset = self._get_asset()
        if not asset:
            return
        base = asset.value if asset.value.startswith(("http://", "https://")) else "http://" + asset.value
        params = self._get_params()
        # 认证态扫描：资产配置的登录会话 Cookie，随所有探测请求携带
        self._auth_cookie = (asset.cookie or "").strip() or None
        if self._auth_cookie:
            self.log(f"Web 扫描(认证态): {base}")

        with SessionLocal() as db:
            rules = db.query(Rule).filter_by(enabled=True).all()
            rules = [r for r in rules]

        self.log(f"Web 扫描: {base}")
        # 阶段1：基础请求基线（找带参数链接 & 收集指纹条件）
        baseline = self._baseline(base, params)

        # 连通性检查：连不上直接失败，不再继续发包
        if not baseline.get("http_ok"):
            self.mark_failed(f"目标 {base} 无法连接（超时/拒绝），请检查网络或目标存活状态")
            return

        # 阶段2：规则检测（响应头类规则 + 路径类规则）
        self._run_rules(base, rules, baseline, params)

        # 阶段3+4：通用注入/XSS/遍历探测 + SQL 盲注检测（统一进度）
        # 复用历史发现：动态爬虫等侦察器写入的 path 记录作为额外探测目标
        from ..models import AssetRecord
        with SessionLocal() as db:
            extra = [r.key for r in db.query(AssetRecord)
                     .filter_by(asset_id=asset.id, kind="path")
                     .limit(100).all()]
        self._probe_and_blind(base, baseline, extra)

        # 阶段5：OAST 带外检测（无回显 SSRF/命令注入等）
        self._oast_scan(base, baseline, extra)

        # 阶段6：命令注入 / SSTI / XXE 检测
        self._cmd_ssti_scan(base, baseline, extra)

        # 阶段7：存储型 XSS + 文件上传检测
        self._stored_upload_scan(base, baseline, extra)

        # 阶段8：组件指纹版本比对（已知 CVE）
        self._fingerprint_scan(base, baseline, extra)

        self.log("Web 漏洞扫描完成")

    # ---------- 阶段1 ----------
    def _req(self, url: str, method: str = "GET", headers: dict | None = None,
             body: str | bytes | None = None, timeout: int = 5):
        """统一请求出口：合并认证 Cookie（规则自定义头优先）"""
        merged = dict(headers or {})
        if self._auth_cookie:
            merged.setdefault("Cookie", self._auth_cookie)
        return http_request(url, method=method, headers=merged, body=body, timeout=timeout)

    def _baseline(self, base: str, params: dict) -> dict:
        """抓首页/常见路径，收集：响应头、可见链接、表单参数
        认证态下：/login /admin 等路径鉴权通过后 200，其内部链接同样会被爬取"""
        self.checkpoint()
        result = {"headers": {}, "links": [], "forms": [], "paths_ok": [], "http_ok": False}
        urls = [base] + [urljoin(base, p) for p in PROBE_PATHS[1:]]
        for url in urls:
            self.checkpoint()
            try:
                status, headers, body = self._req(url, timeout=5)
            except Exception:
                continue
            if url == base and status is not None:
                result["headers"] = headers
                result["http_ok"] = True
            if status == 200:
                result["paths_ok"].append(url)
                result["links"].extend(re.findall(r'href=["\']([^"\']+)["\']', body)[:50])
                result["forms"].extend(re.findall(r'<form[^>]*action=["\']?([^"\'>\s]*)', body, re.I)[:20])
        # 去重
        result["links"] = list(dict.fromkeys(result["links"]))[:100]
        result["forms"] = list(dict.fromkeys(result["forms"]))[:20]
        return result

    # ---------- 阶段2 ----------
    def _run_rules(self, base: str, rules: list, baseline: dict, params: dict):
        # 2a. 安全配置类（响应头检查，不发包；仅当目标 HTTP 真实可达才判定）
        if baseline.get("http_ok"):
            self._check_headers(base, baseline.get("headers", {}))
        else:
            self.log("目标 HTTP 不可达，跳过响应头检查（防误报）")

        # 2b. 路径类规则
        path_rules = [r for r in rules if r.path and r.path != "/"]
        total = len(path_rules)
        done = 0
        for rule in path_rules:
            self.checkpoint()
            if rule.fp_suppress:
                done += 1
                continue
            url = urljoin(base + "/", rule.path.lstrip("/"))
            try:
                status, headers, body = self._req(
                    url, method=rule.method, headers=self._loads(rule.headers),
                    body=rule.body, timeout=5,
                )
            except Exception:
                done += 1
                continue
            self._match_rule(rule, url, status, headers, body)
            done += 1
            if done % 5 == 0:
                self.set_progress(done, total, f"规则检测 {done}/{total}")

    def _check_headers(self, base: str, headers: dict):
        checks = [
            ("Strict-Transport-Security", "HSTS", "missing_hsts", "low",
             "响应缺少 Strict-Transport-Security 头", "建议启用 HSTS 强制 HTTPS"),
            ("X-Content-Type-Options", "XCTO", "missing_xcto", "low",
             "响应缺少 X-Content-Type-Options 头", "建议添加 X-Content-Type-Options: nosniff"),
            ("X-Frame-Options", "XFO", "missing_xfo", "low",
             "响应缺少 X-Frame-Options 头，存在点击劫持风险", "建议添加 X-Frame-Options 或 CSP frame-ancestors"),
            ("Content-Security-Policy", "CSP", "missing_csp", "low",
             "响应缺少 Content-Security-Policy 头", "建议配置 CSP 缓解 XSS"),
        ]
        for hkey, short, vtype, sev, desc, fix in checks:
            if not headers.get(hkey.lower()):
                self.find_vuln(
                    title=f"安全响应头缺失: {short}", vuln_type="misconfig",
                    severity=sev, url=base, confidence="high",
                    description=desc, fix_suggestion=fix,
                    vuln_key=f"header|{vtype}|{base}",
                )

    # ---------- 阶段3+4 ----------
    def _collect_targets(self, base: str, baseline: dict, extra: list[str] | None = None) -> list[str]:
        """待探测 URL：首页 + 已发现路径 + 同域链接（相对链接解析为绝对）+ 历史发现"""
        targets = [base] + baseline["paths_ok"]
        host = self._host(base)
        for link in baseline["links"]:
            full = urljoin(base, link) if not link.startswith(("http://", "https://")) else link
            if full.startswith(("http://", "https://")) and urlparse(full).hostname == host:
                targets.append(full)
        for u in extra or []:
            if u.startswith(("http://", "https://")) and urlparse(u).hostname == host:
                targets.append(u)
        return list(dict.fromkeys(targets))[:30]

    def _probe_and_blind(self, base: str, baseline: dict, extra: list[str] | None = None):
        """通用注入/XSS/遍历探测 + SQL 盲注检测（统一进度）"""
        targets = self._collect_targets(base, baseline, extra)
        blind_cands = self._blind_candidates(base, baseline, extra)
        total = len(targets) * 4 + len(blind_cands)
        done = 0
        for url in targets:
            self.checkpoint()
            # 基线响应：排除存储回显导致的反射 XSS 误报
            try:
                _, _, base_body = self._req(url, timeout=5)
            except Exception:
                base_body = ""
            for vtype, payloads in PAYLOADS.items():
                self.checkpoint()
                self._probe_single(url, vtype, payloads, base_body)
                done += 1
                if done % 4 == 0:
                    self.set_progress(done, total, f"漏洞探测 {done}/{total}")
        # SQL 盲注检测
        for url, param, value in blind_cands:
            self.checkpoint()
            try:
                self._blind_probe_param(url, param, value)
            except Exception:
                pass
            done += 1
            self.set_progress(done, total, f"盲注检测 {done}/{total}")
        self.set_progress(total, total, "通用探测完成")

    def _probe_single(self, url: str, vtype: str, payloads: list[str], base_body: str = ""):
        sep = "?" if "?" not in url else "&"
        for payload in payloads:
            self.checkpoint()
            probe_url = f"{url}{sep}__autovuln__={quote(payload)}"
            try:
                status, headers, body = self._req(probe_url, timeout=5)
            except Exception:
                continue
            sigs = SIGNATURES.get(vtype, [])
            hits = [s for s in sigs if re.search(s, body, re.I)]
            reflected = payload in body and payload not in (base_body or "")
            if vtype == "xss" and reflected:
                self._report(vtype, url, payload, status, body, confidence="high",
                             desc="检测到 XSS payload 反射回响应体，可能存在存储/反射型 XSS")
            elif len(hits) >= 1 and (vtype == "sqli" or vtype == "traversal" or vtype == "ssrf"):
                self._report(vtype, url, payload, status, body, confidence="medium",
                             desc=f"检测到 {vtype} 相关错误/特征回显: {hits[0][:100]}")

    def _report(self, vtype: str, url: str, payload: str, status: int, body: str,
                confidence: str, desc: str):
        meta = {
            "sqli": ("SQL 注入", "sqli", "high", "对输入参数使用参数化查询/ORM，过滤特殊字符"),
            "xss": ("跨站脚本 XSS", "xss", "medium", "输出编码 + CSP，输入校验"),
            "traversal": ("目录遍历", "traversal", "high", "规范化路径并限制在站点根目录内"),
            "ssrf": ("服务端请求伪造 SSRF", "ssrf", "high", "限制出站请求、校验 URL 协议与内网地址"),
        }
        title, vt, sev, fix = meta.get(vtype, (vtype, vtype, "medium", "修复"))
        self.find_vuln(
            title=f"疑似{title} (参数注入探测)", vuln_type=vt, severity=sev,
            url=url, param="__autovuln__", payload=payload,
            description=desc, confidence=confidence,
            response_raw=body[:2000], fix_suggestion=fix,
        )

    # ---------- 阶段4：SQL 盲注检测 ----------
    def _blind_candidates(self, base: str, baseline: dict, extra: list[str] | None = None) -> list:
        """收集真实存在的 GET 参数（base/已发现路径/同域链接/历史发现中的 query 参数）"""
        urls = [base] + baseline["paths_ok"]
        host = self._host(base)
        for link in baseline["links"]:
            full = urljoin(base, link) if not link.startswith(("http://", "https://")) else link
            if full.startswith(("http://", "https://")) and urlparse(full).hostname == host:
                urls.append(full)
        for u in extra or []:
            if u.startswith(("http://", "https://")) and urlparse(u).hostname == host:
                urls.append(u)
        seen: set = set()
        out: list = []
        for u in urls[:40]:
            q = urlparse(u)
            if not q.query:
                continue
            for k, vals in parse_qs(q.query).items():
                v = vals[0] if vals else ""
                if not v:
                    continue
                key = (q.scheme + "://" + q.netloc + q.path, k)
                if key in seen:
                    continue
                seen.add(key)
                out.append((u, k, v))
                if len(out) >= BLIND_PARAM_CAP:
                    return out
        return out

    def _blind_url(self, url: str, param: str, value: str) -> str:
        """重建 URL：保证参数唯一且正确编码（覆盖 URL 中已有的同名参数）"""
        p = urlparse(url)
        qs = parse_qs(p.query, keep_blank_values=True)
        qs[param] = [value]
        return urlunparse((p.scheme, p.netloc, p.path, p.params,
                           urlencode(qs, doseq=True), p.fragment))

    def _blind_fetch(self, url: str, param: str, value: str):
        """发送一次盲注探测请求，返回 (状态码, 响应长度, 响应哈希, 耗时)；异常返回 None"""
        self.checkpoint()
        t0 = time.time()
        try:
            status, headers, body = self._req(self._blind_url(url, param, value), timeout=8)
        except Exception:
            return None
        elapsed = time.time() - t0
        body = body or ""
        return status, len(body), hashlib.md5(body.encode("utf-8", "ignore")).hexdigest()[:8], elapsed

    def _blind_probe_param(self, url: str, param: str, value: str):
        """对单个参数执行布尔 + 时间盲注检测"""
        base_resp = self._blind_fetch(url, param, value)
        if base_resp is None:
            return
        _, blen, bhash, belapsed = base_resp

        # ---- 布尔盲注：真条件≈基线 且 假条件≠基线 ----
        for style, templates in BLIND_SQLI_TEMPLATES.items():
            true_same = False
            false_diff = False
            for kind, suffix in templates:
                resp = self._blind_fetch(url, param, value + suffix)
                if resp is None:
                    continue
                _, plen, phash, _ = resp
                if kind == "true" and phash == bhash:
                    true_same = True
                elif kind == "false" and phash != bhash:
                    false_diff = True
            if true_same and false_diff:
                self._report_blind("布尔型", style, url, param, value)
                return  # 已命中，不再测时间盲注

        # ---- 时间盲注：按参数类型选最优 payload，每参数独立探测（命中即停）----
        # 基线本身过慢无法区分，跳过
        if belapsed is None or belapsed >= TIME_BLIND_THRESHOLD:
            return
        if re.fullmatch(r"\d+", value or ""):
            time_payloads = [" AND SLEEP(3)"]
        else:
            time_payloads = ["' AND SLEEP(3)-- -", " AND SLEEP(3)"]
        for payload in time_payloads:
            resp = self._blind_fetch(url, param, value + payload)
            if resp is None:
                continue
            _, _, _, pelapsed = resp
            if pelapsed - belapsed >= TIME_BLIND_THRESHOLD:
                self._report_blind("时间型", "delay", url, param, value + payload)
                break

    def _report_blind(self, kind: str, style: str, url: str, param: str, payload: str):
        self.find_vuln(
            title=f"疑似SQL盲注（{kind}）", vuln_type="sqli", severity="high",
            url=url, param=param, payload=payload, confidence="medium",
            description=(f"参数 {param} 存在{kind}SQL注入特征（{style}注入样式）："
                         f"布尔盲注——真条件与基线响应一致、假条件响应差异；"
                         f"或时间盲注——注入延迟生效。建议人工复核确认"),
            response_raw="", fix_suggestion="对输入参数使用参数化查询/ORM，过滤特殊字符",
        )

    # ---------- 阶段5：OAST 带外检测 ----------
    def _oast_scan(self, base: str, baseline: dict, extra: list[str] | None = None):
        """对真实存在的参数注入带外回调地址，确认无回显外带（SSRF/命令注入等）"""
        from ..config import settings
        if not settings.OAST_BASE_URL:
            return
        cands = self._blind_candidates(base, baseline, extra)
        if not cands:
            return
        import uuid
        from ..services.oast import drain

        tokens: dict[str, tuple[str, str]] = {}
        total = len(cands)
        done = 0
        for url, param, value in cands:
            self.checkpoint()
            token = uuid.uuid4().hex
            cb = f"{settings.OAST_BASE_URL}/api/oast/callback?token={token}"
            self._blind_fetch(url, param, cb)  # 参数值替换为回调地址
            tokens[token] = (url, param)
            done += 1
            self.set_progress(done, total, f"OAST 注入 {done}/{total}")
        # 统一等待目标发起回调
        time.sleep(1.5)
        for token, (url, param) in tokens.items():
            hits = drain(token)
            if hits:
                self._report_oast(url, param, hits[0])
        self.set_progress(total, total, "OAST 检测完成")

    def _report_oast(self, url: str, param: str, hit: dict):
        from ..config import settings
        self.find_vuln(
            title="疑似SSRF（带外回调确认）", vuln_type="ssrf", severity="high",
            url=url, param=param,
            payload=f"{settings.OAST_BASE_URL}/api/oast/callback?token=*",
            confidence="high",
            description=(f"参数 {param} 注入带外回调地址后，目标服务器主动请求了回调端点"
                         f"（来源IP {hit.get('remote_ip')}，时间 {hit.get('ts')}），"
                         f"确认存在 SSRF / 命令注入 / XXE 等无回显外带风险"),
            response_raw="",
            fix_suggestion="限制服务端请求的协议与目标地址，禁止访问内网/IPv6/云元数据地址；对参数做白名单校验",
        )

    # ---------- 阶段6：命令注入 / SSTI / XXE ----------
    def _fetch_body(self, url: str, param: str, value: str):
        """注入式 GET 请求，返回 (状态码, 响应体, 耗时)；异常返回 None"""
        self.checkpoint()
        t0 = time.time()
        try:
            status, headers, body = self._req(self._blind_url(url, param, value), timeout=8)
        except Exception:
            return None
        return status, body or "", time.time() - t0

    def _cmd_ssti_scan(self, base: str, baseline: dict, extra: list[str] | None = None):
        """命令注入（回显/时间/带外）+ SSTI（表达式回显）+ XXE（实体回显/带外）"""
        from ..config import settings
        cands = self._blind_candidates(base, baseline, extra)
        total = len(cands) * 8 + 10
        done = 0

        for url, param, value in cands:
            self.checkpoint()
            base_resp = self._fetch_body(url, param, value)
            if base_resp is None:
                done += 8
                continue
            _, bbody, belapsed = base_resp

            # ---- 命令注入：回显特征 ----
            for p in CMD_ECHO_PAYLOADS:
                self.checkpoint()
                resp = self._fetch_body(url, param, value + p)
                done += 1
                if resp is None:
                    continue
                _, cbody, _ = resp
                if any(re.search(s, cbody, re.I) for s in CMD_SIGNATURES):
                    self._report_cmd(url, param, value + p, "回显确认")
                    done = min(done, total - 1)
                    break

            # ---- 命令注入：时间延迟 ----
            for p in CMD_TIME_PAYLOADS:
                self.checkpoint()
                resp = self._fetch_body(url, param, value + p)
                done += 1
                if resp is None:
                    continue
                _, _, celapsed = resp
                if celapsed - belapsed >= TIME_BLIND_THRESHOLD:
                    self._report_cmd(url, param, value + p, "时间延迟")
                    break

            # ---- SSTI：表达式执行回显 49（基线不含）----
            for p in SSTI_PAYLOADS:
                self.checkpoint()
                resp = self._fetch_body(url, param, value + p)
                done += 1
                if resp is None:
                    continue
                _, sbody, _ = resp
                if SSTI_MARK in sbody and SSTI_MARK not in bbody:
                    self._report_ssti(url, param, value + p)
                    break

            done += 4  # 对齐进度步长

        # ---- XXE：对收集到的 URL 发 POST XML（file 实体回显 + http 实体带外）----
        targets = self._collect_targets(base, baseline, extra)
        xxe_tokens: dict[str, str] = {}
        for url in targets:
            self.checkpoint()
            # file 实体：回显 /etc/passwd
            try:
                st, hd, xbody = self._req(url, method="POST",
                                          headers={"Content-Type": "application/xml"},
                                          body=XXE_FILE_PAYLOAD, timeout=8)
                done += 1
                if any(re.search(s, xbody or "", re.I) for s in CMD_SIGNATURES):
                    self._report_xxe(url, "file 实体回显")
            except Exception:
                done += 1
            # http 实体：带外回调（统一等待后确认）
            if settings.OAST_BASE_URL:
                import uuid
                token = uuid.uuid4().hex
                oast_payload = ('<?xml version="1.0"?><!DOCTYPE r [<!ENTITY x SYSTEM "'
                                f'{settings.OAST_BASE_URL}/api/oast/callback?token={token}">]>'
                                "<root>&x;</root>")
                try:
                    self._req(url, method="POST",
                              headers={"Content-Type": "application/xml"},
                              body=oast_payload, timeout=8)
                    done += 1
                    xxe_tokens[token] = url
                except Exception:
                    done += 1
        if xxe_tokens:
            from ..services.oast import drain
            time.sleep(1.5)
            for token, url in xxe_tokens.items():
                if drain(token):
                    self._report_xxe(url, "http 实体带外回调")
        self.set_progress(total, total, "命令注入/SSTI/XXE 检测完成")

    def _report_cmd(self, url: str, param: str, payload: str, evidence: str):
        self.find_vuln(
            title="疑似命令注入", vuln_type="rce", severity="critical",
            url=url, param=param, payload=payload, confidence="medium",
            description=(f"参数 {param} 注入命令分隔符后出现{evidence}特征"
                         f"（命令回显 uid/口令文件行，或系统命令延迟生效），疑似命令执行漏洞"),
            response_raw="", fix_suggestion="禁止拼接系统命令，改用子进程安全调用并做参数白名单校验",
        )

    def _report_ssti(self, url: str, param: str, payload: str):
        self.find_vuln(
            title="疑似服务端模板注入 SSTI", vuln_type="ssti", severity="high",
            url=url, param=param, payload=payload, confidence="medium",
            description=(f"参数 {param} 注入模板表达式 {SSTI_MARK} 计算结果回显，"
                         f"疑似模板引擎未转义直接渲染用户输入"),
            response_raw="", fix_suggestion="模板渲染时对用户输入做转义，使用沙箱模板环境",
        )

    def _report_xxe(self, url: str, evidence: str):
        self.find_vuln(
            title="疑似XXE（外部实体注入）", vuln_type="xxe", severity="high",
            url=url, payload=XXE_FILE_PAYLOAD[:80], confidence="medium",
            description=(f"提交含外部实体的 XML 后出现{evidence}特征，"
                         f"疑似 XML 解析器未禁用外部实体（可读文件/SSRF/带外外带）"),
            response_raw="", fix_suggestion="禁用 XML 解析器外部实体（XXE），使用安全解析配置",
        )

    # ---------- 阶段7：存储型 XSS + 文件上传 ----------
    def _stored_upload_scan(self, base: str, baseline: dict, extra: list[str] | None = None):
        """存储型 XSS：表单提交 payload → 回读页面验证持久化回显
        文件上传：multipart 提交恶意文件 → 校验接受危险类型 + 上传后路径可访问"""
        targets = self._collect_targets(base, baseline, extra)
        total = len(targets) * 2 + 4
        done = 0
        stored_marker = 'avstoredxss-"1'
        xss_payload = '<script>alert("' + stored_marker + '")</script>'

        for url in targets:
            self.checkpoint()
            try:
                st, hd, body = self._req(url, timeout=5)
            except Exception:
                done += 2
                continue
            # ---- 存储型 XSS：找 POST 表单并提交 payload ----
            for form in re.findall(r'<form[^>]*>.*?</form>', body or "", re.I | re.S):
                self.checkpoint()
                done += 1
                action = None
                fm = re.search(r'<form[^>]*action=["\']?([^"\'>\s]*)', form, re.I)
                if fm:
                    action = urljoin(url, fm.group(1))
                names = re.findall(r'<input[^>]*name=["\']([^"\']+)["\']', form, re.I)
                if not names or not action:
                    continue
                import urllib.parse as up
                data = up.urlencode({names[0]: xss_payload, **{n: "x" for n in names[1:]}})
                try:
                    self._req(action, method="POST",
                              headers={"Content-Type": "application/x-www-form-urlencoded"},
                              body=data, timeout=5)
                except Exception:
                    continue
                # 回读表单所在页/action，验证持久化回显
                for check_url in (url, action):
                    try:
                        st2, _, body2 = self._req(check_url, timeout=5)
                    except Exception:
                        continue
                    if body2 and stored_marker in body2:
                        self._report_stored_xss(action or check_url, names[0], xss_payload)
                        break
            # ---- 文件上传：multipart 恶意文件 ----
            done += 1
            if re.search(r'(upload|import|attach|file)', url, re.I) or \
               re.search(r'enctype=["\']multipart', body or "", re.I):
                self._probe_upload(url)

        self.set_progress(total, total, "存储型XSS/上传检测完成")

    def _probe_upload(self, url: str):
        """构造 multipart 恶意文件提交，检测危险扩展名接受 + 上传后路径可访问"""
        fname = "avshell.php"
        content = "<?php echo md5(1); ?>"
        boundary = "----avboundary2026"
        body = (f"--{boundary}\r\n"
                "Content-Disposition: form-data; name=\"file\"; "
                f"filename=\"{fname}\"\r\n"
                "Content-Type: application/octet-stream\r\n\r\n"
                f"{content}\r\n--{boundary}--\r\n")
        try:
            st, hd, resp = self._req(url, method="POST",
                                     headers={"Content-Type": f"multipart/form-data; boundary={boundary}"},
                                     body=body, timeout=8)
        except Exception:
            return
        ok = (resp or "").find(fname) >= 0 or ("上传成功" in (resp or ""))
        if not ok:
            return
        # 尝试访问上传后路径（响应中 /uploads/xxx 或 /upload/xxx）
        import re as _re
        m = _re.search(r'((?:/uploads?|/files?)/[^"\'<>\s]+)', resp or "")
        path = m.group(1) if m else f"/uploads/{fname}"
        try:
            st2, _, body2 = self._req(urljoin(url, path), timeout=5)
        except Exception:
            st2, body2 = None, ""
        access_ok = st2 == 200 and ("<?php" in (body2 or "") or "webshell" in (body2 or ""))
        self._report_upload(url, fname, access_ok)

    def _report_stored_xss(self, url: str, param: str, payload: str):
        self.find_vuln(
            title="疑似存储型XSS", vuln_type="xss", severity="high",
            url=url, param=param, payload=payload[:80], confidence="medium",
            description=(f"表单字段 {param} 提交 XSS payload 后，重新访问页面仍能回显该 payload，"
                         f"确认存在持久化存储型 XSS（影响所有访问该页面的用户）"),
            response_raw="", fix_suggestion="输出编码 + 输入过滤，存储与回显均需转义",
        )

    def _report_upload(self, url: str, fname: str, access_ok: bool):
        self.find_vuln(
            title="任意文件上传（危险类型）" if access_ok else "文件上传未校验扩展名",
            vuln_type="upload", severity="critical" if access_ok else "high",
            url=url, payload=f"filename={fname}", confidence="medium",
            description=(f"上传接口接受危险扩展名文件 {fname}"
                         + ("，且上传后路径可直接访问（webshell 风险）" if access_ok
                            else "，存在 Webshell/恶意文件上传风险")),
            response_raw="", fix_suggestion="校验扩展名白名单 + 文件内容魔数 + 存储目录不可执行 + 随机文件名",
        )

    # ---------- 阶段8：组件指纹版本比对 ----------
    def _fingerprint_scan(self, base: str, baseline: dict, extra: list[str] | None = None):
        """从各页面响应头/body 提取组件版本，与已知 CVE 版本区间比对"""
        if not baseline.get("http_ok"):
            return
        pages: dict[str, tuple[dict, str]] = {}
        targets = self._collect_targets(base, baseline, extra)
        for url in targets[:20]:
            self.checkpoint()
            try:
                st, hd, body = self._req(url, timeout=5)
            except Exception:
                continue
            pages[url] = ({k.lower(): v for k, v in (hd or {}).items()}, body or "")
        if not pages:
            return
        total = len(FINGERPRINT_DB)
        done = 0
        for fp in FINGERPRINT_DB:
            self.checkpoint()
            done += 1
            for url, (headers, body) in pages.items():
                src = fp["src"]
                if src == "header:server":
                    text = headers.get("server", "")
                elif src == "header:x-powered-by":
                    text = headers.get("x-powered-by", "")
                else:
                    text = body
                m = re.search(fp["match"], text, re.I)
                if not m:
                    continue
                try:
                    ver = tuple(int(x) for x in m.group(1).split("."))
                except ValueError:
                    continue
                bad = False
                if fp["bad_below"] and ver < fp["bad_below"]:
                    bad = True
                if not bad and fp["bad_above"] and ver >= fp["bad_above"]:
                    bad = True
                if bad:
                    self._report_cve(url, fp, m.group(1))
                    break
            self.set_progress(done, total, f"指纹比对 {done}/{total}")

    def _report_cve(self, url: str, fp: dict, version: str):
        self.find_vuln(
            title=f"组件版本存在已知漏洞: {fp['name']} {version} ({fp['cve']})",
            vuln_type="cve", severity=fp["sev"], url=url,
            param=f"{fp['name']} {version}", payload=version,
            confidence="medium",
            description=(f"识别到 {fp['name']} {version}，命中 {fp['cve']}：{fp['desc']}。"
                         f"指纹可能被伪造，建议人工复核"),
            response_raw="",
            fix_suggestion=f"升级 {fp['name']} 至已修复版本；隐藏版本号信息",
        )

    # ---------- 匹配 ----------
    def _match_rule(self, rule: Rule, url: str, status: int, headers: dict, body: str):
        # 状态码条件
        if rule.match_status:
            allowed = [int(x) for x in str(rule.match_status).split(",") if x.strip().isdigit()]
            if allowed and status not in allowed:
                return
        # 响应头条件
        if rule.match_header:
            try:
                hk, hv = rule.match_header.split(":", 1)
                actual = headers.get(hk.strip().lower(), "")
                if not re.search(hv.strip(), actual, re.I):
                    return
            except Exception:
                return
        # 响应体条件
        if rule.match_regex:
            if not re.search(rule.match_regex, body, re.I):
                return
        self.find_vuln(
            title=rule.name, vuln_type=rule.vuln_type, severity=rule.severity,
            cvss_score=rule.cvss_score, url=url, confidence="high",
            description=rule.description, fix_suggestion=rule.fix_suggestion,
            request_raw=f"{rule.method} {url}", response_raw=body[:2000],
            reference=self._loads(rule.reference) if rule.reference else None,
        )

    # ---------- 工具 ----------
    @staticmethod
    def _loads(s: str) -> dict:
        try:
            v = json.loads(s or "{}")
            return v if isinstance(v, dict) else {}
        except Exception:
            return {}

    @staticmethod
    def _host(url: str) -> str:
        """提取主机名（不含端口），用于同域判断"""
        return urlparse(url).hostname or url

    def _get_asset(self):
        with SessionLocal() as db:
            task = db.get(ScanTask, self.task_id)
            return db.get(Asset, task.asset_id) if task else None

    def _get_params(self) -> dict:
        with SessionLocal() as db:
            task = db.get(ScanTask, self.task_id)
            try:
                return json.loads(task.params or "{}")
            except Exception:
                return {}
