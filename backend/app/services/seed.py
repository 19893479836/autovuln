"""内置种子数据：漏洞规则 / 指纹规则 / POC（首次启动自动加载）

所有规则均可被外部导入/在线更新覆盖，非写死逻辑。
"""
import json
from datetime import datetime

from ..config import settings
from ..database import SessionLocal
from ..models import FingerprintRule, PocScript, Rule

# ---------------- 漏洞检测规则 ----------------
WEB_RULES: list[dict] = [
    {
        "rule_key": "info-svn-entries", "name": "SVN 目录泄露 (.svn/entries)",
        "vuln_type": "info_leak", "severity": "medium", "cvss_score": 5.0,
        "method": "GET", "path": "/.svn/entries",
        "match_regex": r"^\d{1,2}\s*$|dir\n", "match_status": "200",
        "description": "目标暴露 SVN 版本控制目录，可能泄露源代码与敏感信息",
        "fix_suggestion": "禁止 Web 服务访问 .svn 目录",
    },
    {
        "rule_key": "info-git-config", "name": "Git 配置泄露 (.git/config)",
        "vuln_type": "info_leak", "severity": "high", "cvss_score": 7.5,
        "method": "GET", "path": "/.git/config",
        "match_regex": r"\[core\]|repositoryformatversion", "match_status": "200",
        "description": "目标暴露 .git/config，攻击者可下载完整源码",
        "fix_suggestion": "禁止 Web 服务访问 .git 目录",
    },
    {
        "rule_key": "info-env", "name": ".env 环境变量泄露",
        "vuln_type": "info_leak", "severity": "high", "cvss_score": 7.5,
        "method": "GET", "path": "/.env",
        "match_regex": r"(APP_KEY|DB_|SECRET|TOKEN|PASSWORD)\s*=", "match_status": "200",
        "description": "目标暴露 .env 配置文件，可能包含数据库口令与密钥",
        "fix_suggestion": "移除 .env 的 Web 可访问性",
    },
    {
        "rule_key": "info-phpinfo", "name": "PHP 探针泄露 (phpinfo)",
        "vuln_type": "info_leak", "severity": "medium", "cvss_score": 5.0,
        "method": "GET", "path": "/phpinfo.php",
        "match_regex": r"PHP Version|phpinfo\(\)", "match_status": "200",
        "description": "目标暴露 phpinfo 探针，泄露配置与环境信息",
        "fix_suggestion": "删除生产环境的 phpinfo 文件",
    },
    {
        "rule_key": "info-actuator", "name": "Spring Actuator 未授权访问",
        "vuln_type": "unauthorized", "severity": "high", "cvss_score": 7.8,
        "method": "GET", "path": "/actuator/env",
        "match_regex": r"propertySources|activeProfiles", "match_status": "200",
        "description": "Spring Boot Actuator 端点未鉴权，可读取环境变量与配置",
        "fix_suggestion": "对 Actuator 端点启用认证并限制暴露",
    },
    {
        "rule_key": "info-swagger", "name": "API 文档未授权暴露 (Swagger)",
        "vuln_type": "unauthorized", "severity": "low", "cvss_score": 3.1,
        "method": "GET", "path": "/v2/api-docs",
        "match_regex": r"swagger|openapi|paths", "match_status": "200",
        "description": "Swagger API 文档对外开放，泄露接口结构",
        "fix_suggestion": "生产环境关闭 API 文档端点",
    },
    {
        "rule_key": "info-druid", "name": "Druid 监控未授权访问",
        "vuln_type": "unauthorized", "severity": "high", "cvss_score": 7.5,
        "method": "GET", "path": "/druid/index.html",
        "match_regex": r"Druid|StatViewServlet", "match_status": "200",
        "description": "Druid 数据库监控页面未授权访问，可查看 SQL 与会话",
        "fix_suggestion": "为 Druid 监控页配置登录鉴权",
    },
    {
        "rule_key": "misconfig-backup", "name": "备份文件泄露",
        "vuln_type": "info_leak", "severity": "medium", "cvss_score": 5.3,
        "method": "GET", "path": "/backup.zip",
        "match_regex": r"PK\x03\x04", "match_status": "200",
        "description": "站点根目录存在可下载的备份压缩包",
        "fix_suggestion": "移除备份文件并阻止压缩包下载",
    },
    {
        "rule_key": "misconfig-http-put", "name": "WebDAV PUT 方法开启",
        "vuln_type": "misconfig", "severity": "medium", "cvss_score": 6.5,
        "method": "OPTIONS", "path": "/",
        "match_header": "allow: PUT|DAV", "match_status": "200",
        "description": "服务器允许 PUT 方法，攻击者可能上传恶意文件",
        "fix_suggestion": "禁用不必要的 HTTP 方法",
    },
    {
        "rule_key": "misconfig-cors", "name": "宽松 CORS 配置 (Access-Control-Allow-Origin: *)",
        "vuln_type": "misconfig", "severity": "low", "cvss_score": 3.1,
        "method": "GET", "path": "/",
        "match_header": r"access-control-allow-origin: \*",
        "description": "CORS 允许任意来源，配合凭证可能导致跨域数据窃取",
        "fix_suggestion": "CORS 白名单化并避免使用通配符+凭证",
    },
    {
        "rule_key": "unauth-consul", "name": "Consul 未授权访问",
        "vuln_type": "unauthorized", "severity": "high", "cvss_score": 7.5,
        "method": "GET", "path": "/v1/agent/services",
        "match_regex": r"ID|Service|Address", "match_status": "200",
        "description": "Consul Agent API 未授权，可读取服务注册信息",
        "fix_suggestion": "为 Consul API 启用 ACL 认证",
    },
    {
        "rule_key": "unauth-jenkins", "name": "Jenkins 未授权访问",
        "vuln_type": "unauthorized", "severity": "high", "cvss_score": 7.5,
        "method": "GET", "path": "/script",
        "match_regex": r"Groovy|script|Jenkins", "match_status": "200",
        "description": "Jenkins Script Console 未授权，可执行系统命令",
        "fix_suggestion": "为 Jenkins 配置认证与授权",
    },
]

# ---------------- 组件 CVE 规则 ----------------
# 指纹命中即提示"疑似受影响，需人工复核"；不替代精确版本比对。
CVE_RULES: list[dict] = [
    {
        "rule_key": "cve-fastjson-rce", "name": "Fastjson 反序列化远程代码执行 (CVE-2017-18349)",
        "vuln_type": "cve", "severity": "critical", "cvss_score": 9.8,
        "fingerprint_hint": "fastjson",
        "description": "检测到 Fastjson 指纹，1.2.24 及以下版本存在反序列化 RCE（CVE-2017-18349），需人工复核版本",
        "fix_suggestion": "升级 fastjson 至 1.2.83 及以上，或启用 safeMode",
        "reference": "https://nvd.nist.gov/vuln/detail/CVE-2017-18349",
    },
    {
        "rule_key": "cve-shiro-rce", "name": "Apache Shiro 反序列化 RCE (CVE-2016-4437)",
        "vuln_type": "cve", "severity": "critical", "cvss_score": 9.8,
        "fingerprint_hint": "shiro",
        "description": "检测到 Shiro 指纹（rememberMe），默认密钥场景存在反序列化 RCE（CVE-2016-4437），需人工复核",
        "fix_suggestion": "升级 Shiro 至 1.4.2 及以上并更换默认密钥",
        "reference": "https://nvd.nist.gov/vuln/detail/CVE-2016-4437",
    },
    {
        "rule_key": "cve-weblogic-rce", "name": "WebLogic 反序列化 RCE (CVE-2019-2725)",
        "vuln_type": "cve", "severity": "critical", "cvss_score": 9.8,
        "fingerprint_hint": "weblogic",
        "description": "检测到 WebLogic 指纹，部分版本 wls9_async_response 组件存在反序列化 RCE（CVE-2019-2725），需人工复核",
        "fix_suggestion": "升级 WebLogic 至官方修复版本或按 Oracle 公告处理",
        "reference": "https://nvd.nist.gov/vuln/detail/CVE-2019-2725",
    },
    {
        "rule_key": "cve-thinkphp-rce", "name": "ThinkPHP 5 远程代码执行 (CVE-2018-20062)",
        "vuln_type": "cve", "severity": "critical", "cvss_score": 9.8,
        "fingerprint_hint": "thinkphp",
        "description": "检测到 ThinkPHP 指纹，5.0.x 部分版本存在远程代码执行（CVE-2018-20062），需人工复核",
        "fix_suggestion": "升级 ThinkPHP 至最新版本",
        "reference": "https://nvd.nist.gov/vuln/detail/CVE-2018-20062",
    },
    {
        "rule_key": "cve-spring4shell", "name": "Spring Framework RCE (CVE-2022-22965)",
        "vuln_type": "cve", "severity": "critical", "cvss_score": 9.8,
        "fingerprint_hint": "spring",
        "description": "检测到 Spring 指纹，5.3.0-5.3.17 / 5.2.0-5.2.19 等版本存在 Spring4Shell RCE（CVE-2022-22965），需人工复核",
        "fix_suggestion": "升级 Spring Framework 至 5.3.18 / 5.2.20 及以上",
        "reference": "https://nvd.nist.gov/vuln/detail/CVE-2022-22965",
    },
]

# ---------------- 指纹规则 ----------------
FINGERPRINT_RULES: list[dict] = [
    {"fp_key": "nginx", "name": "nginx", "category": "server",
     "rules": [{"type": "header", "key": "server", "pattern": r"nginx"}], "cpe": "cpe:/a:nginx:nginx"},
    {"fp_key": "apache", "name": "Apache httpd", "category": "server",
     "rules": [{"type": "header", "key": "server", "pattern": r"apache"}], "cpe": "cpe:/a:apache:http_server"},
    {"fp_key": "iis", "name": "Microsoft IIS", "category": "server",
     "rules": [{"type": "header", "key": "server", "pattern": r"microsoft-iis"}], "cpe": "cpe:/a:microsoft:iis"},
    {"fp_key": "tomcat", "name": "Apache Tomcat", "category": "middleware",
     "rules": [{"type": "header", "key": "server", "pattern": r"tomcat|coYote"},
               {"type": "header", "key": "x-powered-by", "pattern": r"tomcat"}],
     "cpe": "cpe:/a:apache:tomcat"},
    {"fp_key": "wordpress", "name": "WordPress", "category": "cms",
     "rules": [{"type": "header", "key": "x-powered-by", "pattern": r"wordpress"},
               {"type": "body", "pattern": r"wp-content|wp-includes|wordpress"}], "cpe": "cpe:/a:wordpress:wordpress"},
    {"fp_key": "thinkphp", "name": "ThinkPHP", "category": "cms",
     "rules": [{"type": "header", "key": "x-powered-by", "pattern": r"thinkphp"},
               {"type": "body", "pattern": r"thinkphp"}], "cpe": "cpe:/a:thinkphp:thinkphp"},
    {"fp_key": "spring", "name": "Spring Framework", "category": "framework",
     "rules": [{"type": "header", "key": "x-application-context", "pattern": r"."},
               {"type": "body", "pattern": r"Whitelabel Error Page|springframework"}],
     "cpe": "cpe:/a:pivotal_software:spring_framework"},
    {"fp_key": "django", "name": "Django", "category": "framework",
     "rules": [{"type": "header", "key": "server", "pattern": r"wsgiserver"},
               {"type": "body", "pattern": r"django\.core|csrftoken"}], "cpe": "cpe:/a:djangoproject:django"},
    {"fp_key": "redis", "name": "Redis", "category": "component",
     "rules": [{"type": "header", "key": "server", "pattern": r"redis"}], "cpe": "cpe:/a:redis:redis"},
    {"fp_key": "grafana", "name": "Grafana", "category": "component",
     "rules": [{"type": "header", "key": "x-grafana-request-id", "pattern": r"."},
               {"type": "body", "pattern": r"grafana"}], "cpe": "cpe:/a:grafana:grafana"},
    {"fp_key": "druid", "name": "Druid", "category": "component",
     "rules": [{"type": "body", "pattern": r"druid|StatViewServlet"}], "cpe": "cpe:/a:alibaba:druid"},
    {"fp_key": "fastjson", "name": "Fastjson", "category": "component",
     "rules": [{"type": "body", "pattern": r"fastjson"}], "cpe": "cpe:/a:alibaba:fastjson"},
    {"fp_key": "shiro", "name": "Apache Shiro", "category": "framework",
     "rules": [{"type": "header", "key": "set-cookie", "pattern": r"rememberMe=deleteMe"}],
     "cpe": "cpe:/a:apache:shiro"},
    {"fp_key": "weblogic", "name": "Oracle WebLogic", "category": "middleware",
     "rules": [{"type": "header", "key": "server", "pattern": r"weblogic"},
               {"type": "body", "pattern": r"Oracle WebLogic Server"}],
     "cpe": "cpe:/a:oracle:weblogic_server"},
    {"fp_key": "jboss", "name": "JBoss/WildFly", "category": "middleware",
     "rules": [{"type": "header", "key": "x-powered-by", "pattern": r"jboss|wildfly"}],
     "cpe": "cpe:/a:redhat:jboss_enterprise_application_platform"},
    {"fp_key": "drupal", "name": "Drupal", "category": "cms",
     "rules": [{"type": "header", "key": "x-generator", "pattern": r"drupal"},
               {"type": "body", "pattern": r"drupal|drupal\.settings"}], "cpe": "cpe:/a:drupal:drupal"},
    {"fp_key": "joomla", "name": "Joomla", "category": "cms",
     "rules": [{"type": "body", "pattern": r"/media/system/js|com_content"}], "cpe": "cpe:/a:joomla:joomla"},
    {"fp_key": "cacti", "name": "Cacti", "category": "cms",
     "rules": [{"type": "body", "pattern": r"cacti"}], "cpe": "cpe:/a:cacti:cacti"},
    {"fp_key": "zabbix", "name": "Zabbix", "category": "component",
     "rules": [{"type": "body", "pattern": r"zabbix"}], "cpe": "cpe:/a:zabbix:zabbix"},
]

# ---------------- POC 脚本 ----------------
POCS: list[dict] = [
    {
        "poc_key": "poc-actuator-env", "name": "Spring Actuator 环境变量读取",
        "vuln_type": "unauthorized", "severity": "high", "script_type": "http",
        "script_data": {"method": "GET", "path": "/actuator/env",
                        "match": {"status": 200, "regex": r"propertySources"}},
        "fingerprint_hint": "spring",
    },
    {
        "poc_key": "poc-git-config", "name": "Git 源码泄露读取",
        "vuln_type": "info_leak", "severity": "high", "script_type": "http",
        "script_data": {"method": "GET", "path": "/.git/config",
                        "match": {"status": 200, "regex": r"\[core\]"}},
    },
    {
        "poc_key": "poc-consul-agent", "name": "Consul Agent 服务枚举",
        "vuln_type": "unauthorized", "severity": "high", "script_type": "http",
        "script_data": {"method": "GET", "path": "/v1/agent/services",
                        "match": {"status": 200, "regex": r"Service|Address"}},
    },
]


def ensure_seed_data() -> None:
    """幂等补种内置规则（按 rule_key 缺失补种，已有数据不重复加载、不覆盖）"""
    with SessionLocal() as db:
        for item in WEB_RULES + CVE_RULES:
            if not db.query(Rule).filter_by(rule_key=item["rule_key"]).first():
                db.add(Rule(**item, source="builtin", enabled=True))
        for item in FINGERPRINT_RULES:
            if not db.query(FingerprintRule).filter_by(fp_key=item["fp_key"]).first():
                db.add(FingerprintRule(
                    fp_key=item["fp_key"], name=item["name"], category=item["category"],
                    rules=json.dumps(item["rules"], ensure_ascii=False),
                    cpe=item.get("cpe"), enabled=True, source="builtin",
                ))
        for item in POCS:
            if not db.query(PocScript).filter_by(poc_key=item["poc_key"]).first():
                db.add(PocScript(
                    poc_key=item["poc_key"], name=item["name"],
                    vuln_type=item["vuln_type"], severity=item["severity"],
                    script_type=item["script_type"],
                    script_data=json.dumps(item["script_data"], ensure_ascii=False),
                    fingerprint_hint=item.get("fingerprint_hint"),
                    enabled=True, source="builtin",
                ))
        db.commit()
