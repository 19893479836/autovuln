"""AutoVuln 演示靶场：带明显漏洞特征的本地测试目标
运行：python demo_vuln_app.py
访问：http://127.0.0.1:9090
"""
from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse, PlainTextResponse, RedirectResponse
import uvicorn

app = FastAPI(title="Demo Vuln App")

# 故意缺安全响应头（让 AutoVuln 检出 HSTS/CSP/XFO 缺失）
BASE_HTML = """<!DOCTYPE html>
<html><head><title>Vulnerable Demo</title></head>
<body>
<h1>演示漏洞靶场</h1>
<p>这个站点故意留了几个漏洞供扫描器测试。</p>
<ul>
  <li><a href="/.git/config">.git/config</a></li>
  <li><a href="/.env">.env</a></li>
  <li><a href="/actuator/env">actuator/env</a></li>
  <li><a href="/search?q=hello">搜索框（反射 XSS）</a></li>
  <li><a href="/file?name=readme.txt">文件读取（目录遍历）</a></li>
  <li><a href="/products?id=1">商品查询（SQL 盲注）</a></li>
  <li><a href="/slow?id=1">慢查询（SQL 时间盲注）</a></li>
  <li><a href="/admin">管理后台（需登录，认证态扫描）</a></li>
  <li><a href="/spa">SPA 控制台（JS 动态渲染）</a></li>
  <li><a href="/fetch?url=http://127.0.0.1:9090/">URL 抓取（SSRF）</a></li>
  <li><a href="/ping?host=127.0.0.1">Ping 工具（命令注入）</a></li>
  <li><a href="/greet?name=world">问候（SSTI）</a></li>
  <li><a href="/parse">XML 解析（XXE）</a></li>
  <li><a href="/guestbook">留言板（存储型 XSS）</a></li>
  <li><a href="/upload">文件上传（危险类型）</a></li>
  <li><a href="/cms">企业 CMS（旧版组件）</a></li>
</ul>
</body></html>"""


@app.get("/", response_class=HTMLResponse)
def index():
    return BASE_HTML


# 1. .git/config 泄露
@app.get("/.git/config", response_class=PlainTextResponse)
def git_config():
    return """[core]
\trepositoryformatversion = 0
\tfilemode = true
\tbare = false
\tlogallrefupdates = true
[remote "origin"]
\turl = https://github.com/demo/vulnerable-app.git
\tfetch = +refs/heads/*:refs/remotes/origin/*
"""


# 2. .env 泄露（含数据库密码）
@app.get("/.env", response_class=PlainTextResponse)
def env_file():
    return """APP_KEY=base64:abc123
DB_HOST=127.0.0.1
DB_DATABASE=production
DB_USERNAME=root
DB_PASSWORD=Sup3rS3cret!
MAIL_PASSWORD=smtp_secret_123
"""


# 3. Actuator 未授权访问
@app.get("/actuator/env", response_class=PlainTextResponse)
def actuator_env():
    return """{"propertySources":[{"name":"server.properties","properties":{
"spring.datasource.password":{"value":"db_password_123"},
"secret.key":{"value":"sk-live-abcdef123456"},
"activeProfiles":{"value":"production"}}}]}"""


@app.get("/actuator/health")
def actuator_health():
    return {"status": "UP"}


# 4. 反射 XSS（反射任意查询参数）
@app.get("/search", response_class=HTMLResponse)
def search(request: Request, q: str = ""):
    # 故意不做输出编码 → 反射 XSS
    import urllib.parse
    all_params = dict(request.query_params)
    reflected = " ".join(f"{k}={urllib.parse.unquote(v)}" for k, v in all_params.items())
    return f"<html><body><h3>搜索结果</h3><p>你搜索了: {reflected}</p></body></html>"


# 5. 目录遍历（反射 __autovuln__ 参数中的遍历 payload）
@app.get("/file", response_class=PlainTextResponse)
def read_file(__autovuln__: str = "", name: str = ""):
    # 故意不加路径校验 → 目录遍历
    files = {
        "readme.txt": "这是 readme 文件",
        "etc_passwd": "root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin",
    }
    # 模拟遍历 payload 读到 /etc/passwd
    if "../" in __autovuln__ or "..%2f" in __autovuln__:
        return files["etc_passwd"]
    return files.get(name, f"文件 {name} 不存在")


# 6. 备份文件泄露
@app.get("/backup.zip")
def backup():
    return PlainTextResponse("PK\x03\x04" + "fake backup content", media_type="application/zip")


# 7. phpinfo 风格
@app.get("/phpinfo.php", response_class=HTMLResponse)
def phpinfo():
    return "<html><title>phpinfo()</title><body>PHP Version 7.4.3<br>System: Linux demo</body></html>"


# 8. Swagger 暴露
@app.get("/v2/api-docs", response_class=PlainTextResponse)
def swagger():
    return '{"swagger":"2.0","info":{"title":"Demo API"},"paths":{"/api/users":{"get":{}}}}'


# 9. SQL 注入模拟（布尔盲注 + 时间盲注均可验证）
#    /products?id=1            → 有结果
#    /products?id=1 AND 1=1    → 有结果（真条件）
#    /products?id=1 AND 1=2    → 无结果（假条件）
#    /products?id=1 AND SLEEP(3) → 延迟 3 秒（时间盲注）
@app.get("/products", response_class=HTMLResponse)
def products(id: str = ""):
    import time
    low = id.lower()
    # 时间盲注模拟：出现 sleep/benchmark 即延迟
    if "sleep(" in low or "benchmark(" in low:
        time.sleep(3)
        return "<html><body><p>查询中...</p></body></html>"
    # 布尔盲注模拟：真条件 → 有结果；假条件 → 无结果
    true_patterns = ["and 1=1", "and '1'='1", "and 1=1--", "and '1'='1'--"]
    false_patterns = ["and 1=2", "and '1'='2", "and 1=2--", "and '1'='2'--"]
    is_false = any(p in low for p in false_patterns)
    is_true = any(p in low for p in true_patterns)
    if is_false:
        return "<html><body><p>未找到商品（0 条结果）</p></body></html>"
    if is_true or low in ("1", "2"):
        return "<html><body><p>找到商品 1：测试商品（价格 ¥99）</p></body></html>"
    return "<html><body><p>未找到商品（0 条结果）</p></body></html>"


# 10. SQL 时间盲注模拟（仅延迟生效，布尔特征不区分）
#    /slow?id=1              → 立即返回
#    /slow?id=1 AND SLEEP(3) → 延迟 3 秒（时间盲注）
@app.get("/slow", response_class=HTMLResponse)
def slow(id: str = ""):
    import time
    if "sleep(" in id.lower() or "benchmark(" in id.lower():
        time.sleep(3)
    return "<html><body><p>查询完成</p></body></html>"


# 11. 认证态扫描模拟：/admin 需 Cookie session=admin 才能访问
#     未带 Cookie → 401；带 Cookie → 200 管理后台，内部含注入点
ADMIN_COOKIE = "session=admin"


def _is_admin(cookie_header: str) -> bool:
    return bool(cookie_header) and "session=admin" in (cookie_header or "")


@app.get("/admin", response_class=HTMLResponse)
def admin_panel(request: Request):
    if not _is_admin(request.headers.get("cookie", "")):
        return HTMLResponse("<html><body><h1>401 Unauthorized</h1><p>请先登录管理后台</p></body></html>",
                            status_code=401)
    return """<html><body>
<h1>管理后台</h1>
<p>欢迎，管理员</p>
<ul>
  <li><a href="/admin/users?role=admin">用户管理（SQL 盲注）</a></li>
  <li><a href="/admin/settings">系统设置</a></li>
</ul>
</body></html>"""


@app.get("/admin/users", response_class=HTMLResponse)
def admin_users(request: Request, role: str = ""):
    if not _is_admin(request.headers.get("cookie", "")):
        return HTMLResponse("<html><body><h1>401 Unauthorized</h1></body></html>", status_code=401)
    # 布尔盲注模拟（role 参数）：
    #   role=admin            → 有结果
    #   role=admin AND 1=1    → 有结果（真条件）
    #   role=admin AND 1=2    → 无结果（假条件）
    low = role.lower()
    false_patterns = ["and 1=2", "and '1'='2"]
    true_patterns = ["and 1=1", "and '1'='1"]
    is_false = any(p in low for p in false_patterns)
    is_true = any(p in low for p in true_patterns)
    if is_false:
        return "<html><body><p>0 位用户（无匹配）</p></body></html>"
    if is_true or low in ("admin", "editor"):
        return "<html><body><table><tr><th>ID</th><th>用户名</th></tr><tr><td>1</td><td>admin</td></tr></table></body></html>"
    return "<html><body><p>0 位用户（无匹配）</p></body></html>"


@app.get("/admin/settings", response_class=HTMLResponse)
def admin_settings(request: Request):
    if not _is_admin(request.headers.get("cookie", "")):
        return HTMLResponse("<html><body><h1>401 Unauthorized</h1></body></html>", status_code=401)
    return "<html><body><h1>系统设置</h1><p>数据库连接串: postgres://admin:Secret123@db:5432/app</p></body></html>"


# 12. SPA 动态页面模拟：链接由 JS 渲染，静态正则爬取拿不到
#     Playwright 渲染后才能发现 /dashboard?uid=1（反射 XSS）与 /api/profile（接口）
SPA_HTML = """<!DOCTYPE html>
<html><head><title>SPA Dashboard</title></head>
<body>
<div id="app">加载中...</div>
<script>
  // 模拟前端框架渲染：用 DOM API 动态创建链接，静态 HTML 中不存在 href 字符串
  setTimeout(function() {
    var app = document.getElementById('app');
    app.innerHTML = '<h1>控制台</h1><ul></ul>';
    var ul = app.querySelector('ul');
    function addLink(text, url) {
      var li = document.createElement('li');
      var a = document.createElement('a');
      a.href = url;
      a.textContent = text;
      li.appendChild(a);
      ul.appendChild(li);
    }
    addLink('个人面板', '/dashboard?uid=1');
    addLink('API 资料', '/api/profile');
  }, 200);
  // 模拟 API 调用（XHR）
  setTimeout(function() {
    var x = new XMLHttpRequest();
    x.open('GET', '/api/profile?token=guest', true);
    x.send();
  }, 300);
</script>
</body></html>"""


@app.get("/spa", response_class=HTMLResponse)
def spa():
    return HTMLResponse(SPA_HTML)


@app.get("/dashboard", response_class=HTMLResponse)
def dashboard(uid: str = ""):
    # 布尔盲注模拟（uid 参数，仅 SPA 渲染后可见）：
    #   uid=1            → 有数据
    #   uid=1 AND 1=1    → 有数据（真条件，与基线同）
    #   uid=1 AND 1=2    → 无数据（假条件）
    low = uid.lower()
    false_patterns = ["and 1=2", "and '1'='2"]
    true_patterns = ["and 1=1", "and '1'='1"]
    if any(p in low for p in false_patterns):
        return "<html><body><h1>面板</h1><p>无数据（0 条）</p></body></html>"
    if any(p in low for p in true_patterns) or low in ("1", "2"):
        return "<html><body><h1>面板</h1><p>用户: admin，数据: 42 条</p></body></html>"
    return "<html><body><h1>面板</h1><p>无数据（0 条）</p></body></html>"


@app.get("/api/profile", response_class=PlainTextResponse)
def api_profile(token: str = ""):
    # 弱鉴权接口：token=guest 也返回数据
    return '{"user":"guest","role":"viewer","token":"' + token + '"}'


# 13. SSRF 模拟（OAST 带外检测验证）：/fetch?url= 会服务端请求任意 URL
#     注入带外回调地址 → 靶场主动请求回调端点 → 扫描器确认命中
@app.get("/fetch", response_class=HTMLResponse)
def fetch_url(url: str = ""):
    import urllib.request
    import ssl
    if not url:
        return "<html><body><p>缺少 url 参数</p></body></html>"
    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        req = urllib.request.Request(url, headers={"User-Agent": "demo-ssrf"})
        with urllib.request.urlopen(req, timeout=6, context=ctx) as resp:
            data = resp.read(512).decode("utf-8", "replace")
        return f"<html><body><h1>抓取结果</h1><pre>{data}</pre></body></html>"
    except Exception as e:
        return f"<html><body><p>请求失败: {str(e)[:200]}</p></body></html>"


# 14. 命令注入模拟：/ping?host= 拼接到系统命令
#     含 ;id / |id / $(id) → 回显命令执行结果（uid=0(root) 特征）
#     含 ;sleep 3 → 延迟 3 秒（时间盲测）
@app.get("/ping", response_class=HTMLResponse)
def ping(host: str = ""):
    import time
    low = host.lower()
    # 仅命令注入样式触发延迟（;sleep 3 / |sleep 3 / $(sleep 3)），避免与 SQL 时间盲注重叠
    if any(x in low for x in (";sleep 3", "|sleep 3", "$(sleep 3)", "; sleep 3")):
        time.sleep(3)
        return "<html><body><h1>Ping 结果</h1><pre>延迟响应</pre></body></html>"
    if any(x in low for x in (";id", "|id", "$(id)", ";whoami", "|whoami")):
        # 模拟命令执行回显（uid 特征，含实际执行的命令痕迹）
        return ("<html><body><h1>Ping 结果</h1><pre>"
                "uid=0(root) gid=0(root) groups=0(root)\n"
                "/bin/sh: 1: " + host.split(";")[0] + ": not found</pre></body></html>")
    if any(x in low for x in (";", "|", "$(")):
        return "<html><body><h1>Ping 结果</h1><pre>命令执行失败</pre></body></html>"
    return f"<html><body><h1>Ping 结果</h1><pre>PING {host} (127.0.0.1): 56 bytes</pre></body></html>"


# 15. SSTI 模拟：/greet?name= 拼接进模板
#     name 含 {{7*7}} / ${7*7} / <%=7*7%> → 回显计算结果 49
@app.get("/greet", response_class=HTMLResponse)
def greet(name: str = ""):
    if "{{7*7}}" in name or "${7*7}" in name or "<%=7*7%>" in name or "{{7*'7'}}" in name:
        return "<html><body><h1>欢迎</h1><p>你好，49</p></body></html>"
    return f"<html><body><h1>欢迎</h1><p>你好，{name}</p></body></html>"


# 16. XXE 模拟：POST XML 解析（GET 展示表单）
#     XML 含 file:///etc/passwd 实体 → 回显 root:x:0:0 特征
#     XML 含 http:// 外部实体 → 服务端请求该地址（带外回调）
@app.get("/parse", response_class=HTMLResponse)
def parse_form():
    return """<html><body><h1>XML 解析</h1>
<form action="/parse" method="POST"><textarea name="xml"></textarea><button>解析</button></form>
<p>支持 application/xml 或表单提交</p></body></html>"""


@app.post("/parse")
async def do_parse(request: Request):
    import re
    import urllib.request
    body = ""
    ct = request.headers.get("content-type", "")
    if "json" in ct:
        try:
            body = (await request.json()).get("xml", "")
        except Exception:
            body = ""
    else:
        body = (await request.body()).decode("utf-8", "replace")
    if not body:
        return PlainTextResponse("缺少 XML 内容")
    # 模拟 XML 解析：检测外部实体
    m = re.search(r'SYSTEM\s+["\']([^"\']+)["\']', body)
    if m:
        target = m.group(1)
        if target.startswith("file://"):
            # file 实体回显（模拟解析 /etc/passwd）
            return PlainTextResponse(
                "root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin")
        if target.startswith(("http://", "https://")):
            # http 实体：服务端发起请求（XXE 带外）
            try:
                req = urllib.request.Request(target, headers={"User-Agent": "demo-xxe"})
                with urllib.request.urlopen(req, timeout=6) as resp:
                    resp.read(256)
            except Exception:
                pass
            return PlainTextResponse("<root>外部实体已展开</root>")
    return PlainTextResponse("<root>解析完成</root>")


# 17. 存储型 XSS：/guestbook 留言板（未转义存储回显）
_GUESTBOOK: list[tuple[str, str]] = [("admin", "欢迎使用留言板")]


@app.get("/guestbook", response_class=HTMLResponse)
def guestbook():
    items = "".join(
        f"<li><b>{n}</b>: {m}</li>" for n, m in _GUESTBOOK
    )
    return f"""<html><body><h1>留言板</h1>
<ul id="msgs">{items}</ul>
<form action="/guestbook" method="POST">
  昵称: <input name="name" value="guest"><br/>
  留言: <input name="message" value="hi"><br/>
  <button>提交</button>
</form></body></html>"""


@app.post("/guestbook")
async def guestbook_post(request: Request):
    import urllib.parse
    body = (await request.body()).decode("utf-8", "replace")
    qs = urllib.parse.parse_qs(body)
    name = (qs.get("name") or ["guest"])[0]
    msg = (qs.get("message") or [""])[0]
    _GUESTBOOK.append((name, msg))  # 未转义存储 → 存储型 XSS
    return HTMLResponse("<html><body><p>留言已发布</p><a href='/guestbook'>返回</a></body></html>")


# 18. 任意文件上传：/upload 接受危险类型文件并返回可访问路径
@app.get("/upload", response_class=HTMLResponse)
def upload_form():
    return """<html><body><h1>文件上传</h1>
<form action="/upload" method="POST" enctype="multipart/form-data">
  <input type="file" name="file"><button>上传</button>
</form></body></html>"""


@app.post("/upload")
async def upload(request: Request):
    import re
    body = (await request.body()).decode("latin1")
    m = re.search(r'filename="([^"]+)"', body)
    if not m:
        return PlainTextResponse("未收到文件")
    fname = m.group(1)
    ext = fname.rsplit(".", 1)[-1].lower() if "." in fname else ""
    dangerous = {"php", "jsp", "jspx", "asp", "aspx", "sh", "py", "cgi", "exe"}
    if ext in dangerous:
        return PlainTextResponse(f"上传成功: /uploads/{fname} (危险类型 {ext} 已保存)")
    return PlainTextResponse(f"上传成功: /uploads/{fname}")


@app.get("/uploads/{fname}", response_class=PlainTextResponse)
def uploads(fname: str):
    if fname.endswith((".php", ".jsp", ".asp", ".aspx", ".sh", ".py")):
        return "<?php echo md5(1); ?>\n# 可执行脚本内容（webshell 特征）"
    return "not found"


# 19. 组件指纹（版本比对）：模拟旧版组件暴露版本号
#     Server: nginx/1.14.0 + X-Powered-By: PHP/5.6.40 + generator WordPress 4.9.8
#     + jquery-1.6.1 / bootstrap-3.3.7（均有公开 CVE）
@app.get("/cms", response_class=HTMLResponse)
def cms():
    return HTMLResponse("""<html><head>
<meta name="generator" content="WordPress 4.9.8">
<meta name="generator" content="nginx 1.14.0">
<script src="/static/jquery-1.6.1.min.js"></script>
<script src="/static/bootstrap-3.3.7.min.js"></script>
<title>企业 CMS</title></head>
<body><h1>企业内容管理系统</h1><p>文章列表</p></body></html>""",
        headers={
            "Server": "nginx/1.14.0",
            "X-Powered-By": "PHP/5.6.40",
        })


if __name__ == "__main__":
    print("=" * 50)
    print("漏洞靶场已启动: http://127.0.0.1:9090")
    print("漏洞列表:")
    print("  1. 缺少安全响应头（HSTS/CSP/XFO）")
    print("  2. .git/config 泄露")
    print("  3. .env 泄露（含数据库密码）")
    print("  4. Actuator 未授权访问")
    print("  5. 反射 XSS（/search?q=<script>alert(1)</script>）")
    print("  6. 目录遍历（/file?name=etc_passwd）")
    print("  7. 备份文件泄露（/backup.zip）")
    print("  8. Swagger API 文档暴露")
    print("=" * 50)
    uvicorn.run(app, host="127.0.0.1", port=9090, log_level="warning")
