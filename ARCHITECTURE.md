# AutoVuln 架构说明

> 本文档描述 AutoVuln 平台的系统架构、核心设计决策与扩展点，面向贡献者与二次开发者。

## 1. 系统总览

AutoVuln 采用**前后端分离 + 单容器托管**架构：

- **前端**：Vue3 + Vite + Element Plus + ECharts，SPA 管理后台
- **后端**：Python FastAPI，REST API + JWT 鉴权，生产模式下直接托管前端构建产物（`frontend/dist`）
- **存储**：SQLite（生产可切 MySQL，通过 SQLAlchemy ORM 抽象），文件存储承载证据/报告/规则包
- **扫描目标**：内置本地漏洞靶场 `demo_vuln_app.py`（20 个故意构造的漏洞端点，仅限授权环境）

```
┌────────────────────────────────────────────────────────┐
│                  浏览器（Vue3 SPA）                      │
│  态势总览 / 资产管理 / 扫描任务 / 漏洞管理 / 报告 / 规则   │
└──────────────────────────┬─────────────────────────────┘
                           │ REST /api（JWT Bearer）
┌──────────────────────────▼─────────────────────────────┐
│                 FastAPI 后端（app/main.py）              │
│  ┌─────────┐ ┌─────────┐ ┌─────────┐ ┌───────────────┐  │
│  │ api/    │ │ core/   │ │ services│ │ scanners/     │  │
│  │ 路由层   │ │ 安全核心 │ │ 业务服务 │ │ 扫描引擎       │  │
│  └────┬────┘ └────┬────┘ └────┬────┘ └───────┬───────┘  │
│       │          │           │               │          │
│  ┌────▼──────────▼───────────▼───────────────▼───────┐  │
│  │ models/（SQLAlchemy：用户/资产/扫描/漏洞/规则/审计）  │  │
│  │ database.py（会话管理）→ SQLite / MySQL            │  │
│  └────────────────────────────────────────────────────┘  │
└──────────────────────────┬─────────────────────────────┘
                           │
              ┌────────────▼────────────┐
              │  文件存储：证据/报告/规则  │
              │  backend/data/          │
              └─────────────────────────┘
```

## 2. 目录结构

```
backend/
├── app/
│   ├── main.py              # FastAPI 入口：/api 路由优先 + SPA 托管（history 回退）
│   ├── config.py            # 环境变量 + .env 加载；SECRET_KEY 持久化到 data/secret.key
│   ├── database.py          # SQLAlchemy engine / SessionLocal / Base
│   ├── api/                 # REST 路由：auth/assets/scans/vulns/reports/rules/admin/oast
│   ├── core/                # security.py(JWT+PBKDF2) deps.py(依赖注入) audit.py(操作审计)
│   ├── models/              # user/asset/scan/vuln/rule/audit 数据模型
│   ├── scanners/            # 扫描引擎（见 §3）
│   ├── services/            # asset_service/vuln_service(状态机)/report/dashboard/notify/oast/seed
│   └── utils/               # net.py（安全出站请求） text.py
├── tests/
│   └── e2e_smoke.py         # 20 项端到端闭环测试
└── tools/
    └── import_nuclei.py     # nuclei YAML 模板导入器

frontend/src/
├── router/                  # 登录/总览/资产/扫描/漏洞/报告/规则/系统管理
└── views/                   # 对应页面组件
```

## 3. 扫描引擎（scanners/）

扫描引擎采用**插件式扫描器 + 任务调度中心**设计，每个扫描器继承 `base.py` 中的统一基类（含限速、checkpoint、进度上报、证据留存）。

| 模块 | 职责 | 核心逻辑 |
|---|---|---|
| `subdomain.py` | 子域名枚举 | crt.sh 证书日志（被动）+ 字典 DNS 爆破（主动）双通道 |
| `portscan.py` | 端口服务识别 | 常用/全端口并发 TCP 探测 + Banner 抓取 |
| `fingerprint.py` | 指纹识别 | 响应头/标题/正文正则匹配，规则库可更新 |
| `jsapi.py` | JS/API 提取 | 自动抓取 JS 文件，正则提取接口/路径 |
| `pathscan.py` | 路径爆破 | 内置字典探测敏感路径，敏感文件自动告警 |
| `crawler.py` | 动态爬虫 | Playwright 无头 Chromium 渲染 SPA，提取 JS 动态链接 + XHR/fetch 接口 |
| `webscan.py` | Web 漏洞扫描 | **8 阶段流水线**（见下） |
| `cve.py` | 组件 CVE 比对 | 响应头/页面提取组件版本 → 已知 CVE 版本区间匹配 |
| `weakpass.py` | 弱口令检测 | 内置常见弱口令 + 未授权路径探测 |
| `poc_engine.py` | POC 执行 | HTTP 结构化 POC；Python 型 POC 因沙箱逃逸 RCE 风险已禁用 |
| `scheduler.py` | 任务调度 | 线程池调度、并发上限、暂停/恢复/取消、进度上报 |

### Web 扫描 8 阶段流水线

`webscan.py` 是核心检测链，对目标 URL 依序执行：

1. **基线采集**：正常响应快照（状态码/标题/长度/特征），作为后续误报过滤基准
2. **认证态注入**：若资产配置 Cookie，统一注入所有请求
3. **规则驱动检测**：注入/XSS/目录遍历/SSRF/未授权/信息泄露（规则库驱动，可在线更新）
4. **SQL 盲注**：布尔盲注（真/假条件响应比对）+ 时间盲注（SLEEP 延迟检测）
5. **OAST 带外**：注入唯一 token 回调地址，目标主动请求回调即确认无回显漏洞（SSRF/XXE/命令注入）
6. **命令注入/SSTI/XXE**：回显特征 + 时间延迟 + OAST 三通道
7. **存储型 XSS / 文件上传**：表单提交 payload → 回读页面验证持久化回显；multipart 恶意文件 + 上传后路径可访问验证
8. **指纹 CVE 比对**：提取组件版本 → 匹配已知漏洞区间（内置 nginx/PHP/WordPress/jQuery/Bootstrap/Tomcat）

### 误报过滤机制

- **基线对比**：检测结果与正常响应做差异比对，过滤通用特征误报
- **vuln_key 幂等去重**：同资产+同类型+同参数去重
- **多签名命中**：需多个独立特征同时命中
- **误报反馈闭环**：人工标记误报反哺规则库，≥3 次自动抑制

## 4. 数据模型

| 模型 | 关键字段 | 说明 |
|---|---|---|
| User | username/email/password_hash/role | PBKDF2 哈希；admin/user 双角色 |
| Asset | target/kind/group/tags/status/cookie | 目标资产；cookie 用于认证态扫描 |
| Scan | asset_id/kind/status/progress/round | 扫描任务；多轮次 |
| Vuln | asset_id/scan_id/type/severity/status/vuln_key | 漏洞；状态机流转 |
| Rule | type/category/name/content/severity | Web/指纹/POC 规则库 |
| AuditLog | user/action/target/detail | 全操作审计 |

## 5. 核心设计决策

### 5.1 多租户隔离
所有数据查询强制 `user_id` 边界过滤（在 `core/deps.py` 统一注入），越权访问一律返回 404（不暴露资源存在性）。漏洞/资产/扫描/报告均按用户隔离。

### 5.2 认证与安全（平台自身）
- JWT Bearer 鉴权，`SECRET_KEY` 生产必设（留空自动生成并持久化）
- 密码 PBKDF2 哈希存储
- 邀请码必填注册（`INVITE_CODE` 环境变量）
- CORS 白名单；出站请求 SSRF 防护（`utils/net.py` 阻止内网地址）
- Python 型 POC 禁用执行（沙箱逃逸 RCE 风险），仅允许 HTTP POC

### 5.3 扫描安全控制
- **限速硬下限 50ms/请求**，并发可配，防压垮目标
- 任务控制中心支持暂停/恢复/取消
- checkpoint 机制：扫描中断可恢复，进度实时上报

### 5.4 漏洞运营闭环
漏洞状态机：`发现 → 确认 → 修复中 → 已修复 → 复测通过`，非法流转拦截，全程审计留痕。跨扫描轮次对比自动识别新增/已修复/复发。

## 6. 扩展点

| 扩展方向 | 方式 |
|---|---|
| 新增漏洞检测 | 规则库 JSON 导入（`POST /api/rules/import`）或远程 URL 拉取 |
| nuclei 模板 | `python backend/tools/import_nuclei.py <模板目录>` 批量导入 |
| 新增扫描器 | 继承 `scanners/base.py` 基类，注册到调度器 |
| 数据层扩展 | SQLAlchemy 切换 MySQL（改连接串即可） |
| 分布式节点 | 预留扩展位：扫描引擎与 API 已按可拆分设计 |
| 通知渠道 | Webhook/邮件通道，高危触发可配置 |

## 7. 测试

```bash
cd backend
python tests/e2e_smoke.py   # 20 项闭环测试：注册→资产→扫描→漏洞→轮次对比→报告→租户隔离
```

---

## 合规声明

AutoVuln 是**双用途安全工具**：仅用于获得明确授权的安全测试与资产管理工作。使用者须对扫描目标拥有合法授权，因滥用造成的后果由使用者自行承担。
