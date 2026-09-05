# AICP - 自动化信息收集平台

> **A**utomated **I**nformation **C**ollection **P**latform — 编排 OneForAll / Nmap / httpx / Wappalyzer / dirsearch / Nuclei 的安全资产收集流水线。

[![English](https://img.shields.io/badge/lang-en-blue.svg)](README.en.md)
[![中文](https://img.shields.io/badge/lang-zh-green.svg)](README.md)

[![Python](https://img.shields.io/badge/python-3.10+-blue.svg)](https://www.python.org/)
[![License](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)
[![CI](https://github.com/bmslos/AICP/actions/workflows/ci.yml/badge.svg)](https://github.com/bmslos/AICP/actions)

***

## 目录

- [项目简介](#项目简介)

- [核心特性](#核心特性)

- [合规声明](#合规声明)

- [快速开始](#快速开始)

- [安装](#安装)

- [CLI 使用](#cli-使用)

- [Web 界面](#web-界面)

- [报告格式](#报告格式)

- [项目结构](#项目结构)

- [开发与测试](#开发与测试)

- [FAQ](#faq)

- [许可证](#许可证)

***

## 项目简介

AICP 是一个面向**已授权**安全研究与企业资产盘点的自动化信息收集平台。它将业内主流的开源工具(OneForAll、Nmap、httpx、Wappalyzer、dirsearch、Nuclei)编排成一条流水线,自动完成子域名收集 → 端口扫描 → Web 指纹识别 → 目录枚举 → 漏洞扫描 → 资产关联去重六个阶段,并生成 HTML / JSON / Markdown / CSV 四种格式的报告。

**适用场景:**

- 企业安全团队对**自有资产**进行暴露面梳理

- 安全研究者在**已获书面授权**的目标系统上进行资产收集

- CTF / 安全实验教学

**不适合的场景:**

- 未经授权对任何第三方系统进行扫描(可能违法)

- 大规模无差别扫描(本项目未做高并发优化)

***

## 核心特性

### 1. 流水线编排

六个阶段自动串联,前阶段的产出自动作为后阶段的输入:

```
SUBDOMAIN  →  PORTSCAN  →  FINGERPRINT  →  DIRSCAN  →  VULNERABILITY  →  CORRELATE
(OneForAll)   (Nmap)       (httpx +       (dirsearch)   (Nuclei)         (内置合并
                            Wappalyzer)                                  去重)
```

### 2. 强制授权机制

- 启动扫描前必须填写授权人、授权说明、授权范围

- 所有目标必须落在授权范围内,否则拒绝执行

- 默认拒绝私有/保留 IP 段(防 SSRF 与内网探测),需显式 `--allow-private` 才能扫描内网

- IPv4 映射 IPv6 地址(`::ffff:x.x.x.x`)在匹配黑名单前归一化为 IPv4,防止 `::ffff:169.254.169.254` 等绕过私有 IP 检查的 SSRF 攻击

- 域名目标在授权校验时做 DNS 解析,解析结果落入私有/保留段(如攻击者 DNS 把授权域名指向云元数据地址)即拒绝,封 DNS rebinding SSRF

- 授权范围含域名时,该域名解析出的 IP 同样视为在范围内(否则 nmap 等工具解析域名得到的 IP/端口资产会被误清空)

- `save_asset` 改用 `INSERT OR IGNORE` 原子操作,消除多线程并发写同一资产时的 TOCTOU 竞态

- OneForAll CSV 解析按表头列名匹配 `subdomain` 列(大小写不敏感),不再依赖"第一列固定是 subdomain"的脆弱假设,提升工具版本兼容性

- 目标解析统一提取 host(域名 / IP / URL / host:port / IPv6 均支持),与授权校验逻辑保持一致,避免 URL 型目标被误判为域名、裸 IPv6 目标被错误拆段

### 3. 断点续传

- 任务状态、阶段状态、资产全部持久化到 SQLite

- 任务失败后可从最近未完成阶段恢复,已完成的阶段不重跑

- 进程正常退出时,`atexit` 钩子自动把 RUNNING 任务标记为 FAILED;强杀/断电残留的 RUNNING 任务在下一次命令启动时清理

- 任务租约(`owner`/`heartbeat_at`/`lease_expires_at`):CLI 与 Web 双入口并存时互不误杀、同一任务拒绝并发双跑;持有者崩溃(租约过期)后他方可接管恢复

### 4. 工具进程树托管

- 子进程加入 Windows Job Object(KILL\_ON\_JOB\_CLOSE):AICP 进程被强杀时内核终止整棵进程树,杜绝孤儿孙进程继续对目标发包(超出授权范围的合规风险)

- 工具级超时(默认 30 分钟)后终止整棵进程树(Windows `taskkill /T` / POSIX `killpg`)

- 工具原始输出(完整命令行 + stdout/stderr)追加落盘 `work/{task_id}/logs/{tool}.log`,保留事故取证第一现场

### 5. 统一资产模型

所有工具的输出归一化为 `Asset` 对象,字段包括 `id` / `type` / `value` / `source` / `task_id` / `discovered_at` / `parent_id` / `technologies` / `status_code` / `title` / `raw`,便于跨阶段关联与去重。

漏洞资产(`vulnerability`)按 **(URL, 模板 ID)** 去重:同一 URL 上不同模板命中的多个漏洞可并存,不会互相覆盖丢失。

### 6. 多格式报告

- **HTML**: 单文件,带样式,适合浏览器查看

- **JSON**: 结构化数据,适合程序处理

- **Markdown**: 纯文本,适合版本控制与 CI 集成

- **CSV**: 扁平化资产表(utf-8-sig 编码),Excel 直接打开,适合安全分析师离线处理

用户可按需选择生成哪种格式(`--format html|json|md|csv|all`),只生成选定的那一种。

### 6. 状态机驱动

任务和阶段都有显式状态机,非法状态迁移会抛 `IllegalTransitionError`,避免并发调度与断点续传时的状态混乱。

***

## 合规声明

**本项目仅供合法授权用途使用。** 启动任何扫描前,AICP 强制要求:

1. **授权人姓名/单位** — 必填
2. **授权说明**(如授权书编号)— 必填
3. **授权范围**(域名 / IP / CIDR)— 必填,所有扫描目标必须在此范围内

详细法律条款请阅读 [DISCLAIMER.md](DISCLAIMER.md)。在中国大陆地区,特别提示:

- 《中华人民共和国网络安全法》

- 《中华人民共和国刑法》第二百八十五条、第二百八十六条

- 《信息安全技术 网络安全漏洞管理规定》

**未经授权**对任何第三方系统进行扫描、探测等行为,可能构成违法甚至犯罪。本项目作者不承担因违规使用产生的任何法律责任。

***

## 快速开始

```bash
# 安装
pip install -e .

# 执行一次完整扫描(会自动生成 HTML+JSON+Markdown+CSV 报告)
aicp scan example.com \
    --authorized-by "张三" \
    --authorization-note "AUTH-2026-001" \
    --scope example.com \
    --scope 1.2.3.4

# 查看任务列表
aicp list

# 查看任务详情
aicp show <task_id>

# 只生成 Markdown 报告
aicp report <task_id> --format md

# 启动 Web 界面
aicp web
# 浏览器访问 http://127.0.0.1:5000/
```

***

## 安装

### 环境要求

- **Python**: 3.10 或更高版本

- **操作系统**: Windows / Linux / macOS(本项目在 Windows 原生环境开发与测试)

- **外部工具**(可选,缺失时对应阶段会失败但不影响其他阶段):

  - [OneForAll](https://github.com/shmilylty/OneForAll) — 子域名收集

  - [Nmap](https://nmap.org/) — 端口扫描

  - [httpx](https://github.com/projectdiscovery/httpx) — Web 探测

  - [python-Wappalyzer](https://github.com/chorsley/python-Wappalyzer) — Web 指纹识别(`pip install python-Wappalyzer`)

  - [dirsearch](https://github.com/maurosoria/dirsearch) — 目录枚举

  - [Nuclei](https://github.com/projectdiscovery/nuclei) — 漏洞扫描

### 安装步骤

```bash
# 1. 克隆仓库
git clone https://github.com/bmslos/AICP.git
cd AICP

# 2. 安装(推荐在虚拟环境中)
python -m venv venv
# Windows
venv\Scripts\activate
# Linux / macOS
source venv/bin/activate

pip install -e .

# 3. 验证安装
aicp --version
```

### 开发依赖

```bash
pip install -e ".[dev]"
# 会额外安装 pytest
```

***

## CLI 使用

AICP 提供 8 个子命令:`scan` / `resume` / `report` / `list` / `show` / `diff` / `cancel` / `config`,以及一个 `web` 命令启动 Web 界面。

### `scan` — 新建并执行扫描任务

```bash
aicp scan <targets...> \
    [--authorized-by <授权人>] \
    [--authorization-note <授权说明>] \
    [--scope <授权范围>...] \
    [--config <配置文件>] \
    [--tools oneforall,nmap,httpx,wappalyzer,dirsearch,nuclei] \
    [--format html|json|md|csv|all] \
    [--rate-limit <req/s>] \
    [--tool-args "nuclei=-t /path/templates"] \
    [--no-report] \
    [--allow-private] \
    [--quiet]
```

**参数说明:**

| 参数                     | 必填  | 说明                                                         |
| ---------------------- | --- | ---------------------------------------------------------- |
| `targets`              | 是   | 要扫描的目标(域名 / IP / CIDR),至少 1 个                              |
| `--authorized-by`      | 否\* | 授权人姓名(默认读 config.toml 的 `[auth]`)                          |
| `--authorization-note` | 否\* | 授权说明(如授权书编号,默认读 config.toml)                               |
| `--scope`              | 否\* | 授权范围,可多次指定(默认读 config.toml)                                |
| `--config`             | 否   | 配置文件路径(默认 `.aicp/config.toml`)                             |
| `--tools`              | 否   | 启用工具子集,逗号分隔                                                |
| `--format`             | 否   | 报告格式,默认 `all`                                              |
| `--rate-limit`         | 否   | 全局速率限制(req/s),透传给支持的工具                                     |
| `--tool-args`          | 否   | 按工具透传额外参数,如 `--tool-args "nuclei=-t /path/templates"`(可多次) |
| `--no-report`          | 否   | 不自动生成报告                                                    |
| `--allow-private`      | 否   | 允许扫描私有 IP 段(默认拒绝)                                          |
| `--quiet`              | 否   | 减少控制台输出                                                    |

> `*` 必填三者(授权人/说明/范围)必须提供其一来源:CLI 参数或配置文件(否则拒绝执行)。

**示例:**

```bash
# 只跑子域名收集 + 端口扫描,只生成 Markdown 报告
aicp scan example.com \
    --authorized-by "张三" \
    --authorization-note "AUTH-2026-001" \
    --scope example.com \
    --tools oneforall,nmap \
    --format md

# 从 .aicp/config.toml 读取授权信息与速率,只需指定目标
aicp config init        # 首次生成配置文件并填入授权信息
aicp scan example.com   # 授权人/说明/范围/限速全部来自配置

# 扫描内网(需显式授权)
aicp scan 192.168.1.0/24 \
    --authorized-by "内网盘点" \
    --authorization-note "INTERNAL-2026-001" \
    --scope 192.168.1.0/24 \
    --allow-private
```

### `resume` — 断点续传

```bash
aicp resume <task_id>
```

任务必须处于 `AUTHORIZED` / `PAUSED` / `FAILED` 状态;卡在 `RUNNING` 的僵死任务(持有者已崩溃、租约过期)也可 resume,编排器会自动接管并重置阶段状态。已完成的阶段不会重跑,只执行未完成或失败的部分。

### `report` — 单独生成报告

```bash
aicp report <task_id> [--format html|json|md|csv|all] [-o <输出路径>]
```

**示例:**

```bash
# 只生成 Markdown 报告到指定路径
aicp report abc123 --format md -o ./my_report.md
```

### `list` — 列出所有任务

```bash
aicp list [--status <状态过滤>]
```

### `show` — 查看任务详情

```bash
aicp show <task_id>
```

### `diff` — 资产差异比较(攻击面变更追踪)

```bash
aicp diff <task_a> <task_b>
```

比较两个任务的资产差异:新增/消失的子域名、IP、端口、URL,以及新增/已修复的漏洞(按严重度降序)。配合 cron 即可形成攻击面监控。

### `cancel` — 请求取消运行中的任务

```bash
aicp cancel <task_id>
```

对 RUNNING 任务写入取消请求,在当前阶段结束后生效(子进程跑完当前阶段退出)。Web 界面的任务详情页在运行中也会显示"取消任务"按钮。

### `config` — 配置文件管理

```bash
aicp config init            # 生成 .aicp/config.toml 示例 (--force 覆盖)
aicp config show            # 显示配置文件与环境变量合并后的结果
```

配置文件支持授权信息(授权人/说明/范围)与扫描参数(限速/工具路径等),避免每次扫描重复敲参数。取值优先级:**CLI 参数 > config.toml > 环境变量 (`AICP_*`) > 代码默认值**。

```toml
[auth]
authorized_by = "安全部"
authorization_note = "AUTH-2026-001"
scope = ["example.com", "1.2.3.0/24"]

[scan]
rate_limit = 50
allow_private = false
work_dir = ".aicp/work"
```

> 授权信息写入配置后,每次 scan 仍会打印 `ConfirmationBanner` 二次确认。如不愿授权信息落盘,删除 `[auth]` 段、每次显式传入即可。

### `web` — 启动 Web 界面

```bash
aicp web [--host 127.0.0.1] [--port 5000] [--auth-token <令牌>] [--debug]
```

**`--auth-token`** **选项(推荐):** 设置后所有请求必须携带 `Authorization: Bearer <令牌>` 头(或 `?token=<令牌>` 查询参数)才能访问,未通过返回 401。**无论是否启用认证,POST 请求都必须携带** **`X-CSRF-Token`** **头**(值为服务端生成的独立 CSRF 令牌),否则返回 403——未启用认证时同样强制 CSRF,防止本机浏览器中的恶意网页跨站提交扫描表单。前端模板已自动注入 JS:访问页面后 JS 会先拉取 `/csrf-token`,再拦截表单 POST 与站内导航链接、附加相应头,浏览器中无需手动操作。

> **安全建议:** 默认仅监听 `127.0.0.1`,只能本机访问。**不建议**用 `--host 0.0.0.0` 直接暴露到公网;如确需暴露,务必设置 `--auth-token`,否则任何人都可创建/恢复任务并下载报告。

***

## Web 界面

启动 `aicp web` 后,浏览器访问 <http://127.0.0.1:5000/>。

**功能:**

- 任务列表与详情查看

- 通过表单提交新任务(后台线程执行,不阻塞 HTTP)

- 任务详情页用 JS 轮询状态,实时显示阶段进度

- 失败任务可一键恢复

- 三种格式报告在线查看 / 下载:

  - `/tasks/<id>/report` — 内嵌 HTML 报告

  - `/tasks/<id>/report.json` — 下载 JSON

  - `/tasks/<id>/report.md` — 下载 Markdown

- 健康探针(免认证,供外部拨测用):`/health`(进程存活)与 `/readyz`(数据库就绪,DB 故障时返回 503)

**认证与 CSRF:** POST 请求**始终**需要 CSRF 令牌(未启用认证时同样强制);`--auth-token` 启用后所有请求还需认证:

- 所有请求需带 `Authorization: Bearer <令牌>` 头或 `?token=<令牌>` 查询参数

- POST 请求需额外带 `X-CSRF-Token` 头(值为独立的 CSRF 令牌,由服务端随机生成,与认证令牌不同)

- 提供 `GET /csrf-token` 端点供前端获取 CSRF 令牌(启用认证时需先通过认证)

- 前端 JS 自动拦截表单 POST 与站内导航链接并附加相应头,以 `http://127.0.0.1:5000/?token=<令牌>` 访问后即可正常使用全部功能

***

## 报告格式

AICP 支持四种报告格式。HTML / JSON / Markdown 内容结构一致(8 个 section),只是渲染方式不同;CSV 是扁平化资产表,面向离线分析:

| 格式           | 用途        | 特点                             |
| ------------ | --------- | ------------------------------ |
| **HTML**     | 浏览器查看     | 单文件,带样式,可内嵌图片                  |
| **JSON**     | 程序处理      | 结构化数据,可被其他系统消费                 |
| **Markdown** | 版本控制 / CI | 纯文本,Git diff 友好                |
| **CSV**      | 离线分析      | 扁平化资产表,utf-8-sig 编码,Excel 直接打开 |

**报告内容(HTML / JSON / Markdown 的 8 个 section):**

1. **任务信息** — 任务 ID、状态、目标、授权人、授权范围、授权说明、时间戳
2. **资产统计** — 各类型资产数量汇总(含漏洞/目录)、识别到的技术栈、漏洞严重度计数
3. **资产详情** — 主机与端口表、域名列表(含解析 IP)
4. **漏洞清单** — Nuclei 产出的漏洞明细(严重度降序,含严重度计数 / 名称 / 模板 ID / 目标 URL)
5. **目录枚举** — dirsearch 产出的目录明细(路径 / 状态码 / 大小 / 跳转)
6. **阶段时间线** — 6 个阶段的执行状态、开始/结束时间、尝试次数、错误
7. **审计日志** — 所有状态变更与工具执行记录
8. **头部** — 生成时间戳

**CSV 报告**:每行一个资产,列包括 `task_id / asset_id / type / value / source / parent_id / status_code / title / technologies / severity / template_id / size / redirect / discovered_at`,适合 Excel / pandas 离线处理。漏洞行的 `value` 为干净的 URL,`severity` / `template_id` 从原始输出展开。

**生成策略:**

- CLI `scan` / `resume` 默认生成四种格式(`--format all`),可用 `--format md` 等只生成选定的格式

- Web 路由采用**懒生成**:首次访问时生成并缓存,二次访问直接复用

- 用户选择哪种格式,就只生成那种格式,不浪费资源

***

## 项目结构

```
aicp/
├── aicp/                          # 主包
│   ├── auth/                      # 授权校验
│   │   └── verifier.py            #   AuthorizationVerifier + ConfirmationBanner
│   ├── models/                    # 数据模型
│   │   ├── asset.py               #   Asset (统一资产 schema)
│   │   └── task.py                #   Task / Stage / 状态枚举
│   ├── scheduler/                 # 持久化与状态机
│   │   ├── store.py               #   SQLite 封装 (任务/阶段/资产/审计)
│   │   └── state_machine.py       #   状态迁移校验
│   ├── tools/                     # 工具适配层
│   │   ├── base.py                #   Tool 抽象接口
│   │   ├── registry.py            #   插件注册发现 (ToolRegistry)
│   │   ├── oneforall.py           #   OneForAll 适配器
│   │   ├── nmap.py                #   Nmap 适配器
│   │   ├── httpx_tool.py          #   httpx 适配器
│   │   ├── wappalyzer.py          #   Wappalyzer 适配器
│   │   ├── dirsearch.py           #   dirsearch 适配器
│   │   └── nuclei.py              #   Nuclei 适配器
│   ├── pipeline/                  # 流水线编排
│   │   └── orchestrator.py        #   Orchestrator (阶段串联/断点续传/失败隔离/任务租约)
│   ├── correlate/                 # 数据关联
│   │   └── merger.py              #   merge_assets → AssetGraph
│   ├── report/                    # 报告生成
│   │   ├── html.py                #   HTML 报告
│   │   ├── json_report.py         #   JSON 报告
│   │   ├── markdown.py            #   Markdown 报告
│   │   └── csv_report.py          #   CSV 报告 (utf-8-sig, Excel 兼容)
│   ├── web/                       # Web 界面
│   │   ├── app.py                 #   Flask 路由 (认证/CSRF/健康探针)
│   │   ├── runner.py              #   后台任务执行器
│   │   ├── templates/             #   Jinja2 模板
│   │   └── static/                #   CSS
│   ├── observability.py           # JSON 日志 + task_id 注入 (可观测性底座)
│   ├── config.py                  #   配置文件支持 (P1-2)
│   ├── diff.py                    #   资产差异比较 (P2-1)
│   └── cli.py                     # CLI 入口 (click, 含进程树托管)
├── tests/                         # 测试 (427 个用例)
├── scripts/                       # 端到端测试脚本
├── pyproject.toml                 # 项目配置
├── DISCLAIMER.md                  # 免责声明
└── README.md                      # 本文件
```

***

## 开发与测试

### 运行测试

```bash
# 全量测试(427 个用例,约 15 秒)
python -m pytest

# 带详细输出
python -m pytest -v

# 只跑恢复验证套件(断点续传/租约/进程树清理等恢复路径)
python -m pytest -m recovery

# 只跑某个测试文件
python -m pytest tests/test_orchestrator.py

# 只跑某个测试
python -m pytest tests/test_orchestrator.py::test_full_pipeline_run_completes_all_stages
```

### 测试覆盖

| 测试文件                         | 用例数 | 覆盖范围                                       |
| ---------------------------- | --- | ------------------------------------------ |
| `test_auth.py`               | 28  | 授权校验、范围匹配、私有 IP 拒绝、域名 DNS 解析防 SSRF         |
| `test_audit_fixes.py`        | 8   | 审计日志修复                                     |
| `test_cli.py`                | 38  | CLI 命令、报告格式、工具子集、config、cancel             |
| `test_correlate.py`          | 9   | 资产关联与合并                                    |
| `test_csv_report.py`         | 9   | CSV 报告 (扁平化/utf-8-sig BOM)                 |
| `test_diff.py`               | 2   | 资产差异比较 (P2-1)                              |
| `test_dirsearch.py`          | 11  | dirsearch 适配器 (JSON 解析/404 过滤)             |
| `test_models.py`             | 5   | 数据模型                                       |
| `test_nuclei.py`             | 12  | Nuclei 适配器 (JSONL 解析/severity/漏洞去重/旧输出清理)  |
| `test_observability.py`      | 6   | JSON 日志/task\_id 注入/日志落盘                   |
| `test_orchestrator.py`       | 24  | 流水线、断点续传、失败隔离、重试上限、取消、参数透传、任务租约、输出落盘       |
| `test_process_runner.py`     | 3   | 进程树托管(超时杀树/强杀遏制)                           |
| `test_registry.py`           | 22  | 插件系统 (注册/entry\_points 发现/单例)              |
| `test_report.py`             | 12  | HTML / JSON 报告 (含漏洞/目录)                    |
| `test_report_markdown.py`    | 14  | Markdown 报告                                |
| `test_security_hardening.py` | 83  | IP 黑名单、CIDR、atexit 清理                      |
| `test_state_machine.py`      | 24  | 状态机迁移                                      |
| `test_store.py`              | 42  | SQLite 持久化、索引、迁移、取消标记、任务租约                 |
| `test_tools.py`              | 24  | 工具适配器 (含 IPv6 目标解析、Wappalyzer 并发、域名 scope) |
| `test_web.py`                | 51  | Web 路由、报告下载、路径遍历防护、认证/CSRF、取消、健康探针、租约 409  |

CI 在 lint 与测试之外还执行覆盖率门禁(`--cov-fail-under=75`),并覆盖 ubuntu / windows 双平台矩阵。

### 端到端测试

```bash
# 真实工具联调(需要安装 OneForAll / Nmap / httpx)
python scripts/e2e_real.py

# Web 端到端
python scripts/e2e_web.py
```

### 添加新工具

AICP 内置插件系统(`aicp/tools/registry.py` 的 `ToolRegistry`),推荐通过注册机制接入新工具:

1. 在 `aicp/tools/` 下新建 `your_tool.py`
2. 继承 `Tool` 抽象类,实现 `run(inputs, ctx) -> ToolResult`
3. 声明 `stage` / `input_asset_types` / `output_asset_types`
4. 注册方式二选一:

   - **显式注册**:在 `aicp/cli.py` 的 `_default_tools()` 中 import 并 append(内置工具做法)

   - **插件发现**:通过 entry\_points 声明 `[project.entry-points."aicp.tools"]` 由 `tool_registry.discover()` 自动发现;或直接调用 `tool_registry.register(YourTool)`
5. 写单元测试(参考 `tests/test_nuclei.py` / `tests/test_registry.py`)

详见 [TECHNICAL.md](TECHNICAL.md) 中的「工具适配层」与「如何扩展」章节。

***

## FAQ

### Q1: 工具未安装会怎样?

A: 对应阶段会失败(标记为 `FAILED`),但不影响其他阶段。例如未装 Nmap,PORTSCAN 阶段失败,FINGERPRINT 仍可基于 SUBDOMAIN 产出的域名继续(若 httpx 已安装)。

### Q2: 任务失败了怎么恢复?

A: 用 `aicp resume <task_id>`。已完成的阶段不会重跑,只执行未完成或失败的部分。任务必须处于 `AUTHORIZED` / `PAUSED` / `FAILED` 状态。

### Q3: 如何只生成 Markdown 报告?

A: `aicp report <task_id> --format md`,或在 `scan` 时加 `--format md`。

### Q4: 默认目录在哪里?

A: 当前工作目录下的 `.aicp/`:

- `.aicp/aicp.db` — SQLite 数据库

- `.aicp/work/` — 工具工作目录(临时文件)

- `.aicp/reports/` — 报告输出

### Q5: 如何扫描内网?

A: 默认拒绝私有 IP 段(防 SSRF)。需显式加 `--allow-private`,且授权范围必须包含内网网段。

### Q6: 支持并发扫描多个任务吗?

A: CLI 是同步的,一次跑一个任务。Web 界面支持后台线程执行,多个任务可并行(每个任务用独立的 SQLite 连接,WAL 模式支持多读单写)。

### Q7: 如何保护 Web 界面?

A: 用 `--auth-token` 设置认证令牌,例如:

```bash
aicp web --auth-token "your-secret-token-here"
```

启用后所有请求需带 `Authorization: Bearer <令牌>` 头(或 `?token=<令牌>` 查询参数);POST 请求无论是否启用认证都需额外带 `X-CSRF-Token` 头(防 CSRF,值为服务端生成的独立令牌)。以 `http://127.0.0.1:5000/?token=<令牌>` 访问后,前端 JS 会自动读取该令牌并附加到所有请求,普通用户无需手动操作。**默认仅监听 127.0.0.1;若用** **`--host 0.0.0.0`** **暴露到公网,务必设置** **`--auth-token`。**

***

## 许可证

[MIT License](LICENSE)

Copyright (c) 2026 aicp contributors

本项目按"现状"提供,不提供任何明示或暗示的担保。因使用本工具造成的任何直接或间接损失,作者不承担责任。使用者需对自身行为的合法性负全部责任。

***

## 致谢

本项目编排以下开源工具,感谢它们的贡献:

- [OneForAll](https://github.com/shmilylty/OneForAll) — 子域名收集

- [Nmap](https://nmap.org/) — 网络扫描

- [httpx](https://github.com/projectdiscovery/httpx) — Web 探测

- [Wappalyzer](https://github.com/AliasIO/Wappalyzer) — 技术指纹识别

- [dirsearch](https://github.com/maurosoria/dirsearch) — 目录枚举

- [Nuclei](https://github.com/projectdiscovery/nuclei) — 漏洞扫描

