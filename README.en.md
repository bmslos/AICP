# AICP - Automated Information Collection Platform

> Orchestrating OneForAll / Nmap / httpx / Wappalyzer / dirsearch / Nuclei into a unified security asset collection pipeline.

[![English](https://img.shields.io/badge/lang-en-blue.svg)](README.en.md)
[![中文](https://img.shields.io/badge/lang-zh-green.svg)](README.md)

[![Python](https://img.shields.io/badge/python-3.10+-blue.svg)](https://www.python.org/)
[![License](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)
[![CI](https://github.com/bmslos/AICP/actions/workflows/ci.yml/badge.svg)](https://github.com/bmslos/AICP/actions)

---

## Table of Contents

- [Overview](#overview)
- [Key Features](#key-features)
- [Compliance Notice](#compliance-notice)
- [Quick Start](#quick-start)
- [Installation](#installation)
- [CLI Usage](#cli-usage)
- [Web Interface](#web-interface)
- [Report Formats](#report-formats)
- [Project Structure](#project-structure)
- [Development & Testing](#development--testing)
- [FAQ](#faq)
- [License](#license)

---

## Overview

AICP is an automated information collection platform designed for **authorized** security research and enterprise asset inventory. It orchestrates industry-standard open-source tools (OneForAll, Nmap, httpx, Wappalyzer, dirsearch, Nuclei) into a pipeline that automatically performs six stages: subdomain enumeration → port scanning → web fingerprinting → directory enumeration → vulnerability scanning → asset correlation and deduplication, and generates reports in HTML / JSON / Markdown / CSV formats.

**Use cases:**
- Enterprise security teams performing **self-owned asset** inventory and exposure management
- Security researchers conducting asset collection on **explicitly authorized** target systems
- CTF / security education labs

**Not suitable for:**
- Unauthorized scanning of any third-party system (may be illegal)
- Large-scale indiscriminate scanning (this project is not optimized for high concurrency)

---

## Key Features

### 1. Pipeline Orchestration
Six stages are automatically chained, with each stage's output serving as the next stage's input:

```
SUBDOMAIN  →  PORTSCAN  →  FINGERPRINT  →  DIRSCAN  →  VULNERABILITY  →  CORRELATE
(OneForAll)   (Nmap)       (httpx +       (dirsearch)   (Nuclei)         (built-in
                            Wappalyzer)                                  merge & dedup)
```

### 2. Mandatory Authorization Mechanism
- Before launching any scan, you must provide authorizer name, authorization note, and authorization scope
- All targets must fall within the authorization scope, otherwise execution is refused
- Private/reserved IP ranges are rejected by default (SSRF and internal network probing protection); an explicit `--allow-private` flag is required to scan internal networks
- IPv4-mapped IPv6 addresses (`::ffff:x.x.x.x`) are normalized to IPv4 before blacklist matching, preventing SSRF attacks that use forms like `::ffff:169.254.169.254` to bypass the private IP check
- Domain targets are DNS-resolved during authorization verification; if any resolved address falls into a private/reserved range (e.g., an attacker-controlled DNS pointing an authorized domain at the cloud metadata address), the task is rejected — blocking DNS rebinding SSRF
- When the authorization scope contains domains, the IPs those domains resolve to are also treated as in-scope (otherwise IP/port assets resolved by tools like nmap would be incorrectly wiped)
- `save_asset` now uses an atomic `INSERT OR IGNORE` operation, eliminating TOCTOU race conditions when multiple threads write the same asset concurrently
- OneForAll CSV parsing matches the `subdomain` column by header name (case-insensitive), no longer relying on the fragile assumption that "the first column is always subdomain", improving compatibility across tool versions
- Target parsing uniformly extracts the host (domain / IP / URL / host:port / IPv6), consistent with authorization verification, preventing URL-like targets from being misclassified as domains or bare IPv6 targets from being split incorrectly

### 3. Breakpoint Resume
- Task state, stage state, and assets are all persisted to SQLite
- After a task fails, it can resume from the most recent uncompleted stage; completed stages are not re-executed
- When the process exits unexpectedly, the `atexit` hook automatically marks RUNNING tasks as FAILED

### 4. Unified Asset Model
All tool outputs are normalized into `Asset` objects with fields including `id` / `type` / `value` / `source` / `task_id` / `discovered_at` / `parent_id` / `technologies` / `status_code` / `title` / `raw`, enabling cross-stage correlation and deduplication.

Vulnerability assets are deduplicated by **(URL, template ID)**: multiple vulnerabilities found by different templates on the same URL can coexist without overwriting each other.

### 6. Multi-format Reports
- **HTML**: Single file, styled, suitable for browser viewing
- **JSON**: Structured data, suitable for programmatic processing
- **Markdown**: Plain text, suitable for version control and CI integration
- **CSV**: Flat asset table (utf-8-sig encoding), opens directly in Excel, ideal for offline analysis by security analysts

Users can choose which format to generate on demand (`--format html|json|md|csv|all`); only the selected format is generated.

### 6. State Machine Driven
Both tasks and stages have explicit state machines; illegal state transitions raise `IllegalTransitionError`, avoiding state confusion during concurrent scheduling and breakpoint resume.

---

## Compliance Notice

**This project is for lawful authorized use only.** Before launching any scan, AICP requires:

1. **Authorizer name/organization** — required
2. **Authorization note** (e.g., authorization letter number) — required
3. **Authorization scope** (domain / IP / CIDR) — required; all scan targets must be within this scope

Read [DISCLAIMER.md](DISCLAIMER.md) for detailed legal terms.

**Unauthorized** scanning, probing, or enumeration of any third-party system may constitute a violation or even a crime. The project authors bear no legal responsibility for misuse.

---

## Quick Start

```bash
# Install
pip install -e .

# Run a complete scan (auto-generates HTML+JSON+Markdown+CSV reports)
aicp scan example.com \
    --authorized-by "John Doe" \
    --authorization-note "AUTH-2026-001" \
    --scope example.com \
    --scope 1.2.3.4

# List tasks
aicp list

# Show task details
aicp show <task_id>

# Generate only Markdown report
aicp report <task_id> --format md

# Start Web UI
aicp web
# Open http://127.0.0.1:5000/ in browser
```

---

## Installation

### Requirements

- **Python**: 3.10 or higher
- **OS**: Windows / Linux / macOS (developed and tested on native Windows)
- **External tools** (optional; if missing, the corresponding stage fails but others are unaffected):
  - [OneForAll](https://github.com/shmilylty/OneForAll) — subdomain enumeration
  - [Nmap](https://nmap.org/) — port scanning
  - [httpx](https://github.com/projectdiscovery/httpx) — web probing
  - [python-Wappalyzer](https://github.com/chorsley/python-Wappalyzer) — web fingerprinting (`pip install python-Wappalyzer`)
  - [dirsearch](https://github.com/maurosoria/dirsearch) — directory enumeration
  - [Nuclei](https://github.com/projectdiscovery/nuclei) — vulnerability scanning

### Steps

```bash
# 1. Clone the repository
git clone https://github.com/your-org/aicp.git
cd aicp

# 2. Install (recommended in a virtual environment)
python -m venv venv
# Windows
venv\Scripts\activate
# Linux / macOS
source venv/bin/activate

pip install -e .

# 3. Verify installation
aicp --version
```

### Development Dependencies

```bash
pip install -e ".[dev]"
# Installs pytest / pytest-cov / psutil (the latter two for coverage gate and process-tree regression tests)
```

---

## CLI Usage

AICP provides 8 subcommands: `scan` / `resume` / `report` / `list` / `show` / `diff` / `cancel` / `config`, plus a `web` command to start the Web UI.

### `scan` — Create and execute a scan task

```bash
aicp scan <targets...> \
    [--authorized-by <authorizer>] \
    [--authorization-note <note>] \
    [--scope <scope>...] \
    [--config <config-file>] \
    [--tools oneforall,nmap,httpx,wappalyzer,dirsearch,nuclei] \
    [--format html|json|md|csv|all] \
    [--rate-limit <req/s>] \
    [--tool-args "nuclei=-t /path/templates"] \
    [--no-report] \
    [--allow-private] \
    [--quiet]
```

**Parameters:**

| Parameter | Required | Description |
|---|---|---|
| `targets` | Yes | Targets to scan (domain / IP / CIDR), at least 1 |
| `--authorized-by` | No* | Authorizer name (defaults to `[auth]` in config.toml) |
| `--authorization-note` | No* | Authorization note (defaults to config.toml) |
| `--scope` | No* | Authorization scope; repeatable (defaults to config.toml) |
| `--config` | No | Config file path (default `.aicp/config.toml`) |
| `--tools` | No | Tool subset to enable, comma-separated |
| `--format` | No | Report format, default `all` |
| `--rate-limit` | No | Global rate limit (req/s), passed to supported tools |
| `--tool-args` | No | Per-tool extra args, e.g. `--tool-args "nuclei=-t /path/templates"` (repeatable) |
| `--no-report` | No | Do not auto-generate reports |
| `--allow-private` | No | Allow scanning private IP ranges (rejected by default) |
| `--quiet` | No | Reduce console output |

> `*` The three authorization fields (authorizer / note / scope) must come from either CLI args or the config file; otherwise execution is refused.

**Examples:**

```bash
# Run only subdomain enumeration + port scanning, generate only Markdown report
aicp scan example.com \
    --authorized-by "John Doe" \
    --authorization-note "AUTH-2026-001" \
    --scope example.com \
    --tools oneforall,nmap \
    --format md

# Read authorization info and rate limit from .aicp/config.toml, only specify the target
aicp config init        # generate config file once and fill in authorization
aicp scan example.com   # authorizer / note / scope / rate limit all come from config

# Scan internal network (requires explicit authorization)
aicp scan 192.168.1.0/24 \
    --authorized-by "Internal Inventory" \
    --authorization-note "INTERNAL-2026-001" \
    --scope 192.168.1.0/24 \
    --allow-private
```

### `resume` — Breakpoint resume

```bash
aicp resume <task_id>
```

The task must be in `AUTHORIZED` / `PAUSED` / `FAILED` state. Completed stages are not re-executed; only uncompleted or failed stages run.

### `report` — Generate reports separately

```bash
aicp report <task_id> [--format html|json|md|csv|all] [-o <output-path>]
```

**Example:**

```bash
# Generate only Markdown report to a specific path
aicp report abc123 --format md -o ./my_report.md
```

### `list` — List all tasks

```bash
aicp list [--status <status-filter>]
```

### `show` — View task details

```bash
aicp show <task_id>
```

### `diff` — Asset diff (attack-surface change tracking)

```bash
aicp diff <task_a> <task_b>
```

Compares asset changes between two tasks: added/removed subdomains, IPs, ports, URLs, and added/fixed vulnerabilities (sorted by severity). Combined with cron, this forms an attack-surface monitoring system.

### `cancel` — Request cancellation of a running task

```bash
aicp cancel <task_id>
```

Writes a cancel request for a RUNNING task; it takes effect at the next stage boundary (the current subprocess finishes the current stage first). The Web task detail page also shows a "Cancel Task" button while running.

### `config` — Config file management

```bash
aicp config init            # generate .aicp/config.toml example (--force to overwrite)
aicp config show            # show merged config (file + environment variables)
```

The config file supports authorization info (authorizer / note / scope) and scan parameters (rate limit, tool paths, etc.), avoiding repetitive typing on every scan. Precedence: **CLI args > config.toml > environment variables (`AICP_*`) > code defaults**.

```toml
[auth]
authorized_by = "Security Dept"
authorization_note = "AUTH-2026-001"
scope = ["example.com", "1.2.3.0/24"]

[scan]
rate_limit = 50
allow_private = false
work_dir = ".aicp/work"
```

> Even when authorization info is stored in the config file, every `scan` still prints the `ConfirmationBanner` for a second confirmation. If you prefer not to persist authorization info, remove the `[auth]` section and pass it explicitly each time.

### `web` — Start Web UI

```bash
aicp web [--host 127.0.0.1] [--port 5000] [--auth-token <token>] [--debug]
```

**`--auth-token` option (recommended):** When set, every request must carry an `Authorization: Bearer <token>` header (or a `?token=<token>` query parameter) or a 401 is returned. POST requests additionally require an `X-CSRF-Token` header (a server-generated independent CSRF token, different from the auth token), otherwise a 403 is returned. The frontend template has JS injected automatically: once you visit `http://127.0.0.1:5000/?token=<token>`, the JS reads that token as `Authorization` and automatically intercepts form POSTs and in-site navigation links, attaching the required headers.

> **Security recommendation:** By default the server listens on `127.0.0.1` only (localhost access). It is **not recommended** to use `--host 0.0.0.0` to expose it directly to the public network. If you must expose it, be sure to set `--auth-token`; otherwise anyone can create/resume tasks and download reports.

---

## Web Interface

After running `aicp web`, open [http://127.0.0.1:5000/](http://127.0.0.1:5000/) in your browser.

**Features:**

- Task list and detail viewing
- Submit new tasks via form (executed in background thread, non-blocking HTTP)
- Task detail page uses JS polling to display stage progress in real time
- One-click resume for failed tasks
- Three report formats available online / for download:
  - `/tasks/<id>/report` — embedded HTML report
  - `/tasks/<id>/report.json` — download JSON
  - `/tasks/<id>/report.md` — download Markdown
- Health probes (no authentication, for external uptime monitoring): `/health` (process liveness) and `/readyz` (database readiness; returns 503 on DB failure)

**Auth & CSRF:** POST requests **always** require a CSRF token (enforced even without authentication); when `--auth-token` is enabled, all requests additionally require authentication:

- All requests must carry an `Authorization: Bearer <token>` header or a `?token=<token>` query parameter
- POST requests additionally require an `X-CSRF-Token` header (value is an independent CSRF token, randomly generated by the server, different from the auth token)
- A `GET /csrf-token` endpoint is provided for the frontend to fetch the CSRF token (requires authentication when enabled)
- The frontend JS automatically intercepts form POSTs and in-site navigation links and attaches the required headers; visit `http://127.0.0.1:5000/?token=<token>` to use all features normally

---

## Report Formats

AICP supports four report formats. HTML / JSON / Markdown share a consistent content structure (6 sections), differing only in rendering; CSV is a flat asset table for offline analysis:

| Format | Use Case | Characteristics |
|---|---|---|
| **HTML** | Browser viewing | Single file, styled, can embed images |
| **JSON** | Programmatic processing | Structured data, consumable by other systems |
| **Markdown** | Version control / CI | Plain text, Git diff friendly |
| **CSV** | Offline analysis | Flat asset table, utf-8-sig encoding, opens directly in Excel |

**Report content (8 sections for HTML / JSON / Markdown):**

1. **Task Info** — Task ID, status, targets, authorizer, authorization scope, note, timestamps
2. **Asset Statistics** — Counts per asset type (incl. vulnerabilities / directories), identified technology stacks, vulnerability severity counts
3. **Asset Details** — Host and port tables, domain list (with resolved IPs)
4. **Vulnerability List** — Nuclei findings (sorted by severity, with severity counts / name / template ID / target URL)
5. **Directory Enumeration** — dirsearch findings (path / status code / size / redirect)
6. **Stage Timeline** — Execution status, start/end times, attempt counts, errors for 6 stages
7. **Audit Log** — All state changes and tool execution records
8. **Header** — Generation timestamp

**CSV report**: one row per asset, with columns `task_id / asset_id / type / value / source / parent_id / status_code / title / technologies / severity / template_id / size / redirect / discovered_at`, ideal for offline processing with Excel / pandas. Vulnerability rows use a clean URL as `value`, with `severity` / `template_id` expanded from the raw output.

**Generation strategy:**

- CLI `scan` / `resume` defaults to generating all four formats (`--format all`); use `--format md` etc. to generate only the selected format
- Web routes use **lazy generation**: generated on first access and cached, reused on subsequent access
- Only the format the user selects is generated; no resources are wasted

---

## Project Structure

```
aicp/
├── aicp/                          # Main package
│   ├── auth/                      # Authorization
│   │   └── verifier.py            #   AuthorizationVerifier + ConfirmationBanner
│   ├── models/                    # Data models
│   │   ├── asset.py               #   Asset (unified schema)
│   │   └── task.py                #   Task / Stage / state enums
│   ├── scheduler/                 # Persistence and state machine
│   │   ├── store.py               #   SQLite wrapper (tasks/stages/assets/audit)
│   │   └── state_machine.py       #   State transition validation
│   ├── tools/                     # Tool adaptation layer
│   │   ├── base.py                #   Tool abstract interface
│   │   ├── registry.py            #   Plugin registration & discovery (ToolRegistry)
│   │   ├── oneforall.py           #   OneForAll adapter
│   │   ├── nmap.py                #   Nmap adapter
│   │   ├── httpx_tool.py          #   httpx adapter
│   │   ├── wappalyzer.py          #   Wappalyzer adapter
│   │   ├── dirsearch.py           #   dirsearch adapter
│   │   └── nuclei.py              #   Nuclei adapter
│   ├── pipeline/                  # Pipeline orchestration
│   │   └── orchestrator.py        #   Orchestrator (stage chaining/resume/failure isolation/task lease)
│   ├── correlate/                 # Data correlation
│   │   └── merger.py              #   merge_assets → AssetGraph
│   ├── report/                    # Report generation
│   │   ├── html.py                #   HTML report
│   │   ├── json_report.py         #   JSON report
│   │   ├── markdown.py            #   Markdown report
│   │   └── csv_report.py          #   CSV report (utf-8-sig, Excel compatible)
│   ├── web/                       # Web UI
│   │   ├── app.py                 #   Flask routes (auth/CSRF/health probes)
│   │   ├── runner.py              #   Background task runner
│   │   ├── templates/             #   Jinja2 templates
│   │   └── static/                #   CSS
│   ├── observability.py           # JSON logging + task_id injection (observability base)
│   ├── config.py                  #   Config file support (P1-2)
│   ├── diff.py                    #   Asset diff (P2-1)
│   └── cli.py                     # CLI entry (click, incl. process-tree management)
├── tests/                         # Tests (427 cases)
├── scripts/                       # End-to-end test scripts
├── pyproject.toml                 # Project config
├── DISCLAIMER.md                  # Disclaimer
└── README.md                      # This file
```

---

## Development & Testing

### Running Tests

```bash
# Full test suite (427 cases, ~15 seconds)
python -m pytest

# Verbose output
python -m pytest -v

# Run only the recovery suite (resume/lease/process-tree cleanup recovery paths)
python -m pytest -m recovery

# Run a specific test file
python -m pytest tests/test_orchestrator.py

# Run a specific test
python -m pytest tests/test_orchestrator.py::test_full_pipeline_run_completes_all_stages
```

### Test Coverage

| Test File | Cases | Coverage |
|---|---|---|
| `test_auth.py` | 28 | Authorization, scope matching, private IP rejection, domain DNS resolution (SSRF) |
| `test_audit_fixes.py` | 8 | Audit log fixes |
| `test_cli.py` | 38 | CLI commands, report formats, tool subsets, config, cancel |
| `test_correlate.py` | 9 | Asset correlation and merging |
| `test_csv_report.py` | 9 | CSV report (flat table / utf-8-sig BOM) |
| `test_diff.py` | 2 | Asset diff (P2-1) |
| `test_dirsearch.py` | 11 | dirsearch adapter (JSON parsing / 404 filtering) |
| `test_models.py` | 5 | Data models |
| `test_nuclei.py` | 12 | Nuclei adapter (JSONL parsing / severity / vuln dedup / stale-output cleanup) |
| `test_observability.py` | 6 | JSON logging / task_id injection / log persistence |
| `test_orchestrator.py` | 24 | Pipeline, resume, failure isolation, retry limit, cancel, pass-through, task lease, output logging |
| `test_process_runner.py` | 3 | Process-tree management (timeout tree kill / force-kill containment) |
| `test_registry.py` | 22 | Plugin system (registration / entry_points discovery / singleton) |
| `test_report.py` | 12 | HTML / JSON reports (incl. vulnerabilities / directories) |
| `test_report_markdown.py` | 14 | Markdown report |
| `test_security_hardening.py` | 83 | IP blacklist, CIDR, atexit cleanup |
| `test_state_machine.py` | 24 | State machine transitions |
| `test_store.py` | 42 | SQLite persistence, indexes, migrations, cancel marker, task leases |
| `test_tools.py` | 24 | Tool adapters (incl. IPv6 parsing, Wappalyzer concurrency, domain scope) |
| `test_web.py` | 51 | Web routes, report downloads, path traversal, auth/CSRF, cancel, health probes, lease 409 |

In addition to lint and tests, CI enforces a coverage gate (`--cov-fail-under=75`) across an ubuntu / windows matrix.

### End-to-End Testing

```bash
# Real tool integration (requires OneForAll / Nmap / httpx installed)
python scripts/e2e_real.py

# Web end-to-end
python scripts/e2e_web.py
```

### Adding a New Tool

AICP ships with a built-in plugin system (`ToolRegistry` in `aicp/tools/registry.py`); the recommended way to add a tool is via registration:

1. Create `your_tool.py` under `aicp/tools/`
2. Inherit from the `Tool` abstract class, implement `run(inputs, ctx) -> ToolResult`
3. Declare `stage` / `input_asset_types` / `output_asset_types`
4. Register in one of two ways:
   - **Explicit registration**: import and append in `_default_tools()` in `aicp/cli.py` (how built-in tools are registered)
   - **Plugin discovery**: declare `[project.entry-points."aicp.tools"]` so `tool_registry.discover()` auto-discovers it; or call `tool_registry.register(YourTool)` directly
5. Write unit tests (see `tests/test_nuclei.py` / `tests/test_registry.py` for reference)

See the "Tool Adaptation Layer" and "How to Extend" sections in [TECHNICAL.md](TECHNICAL.md) for details.

---

## FAQ

### Q1: What happens if a tool is not installed?

A: The corresponding stage fails (marked `FAILED`), but other stages are unaffected. For example, if Nmap is not installed, the PORTSCAN stage fails, but FINGERPRINT can still proceed based on domains from SUBDOMAIN (if httpx is installed).

### Q2: How do I recover a failed task?

A: Use `aicp resume <task_id>`. Completed stages are not re-executed; only uncompleted or failed stages run. The task must be in `AUTHORIZED` / `PAUSED` / `FAILED` state.

### Q3: How do I generate only a Markdown report?

A: `aicp report <task_id> --format md`, or add `--format md` when running `scan`.

### Q4: Where is the default directory?

A: Under `.aicp/` in the current working directory:
- `.aicp/aicp.db` — SQLite database
- `.aicp/work/` — Tool working directory (temp files)
- `.aicp/reports/` — Report output

### Q5: How do I scan an internal network?

A: Private IP ranges are rejected by default (SSRF protection). You must explicitly add `--allow-private`, and the authorization scope must include the internal network range.

### Q6: Does it support concurrent scanning of multiple tasks?

A: CLI is synchronous, running one task at a time. The Web UI supports background thread execution, allowing multiple tasks to run in parallel (each task uses an independent SQLite connection; WAL mode supports multiple readers and a single writer).

### Q7: How do I protect the Web UI?

A: Set an authentication token with `--auth-token`, for example:

```bash
aicp web --auth-token "your-secret-token-here"
```

Once enabled, all requests must carry an `Authorization: Bearer <token>` header (or a `?token=<token>` query parameter); POST requests require an `X-CSRF-Token` header regardless of whether authentication is enabled (CSRF protection; a server-generated independent token). After visiting `http://127.0.0.1:5000/?token=<token>`, the frontend JS automatically reads that token and attaches it to all requests, so users do not need to add it manually. **By default the server listens on 127.0.0.1 only; if you expose it with `--host 0.0.0.0`, you must set `--auth-token`.**

---

## License

[MIT License](LICENSE)

Copyright (c) 2026 aicp contributors

This project is provided "as is", without any express or implied warranties. The authors bear no responsibility for any direct or indirect losses caused by using this tool. Users are fully responsible for the legality of their own actions.

---

## Acknowledgments

This project orchestrates the following open-source tools; thanks for their contributions:

- [OneForAll](https://github.com/shmilylty/OneForAll) — Subdomain enumeration
- [Nmap](https://nmap.org/) — Network scanning
- [httpx](https://github.com/projectdiscovery/httpx) — Web probing
- [Wappalyzer](https://github.com/AliasIO/Wappalyzer) — Technology fingerprinting
- [dirsearch](https://github.com/maurosoria/dirsearch) — Directory enumeration
- [Nuclei](https://github.com/projectdiscovery/nuclei) — Vulnerability scanning
