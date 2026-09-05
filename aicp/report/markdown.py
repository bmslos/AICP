"""Markdown 报告生成。

生成单文件 Markdown 报告 (无外部依赖)，内容结构与 HTML 报告对齐:
- 任务元信息与合规信息
- 资产统计摘要 (表格)
- 资产关联树 (按 host -> port -> url 展开)
- 阶段执行时间线
- 审计日志

安全: Markdown 表格单元格内的 `|` 替换为 `\\|` 转义，避免破坏表格结构。
"""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
from typing import List

from ..correlate import AssetGraph
from ..models import Task
from ..scheduler import Store
from .common import build_report_data, vulns_by_severity


def generate_markdown_report(task: Task, store: Store) -> str:
    """生成 Markdown 报告字符串。"""
    data = build_report_data(task, store)

    parts: List[str] = []
    parts.append(_render_head(task))
    parts.append(_render_task_card(task))
    parts.append(_render_summary(data.stats))
    parts.append(_render_assets(data.graph))
    parts.append(_render_vulnerabilities(data))
    parts.append(_render_directories(data))
    parts.append(_render_stages(data.stages))
    parts.append(_render_audit(data.audit))
    return "\n\n".join(parts) + "\n"


def write_markdown_report(task: Task, store: Store, output_path: str | Path) -> Path:
    """生成 Markdown 报告并写入文件。"""
    content = generate_markdown_report(task, store)
    out = Path(output_path)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(content, encoding="utf-8")
    return out


# ---------------- 内部渲染函数 ----------------


def _escape_cell(s: str) -> str:
    """转义 Markdown 表格单元格内的 `|` 与换行，避免破坏表格结构。"""
    if s is None:
        return ""
    return str(s).replace("|", "\\|").replace("\n", " ")


def _fmt_dt(dt) -> str:
    if dt is None:
        return "-"
    if hasattr(dt, "isoformat"):
        return dt.isoformat()
    return str(dt)


def _render_head(task: Task) -> str:
    return (
        f"# AICP 资产报告\n\n"
        f"> 生成时间: {datetime.now(timezone.utc).isoformat()}"
    )


def _render_task_card(task: Task) -> str:
    targets = ", ".join(task.targets) or "(无)"
    scope = ", ".join(task.authorized_scope) or "(空)"
    error_line = f"- **错误**: {_escape_cell(task.error)}\n" if task.error else ""
    return (
        "## 任务信息\n\n"
        f"- **任务 ID**: `{task.id}`\n"
        f"- **状态**: {task.status.value}\n"
        f"- **目标**: {_escape_cell(targets)}\n"
        f"- **授权人**: {_escape_cell(task.authorized_by or '(未填写)')}\n"
        f"- **授权范围**: {_escape_cell(scope)}\n"
        f"- **授权说明**: {_escape_cell(task.authorization_note or '(未填写)')}\n"
        f"- **授权时间**: {_escape_cell(_fmt_dt(task.authorized_at))}\n"
        f"- **开始时间**: {_escape_cell(_fmt_dt(task.started_at))}\n"
        f"- **结束时间**: {_escape_cell(_fmt_dt(task.finished_at))}\n"
        f"{error_line}"
    ).rstrip("\n")


def _render_summary(stats: dict) -> str:
    techs = ", ".join(f"`{t}`" for t in stats["technologies"]) or "(无)"
    return (
        "## 资产统计\n\n"
        "| 类型 | 数量 |\n"
        "|---|---:|\n"
        f"| 域名 (Domain) | {stats['domains']} |\n"
        f"| IP | {stats['ips']} |\n"
        f"| 开放端口 (Port) | {stats['ports']} |\n"
        f"| URL | {stats['urls']} |\n"
        f"| Web 服务 | {stats['web_services']} |\n"
        f"| 漏洞 (Vulnerability) | {stats['vulnerabilities']} |\n"
        f"| 目录 (Directory) | {stats['directories']} |\n\n"
        f"### 识别到的技术栈\n\n{techs}"
    )


def _render_assets(graph: AssetGraph) -> str:
    """渲染资产关联树。"""
    if not graph.hosts and not graph.domains:
        return "## 资产详情\n\n(无资产)"

    parts: List[str] = ["## 资产详情"]

    # 主机与端口
    parts.append("### 主机与端口")
    if graph.hosts:
        parts.append("| IP | 开放端口 | 关联域名 | Web 服务 |")
        parts.append("|---|---|---|---|")
        for host in graph.hosts:
            ports = ", ".join(f"`{p.value}`" for p in host.ports) or "(无开放端口)"
            domains = graph.domains_by_ip.get(host.ip, [])
            domains_str = ", ".join(domains) or "-"
            ws = _render_host_web_services(host)
            parts.append(
                f"| `{_escape_cell(host.ip)}` "
                f"| {_escape_cell(ports)} "
                f"| {_escape_cell(domains_str)} "
                f"| {_escape_cell(ws)} |"
            )
    else:
        parts.append("(无主机资产)")

    # 域名列表
    if graph.domains:
        parts.append("### 域名列表")
        parts.append("| 域名 | 解析 IP | 来源 |")
        parts.append("|---|---|---|")
        for d in graph.domains:
            ip_str = ", ".join(d.resolved_ips) or "-"
            parts.append(
                f"| {_escape_cell(d.domain)} "
                f"| {_escape_cell(ip_str)} "
                f"| `{_escape_cell(d.source)}` |"
            )

    return "\n\n".join(parts)


def _render_host_web_services(host) -> str:
    """渲染某 host 下所有端口的 web 服务摘要 (单行, 用分号分隔)。"""
    items = []
    for p in host.ports:
        for u in p.urls:
            if u.web_service:
                techs = ",".join(u.web_service.technologies) or "(无)"
                status = u.web_service.status_code or "-"
                title = u.web_service.title or ""
                items.append(f"{u.url} [HTTP {status}] {title} ({techs})")
    return "; ".join(items) or "(无)"


def _render_vulnerabilities(data) -> str:
    """渲染漏洞清单 section (severity 降序)。"""
    if not data.vulnerabilities:
        return ""
    parts = ["## 漏洞清单"]
    counts = vulns_by_severity(data.vulnerabilities)
    if counts:
        parts.append(", ".join(f"`{s}`: {n}" for s, n in counts.items()))
    parts.append("| 严重度 | 名称 | 模板 ID | 目标 URL |")
    parts.append("|---|---|---|---|")
    for v in data.vulnerabilities:
        parts.append(
            f"| {_escape_cell(v['severity'])} "
            f"| {_escape_cell(v['name'] or '-')} "
            f"| `{_escape_cell(v['template_id'] or '-')}` "
            f"| {_escape_cell(v['url'])} |"
        )
    return "\n\n".join(parts)


def _render_directories(data) -> str:
    """渲染目录枚举 section。"""
    if not data.directories:
        return ""
    parts = ["## 目录枚举"]
    parts.append("| 路径 | 状态码 | 大小 | 跳转 |")
    parts.append("|---|---|---|---|")
    for d in data.directories:
        parts.append(
            f"| {_escape_cell(d['url'])} "
            f"| {d['status_code'] if d['status_code'] is not None else '-'} "
            f"| {d['size'] if d['size'] is not None else '-'} "
            f"| {_escape_cell(d['redirect'] or '-')} |"
        )
    return "\n\n".join(parts)


def _render_stages(stages) -> str:
    parts = ["## 阶段时间线"]
    if not stages:
        parts.append("(无阶段记录)")
        return "\n\n".join(parts)
    parts.append("| 阶段 | 状态 | 开始 | 结束 | 尝试 | 错误 |")
    parts.append("|---|---|---|---|---:|---|")
    for s in stages:
        parts.append(
            f"| {_escape_cell(s.name.value)} "
            f"| {_escape_cell(s.status.value)} "
            f"| {_escape_cell(_fmt_dt(s.started_at))} "
            f"| {_escape_cell(_fmt_dt(s.finished_at))} "
            f"| {s.attempt} "
            f"| {_escape_cell(s.error) if s.error else '-'} |"
        )
    return "\n\n".join(parts)


def _render_audit(audit: List[dict]) -> str:
    parts = ["## 审计日志"]
    if not audit:
        parts.append("(无审计记录)")
        return "\n\n".join(parts)
    parts.append("| 时间 | 事件 | 详情 |")
    parts.append("|---|---|---|")
    for a in audit:
        parts.append(
            f"| {_escape_cell(a.get('ts') or '')} "
            f"| `{_escape_cell(a.get('event') or '')}` "
            f"| {_escape_cell(a.get('detail') or '')} |"
        )
    return "\n\n".join(parts)
