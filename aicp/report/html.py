"""HTML 报告生成。

生成单文件 HTML 报告 (无外部依赖)，包含:
- 任务元信息与合规信息
- 资产统计摘要 (表格)
- 资产关联树 (按 domain -> host -> port -> url 展开)
- 阶段执行时间线
- 审计日志

安全: 所有插入 HTML 的文本都经过 html.escape 转义，防止 XSS。
"""

from __future__ import annotations

import html
from datetime import datetime, timezone
from pathlib import Path
from typing import List

from ..correlate import AssetGraph
from ..models import Task
from ..scheduler import Store
from .common import build_report_data, vulns_by_severity


def generate_html_report(task: Task, store: Store) -> str:
    """生成 HTML 报告字符串。"""
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
    parts.append("</body></html>")
    return "\n".join(parts)


def write_html_report(task: Task, store: Store, output_path: str | Path) -> Path:
    """生成 HTML 报告并写入文件。"""
    content = generate_html_report(task, store)
    out = Path(output_path)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(content, encoding="utf-8")
    return out


# ---------------- 内部渲染函数 ----------------


def _render_head(task: Task) -> str:
    return f"""<!DOCTYPE html>
<html lang="zh-CN">
<head>
<meta charset="UTF-8">
<title>AICP 资产报告 - {html.escape(task.id[:8])}</title>
<style>
  body {{ font-family: -apple-system, "Segoe UI", "Microsoft YaHei", sans-serif;
         margin: 0; padding: 24px; background: #f5f5f7; color: #1d1d1f; }}
  h1, h2, h3 {{ color: #1d1d1f; }}
  h1 {{ border-bottom: 2px solid #0071e3; padding-bottom: 8px; }}
  .card {{ background: #fff; border-radius: 8px; padding: 16px 20px;
           margin: 16px 0; box-shadow: 0 1px 3px rgba(0,0,0,0.08); }}
  table {{ border-collapse: collapse; width: 100%; font-size: 14px; }}
  th, td {{ border: 1px solid #d2d2d7; padding: 6px 10px; text-align: left; }}
  th {{ background: #f5f5f7; font-weight: 600; }}
  .tag {{ display: inline-block; background: #e8f0fe; color: #1a73e8;
          padding: 2px 8px; border-radius: 4px; margin: 2px; font-size: 12px; }}
  .tag-warn {{ background: #fff4e5; color: #b06000; }}
  .tag-ok {{ background: #e6f4ea; color: #137333; }}
  .tag-fail {{ background: #fce8e6; color: #c5221f; }}
  .meta dt {{ float: left; width: 100px; color: #6e6e73; }}
  .meta dd {{ margin-left: 120px; }}
  ul.tree {{ list-style: none; padding-left: 20px; }}
  ul.tree li {{ margin: 4px 0; }}
  .toggle {{ cursor: pointer; color: #0071e3; user-select: none; }}
  .footer {{ color: #6e6e73; font-size: 12px; text-align: center;
             margin-top: 32px; padding-top: 16px; border-top: 1px solid #d2d2d7; }}
</style>
</head>
<body>
<h1>自动化信息收集平台 - 资产报告</h1>
<p style="color:#6e6e73;">生成时间: {html.escape(datetime.now(timezone.utc).isoformat())}</p>
"""


def _render_task_card(task: Task) -> str:
    targets = ", ".join(html.escape(t) for t in task.targets)
    scope = ", ".join(html.escape(s) for s in task.authorized_scope) or "(空)"
    status_tag = _status_tag(task.status.value)

    return f"""
<div class="card">
  <h2>任务信息</h2>
  <dl class="meta">
    <dt>任务 ID</dt><dd>{html.escape(task.id)}</dd>
    <dt>状态</dt><dd>{status_tag}</dd>
    <dt>目标</dt><dd>{targets}</dd>
    <dt>授权人</dt><dd>{html.escape(task.authorized_by or "(未填写)")}</dd>
    <dt>授权范围</dt><dd>{scope}</dd>
    <dt>授权说明</dt><dd>{html.escape(task.authorization_note or "(未填写)")}</dd>
    <dt>授权时间</dt><dd>{html.escape(_fmt_dt(task.authorized_at))}</dd>
    <dt>开始时间</dt><dd>{html.escape(_fmt_dt(task.started_at))}</dd>
    <dt>结束时间</dt><dd>{html.escape(_fmt_dt(task.finished_at))}</dd>
    {f'<dt>错误</dt><dd class="tag-fail">{html.escape(task.error)}</dd>' if task.error else ''}
  </dl>
</div>
"""


def _render_summary(stats: dict) -> str:
    techs = " ".join(f'<span class="tag">{html.escape(t)}</span>' for t in stats["technologies"]) or "(无)"
    return f"""
<div class="card">
  <h2>资产统计</h2>
  <table>
    <tr><th>类型</th><th>数量</th></tr>
    <tr><td>域名 (Domain)</td><td>{stats['domains']}</td></tr>
    <tr><td>IP</td><td>{stats['ips']}</td></tr>
    <tr><td>开放端口 (Port)</td><td>{stats['ports']}</td></tr>
    <tr><td>URL</td><td>{stats['urls']}</td></tr>
    <tr><td>Web 服务</td><td>{stats['web_services']}</td></tr>
    <tr><td>漏洞 (Vulnerability)</td><td>{stats['vulnerabilities']}</td></tr>
    <tr><td>目录 (Directory)</td><td>{stats['directories']}</td></tr>
  </table>
  <h3>识别到的技术栈</h3>
  <div>{techs}</div>
</div>
"""


def _render_assets(graph: AssetGraph) -> str:
    """渲染资产关联树。"""
    if not graph.hosts and not graph.domains:
        return '<div class="card"><h2>资产详情</h2><p>(无资产)</p></div>'

    parts = ['<div class="card">', '<h2>资产详情</h2>']

    # 按 host 分组展示 (最常见视图)
    parts.append("<h3>主机与端口</h3>")
    if graph.hosts:
        parts.append('<table><tr><th>IP</th><th>开放端口</th><th>关联域名</th><th>Web 服务</th></tr>')
        for host in graph.hosts:
            ip = html.escape(host.ip)
            ports_html = ", ".join(
                f'<span class="tag">{html.escape(p.value)}</span>'
                for p in host.ports
            ) or "(无开放端口)"
            domains = graph.domains_by_ip.get(host.ip, [])
            domains_html = ", ".join(html.escape(d) for d in domains) or "-"
            ws_html = _render_host_web_services(host)
            parts.append(
                f'<tr><td>{ip}</td><td>{ports_html}</td>'
                f'<td>{domains_html}</td><td>{ws_html}</td></tr>'
            )
        parts.append('</table>')
    else:
        parts.append('<p>(无主机资产)</p>')

    # 域名列表
    if graph.domains:
        parts.append("<h3>域名列表</h3>")
        parts.append('<table><tr><th>域名</th><th>解析 IP</th><th>来源</th></tr>')
        for d in graph.domains:
            ip_str = ", ".join(html.escape(ip) for ip in d.resolved_ips) or "-"
            parts.append(
                f'<tr><td>{html.escape(d.domain)}</td>'
                f'<td>{ip_str}</td>'
                f'<td><span class="tag">{html.escape(d.source)}</span></td></tr>'
            )
        parts.append('</table>')

    parts.append('</div>')
    return "\n".join(parts)


def _render_host_web_services(host) -> str:
    """渲染某 host 下所有端口的 web 服务摘要。"""
    items = []
    for p in host.ports:
        for u in p.urls:
            if u.web_service:
                techs = " ".join(
                    f'<span class="tag">{html.escape(t)}</span>'
                    for t in u.web_service.technologies
                ) or "(无)"
                status = u.web_service.status_code or "-"
                title = html.escape(u.web_service.title or "")
                items.append(
                    f'<div style="margin:4px 0;">'
                    f'<code>{html.escape(u.url)}</code> '
                    f'<span class="tag tag-ok">HTTP {status}</span> '
                    f'<span style="color:#6e6e73;">{title}</span><br>'
                    f'{techs}</div>'
                )
    return "".join(items) or "(无)"


def _render_vulnerabilities(data) -> str:
    """渲染漏洞清单 section (severity 降序)。"""
    if not data.vulnerabilities:
        return ""
    parts = ['<div class="card">', '<h2>漏洞清单</h2>']
    counts = vulns_by_severity(data.vulnerabilities)
    if counts:
        badges = " ".join(
            f'<span class="tag {_severity_tag_cls(s)}">{s}: {n}</span>'
            for s, n in counts.items()
        )
        parts.append(f"<p>{badges}</p>")
    parts.append('<table><tr><th>严重度</th><th>名称</th><th>模板 ID</th><th>目标 URL</th></tr>')
    for v in data.vulnerabilities:
        parts.append(
            f'<tr><td><span class="tag {_severity_tag_cls(v["severity"])}">'
            f'{html.escape(v["severity"])}</span></td>'
            f'<td>{html.escape(v["name"] or "-")}</td>'
            f'<td><code>{html.escape(v["template_id"] or "-")}</code></td>'
            f'<td>{html.escape(v["url"])}</td></tr>'
        )
    parts.append("</table></div>")
    return "\n".join(parts)


def _render_directories(data) -> str:
    """渲染目录枚举 section。"""
    if not data.directories:
        return ""
    parts = ['<div class="card">', '<h2>目录枚举</h2>']
    parts.append('<table><tr><th>路径</th><th>状态码</th><th>大小</th><th>跳转</th></tr>')
    for d in data.directories:
        parts.append(
            f'<tr><td><code>{html.escape(d["url"])}</code></td>'
            f'<td>{d["status_code"] if d["status_code"] is not None else "-"}</td>'
            f'<td>{d["size"] if d["size"] is not None else "-"}</td>'
            f'<td>{html.escape(d["redirect"] or "-")}</td></tr>'
        )
    parts.append("</table></div>")
    return "\n".join(parts)


def _severity_tag_cls(severity: str) -> str:
    return {
        "critical": "tag-fail",
        "high": "tag-fail",
        "medium": "tag-warn",
        "low": "tag-ok",
        "unknown": "tag",
    }.get(severity, "tag")


def _render_stages(stages) -> str:
    parts = ['<div class="card">', '<h2>阶段执行时间线</h2>']
    if not stages:
        parts.append('<p>(无阶段记录)</p>')
    else:
        parts.append('<table><tr><th>阶段</th><th>状态</th><th>开始</th><th>结束</th><th>尝试</th><th>错误</th></tr>')
        for s in stages:
            parts.append(
                f'<tr><td>{html.escape(s.name.value)}</td>'
                f'<td>{_stage_status_tag(s.status.value)}</td>'
                f'<td>{html.escape(_fmt_dt(s.started_at))}</td>'
                f'<td>{html.escape(_fmt_dt(s.finished_at))}</td>'
                f'<td>{s.attempt}</td>'
                f'<td>{html.escape(s.error) if s.error else "-"}</td></tr>'
            )
        parts.append('</table>')
    parts.append('</div>')
    return "\n".join(parts)


def _render_audit(audit: List[dict]) -> str:
    parts = ['<div class="card">', '<h2>审计日志</h2>']
    if not audit:
        parts.append('<p>(无审计记录)</p>')
    else:
        parts.append('<table><tr><th>时间</th><th>事件</th><th>详情</th></tr>')
        for a in audit:
            parts.append(
                f'<tr><td>{html.escape(a.get("ts") or "")}</td>'
                f'<td><span class="tag">{html.escape(a.get("event") or "")}</span></td>'
                f'<td>{html.escape(a.get("detail") or "")}</td></tr>'
            )
        parts.append('</table>')
    parts.append('</div>')
    return "\n".join(parts)


def _status_tag(status: str) -> str:
    cls = {
        "completed": "tag-ok",
        "failed": "tag-fail",
        "cancelled": "tag-fail",
        "paused": "tag-warn",
        "running": "tag",
        "authorized": "tag-ok",
    }.get(status, "tag")
    return f'<span class="{cls}">{html.escape(status)}</span>'


def _stage_status_tag(status: str) -> str:
    cls = {
        "completed": "tag-ok",
        "failed": "tag-fail",
        "skipped": "tag-warn",
        "running": "tag",
    }.get(status, "tag")
    return f'<span class="{cls}">{html.escape(status)}</span>'


def _fmt_dt(dt) -> str:
    if dt is None:
        return "-"
    if hasattr(dt, "isoformat"):
        return dt.isoformat()
    return str(dt)
