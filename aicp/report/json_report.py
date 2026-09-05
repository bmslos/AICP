"""JSON 报告生成。

输出结构化 JSON 报告，包含:
- 任务元信息 (id/targets/授权信息/时间)
- 资产统计摘要 (含漏洞/目录, 漏洞按严重度计数)
- 完整的 AssetGraph + 漏洞/目录平铺列表
- 阶段执行历史
- 审计日志
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path

from ..models import Task
from ..scheduler import Store
from .common import build_report_data, vulns_by_severity


def generate_json_report(task: Task, store: Store) -> dict:
    """生成 JSON 报告字典。

    - task: 任务对象
    - store: 持久化层 (用于读取资产/阶段/审计)
    """
    data = build_report_data(task, store)

    graph_dict = data.graph.to_dict()
    # 漏洞 / 目录是平铺列表, 不挂在关联树上, 单独序列化
    graph_dict["vulnerabilities"] = data.vulnerabilities
    graph_dict["directories"] = data.directories

    # 统计摘要
    stats = {
        "total_domains": data.stats["domains"],
        "total_ips": data.stats["ips"],
        "total_ports": data.stats["ports"],
        "total_urls": data.stats["urls"],
        "total_web_services": data.stats["web_services"],
        "total_vulnerabilities": data.stats["vulnerabilities"],
        "vulns_by_severity": vulns_by_severity(data.vulnerabilities),
        "total_directories": data.stats["directories"],
        "unique_technologies": data.stats["technologies"],
    }

    return {
        "version": "1.0",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "task": task.to_dict(),
        "summary": stats,
        "assets": graph_dict,
        "stages": [s.to_dict() for s in data.stages],
        "audit_log": data.audit,
    }


def write_json_report(task: Task, store: Store, output_path: str | Path) -> Path:
    """生成 JSON 报告并写入文件。"""
    report = generate_json_report(task, store)
    out = Path(output_path)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(
        json.dumps(report, ensure_ascii=False, indent=2),
        encoding="utf-8",
    )
    return out
