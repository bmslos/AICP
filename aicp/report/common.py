"""报告层公共装配。

所有报告生成器 (HTML / JSON / Markdown / CSV) 共用同一套数据装配:
- 一次 list_assets + merge_assets, 避免每份报告重复全量计算 (P3-6)
- 统一 vulnerability / directory 的统计、展开与排序 (P0-1)

漏洞资产 value 形如 "matched_at|template_id" (见 tools/nuclei.py),
此处展开为独立字段, 报告层不再直接展示拼接串。
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, List

from ..correlate import AssetGraph, merge_assets
from ..models import Asset, Task
from ..scheduler import Store


# 漏洞严重度排序: critical 最高
_SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "unknown": 4}


@dataclass
class ReportData:
    """一次报告生成所需的全部数据 (各格式共用)。"""

    task: Task
    assets: List[Asset]
    stages: List
    audit: List[dict]
    graph: AssetGraph
    stats: dict
    vulnerabilities: List[dict] = field(default_factory=list)  # severity 降序
    directories: List[dict] = field(default_factory=list)


def compute_stats(assets: List[Asset]) -> dict:
    """资产统计 (含 vulnerability / directory)。"""
    return {
        "domains": sum(1 for a in assets if a.type == "domain"),
        "ips": sum(1 for a in assets if a.type == "ip"),
        "ports": sum(1 for a in assets if a.type == "port"),
        "urls": sum(1 for a in assets if a.type == "url"),
        "web_services": sum(1 for a in assets if a.type == "web_service"),
        "vulnerabilities": sum(1 for a in assets if a.type == "vulnerability"),
        "directories": sum(1 for a in assets if a.type == "directory"),
        "technologies": sorted({
            t for a in assets if a.type == "web_service" for t in a.technologies
        }),
    }


def _vuln_sort_key(v: dict) -> tuple:
    return (_SEVERITY_ORDER.get(v.get("severity", "unknown"), 4), v.get("url", ""))


def build_vulnerabilities(assets: List[Asset]) -> List[dict]:
    """从 vulnerability 资产展开明细, 按 severity 降序排序。"""
    rows: List[dict] = []
    for a in assets:
        if a.type != "vulnerability":
            continue
        raw = a.raw or {}
        # value 形如 "url|template_id", 展开出干净的 matched_at
        matched_at = raw.get("matched_at") or a.value.split("|", 1)[0]
        rows.append({
            "url": matched_at,
            "template_id": raw.get("template_id", ""),
            "name": raw.get("name", ""),
            "severity": raw.get("severity", "unknown"),
            "matched_at": matched_at,
            "curl_command": raw.get("curl_command", ""),
        })
    rows.sort(key=_vuln_sort_key)
    return rows


def vulns_by_severity(vulnerabilities: List[dict]) -> Dict[str, int]:
    """漏洞严重度计数 (按 critical->unknown 顺序)。"""
    from collections import Counter

    counter = Counter(v.get("severity", "unknown") for v in vulnerabilities)
    return {
        sev: counter.get(sev, 0)
        for sev in ("critical", "high", "medium", "low", "unknown")
        if counter.get(sev, 0) > 0
    }


def build_directories(assets: List[Asset]) -> List[dict]:
    """从 directory 资产展开明细, 按 url 排序。"""
    rows: List[dict] = []
    for a in assets:
        if a.type != "directory":
            continue
        raw = a.raw or {}
        rows.append({
            "url": a.value,
            "status_code": a.status_code,
            "size": raw.get("size"),
            "redirect": raw.get("redirect", ""),
        })
    rows.sort(key=lambda d: d["url"])
    return rows


def build_report_data(task: Task, store: Store) -> ReportData:
    """装配报告所需的全部数据。"""
    assets = store.list_assets(task.id)
    graph = merge_assets(assets)
    return ReportData(
        task=task,
        assets=assets,
        stages=store.list_stages(task.id),
        audit=store.list_audit(task.id),
        graph=graph,
        stats=compute_stats(assets),
        vulnerabilities=build_vulnerabilities(assets),
        directories=build_directories(assets),
    )
