"""资产差异比较 (P2-1): 两次扫描之间的攻击面变更追踪。

`aicp diff <task_a> <task_b>` 输出 B 相对 A 的新增 / 消失资产,
配合报告与 cron 即可形成攻击面监控。

注意: Store 的唯一键是 (task_id, type, value, source), 同一资产可能有多个
source (如 web_service 由 httpx+wappalyzer 产出)。做 diff 时按 (type, value)
聚合去重, 以资产本身而非 source 为准。
"""

from __future__ import annotations

from typing import List, Set, Tuple

from .models import Asset
from .scheduler import Store

_SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "unknown": 4}


def _vuln_sort_key(a: Asset) -> tuple:
    raw = a.raw or {}
    return (_SEVERITY_ORDER.get(raw.get("severity", "unknown"), 4), a.value)


def asset_keys(assets: List[Asset]) -> Set[Tuple[str, str]]:
    """按 (type, value) 聚合去重。"""
    return {(a.type, a.value) for a in assets}


def diff_tasks(store: Store, task_a: str, task_b: str) -> dict:
    """比较两个任务的资产差异 (B 相对 A 的变化)。"""
    assets_a = store.list_assets(task_a)
    assets_b = store.list_assets(task_b)
    keys_a = asset_keys(assets_a)
    keys_b = asset_keys(assets_b)
    added = keys_b - keys_a
    removed = keys_a - keys_b

    def values_of(keys: Set[Tuple[str, str]], type_: str) -> List[str]:
        return sorted({v for t, v in keys if t == type_})

    vuln_by_value_b = {a.value: a for a in assets_b if a.type == "vulnerability"}
    vuln_by_value_a = {a.value: a for a in assets_a if a.type == "vulnerability"}

    added_vuln_values = {v for t, v in added if t == "vulnerability"}
    removed_vuln_values = {v for t, v in removed if t == "vulnerability"}

    return {
        "added_domains": values_of(added, "domain"),
        "removed_domains": values_of(removed, "domain"),
        "added_ips": values_of(added, "ip"),
        "removed_ips": values_of(removed, "ip"),
        "added_ports": values_of(added, "port"),
        "removed_ports": values_of(removed, "port"),
        "added_urls": values_of(added, "url"),
        "removed_urls": values_of(removed, "url"),
        "added_vulns": sorted(
            [vuln_by_value_b[v] for v in added_vuln_values if v in vuln_by_value_b],
            key=_vuln_sort_key,
        ),
        "fixed_vulns": sorted(
            [vuln_by_value_a[v] for v in removed_vuln_values if v in vuln_by_value_a],
            key=_vuln_sort_key,
        ),
    }
