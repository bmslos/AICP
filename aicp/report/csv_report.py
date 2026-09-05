"""CSV 报告生成。

输出扁平化 CSV 文件，便于安全分析师离线处理 (Excel / pandas 等)。
每行一个资产，包含:
- task_id, asset_id, type, value, source, parent_id, status_code, title, technologies, created_at
"""

from __future__ import annotations

import csv
from pathlib import Path
from typing import List

from ..models import Asset, Task
from ..scheduler import Store


# CSV 列定义
_CSV_COLUMNS = [
    "task_id",
    "asset_id",
    "type",
    "value",
    "source",
    "parent_id",
    "status_code",
    "title",
    "technologies",
    "severity",
    "template_id",
    "size",
    "redirect",
    "discovered_at",
]


def generate_csv_rows(task: Task, store: Store) -> List[dict]:
    """生成 CSV 行数据 (字典列表)。

    - task: 任务对象
    - store: 持久化层 (用于读取资产)
    - vulnerability: value 输出为干净的 matched_at, severity/template_id 从 raw 展开
    - directory: size/redirect 从 raw 展开
    """
    assets: List[Asset] = store.list_assets(task.id)
    rows: List[dict] = []
    for a in assets:
        raw = a.raw or {}
        row = {
            "task_id": a.task_id or task.id,
            "asset_id": a.id,
            "type": a.type,
            "value": a.value,
            "source": a.source,
            "parent_id": a.parent_id or "",
            "status_code": a.status_code if a.status_code is not None else "",
            "title": a.title or "",
            "technologies": ";".join(a.technologies) if a.technologies else "",
            "severity": "",
            "template_id": "",
            "size": "",
            "redirect": "",
            "discovered_at": a.discovered_at.isoformat() if a.discovered_at else "",
        }
        if a.type == "vulnerability":
            # value 形如 "url|template_id", 输出干净的 matched_at
            row["value"] = raw.get("matched_at") or a.value.split("|", 1)[0]
            row["severity"] = raw.get("severity", "unknown")
            row["template_id"] = raw.get("template_id", "")
        elif a.type == "directory":
            row["size"] = raw.get("size", "")
            row["redirect"] = raw.get("redirect", "")
        rows.append(row)
    return rows


def write_csv_report(task: Task, store: Store, output_path: str | Path) -> Path:
    """生成 CSV 报告并写入文件。

    使用 utf-8-sig 编码 (带 BOM)，确保 Excel 正确识别中文。
    """
    rows = generate_csv_rows(task, store)
    out = Path(output_path)
    out.parent.mkdir(parents=True, exist_ok=True)

    with open(out, "w", newline="", encoding="utf-8-sig") as f:
        writer = csv.DictWriter(f, fieldnames=_CSV_COLUMNS, extrasaction="ignore")
        writer.writeheader()
        writer.writerows(rows)

    return out
