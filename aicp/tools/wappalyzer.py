"""Wappalyzer 适配器 - Web 指纹增强。

调用 python-Wappalyzer (pip install python-Wappalyzer) 对上游 url 资产做
详细指纹识别，补充 web_service 的 technologies 字段。

设计要点：
- Wappalyzer 是 Python 库而非 CLI，所以不用 ProcessRunner，而是注入
  `analyzer` 可调用对象 (url -> 指纹 dict)，便于测试 mock；
- 输入: type=url 资产；
- 输出: type=web_service 资产 (source=wappalyzer，含完整 technologies)，
  与 httpx 产出的 web_service 并存，由 correlate 阶段合并去重；
- 并发: 用 ThreadPoolExecutor 并发分析 (I/O 密集)，max_workers 可配；
- 单个 url 分析失败不中断整批，记录到 errors。
"""

from __future__ import annotations

from typing import Callable, List, Optional

from ..auth import AuthorizationVerifier
from ..models import Asset, StageName
from .base import Tool, ToolContext, ToolResult, ToolError


# 指纹分析器接口: url -> {"technologies": [...], "version": {...}, "categories": {...}}
Analyzer = Callable[[str], dict]


class WappalyzerTool(Tool):
    """Wappalyzer Web 指纹识别适配器。"""

    name = "wappalyzer"
    stage = StageName.FINGERPRINT
    input_asset_types = ("url",)
    output_asset_types = ("web_service",)

    def __init__(self, *, analyzer: Analyzer, max_workers: int = 8):
        """
        - analyzer: 指纹分析器 (生产环境用 default_analyzer_factory()，
                    测试用 mock)
        - max_workers: 并发分析线程数 (I/O 密集, 默认 8; 测试传 1 保证确定性)
        """
        self._analyzer = analyzer
        self._max_workers = max_workers
        self._verifier = AuthorizationVerifier()

    def run(self, inputs: List[Asset], ctx: ToolContext) -> ToolResult:
        urls = [a for a in inputs if a.type == "url"]
        if not urls:
            return ToolResult(stats={"input_urls": 0})

        # 授权范围过滤
        in_scope_urls, out_of_scope = self._verifier.filter_in_scope(
            [a.value for a in urls], ctx.authorized_scope
        )
        in_scope_set = set(in_scope_urls)
        targets = [u for u in urls if u.value in in_scope_set]

        assets: List[Asset] = []
        errors: List[str] = []

        def analyze_one(url_asset: Asset) -> Optional[Asset]:
            """单个 url 分析; 失败记录错误并返回 None (不中断整批)。

            整个函数体包进 try (审计 5.1): analyzer 返回非 dict (如 None) 时,
            `result.get` 会抛 AttributeError, 若只包住 analyzer 调用, 该异常会
            经 `fut.result()` 重新抛出炸掉整个 FINGERPRINT 阶段。
            """
            try:
                result = self._analyzer(url_asset.value)
                if not isinstance(result, dict):
                    raise TypeError(
                        f"analyzer 返回类型非法: {type(result).__name__}"
                    )
                techs = list(result.get("technologies", []) or [])
                versions = result.get("versions", {}) or {}
                return Asset(
                    type="web_service",
                    value=url_asset.value,
                    source="wappalyzer",
                    task_id=ctx.task_id,
                    parent_id=url_asset.id,
                    technologies=techs,
                    status_code=url_asset.raw.get("status_code") if url_asset.raw else None,
                    raw={
                        "tool": "wappalyzer",
                        "technologies": techs,
                        "versions": versions,
                    },
                )
            except Exception as e:
                errors.append(f"{url_asset.value}: {e}")
                return None

        if self._max_workers <= 1 or len(targets) <= 1:
            # 串行路径 (确定性, 测试/小批量用)
            for url_asset in targets:
                asset = analyze_one(url_asset)
                if asset:
                    assets.append(asset)
        else:
            # 并发路径: ThreadPoolExecutor (I/O 密集, 线程即可)
            from concurrent.futures import ThreadPoolExecutor, as_completed

            with ThreadPoolExecutor(max_workers=self._max_workers) as pool:
                futures = {pool.submit(analyze_one, u): u for u in targets}
                for fut in as_completed(futures):
                    asset = fut.result()  # analyze_one 内部已捕获异常
                    if asset:
                        assets.append(asset)

        raw = "\n".join(errors) if errors else ""
        return ToolResult(
            assets=assets,
            raw_output=raw,
            stats={
                "input_urls": len(urls),
                "analyzed": len(assets),
                "errors": len(errors),
                "skipped_out_of_scope": len(out_of_scope),
            },
        )


def default_analyzer_factory() -> Analyzer:
    """生产环境默认 analyzer 工厂。

    使用 python-Wappalyzer，若未安装则抛 ToolError 提示安装。

    返回的 analyzer 统一输出格式:
        {"technologies": [str, ...], "versions": {tech: [str, ...]}, "categories": {tech: [str, ...]}}

    注意: python-Wappalyzer 0.3.x 的 WebPage.new_from_url 内部用 requests.get
    但不设超时, 且无法传入 session。这里改为自行用 requests.Session 请求
    (显式 30s 超时), 再手工构造 WebPage 对象——每个调用独立 Session,
    彻底去掉早期"monkey-patch requests.get"的全局竞态 (P0-3)。
    analyzer 内异常由调用方 (WappalyzerTool.run) 的 analyze_one 隔离到单 url。
    """
    try:
        from Wappalyzer import Wappalyzer, WebPage
    except ImportError as e:
        raise ToolError(
            "未安装 python-Wappalyzer，请运行: pip install python-Wappalyzer"
        ) from e

    import requests

    wapp = Wappalyzer.latest()

    def _analyze(url: str) -> dict:
        # 每个调用独立 Session (线程安全), 显式超时
        session = requests.Session()
        session.headers.update({"User-Agent": "Mozilla/5.0 (AICP Web Fingerprint)"})
        response = session.get(url, timeout=30)
        response.raise_for_status()
        webpage = WebPage(url=url, html=response.text, headers=response.headers)
        # analyze_with_versions_and_categories 返回 {tech_name: {"versions": [...], "categories": [...]}}
        raw = wapp.analyze_with_versions_and_categories(webpage)
        techs = list(raw.keys())
        versions = {t: v.get("versions", []) for t, v in raw.items()}
        categories = {t: v.get("categories", []) for t, v in raw.items()}
        return {
            "technologies": techs,
            "versions": versions,
            "categories": categories,
        }

    return _analyze
