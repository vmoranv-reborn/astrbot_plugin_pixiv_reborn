"""可复用的 Pixiv 搜索编排（分页 + 热度排序）。"""

from __future__ import annotations

import asyncio
from typing import Any, Awaitable, Callable

from astrbot.api import logger

SearchFunc = Callable[..., Awaitable[Any]]


async def search_popular_illusts(
    search_func: SearchFunc,
    tags: str,
    *,
    duration: str | None = "within_last_week",
    pages: int = 5,
    parse_next_url: Callable[[str], dict[str, Any] | None],
    page_delay: float = 0.3,
) -> list[Any]:
    """按时间范围分页抓取，并按收藏数降序返回作品列表。"""

    all_illusts: list[Any] = []
    next_params: dict[str, Any] | None = None
    page_count = 0

    while page_count < pages:
        try:
            if page_count == 0:
                kwargs: dict[str, Any] = {
                    "word": tags,
                    "search_target": "partial_match_for_tags",
                    "sort": "date_desc",
                    "filter": "for_ios",
                }
                if duration:
                    kwargs["duration"] = duration
            else:
                if not next_params:
                    break
                kwargs = next_params

            result = await search_func(**kwargs)
            if not result or not hasattr(result, "illusts"):
                break

            current = result.illusts
            if not current:
                break

            all_illusts.extend(current)
            page_count += 1
            logger.info(f"热度搜索：已获取第 {page_count} 页，本页 {len(current)} 个")

            next_url = getattr(result, "next_url", None)
            if not next_url:
                break
            next_params = parse_next_url(next_url)
            await asyncio.sleep(page_delay)

        except Exception as exc:
            logger.error(f"热度搜索第 {page_count + 1} 页出错: {exc}")
            break

    return sorted(
        all_illusts,
        key=lambda item: getattr(item, "total_bookmarks", 0),
        reverse=True,
    )
