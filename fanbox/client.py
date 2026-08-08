"""Fanbox 官方 API 封装：分页拉取、帖子详情、二进制下载。"""

import asyncio
import json
from pathlib import Path
from typing import Any, AsyncIterator, Callable

import aiohttp
from astrbot.api import logger

from .models import (
    FanboxPost,
    parse_page_urls,
    parse_post_info,
    parse_post_list,
)
from .rate_limit import (
    CloudflareBlockError,
    RateLimiter,
    classify_http_error,
)

try:  # curl_cffi 为可选依赖：指纹伪装后端（过 Cloudflare）
    from curl_cffi.requests import AsyncSession as CffiAsyncSession
    from curl_cffi.requests.exceptions import RequestException as CffiRequestError
except ImportError:
    CffiAsyncSession = None
    CffiRequestError = ()  # type: ignore[assignment]

_NETWORK_ERRORS: tuple = (aiohttp.ClientError, asyncio.TimeoutError, OSError)
if CffiAsyncSession is not None:
    _NETWORK_ERRORS = _NETWORK_ERRORS + (CffiRequestError,)

API_BASE = "https://api.fanbox.cc"
LIST_PAGE_LIMIT = 300  # 大分页减少请求次数
MAX_429_RETRIES = 4
MAX_CF_CONSECUTIVE = 3  # Cloudflare 连续拦截次数上限
MAX_DOWNLOAD_RETRIES = 5


class FanboxAPIClient:
    """官方 API 客户端，认证头与代理由外部 callable 注入（复用 FanboxHandler）。"""

    def __init__(
        self,
        cookie_getter: Callable[[], str | None],
        ua_getter: Callable[[], str],
        proxy_getter: Callable[[], str | None],
        rate_limiter: RateLimiter | None = None,
        cancel_event: asyncio.Event | None = None,
        api_host: str = "",
        impersonate: str = "",
    ):
        self._cookie_getter = cookie_getter
        self._ua_getter = ua_getter
        self._proxy_getter = proxy_getter
        self._rate_limiter = rate_limiter or RateLimiter()
        self._cancel_event = cancel_event
        # 可选反代 host（复用 pixiv api_proxy_host 同思路，CF Workers 边缘出口过 WAF）
        self._api_base = f"https://{api_host}" if api_host else API_BASE
        # TLS/HTTP2 指纹伪装后端（curl_cffi），如 edge101；空则走 aiohttp
        self._impersonate = impersonate
        self._cffi_session = None
        self._cf_consecutive = 0

    def set_cancel_event(self, event: asyncio.Event):
        """由下载管理器注入取消信号。"""
        self._cancel_event = event

    def _rewrite_url(self, url: str) -> str:
        """API 返回的绝对分页 URL 在反代模式下重写到反代 host。"""
        if self._api_base != API_BASE and url.startswith(API_BASE):
            return self._api_base + url[len(API_BASE):]
        return url

    def _check_cancelled(self):
        if self._cancel_event is not None and self._cancel_event.is_set():
            raise asyncio.CancelledError()

    def _build_headers(self, referer: str) -> dict[str, str]:
        headers = {
            "Accept": "application/json, text/plain, */*",
            "Accept-Language": "ja,en-US;q=0.9,en;q=0.8,zh-CN;q=0.7",
            "Origin": "https://www.fanbox.cc",
            "Referer": referer,
            "Sec-Fetch-Dest": "empty",
            "Sec-Fetch-Mode": "cors",
            "Sec-Fetch-Site": "same-site",
            "User-Agent": self._ua_getter(),
        }
        cookie = self._cookie_getter()
        if cookie:
            headers["Cookie"] = cookie
        return headers

    def _get_cffi_session(self):
        """curl_cffi 会话懒加载（指纹伪装后端）。"""
        if CffiAsyncSession is None:
            raise RuntimeError(
                "配置了 fanbox_dl_impersonate 但未安装 curl_cffi，请 pip install curl_cffi"
            )
        if self._cffi_session is None:
            self._cffi_session = CffiAsyncSession(
                impersonate=self._impersonate, timeout=30
            )
        return self._cffi_session

    async def _raw_get(self, url: str, headers: dict[str, str]):
        """GET 原文请求，返回 (status, text, headers)；按配置选择后端。"""
        proxy = self._proxy_getter()
        if self._impersonate:
            resp = await self._get_cffi_session().get(url, headers=headers, proxy=proxy or None)
            return resp.status_code, resp.text, resp.headers
        timeout = aiohttp.ClientTimeout(total=30)
        async with aiohttp.ClientSession(timeout=timeout) as session:
            async with session.get(url, headers=headers, proxy=proxy) as resp:
                return resp.status, await resp.text(), resp.headers

    async def _get_json(self, url: str, referer: str) -> Any:
        """带限流与 429/Cloudflare 重试的 JSON GET。"""
        last_error: Exception | None = None
        for attempt in range(MAX_429_RETRIES + 1):
            self._check_cancelled()
            await self._rate_limiter.acquire()
            try:
                status, raw, resp_headers = await self._raw_get(
                    url, self._build_headers(referer)
                )
                if status == 429:
                    retry_after = None
                    try:
                        retry_after = float(resp_headers.get("Retry-After", ""))
                    except (TypeError, ValueError):
                        pass
                    last_error = classify_http_error(429, raw)
                    logger.warning(
                        f"Pixiv 插件：Fanbox 429，第 {attempt + 1} 次退避 - {url}"
                    )
                    await self._rate_limiter.backoff_429(attempt, retry_after)
                    continue
                if status != 200:
                    raise classify_http_error(status, raw)
                try:
                    payload = json.loads(raw)
                except Exception as exc:
                    raise CloudflareBlockError(
                        f"Fanbox 返回非 JSON 响应，疑似 Cloudflare 拦截: {raw[:200]}"
                    ) from exc
                self._cf_consecutive = 0
                if isinstance(payload, dict) and payload.get("error"):
                    error = payload["error"]
                    msg = error.get("message") if isinstance(error, dict) else str(error)
                    raise RuntimeError(f"Fanbox API 错误: {msg or error}")
                return payload
            except CloudflareBlockError as exc:
                self._cf_consecutive += 1
                if self._cf_consecutive >= MAX_CF_CONSECUTIVE:
                    raise
                last_error = exc
                logger.warning(
                    f"Pixiv 插件：Fanbox 疑似 Cloudflare 拦截（连续 {self._cf_consecutive} 次），退避重试"
                )
                await self._rate_limiter.backoff_429(attempt)
            except asyncio.CancelledError:
                raise
            except _NETWORK_ERRORS as exc:
                # 网络层失败常见于 Cloudflare 拦截（Failed to fetch / 连接重置）
                self._cf_consecutive += 1
                if self._cf_consecutive >= MAX_CF_CONSECUTIVE:
                    raise CloudflareBlockError(
                        f"连续 {self._cf_consecutive} 次网络失败，疑似 Cloudflare 拦截: {exc}"
                    ) from exc
                last_error = exc
                logger.warning(f"Pixiv 插件：Fanbox 请求网络错误，退避重试 - {exc}")
                await self._rate_limiter.backoff_429(attempt)
        if last_error is not None:
            raise last_error
        raise RuntimeError("Fanbox 请求失败：重试耗尽。")

    async def iter_creator_posts(self, creator_id: str) -> AsyncIterator[FanboxPost]:
        """遍历创作者全部帖子摘要：优先 limit=300 + nextPage，旧格式回退 paginateCreator。"""
        referer = f"https://{creator_id}.fanbox.cc/"
        url = f"{self._api_base}/post.listCreator?creatorId={creator_id}&limit={LIST_PAGE_LIMIT}"
        seen: set[str] = set()

        payload = await self._get_json(url, referer)
        posts, next_page = parse_post_list(payload)
        if next_page is None and not posts:
            # 旧格式回退：paginateCreator 返回 pageUrls 逐页拉取（fanbox-dl 原始路径）
            page_urls = parse_page_urls(
                await self._get_json(
                    f"{self._api_base}/post.paginateCreator?creatorId={creator_id}", referer
                )
            )
            for page_url in page_urls:
                self._check_cancelled()
                page_payload = await self._get_json(self._rewrite_url(page_url), referer)
                page_posts, _ = parse_post_list(page_payload)
                for post in page_posts:
                    if post.id in seen:
                        continue
                    seen.add(post.id)
                    yield post
            return

        while True:
            for post in posts:
                if post.id in seen:
                    continue
                seen.add(post.id)
                yield post
            if not next_page:
                return
            self._check_cancelled()
            payload = await self._get_json(self._rewrite_url(next_page), referer)
            posts, next_page = parse_post_list(payload)

    async def get_post_detail(self, post_id: str) -> FanboxPost | None:
        """post.info：受限或空 body 返回 None。"""
        payload = await self._get_json(
            f"{self._api_base}/post.info?postId={post_id}", "https://www.fanbox.cc/"
        )
        post = parse_post_info(payload)
        if post is None or post.is_restricted:
            return None
        return post

    async def download_asset(
        self,
        url: str,
        dest: Path,
        fallback_url: str | None = None,
        referer: str = "https://www.fanbox.cc/",
    ) -> int:
        """流式下载到 dest，返回字节数；网络错误重试，500 缩略图失败时降级 fallback_url。"""
        headers = self._build_headers(referer)
        headers["Accept"] = "*/*"
        wait = 1.0
        last_error: Exception | None = None
        current_url = url

        for _ in range(MAX_DOWNLOAD_RETRIES):
            self._check_cancelled()
            try:
                status, body_text = await self._raw_download(current_url, headers, dest)
                if status == 500 and body_text == "failed to thumbnailing":
                    # 原图不可用（过大等），降级缩略图，对齐 fanbox-dl
                    if fallback_url:
                        logger.info(
                            f"Pixiv 插件：Fanbox 原图不可用，降级缩略图 - {current_url}"
                        )
                        current_url = fallback_url
                        continue
                    raise RuntimeError("原图不可用（failed to thumbnailing）且无缩略图可降级。")
                if status != 200:
                    raise classify_http_error(status, body_text)
                return dest.stat().st_size
            except asyncio.CancelledError:
                self._remove_partial(dest)
                raise
            except _NETWORK_ERRORS as exc:
                last_error = exc
                self._remove_partial(dest)
                logger.warning(
                    f"Pixiv 插件：Fanbox 下载错误，{wait:.0f}s 后重试 - {current_url} - {exc}"
                )
                await asyncio.sleep(wait)
                wait = min(wait * 2, 30.0)

        self._remove_partial(dest)
        raise RuntimeError(f"下载失败（重试 {MAX_DOWNLOAD_RETRIES} 次）: {last_error}")

    async def _raw_download(self, url: str, headers: dict[str, str], dest: Path):
        """流式 GET：200 时写盘，返回 (status, 非200时的响应文本)。"""
        proxy = self._proxy_getter()
        if self._impersonate:
            session = self._get_cffi_session()
            resp = await session.get(url, headers=headers, proxy=proxy or None, stream=True)
            try:
                if resp.status_code != 200:
                    return resp.status_code, resp.text
                with open(dest, "wb") as fp:
                    async for chunk in resp.aiter_content(64 * 1024):
                        self._check_cancelled()
                        fp.write(chunk)
                return 200, ""
            finally:
                await resp.aclose()
        timeout = aiohttp.ClientTimeout(total=300, connect=15)
        async with aiohttp.ClientSession(timeout=timeout) as session:
            async with session.get(url, headers=headers, proxy=proxy) as resp:
                if resp.status != 200:
                    return resp.status, await resp.text()
                with open(dest, "wb") as fp:
                    async for chunk in resp.content.iter_chunked(64 * 1024):
                        self._check_cancelled()
                        fp.write(chunk)
                return 200, ""

    @staticmethod
    def _remove_partial(dest: Path):
        """删除中断产生的残文件。"""
        try:
            if dest.exists():
                dest.unlink()
        except OSError:
            pass
