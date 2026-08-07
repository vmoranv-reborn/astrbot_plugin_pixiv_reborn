"""Fanbox 请求限流与错误分类。"""

import asyncio
import random
import time


class CookieInvalidError(Exception):
    """401/403：FANBOXSESSID 或 cf_clearance 失效，需用户更新。"""


class CloudflareBlockError(Exception):
    """Cloudflare 拦截：返回非 JSON 挑战页或连接被重置。"""


class RateLimitError(Exception):
    """429 重试耗尽。"""


class RateLimiter:
    """串行间隔限流：列表/详情请求 1.2s + 0~0.6s 抖动。"""

    def __init__(self, base_interval: float = 1.2, jitter: float = 0.6):
        self.base_interval = base_interval
        self.jitter = jitter
        self._lock = asyncio.Lock()
        self._last_request_at = 0.0

    async def acquire(self):
        """等待到距上次请求满足间隔后放行。"""
        async with self._lock:
            now = time.monotonic()
            wait = self.base_interval + random.uniform(0, self.jitter) - (
                now - self._last_request_at
            )
            if wait > 0:
                await asyncio.sleep(wait)
            self._last_request_at = time.monotonic()

    async def backoff_429(self, attempt: int, retry_after: float | None = None):
        """429 退避：优先 Retry-After，否则 45s 起步指数退避（45→90→180）。"""
        delay = retry_after if retry_after and retry_after > 0 else 45.0 * (2 ** attempt)
        await asyncio.sleep(delay)


def classify_http_error(status: int, raw_body: str) -> Exception:
    """按状态码与响应体分类错误。"""
    if status in (401, 403):
        return CookieInvalidError(
            f"HTTP {status}：Cookie 失效或权限不足，请更新 fanbox_sessid（FANBOXSESSID）"
            "与 fanbox_cookie（含 cf_clearance）后重试。"
        )
    if status == 429:
        return RateLimitError("HTTP 429：请求过于频繁。")
    snippet = (raw_body or "")[:200].lower()
    if "<html" in snippet or "cloudflare" in snippet or "attention required" in snippet:
        return CloudflareBlockError(
            f"HTTP {status}：疑似被 Cloudflare 拦截，建议配置 fanbox_cookie"
            "（含 cf_clearance）与浏览器一致的 fanbox_user_agent。"
        )
    return RuntimeError(f"HTTP {status}: {(raw_body or '')[:200]}")
