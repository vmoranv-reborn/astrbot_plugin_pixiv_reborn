"""Fanbox 处理器公共状态与解析辅助。"""

import os
import re
from pathlib import Path
from typing import Any

import aiohttp

from ..fanbox.headers import build_html_headers
from ..fanbox.downloader import FanboxDownloadManager
from ..infra.help import get_help_message
from ..infra.paths import get_plugin_data_dir


class FanboxCommonMixin:
    """共享常量、配置读取、creatorId 解析与下载管理器。"""

    API_BASE = "https://api.fanbox.cc"

    NEKOHOUSE_BASE = "https://nekohouse.su"

    DEFAULT_BROWSER_UA = (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
        "AppleWebKit/537.36 (KHTML, like Gecko) "
        "Chrome/131.0.0.0 Safari/537.36"
    )

    FANBOX_DOMAIN_RE = re.compile(
        r"https?://([a-zA-Z0-9][a-zA-Z0-9_-]*)\.fanbox\.cc", re.IGNORECASE
    )

    PIXIV_CREATOR_RE = re.compile(r"pixiv\.net/fanbox/creator/(\d+)", re.IGNORECASE)

    PIXIV_POST_WITH_USER_RE = re.compile(
        r"pixiv\.net/fanbox/creator/(\d+)/post/(\d+)", re.IGNORECASE
    )

    PIXIV_POST_RE = re.compile(
        r"pixiv\.net/fanbox/creator/\d+/post/(\d+)", re.IGNORECASE
    )

    FANBOX_POST_RE = re.compile(
        r"https?://[a-zA-Z0-9][a-zA-Z0-9_-]*\.fanbox\.cc/posts/(\d+)",
        re.IGNORECASE,
    )

    NEKOHOUSE_USER_RE = re.compile(r"nekohouse\.su/fanbox/user/(\d+)", re.IGNORECASE)

    NEKOHOUSE_POST_RE = re.compile(
        r"nekohouse\.su/fanbox/user/(\d+)/post/(\d+)",
        re.IGNORECASE,
    )

    IMAGE_SUFFIXES = {".jpg", ".jpeg", ".png", ".gif", ".webp", ".bmp"}

    def __init__(
        self,
        pixiv_config,
        context=None,
        data_dir: Path | None = None,
        temp_dir: Path | None = None,
    ):
        self.pixiv_config = pixiv_config
        self.context = context
        self.temp_dir = temp_dir
        self._nekohouse_creators_cache: list[dict[str, Any]] | None = None
        # 批量下载管理器（数据目录缺省时用到再惰性创建）
        self._dl_manager = self._new_dl_manager(data_dir) if data_dir else None

    def _new_dl_manager(self, data_dir: Path) -> FanboxDownloadManager:
        """按 config 策略参数创建下载管理器。"""
        cfg = self.pixiv_config
        return FanboxDownloadManager(
            data_dir,
            concurrency=getattr(cfg, "fanbox_dl_concurrency", 4),
            prefetch_queue=getattr(cfg, "fanbox_dl_prefetch_queue", 4),
        )

    def dl_manager(self) -> FanboxDownloadManager:
        if self._dl_manager is None:
            self._dl_manager = self._new_dl_manager(get_plugin_data_dir())
        return self._dl_manager

    def _missing_sessid_help(self) -> str:
        return get_help_message(
            "pixiv_fanbox_sessid_missing",
            "当前未配置 fanbox_sessid（FANBOXSESSID），可能无法访问受限 Fanbox 内容。",
        )

    def _fanbox_data_source(self) -> str:
        mode = (
            str(getattr(self.pixiv_config, "fanbox_data_source", "auto") or "auto")
            .strip()
            .lower()
        )
        if mode not in {"auto", "official", "nekohouse"}:
            return "auto"
        return mode

    def _get_proxy(self) -> str | None:
        if self.pixiv_config.proxy:
            proxy = self.pixiv_config.proxy.strip()
            if proxy:
                return proxy

        # 兼容系统级代理环境变量
        for key in ("HTTPS_PROXY", "https_proxy", "HTTP_PROXY", "http_proxy"):
            value = os.getenv(key, "").strip()
            if value:
                return value
        return None

    def _fanbox_user_agent(self) -> str:
        ua = str(getattr(self.pixiv_config, "fanbox_user_agent", "") or "").strip()
        return ua or self.DEFAULT_BROWSER_UA

    def _fanbox_cookie_header(self) -> str | None:
        sessid = str(getattr(self.pixiv_config, "fanbox_sessid", "") or "").strip()
        cf_clearance = str(
            getattr(self.pixiv_config, "fanbox_cf_clearance", "") or ""
        ).strip()

        pairs = []
        if sessid:
            pairs.append(f"FANBOXSESSID={sessid}")
        if cf_clearance:
            pairs.append(f"cf_clearance={cf_clearance}")
        return "; ".join(pairs) if pairs else None

    async def _resolve_creator_id_from_user_id(self, user_id: str) -> str:
        url = f"https://www.pixiv.net/fanbox/creator/{user_id}"
        headers = build_html_headers(
            self._fanbox_user_agent(), referer="https://www.pixiv.net/"
        )

        timeout = aiohttp.ClientTimeout(total=20)
        async with aiohttp.ClientSession(timeout=timeout) as session:
            async with session.get(
                url, headers=headers, proxy=self._get_proxy()
            ) as resp:
                html = await resp.text()
                if resp.status != 200:
                    raise RuntimeError(
                        f"无法从 Pixiv 页面解析 creatorId，HTTP {resp.status}"
                    )

        canonical_match = re.search(
            r'rel=["\']canonical["\'][^>]+href=["\']https://([a-zA-Z0-9][a-zA-Z0-9_-]*)\.fanbox\.cc/?["\']',
            html,
            re.IGNORECASE,
        )
        if canonical_match:
            return canonical_match.group(1)

        match = self.FANBOX_DOMAIN_RE.search(html)
        if not match:
            raise RuntimeError(
                "未能从 Pixiv Fanbox 页面中解析 creatorId，请直接使用 creatorId（如 harusono）"
            )
        return match.group(1)

    async def _resolve_creator_id(self, creator_input: str) -> str:
        text = creator_input.strip()
        if not text:
            raise RuntimeError("creator 参数不能为空")

        domain_match = self.FANBOX_DOMAIN_RE.search(text)
        if domain_match:
            return domain_match.group(1)

        pixiv_creator_match = self.PIXIV_CREATOR_RE.search(text)
        if pixiv_creator_match:
            return await self._resolve_creator_id_from_user_id(
                pixiv_creator_match.group(1)
            )

        if text.isdigit():
            return await self._resolve_creator_id_from_user_id(text)

        return text
