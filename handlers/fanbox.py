import re
import os
import html as html_lib
from typing import Any
from urllib.parse import urljoin

import aiohttp
from astrbot.api import logger
from astrbot.api.event import AstrMessageEvent
import astrbot.api.message_components as Comp

from ..utils.help import get_help_message
from ..utils.pixiv_utils import (
    download_image,
    _build_image_from_bytes,
    _build_image_from_url,
)


class FanboxHandler:
    """Pixiv Fanbox 功能处理器。"""

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

    def __init__(self, pixiv_config):
        self.pixiv_config = pixiv_config
        self._nekohouse_creators_cache: list[dict[str, Any]] | None = None

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
        raw_cookie = str(getattr(self.pixiv_config, "fanbox_cookie", "") or "").strip()
        sessid = str(getattr(self.pixiv_config, "fanbox_sessid", "") or "").strip()

        if raw_cookie:
            cookie = raw_cookie.rstrip(";").strip()
            if sessid and "FANBOXSESSID=" not in cookie:
                cookie = f"{cookie}; FANBOXSESSID={sessid}"
            return cookie

        if sessid:
            return f"FANBOXSESSID={sessid}"

        return None

    async def _fetch_text_url(
        self,
        url: str,
        referer: str | None = None,
        timeout_seconds: int = 20,
    ) -> str:
        headers = {
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "Accept-Language": "ja,en-US;q=0.9,en;q=0.8,zh-CN;q=0.7",
            "User-Agent": self._fanbox_user_agent(),
        }
        if referer:
            headers["Referer"] = referer
        if "fanbox.cc" in url.lower():
            cookie = self._fanbox_cookie_header()
            if cookie:
                headers["Cookie"] = cookie

        timeout = aiohttp.ClientTimeout(total=timeout_seconds)
        async with aiohttp.ClientSession(timeout=timeout) as session:
            async with session.get(
                url, headers=headers, proxy=self._get_proxy()
            ) as resp:
                raw = await resp.text()
                if resp.status != 200:
                    short_raw = raw[:240].replace("\n", " ").replace("\r", " ")
                    raise RuntimeError(f"HTTP {resp.status}: {short_raw}")
                return raw

    async def _fetch_nekohouse_json(self, path: str) -> Any:
        url = f"{self.NEKOHOUSE_BASE}{path}"
        headers = {
            "Accept": "application/json, text/plain, */*",
            "Referer": self.NEKOHOUSE_BASE + "/",
            "User-Agent": self._fanbox_user_agent(),
        }
        timeout = aiohttp.ClientTimeout(total=20)
        async with aiohttp.ClientSession(timeout=timeout) as session:
            async with session.get(
                url, headers=headers, proxy=self._get_proxy()
            ) as resp:
                raw = await resp.text()
                if resp.status != 200:
                    short_raw = raw[:240].replace("\n", " ").replace("\r", " ")
                    raise RuntimeError(f"HTTP {resp.status}: {short_raw}")
                try:
                    return await resp.json(content_type=None)
                except Exception as exc:
                    short_raw = raw[:240].replace("\n", " ").replace("\r", " ")
                    raise RuntimeError(
                        f"Nekohouse 返回非 JSON 响应: {short_raw}"
                    ) from exc

    @staticmethod
    def _strip_html_tags(text: str) -> str:
        cleaned = re.sub(r"<[^>]+>", " ", text)
        cleaned = html_lib.unescape(cleaned)
        cleaned = cleaned.replace("\r", " ").replace("\n", " ")
        cleaned = re.sub(r"\s+", " ", cleaned).strip()
        return cleaned

    def _to_abs_nekohouse_url(self, url_or_path: str) -> str:
        return urljoin(self.NEKOHOUSE_BASE + "/", url_or_path)

    @staticmethod
    def _guess_image_ext(url: str) -> str:
        path = url.split("?", 1)[0].split("#", 1)[0].lower()
        for ext in (".jpg", ".jpeg", ".png", ".gif", ".webp", ".bmp"):
            if path.endswith(ext):
                return ext
        return ".jpg"

    async def _emit_post_message_with_images(
        self,
        event: AstrMessageEvent,
        text_message: str,
        images: list[str],
        referer: str,
        max_images: int = 10,
    ):
        target_images = (images or [])[:max_images]
        failed_urls: list[str] = []
        image_components: list[Any] = []
        include_details = bool(getattr(self.pixiv_config, "show_details", True))

        # url 模式无需下载，直接构建 URL 图片组件
        if (
            target_images
            and getattr(self.pixiv_config, "image_send_method", "url") == "url"
        ):
            for url in target_images:
                try:
                    img_comp = _build_image_from_url(url)
                    if img_comp is None:
                        failed_urls.append(url)
                        continue
                    image_components.append(img_comp)
                except Exception as e:
                    logger.warning(f"Pixiv 插件：Fanbox URL 发图失败 - {url} - {e}")
                    failed_urls.append(url)
        elif target_images:
            timeout = aiohttp.ClientTimeout(total=60, connect=15, sock_read=45)
            async with aiohttp.ClientSession(timeout=timeout) as session:
                for url in target_images:
                    try:
                        img_data = await download_image(
                            session, url, headers={"Referer": referer}
                        )
                        if not img_data:
                            failed_urls.append(url)
                            continue
                        ext = self._guess_image_ext(url)
                        img_comp = await _build_image_from_bytes(img_data, ext=ext)
                        image_components.append(img_comp)
                    except Exception as e:
                        logger.warning(f"Pixiv 插件：Fanbox 下载发图失败 - {url} - {e}")
                        failed_urls.append(url)

        message_tail = text_message
        if failed_urls:
            preview = "\n".join(failed_urls[:3])
            more = ""
            if len(failed_urls) > 3:
                more = f"\n... 还有 {len(failed_urls) - 3} 张发送失败"
            message_tail += (
                f"\n\n部分图片发送失败（{len(failed_urls)}/{len(target_images)}）:\n"
                f"{preview}{more}"
            )

        if image_components:
            if include_details or failed_urls:
                yield event.chain_result([*image_components, Comp.Plain(message_tail)])
            else:
                # 纯图片模式：仅发送图片组件，不附加文本
                yield event.chain_result([*image_components])
            return

        yield event.plain_result(message_tail)

    @staticmethod
    def _normalize_creator_token(value: str) -> str:
        return re.sub(r"[^a-z0-9]", "", value.lower())

    async def _get_nekohouse_creators(self) -> list[dict[str, Any]]:
        if self._nekohouse_creators_cache is not None:
            return self._nekohouse_creators_cache

        creators = await self._fetch_nekohouse_json("/api/creators")
        if not isinstance(creators, list):
            raise RuntimeError("Nekohouse creators 响应格式异常。")

        self._nekohouse_creators_cache = [x for x in creators if isinstance(x, dict)]
        return self._nekohouse_creators_cache

    async def _search_nekohouse_fanbox_artists(
        self, keyword: str = "", limit: int = 10
    ) -> list[dict[str, Any]]:
        creators = await self._get_nekohouse_creators()
        matched: list[dict[str, Any]] = []
        kw = keyword.strip().lower()
        normalized_kw = self._normalize_creator_token(kw)

        for creator in creators:
            if creator.get("service") != "fanbox":
                continue

            user_id = str(creator.get("user_id", "")).strip()
            if not user_id.isdigit():
                continue

            name = str(creator.get("name", "")).strip()
            name_lower = name.lower()
            name_normalized = self._normalize_creator_token(name)

            if kw:
                hit = (
                    kw in name_lower
                    or kw in user_id
                    or (normalized_kw and normalized_kw in name_normalized)
                )
                if not hit:
                    continue

            try:
                favorites = int(creator.get("favorites", 0) or 0)
            except Exception:
                favorites = 0

            item = dict(creator)
            item["_name_lower"] = name_lower
            item["_name_normalized"] = name_normalized
            item["_favorites"] = favorites
            matched.append(item)

        if kw:

            def _rank(item: dict[str, Any]) -> tuple[int, int, int, str]:
                name_lower = str(item.get("_name_lower", ""))
                user_id = str(item.get("user_id", ""))
                name_normalized = str(item.get("_name_normalized", ""))
                exact = (
                    (name_lower == kw)
                    or (user_id == kw)
                    or (normalized_kw and name_normalized == normalized_kw)
                )
                prefix = (
                    name_lower.startswith(kw)
                    or user_id.startswith(kw)
                    or (normalized_kw and name_normalized.startswith(normalized_kw))
                )
                return (
                    0 if exact else 1,
                    0 if prefix else 1,
                    -int(item.get("_favorites", 0) or 0),
                    name_lower,
                )

            matched.sort(key=_rank)
        else:
            matched.sort(
                key=lambda x: (
                    -int(x.get("_favorites", 0) or 0),
                    str(x.get("_name_lower", "")),
                )
            )

        final_limit = max(1, min(limit, 50))
        trimmed = matched[:final_limit]

        for item in trimmed:
            item.pop("_name_lower", None)
            item.pop("_name_normalized", None)
            item.pop("_favorites", None)
        return trimmed

    async def _build_nekohouse_artist_search_message(
        self, keyword: str, limit: int
    ) -> str:
        query = keyword.strip()
        results = await self._search_nekohouse_fanbox_artists(query, limit)

        lines = ["# Nekohouse Fanbox 创作者搜索", ""]
        lines.append(f"关键词: {query or '（空，按热度列出）'}")
        lines.append(
            f"数据源: {self.NEKOHOUSE_BASE}/artists（前端） + {self.NEKOHOUSE_BASE}/api/creators（实际数据）"
        )
        lines.append(f"结果: {len(results)} 条")

        if not results:
            lines.append("")
            lines.append("未找到匹配创作者。可尝试：")
            lines.append("- 缩短关键词（如只输入前缀）")
            lines.append("- 直接用 Pixiv userId")
            lines.append("- 直接贴 `https://xxx.fanbox.cc/` 域名")
            return "\n".join(lines)

        domain_re = re.compile(r"^[a-zA-Z0-9][a-zA-Z0-9_-]*$")
        lines.append("")
        for i, creator in enumerate(results, start=1):
            name = str(creator.get("name", "未知")).strip() or "未知"
            user_id = str(creator.get("user_id", "未知")).strip() or "未知"
            favorites = int(creator.get("favorites", 0) or 0)
            lines.append(f"{i}. {name} | userId={user_id} | 收藏 {favorites}")

            if domain_re.match(name):
                lines.append(f"   https://{name}.fanbox.cc/")
            if user_id.isdigit():
                lines.append(f"   {self.NEKOHOUSE_BASE}/fanbox/user/{user_id}")
                lines.append(f"   https://www.pixiv.net/fanbox/creator/{user_id}")

        return "\n".join(lines)

    async def _resolve_user_id_from_nekohouse_creator_id(
        self, creator_id: str
    ) -> str | None:
        cid = creator_id.strip().lower()
        if not cid:
            return None

        creators = await self._get_nekohouse_creators()
        fanbox_creators = [x for x in creators if x.get("service") == "fanbox"]

        # 优先 exact 匹配 name（Nekohouse 的 fanbox creatorId 一般存放在 name 字段）
        for creator in fanbox_creators:
            name = str(creator.get("name", "")).strip().lower()
            user_id = str(creator.get("user_id", "")).strip()
            if name == cid and user_id.isdigit():
                return user_id

        # 再做一次归一化匹配（兼容 -/_/. 差异）
        normalized_cid = self._normalize_creator_token(cid)
        if not normalized_cid:
            return None

        for creator in fanbox_creators:
            name = str(creator.get("name", "")).strip()
            user_id = str(creator.get("user_id", "")).strip()
            if not user_id.isdigit():
                continue
            if self._normalize_creator_token(name) == normalized_cid:
                return user_id

        return None

    def _extract_user_id_from_input(self, text: str) -> str | None:
        raw = text.strip()
        if raw.isdigit():
            return raw

        pixiv_creator_match = self.PIXIV_CREATOR_RE.search(raw)
        if pixiv_creator_match:
            return pixiv_creator_match.group(1)

        pixiv_post_match = self.PIXIV_POST_WITH_USER_RE.search(raw)
        if pixiv_post_match:
            return pixiv_post_match.group(1)

        neko_user_match = self.NEKOHOUSE_USER_RE.search(raw)
        if neko_user_match:
            return neko_user_match.group(1)

        neko_post_match = self.NEKOHOUSE_POST_RE.search(raw)
        if neko_post_match:
            return neko_post_match.group(1)

        return None

    def _extract_post_and_user_id(self, text: str) -> tuple[str, str | None]:
        raw = text.strip()
        if raw.isdigit():
            return raw, None

        pixiv_post_match = self.PIXIV_POST_WITH_USER_RE.search(raw)
        if pixiv_post_match:
            return pixiv_post_match.group(2), pixiv_post_match.group(1)

        neko_post_match = self.NEKOHOUSE_POST_RE.search(raw)
        if neko_post_match:
            return neko_post_match.group(2), neko_post_match.group(1)

        fanbox_post_match = self.FANBOX_POST_RE.search(raw)
        if fanbox_post_match:
            return fanbox_post_match.group(1), None

        pixiv_post_short_match = self.PIXIV_POST_RE.search(raw)
        if pixiv_post_short_match:
            return pixiv_post_short_match.group(1), None

        return raw, None

    async def _fetch_json(
        self,
        endpoint: str,
        params: dict[str, Any] | None = None,
        referer: str = "https://www.fanbox.cc/",
    ) -> Any:
        url = f"{self.API_BASE}/{endpoint}"
        headers = {
            "Accept": "application/json, text/plain, */*",
            "Accept-Language": "ja,en-US;q=0.9,en;q=0.8,zh-CN;q=0.7",
            "Origin": "https://www.fanbox.cc",
            "Referer": referer,
            "Sec-Fetch-Dest": "empty",
            "Sec-Fetch-Mode": "cors",
            "Sec-Fetch-Site": "same-site",
            "User-Agent": self._fanbox_user_agent(),
        }
        cookie = self._fanbox_cookie_header()
        if cookie:
            headers["Cookie"] = cookie

        timeout = aiohttp.ClientTimeout(total=20)
        async with aiohttp.ClientSession(timeout=timeout) as session:
            async with session.get(
                url, params=params, headers=headers, proxy=self._get_proxy()
            ) as resp:
                raw = await resp.text()
                if resp.status != 200:
                    short_raw = raw[:240].replace("\n", " ").replace("\r", " ")
                    raise RuntimeError(f"HTTP {resp.status}: {short_raw}")

                try:
                    payload = await resp.json(content_type=None)
                except Exception as exc:
                    short_raw = raw[:240].replace("\n", " ").replace("\r", " ")
                    raise RuntimeError(f"Fanbox 返回非 JSON 响应: {short_raw}") from exc

        if isinstance(payload, dict) and payload.get("error"):
            error = payload.get("error")
            if isinstance(error, dict):
                msg = error.get("message") or str(error)
            else:
                msg = str(error)
            raise RuntimeError(f"Fanbox API 错误: {msg}")

        if isinstance(payload, dict):
            return payload.get("body")
        return payload

    async def _resolve_creator_id_from_user_id(self, user_id: str) -> str:
        url = f"https://www.pixiv.net/fanbox/creator/{user_id}"
        headers = {
            "Referer": "https://www.pixiv.net/",
            "Accept-Language": "ja,en-US;q=0.9,en;q=0.8,zh-CN;q=0.7",
            "User-Agent": self._fanbox_user_agent(),
        }

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

    def _extract_post_id(self, text: str) -> str:
        post_id, _ = self._extract_post_and_user_id(text)
        return post_id

    @staticmethod
    def _truncate(text: str | None, length: int = 140) -> str:
        if not text:
            return ""
        txt = str(text).replace("\r", " ").replace("\n", " ").strip()
        if len(txt) <= length:
            return txt
        return txt[: length - 1] + "…"

    @staticmethod
    def _extract_post_list(posts_payload: Any) -> list[dict[str, Any]]:
        if isinstance(posts_payload, list):
            return [x for x in posts_payload if isinstance(x, dict)]
        if isinstance(posts_payload, dict):
            for key in ("items", "posts"):
                value = posts_payload.get(key)
                if isinstance(value, list):
                    return [x for x in value if isinstance(x, dict)]
        return []

    @staticmethod
    def _extract_post_media(post: dict[str, Any]) -> tuple[list[str], list[str]]:
        body = post.get("body")
        images: list[str] = []
        files: list[str] = []
        if not isinstance(body, dict):
            return images, files

        image_list = body.get("images")
        if isinstance(image_list, list):
            for img in image_list:
                if not isinstance(img, dict):
                    continue
                img_url = img.get("originalUrl") or img.get("thumbnailUrl")
                if isinstance(img_url, str):
                    images.append(img_url)

        file_list = body.get("files")
        if isinstance(file_list, list):
            for item in file_list:
                if not isinstance(item, dict):
                    continue
                file_url = item.get("url")
                if isinstance(file_url, str):
                    files.append(file_url)

        image_map = body.get("imageMap")
        if isinstance(image_map, dict):
            for item in image_map.values():
                if not isinstance(item, dict):
                    continue
                img_url = item.get("originalUrl") or item.get("thumbnailUrl")
                if isinstance(img_url, str):
                    images.append(img_url)

        file_map = body.get("fileMap")
        if isinstance(file_map, dict):
            for item in file_map.values():
                if not isinstance(item, dict):
                    continue
                file_url = item.get("url")
                if isinstance(file_url, str):
                    files.append(file_url)

        # 去重并保持顺序
        images = list(dict.fromkeys(images))
        files = list(dict.fromkeys(files))
        return images, files

    @staticmethod
    def _extract_post_text_preview(post: dict[str, Any]) -> str:
        body = post.get("body")
        if not isinstance(body, dict):
            return ""

        if isinstance(body.get("text"), str):
            return body["text"]

        blocks = body.get("blocks")
        if isinstance(blocks, list):
            texts = []
            for block in blocks:
                if not isinstance(block, dict):
                    continue
                text = block.get("text")
                if isinstance(text, str) and text.strip():
                    texts.append(text.strip())
            if texts:
                return "\n".join(texts)

        if isinstance(post.get("excerpt"), str):
            return post["excerpt"]

        return ""

    @staticmethod
    def _extract_post_cover_url(post: dict[str, Any]) -> str:
        """提取帖子封面链接，按常见字段优先级回退。"""
        cover = post.get("cover")
        if isinstance(cover, dict):
            for key in ("url", "thumbnailUrl"):
                value = cover.get(key)
                if isinstance(value, str) and value.strip():
                    return value

        for key in ("coverImageUrl", "imageForShare", "thumbnailUrl"):
            value = post.get(key)
            if isinstance(value, str) and value.strip():
                return value

        body = post.get("body")
        if isinstance(body, dict):
            image_list = body.get("images")
            if isinstance(image_list, list):
                for img in image_list:
                    if not isinstance(img, dict):
                        continue
                    img_url = img.get("originalUrl") or img.get("thumbnailUrl")
                    if isinstance(img_url, str) and img_url.strip():
                        return img_url

            image_map = body.get("imageMap")
            if isinstance(image_map, dict):
                for img in image_map.values():
                    if not isinstance(img, dict):
                        continue
                    img_url = img.get("originalUrl") or img.get("thumbnailUrl")
                    if isinstance(img_url, str) and img_url.strip():
                        return img_url

        return ""

    async def _resolve_user_id_from_creator_page(self, creator_id: str) -> str:
        html = await self._fetch_text_url(
            f"https://{creator_id}.fanbox.cc/", referer="https://www.fanbox.cc/"
        )
        match = self.PIXIV_CREATOR_RE.search(html)
        if not match:
            raise RuntimeError("无法从 creator 页面解析 Pixiv userId。")
        return match.group(1)

    async def _fetch_nekohouse_creator_meta(
        self, user_id: str
    ) -> dict[str, Any] | None:
        creators = await self._get_nekohouse_creators()

        for creator in creators:
            if not isinstance(creator, dict):
                continue
            if creator.get("service") != "fanbox":
                continue
            if str(creator.get("user_id", "")).strip() == str(user_id).strip():
                return creator
        return None

    async def _fetch_nekohouse_creator_posts(
        self, user_id: str, limit: int
    ) -> tuple[str, list[dict[str, Any]]]:
        html = await self._fetch_text_url(
            f"{self.NEKOHOUSE_BASE}/fanbox/user/{user_id}",
            referer=f"{self.NEKOHOUSE_BASE}/",
        )

        creator_name = "未知"
        title_match = re.search(
            r"<title>\s*Posts of\s+(.*?)\s+from\b",
            html,
            re.IGNORECASE | re.DOTALL,
        )
        if title_match:
            creator_name = self._strip_html_tags(title_match.group(1))

        blocks = re.findall(
            r"<article[^>]*class=\"[^\"]*post-card[^\"]*\"[^>]*>(.*?)</article>",
            html,
            re.IGNORECASE | re.DOTALL,
        )
        posts: list[dict[str, Any]] = []
        for block in blocks:
            href_match = re.search(
                r"href=\"(/fanbox/user/\d+/post/(\d+))\"",
                block,
                re.IGNORECASE,
            )
            if not href_match:
                continue

            post_id = href_match.group(2)
            title_block_match = re.search(
                r"<header[^>]*class=\"[^\"]*post-card__header[^\"]*\"[^>]*>(.*?)</header>",
                block,
                re.IGNORECASE | re.DOTALL,
            )
            title = "无标题"
            if title_block_match:
                title = self._strip_html_tags(title_block_match.group(1)) or "无标题"

            cover_match = re.search(
                r"<img[^>]*class=\"[^\"]*post-card__image[^\"]*\"[^>]*src=\"([^\"]+)\"",
                block,
                re.IGNORECASE | re.DOTALL,
            )
            cover_url = (
                self._to_abs_nekohouse_url(cover_match.group(1)) if cover_match else ""
            )

            time_match = re.search(
                r"<time[^>]*datetime=\"([^\"]+)\"",
                block,
                re.IGNORECASE,
            )
            publish_time = time_match.group(1) if time_match else "未知时间"

            posts.append(
                {
                    "id": post_id,
                    "title": title,
                    "cover_url": cover_url,
                    "published": publish_time,
                    "nekohouse_url": self._to_abs_nekohouse_url(href_match.group(1)),
                }
            )

            if len(posts) >= limit:
                break

        # 去重（按 post_id）
        deduped: list[dict[str, Any]] = []
        seen_ids: set[str] = set()
        for item in posts:
            post_id = str(item.get("id", ""))
            if post_id in seen_ids:
                continue
            seen_ids.add(post_id)
            deduped.append(item)

        return creator_name, deduped

    async def _fetch_nekohouse_post(self, user_id: str, post_id: str) -> dict[str, Any]:
        html = await self._fetch_text_url(
            f"{self.NEKOHOUSE_BASE}/fanbox/user/{user_id}/post/{post_id}",
            referer=f"{self.NEKOHOUSE_BASE}/fanbox/user/{user_id}",
        )

        if (
            "scrape__title" not in html
            and "scrape__content" not in html
            and "fileThumb" not in html
            and "scrape__attachment-link" not in html
        ):
            if "500 Internal Server Error" in html:
                raise RuntimeError("Nekohouse 返回 500，创作者或帖子可能未收录。")
            raise RuntimeError("Nekohouse 未收录该帖子，无法获取图包。")

        title = "无标题"
        title_match = re.search(
            r"<h1[^>]*class=\"[^\"]*scrape__title[^\"]*\"[^>]*>(.*?)</h1>",
            html,
            re.IGNORECASE | re.DOTALL,
        )
        if title_match:
            title = self._strip_html_tags(title_match.group(1)) or "无标题"
        else:
            page_title_match = re.search(
                r"<title>(.*?)</title>", html, re.IGNORECASE | re.DOTALL
            )
            if page_title_match:
                page_title = self._strip_html_tags(page_title_match.group(1))
                if page_title:
                    title = page_title

        creator_name = "未知"
        creator_match = re.search(
            r"<span[^>]*class=\"[^\"]*scrape__user-name[^\"]*\"[^>]*>(.*?)</span>",
            html,
            re.IGNORECASE | re.DOTALL,
        )
        if creator_match:
            creator_name = self._strip_html_tags(creator_match.group(1)) or "未知"

        publish_time = "未知时间"
        time_match = re.search(
            r"<time[^>]*datetime=\"([^\"]+)\"",
            html,
            re.IGNORECASE,
        )
        if time_match:
            publish_time = time_match.group(1)

        content_preview = ""
        content_match = re.search(
            r"<div[^>]*class=\"[^\"]*scrape__content[^\"]*\"[^>]*>(.*?)</div>",
            html,
            re.IGNORECASE | re.DOTALL,
        )
        if content_match:
            content_preview = self._strip_html_tags(content_match.group(1))

        image_paths = re.findall(
            r"class=\"[^\"]*fileThumb[^\"]*\"[^>]*href=\"([^\"]+)\"",
            html,
            re.IGNORECASE | re.DOTALL,
        )
        attachment_paths = re.findall(
            r"class=\"[^\"]*scrape__attachment-link[^\"]*\"[^>]*href=\"([^\"]+)\"",
            html,
            re.IGNORECASE | re.DOTALL,
        )

        images = [
            self._to_abs_nekohouse_url(path)
            for path in image_paths
            if isinstance(path, str) and path.strip()
        ]
        files = [
            self._to_abs_nekohouse_url(path)
            for path in attachment_paths
            if isinstance(path, str) and path.strip()
        ]

        images = list(dict.fromkeys(images))
        files = [x for x in list(dict.fromkeys(files)) if x not in images]

        return {
            "title": title,
            "creator_name": creator_name,
            "published": publish_time,
            "content_preview": content_preview,
            "images": images,
            "files": files,
            "nekohouse_url": (
                f"{self.NEKOHOUSE_BASE}/fanbox/user/{user_id}/post/{post_id}"
            ),
        }

    async def _resolve_user_id_for_nekohouse_creator(self, creator_input: str) -> str:
        user_id = self._extract_user_id_from_input(creator_input)
        if user_id:
            return user_id

        creator_id_guess = creator_input.strip()
        domain_match = self.FANBOX_DOMAIN_RE.search(creator_id_guess)
        if domain_match:
            creator_id_guess = domain_match.group(1)
        if not creator_id_guess:
            raise RuntimeError("无法解析创作者标识。")

        resolved = await self._resolve_user_id_from_nekohouse_creator_id(
            creator_id_guess
        )
        if resolved:
            return resolved

        suggestions = await self._search_nekohouse_fanbox_artists(creator_id_guess, 5)
        suggestion_lines: list[str] = []
        if suggestions:
            suggestion_lines.append("可用候选（Nekohouse artists 搜索）:")
            for creator in suggestions:
                name = str(creator.get("name", "未知"))
                user_id = str(creator.get("user_id", "未知"))
                suggestion_lines.append(f"- {name} | userId={user_id}")

        suggestion_block = ""
        if suggestion_lines:
            suggestion_block = "\n" + "\n".join(suggestion_lines)

        raise RuntimeError(
            f"Nekohouse 未收录 creatorId `{creator_id_guess}`，无法解析 userId。"
            " 可直接传 pixiv userId 或 Pixiv 链接（/fanbox/creator/<userId>）。"
            " 也可先用 /pixiv_fanbox_artist <关键词> 搜索。" + suggestion_block
        )

    async def _build_nekohouse_creator_message(
        self, creator_input: str, limit: int
    ) -> tuple[str, list[str]]:
        user_id = await self._resolve_user_id_for_nekohouse_creator(creator_input)
        creator_meta = await self._fetch_nekohouse_creator_meta(user_id)
        creator_name, posts = await self._fetch_nekohouse_creator_posts(user_id, limit)
        if creator_meta and creator_meta.get("name"):
            creator_name = str(creator_meta["name"])

        lines = [f"# Pixiv Fanbox 创作者：{creator_name}", ""]
        lines.append(f"pixiv userId: {user_id}")
        lines.append("数据源: Nekohouse")
        lines.append(f"主页: {self.NEKOHOUSE_BASE}/fanbox/user/{user_id}")
        lines.append(f"Pixiv页: https://www.pixiv.net/fanbox/creator/{user_id}")
        lines.append("")
        lines.append(f"最近帖子（{len(posts)} 条）:")

        cover_images: list[str] = []
        if not posts:
            lines.append("- 当前在 Nekohouse 暂无可见帖子")
            return "\n".join(lines), cover_images

        for idx, post in enumerate(posts, start=1):
            post_id = str(post.get("id", "未知"))
            title = self._truncate(str(post.get("title", "无标题")), 80)
            cover_url = str(post.get("cover_url", "") or "")
            publish_time = str(post.get("published", "未知时间"))
            neko_url = str(post.get("nekohouse_url", "") or "")

            lines.append(f"{idx}. {title} (ID: {post_id})")
            if cover_url:
                lines.append("   封面: 已随消息发送")
                cover_images.append(cover_url)
            else:
                lines.append("   封面: （无可用封面）")
            lines.append(f"   发布时间: {publish_time}")
            if neko_url:
                lines.append(f"   Nekohouse: {neko_url}")
            if post_id.isdigit():
                lines.append(
                    f"   Pixiv: https://www.pixiv.net/fanbox/creator/{user_id}/post/{post_id}"
                )

        cover_images = list(dict.fromkeys([x for x in cover_images if x]))
        if cover_images:
            lines.append("")
            lines.append(
                f"封面图: 共 {len(cover_images)} 张（将单独发送前 {min(len(cover_images), 10)} 张）"
            )

        return "\n".join(lines), cover_images

    async def _resolve_user_id_for_nekohouse_post(
        self, raw_text: str, user_id_hint: str | None
    ) -> str:
        if user_id_hint:
            return user_id_hint

        creator_domain_match = self.FANBOX_DOMAIN_RE.search(raw_text)
        if creator_domain_match:
            creator_id_guess = creator_domain_match.group(1)
            resolved = await self._resolve_user_id_from_nekohouse_creator_id(
                creator_id_guess
            )
            if resolved:
                return resolved
            raise RuntimeError(
                f"Nekohouse 未收录 creatorId `{creator_id_guess}`，无法解析 userId。"
                " 请改用包含 userId 的 Pixiv 帖子链接："
                " https://www.pixiv.net/fanbox/creator/<userId>/post/<postId>"
                "；或先用 /pixiv_fanbox_artist <关键词> 搜索 userId。"
            )

        raise RuntimeError("Nekohouse 模式需要可解析到 userId 的帖子链接。")

    async def _build_nekohouse_post_message(
        self, text: str, post_id: str, user_id_hint: str | None
    ) -> tuple[str, list[str]]:
        if not post_id.isdigit():
            raise RuntimeError("postId 无效，Nekohouse 模式需要纯数字 ID。")

        user_id = await self._resolve_user_id_for_nekohouse_post(text, user_id_hint)
        logger.info(
            f"Pixiv 插件：帖子查询进入 Nekohouse 数据源 - userId={user_id}, postId={post_id}"
        )
        archived = await self._fetch_nekohouse_post(user_id, post_id)

        lines = [f"# Pixiv Fanbox 帖子：{archived['title']}", ""]
        lines.append(f"ID: {post_id}")
        lines.append(f"pixiv userId: {user_id}")
        lines.append("数据源: Nekohouse")
        lines.append(f"Nekohouse 链接: {archived.get('nekohouse_url', '')}")
        lines.append(
            f"Pixiv 链接: https://www.pixiv.net/fanbox/creator/{user_id}/post/{post_id}"
        )
        lines.append(f"发布时间: {archived.get('published', '未知时间')}")

        content_preview = self._truncate(str(archived.get("content_preview", "")), 400)
        if content_preview:
            lines.append(f"正文预览: {content_preview}")

        images = archived.get("images") or []

        files = archived.get("files") or []
        if files:
            lines.append("")
            lines.append(f"附件链接（最多展示 10 条，共 {len(files)} 条）:")
            for url in files[:10]:
                lines.append(str(url))

        return "\n".join(lines), images

    async def pixiv_fanbox_recommended(self, event: AstrMessageEvent, args: str = ""):
        """获取 Fanbox 推荐创作者。"""
        text = args.strip()
        if text.lower() == "help":
            help_text = get_help_message(
                "pixiv_fanbox_recommended",
                "用法: /pixiv_fanbox_recommended [数量]\n示例: /pixiv_fanbox_recommended 5",
            )
            yield event.plain_result(help_text)
            return

        count = 5
        if text:
            if not text.isdigit():
                yield event.plain_result("数量必须是数字。")
                return
            count = max(1, min(int(text), 20))

        mode = self._fanbox_data_source()
        if mode == "nekohouse":
            try:
                creators = await self._fetch_nekohouse_json("/api/creators")
                if not isinstance(creators, list):
                    raise RuntimeError("Nekohouse creators 响应格式异常。")
                fanbox_creators = [
                    x
                    for x in creators
                    if isinstance(x, dict) and x.get("service") == "fanbox"
                ]
                fanbox_creators.sort(
                    key=lambda x: int(x.get("favorites", 0) or 0), reverse=True
                )
                selected = fanbox_creators[:count]
                lines = [
                    f"# Pixiv Fanbox 推荐创作者（Nekohouse 前 {len(selected)} 个）",
                    "",
                ]
                for i, creator in enumerate(selected, start=1):
                    user_id = str(creator.get("user_id", "未知"))
                    user_name = str(creator.get("name", "未知"))
                    favorites = int(creator.get("favorites", 0) or 0)
                    lines.append(
                        f"{i}. {user_name} | userId={user_id} | 收藏 {favorites}"
                    )
                    if user_id != "未知":
                        lines.append(f"   {self.NEKOHOUSE_BASE}/fanbox/user/{user_id}")
                        lines.append(
                            f"   https://www.pixiv.net/fanbox/creator/{user_id}"
                        )
                yield event.plain_result("\n".join(lines))
                return
            except Exception as e:
                logger.error(f"Pixiv 插件：Nekohouse 推荐创作者失败 - {e}")
                yield event.plain_result(f"获取 Fanbox 推荐创作者失败: {e}")
                return

        try:
            body = await self._fetch_json("creator.listRecommended")
            if not isinstance(body, list) or not body:
                raise RuntimeError("Fanbox 未返回可用的推荐创作者。")

            creators = [x for x in body if isinstance(x, dict)][:count]
            lines = [f"# Pixiv Fanbox 推荐创作者（前 {len(creators)} 个）", ""]
            for i, creator in enumerate(creators, start=1):
                creator_id = creator.get("creatorId", "未知")
                user = creator.get("user") or {}
                user_name = user.get("name", "未知")
                user_id = user.get("userId", "未知")
                category = creator.get("category") or "未分类"
                adult_flag = "成人向" if creator.get("hasAdultContent") else "全年龄"
                lines.append(
                    f"{i}. {user_name} ({creator_id}) | userId={user_id} | {category} | {adult_flag}"
                )
                lines.append(f"   https://{creator_id}.fanbox.cc/")

            yield event.plain_result("\n".join(lines))
        except Exception as e:
            logger.error(f"Pixiv 插件：获取 Fanbox 推荐创作者失败 - {e}")
            if mode == "official":
                yield event.plain_result(f"获取 Fanbox 推荐创作者失败: {e}")
                return

            # auto 模式下，官方失败回退 Nekohouse
            try:
                creators = await self._fetch_nekohouse_json("/api/creators")
                if not isinstance(creators, list):
                    raise RuntimeError("Nekohouse creators 响应格式异常。")
                fanbox_creators = [
                    x
                    for x in creators
                    if isinstance(x, dict) and x.get("service") == "fanbox"
                ]
                fanbox_creators.sort(
                    key=lambda x: int(x.get("favorites", 0) or 0), reverse=True
                )
                selected = fanbox_creators[:count]
                lines = [
                    f"# Pixiv Fanbox 推荐创作者（Nekohouse 前 {len(selected)} 个）",
                    "",
                ]
                for i, creator in enumerate(selected, start=1):
                    user_id = str(creator.get("user_id", "未知"))
                    user_name = str(creator.get("name", "未知"))
                    favorites = int(creator.get("favorites", 0) or 0)
                    lines.append(
                        f"{i}. {user_name} | userId={user_id} | 收藏 {favorites}"
                    )
                    if user_id != "未知":
                        lines.append(f"   {self.NEKOHOUSE_BASE}/fanbox/user/{user_id}")
                        lines.append(
                            f"   https://www.pixiv.net/fanbox/creator/{user_id}"
                        )
                yield event.plain_result("\n".join(lines))
            except Exception as fallback_error:
                logger.error(
                    f"Pixiv 插件：推荐创作者回退 Nekohouse 失败 - {fallback_error}"
                )
                yield event.plain_result(
                    f"获取 Fanbox 推荐创作者失败: {e}\nNekohouse 回退失败: {fallback_error}"
                )

    async def pixiv_fanbox_artist(self, event: AstrMessageEvent, args: str = ""):
        """按 Nekohouse artists 逻辑搜索 Fanbox 创作者。"""
        text = args.strip()
        if text.lower() == "help":
            help_text = get_help_message(
                "pixiv_fanbox_artist",
                "用法: /pixiv_fanbox_artist <关键词> [数量]\n"
                "示例: /pixiv_fanbox_artist hannari 10",
            )
            yield event.plain_result(help_text)
            return

        limit = 10
        keyword = text
        if text:
            parts = text.split()
            if parts and parts[-1].isdigit():
                limit = max(1, min(int(parts[-1]), 50))
                keyword = " ".join(parts[:-1]).strip()

        try:
            msg = await self._build_nekohouse_artist_search_message(keyword, limit)
            yield event.plain_result(msg)
        except Exception as e:
            logger.error(f"Pixiv 插件：Fanbox artists 搜索失败 - {e}")
            yield event.plain_result(f"Fanbox artists 搜索失败: {e}")

    async def pixiv_fanbox_creator(self, event: AstrMessageEvent, args: str = ""):
        """获取 Fanbox 创作者信息和最近帖子。"""
        text = args.strip()
        if not text or text.lower() == "help":
            help_text = get_help_message(
                "pixiv_fanbox_creator",
                "用法: /pixiv_fanbox_creator <creatorId|pixiv用户ID|链接> [数量]\n"
                "示例: /pixiv_fanbox_creator harusono 5",
            )
            yield event.plain_result(help_text)
            return

        # 兼容：若误将帖子链接传给 creator 命令，自动切换到帖子详情逻辑
        fanbox_post_match = self.FANBOX_POST_RE.search(text)
        pixiv_post_match = self.PIXIV_POST_RE.search(text)
        post_id_from_link = None
        if fanbox_post_match:
            post_id_from_link = fanbox_post_match.group(1)
        elif pixiv_post_match:
            post_id_from_link = pixiv_post_match.group(1)

        if post_id_from_link:
            logger.info(
                f"Pixiv 插件：creator 命令检测到帖子链接，自动切换为帖子查询 - postId={post_id_from_link}"
            )
            # 传递原始参数，避免丢失 userId/域名信息，便于帖子回退逻辑解析
            async for result in self.pixiv_fanbox_post(event, text):
                yield result
            return

        parts = text.split()
        creator_input = parts[0]
        limit = 5
        if len(parts) >= 2:
            if not parts[1].isdigit():
                yield event.plain_result("数量必须是数字。")
                return
            limit = max(1, min(int(parts[1]), 20))

        mode = self._fanbox_data_source()
        if mode == "nekohouse":
            try:
                msg, cover_images = await self._build_nekohouse_creator_message(
                    creator_input, limit
                )
                async for result in self._emit_post_message_with_images(
                    event,
                    msg,
                    cover_images,
                    referer=f"{self.NEKOHOUSE_BASE}/",
                    max_images=10,
                ):
                    yield result
                return
            except Exception as e:
                logger.error(f"Pixiv 插件：Nekohouse 创作者查询失败 - {e}")
                yield event.plain_result(f"获取 Fanbox 创作者失败: {e}")
                return

        try:
            creator_id = await self._resolve_creator_id(creator_input)
            creator = await self._fetch_json(
                "creator.get",
                params={"creatorId": creator_id},
                referer=f"https://{creator_id}.fanbox.cc/",
            )
            posts_payload = await self._fetch_json(
                "post.listCreator",
                params={"creatorId": creator_id, "limit": limit},
                referer=f"https://{creator_id}.fanbox.cc/",
            )
            posts = self._extract_post_list(posts_payload)

            if not isinstance(creator, dict):
                yield event.plain_result("未能获取到创作者详情。")
                return

            user = creator.get("user") or {}
            user_name = user.get("name", "未知")
            user_id = user.get("userId", "未知")
            description = self._truncate(creator.get("description", ""), 220)

            lines = [f"# Pixiv Fanbox 创作者：{user_name}", ""]
            lines.append(f"creatorId: {creator_id}")
            lines.append(f"pixiv userId: {user_id}")
            lines.append(
                f"内容分级: {'成人向' if creator.get('hasAdultContent') else '全年龄'}"
            )
            lines.append(f"主页: https://{creator_id}.fanbox.cc/")
            if user_id != "未知":
                lines.append(f"Pixiv页: https://www.pixiv.net/fanbox/creator/{user_id}")
            if description:
                lines.append(f"简介: {description}")

            lines.append("")
            lines.append(f"最近帖子（{len(posts)} 条）:")
            cover_images: list[str] = []
            if not posts:
                lines.append("- 暂无可见帖子")
            else:
                for idx, post in enumerate(posts, start=1):
                    post_id = post.get("id", "未知")
                    title = self._truncate(post.get("title", "无标题"), 80)
                    cover_url = self._extract_post_cover_url(post)
                    publish_time = post.get("publishedDatetime", "未知时间")
                    likes = post.get("likeCount", 0)
                    comments = post.get("commentCount", 0)

                    lines.append(f"{idx}. {title} (ID: {post_id})")
                    if cover_url:
                        lines.append("   封面: 已随消息发送")
                        cover_images.append(str(cover_url))
                    else:
                        lines.append("   封面: （无可用封面）")
                    lines.append(f"   👍 {likes} | 💬 {comments} | {publish_time}")
                    lines.append(f"   https://{creator_id}.fanbox.cc/posts/{post_id}")
                    if user_id != "未知":
                        lines.append(
                            f"   https://www.pixiv.net/fanbox/creator/{user_id}/post/{post_id}"
                        )

            cover_images = list(dict.fromkeys([x for x in cover_images if x]))
            if cover_images:
                lines.append("")
                lines.append(
                    f"封面图: 共 {len(cover_images)} 张（将单独发送前 {min(len(cover_images), 10)} 张）"
                )

            async for result in self._emit_post_message_with_images(
                event,
                "\n".join(lines),
                cover_images,
                referer=f"https://{creator_id}.fanbox.cc/",
                max_images=10,
            ):
                yield result
        except Exception as e:
            logger.error(f"Pixiv 插件：获取 Fanbox 创作者失败 - {e}")
            if mode == "official":
                yield event.plain_result(f"获取 Fanbox 创作者失败: {e}")
                return
            try:
                msg, cover_images = await self._build_nekohouse_creator_message(
                    creator_input, limit
                )
                async for result in self._emit_post_message_with_images(
                    event,
                    msg,
                    cover_images,
                    referer=f"{self.NEKOHOUSE_BASE}/",
                    max_images=10,
                ):
                    yield result
            except Exception as fallback_error:
                logger.error(
                    f"Pixiv 插件：Nekohouse 回退获取创作者失败 - {fallback_error}"
                )
                yield event.plain_result(
                    f"获取 Fanbox 创作者失败: {e}\nNekohouse 回退也失败: {fallback_error}"
                )

    async def pixiv_fanbox_post(self, event: AstrMessageEvent, args: str = ""):
        """获取 Fanbox 帖子详情。"""
        text = args.strip()
        if not text or text.lower() == "help":
            help_text = get_help_message(
                "pixiv_fanbox_post",
                "用法: /pixiv_fanbox_post <postId|帖子链接>\n"
                "示例: /pixiv_fanbox_post 10451793",
            )
            yield event.plain_result(help_text)
            return

        post_id, user_id_from_input = self._extract_post_and_user_id(text)
        if not post_id.isdigit():
            yield event.plain_result("postId 无效，请提供纯数字 ID 或标准帖子链接。")
            return

        mode = self._fanbox_data_source()
        if mode == "nekohouse":
            try:
                msg, images = await self._build_nekohouse_post_message(
                    text, post_id, user_id_from_input
                )
                async for result in self._emit_post_message_with_images(
                    event,
                    msg,
                    images,
                    referer=f"{self.NEKOHOUSE_BASE}/",
                    max_images=10,
                ):
                    yield result
                return
            except Exception as e:
                logger.error(f"Pixiv 插件：Nekohouse 帖子查询失败 - {e}")
                yield event.plain_result(f"获取 Fanbox 帖子失败: {e}")
                return

        try:
            post = await self._fetch_json(
                "post.info",
                params={"postId": post_id},
                referer="https://www.fanbox.cc/",
            )
            if not isinstance(post, dict):
                yield event.plain_result("未能获取到帖子详情。")
                return

            creator_id = post.get("creatorId", "未知")
            user = post.get("user") or {}
            user_name = user.get("name", "未知")
            user_id = user.get("userId", "未知")
            title = post.get("title", "无标题")
            fee = post.get("feeRequired", 0)
            restricted = bool(post.get("isRestricted"))
            post_type = post.get("type", "未知")
            tags = post.get("tags") or []
            likes = post.get("likeCount", 0)
            comments = post.get("commentCount", 0)
            publish_time = post.get("publishedDatetime", "未知时间")
            excerpt = self._truncate(post.get("excerpt", ""), 180)
            body_preview = self._truncate(self._extract_post_text_preview(post), 400)
            images, files = self._extract_post_media(post)

            lines = [f"# Pixiv Fanbox 帖子：{title}", ""]
            lines.append(f"ID: {post_id}")
            lines.append(f"创作者: {user_name} ({creator_id})")
            lines.append(f"pixiv userId: {user_id}")
            lines.append(f"类型: {post_type}")
            lines.append(
                f"状态: {'受限（需赞助）' if restricted else '公开'} | 门槛: {fee} 日元"
            )
            lines.append(f"互动: 👍 {likes} | 💬 {comments}")
            lines.append(f"发布时间: {publish_time}")
            if tags:
                lines.append(f"标签: {', '.join(str(t) for t in tags)}")
            if excerpt:
                lines.append(f"摘要: {excerpt}")
            if body_preview:
                lines.append(f"正文预览: {body_preview}")

            lines.append("")
            if creator_id != "未知":
                lines.append(
                    f"帖子链接: https://{creator_id}.fanbox.cc/posts/{post_id}"
                )
            if user_id != "未知":
                # 来自 .tmp 的 fanbox 帖子链接格式
                lines.append(
                    f"Pixiv 链接: https://www.pixiv.net/fanbox/creator/{user_id}/post/{post_id}"
                )

            if files:
                lines.append("")
                lines.append(f"附件链接（最多展示 5 条，共 {len(files)} 条）:")
                for url in files[:5]:
                    lines.append(url)

            if restricted and not self.pixiv_config.fanbox_sessid:
                lines.append("")
                lines.append(self._missing_sessid_help())

            async for result in self._emit_post_message_with_images(
                event,
                "\n".join(lines),
                images,
                referer="https://www.fanbox.cc/",
                max_images=10,
            ):
                yield result
        except Exception as e:
            logger.error(f"Pixiv 插件：获取 Fanbox 帖子失败 - {e}")
            if mode == "official":
                hint = (
                    "可能原因: Cloudflare 校验、帖子权限不足或 Fanbox 会话缺失。"
                    " 建议配置 fanbox_cookie(含 cf_clearance + FANBOXSESSID) 与 fanbox_user_agent。"
                    " 可先用 /pixiv_fanbox_creator <creatorId> 查看可见帖子。"
                )
                if not self.pixiv_config.fanbox_sessid:
                    yield event.plain_result(
                        f"获取 Fanbox 帖子失败: {e}\n{hint}\n\n{self._missing_sessid_help()}"
                    )
                    return
                yield event.plain_result(f"获取 Fanbox 帖子失败: {e}\n{hint}")
                return

            fallback_error: Exception | None = None
            try:
                msg, images = await self._build_nekohouse_post_message(
                    text, post_id, user_id_from_input
                )
                async for result in self._emit_post_message_with_images(
                    event,
                    msg,
                    images,
                    referer=f"{self.NEKOHOUSE_BASE}/",
                    max_images=10,
                ):
                    yield result
                return
            except Exception as ex:
                fallback_error = ex
                logger.error(f"Pixiv 插件：Nekohouse 回退获取帖子失败 - {ex}")

            hint = (
                "可能原因: Cloudflare 校验、帖子权限不足或 Fanbox 会话缺失。"
                " 建议配置 fanbox_cookie(含 cf_clearance + FANBOXSESSID) 与 fanbox_user_agent。"
                " 可先用 /pixiv_fanbox_creator <creatorId> 查看可见帖子。"
            )
            if fallback_error is not None:
                hint += f"\nNekohouse 回退失败: {fallback_error}"
            if not self.pixiv_config.fanbox_sessid:
                yield event.plain_result(
                    f"获取 Fanbox 帖子失败: {e}\n{hint}\n\n{self._missing_sessid_help()}"
                )
                return

            yield event.plain_result(f"获取 Fanbox 帖子失败: {e}\n{hint}")
