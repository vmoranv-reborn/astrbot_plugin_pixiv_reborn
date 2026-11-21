"""Fanbox 数据抓取/解析辅助 Mixin。"""

import html as html_lib
import re
from typing import Any
from urllib.parse import urljoin

import aiohttp
from astrbot.api import logger
from astrbot.api.event import AstrMessageEvent
import astrbot.api.message_components as Comp

from ..fanbox.headers import build_api_headers, build_html_headers
from ..media.pixiv_utils import (
    build_image_from_bytes,
    build_image_from_url,
    download_image,
)


class FanboxFetchMixin:
    async def _fetch_text_url(
        self,
        url: str,
        referer: str | None = None,
        timeout_seconds: int = 20,
    ) -> str:
        cookie = self._fanbox_cookie_header() if "fanbox.cc" in url.lower() else None
        headers = build_html_headers(self._fanbox_user_agent(), referer, cookie)
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

    def _strip_html_tags(text: str) -> str:
        cleaned = re.sub(r"<[^>]+>", " ", text)
        cleaned = html_lib.unescape(cleaned)
        cleaned = cleaned.replace("\r", " ").replace("\n", " ")
        cleaned = re.sub(r"\s+", " ", cleaned).strip()
        return cleaned

    def _to_abs_nekohouse_url(self, url_or_path: str) -> str:
        return urljoin(self.NEKOHOUSE_BASE + "/", url_or_path)

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
                    img_comp = build_image_from_url(url)
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
                        img_comp = await build_image_from_bytes(img_data, ext=ext)
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
        headers = build_api_headers(
            self._fanbox_user_agent(), referer, self._fanbox_cookie_header()
        )

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

    def _extract_post_id(self, text: str) -> str:
        post_id, _ = self._extract_post_and_user_id(text)
        return post_id

    def _truncate(text: str | None, length: int = 140) -> str:
        if not text:
            return ""
        txt = str(text).replace("\r", " ").replace("\n", " ").strip()
        if len(txt) <= length:
            return txt
        return txt[: length - 1] + "…"

    def _extract_post_list(posts_payload: Any) -> list[dict[str, Any]]:
        if isinstance(posts_payload, list):
            return [x for x in posts_payload if isinstance(x, dict)]
        if isinstance(posts_payload, dict):
            for key in ("items", "posts"):
                value = posts_payload.get(key)
                if isinstance(value, list):
                    return [x for x in value if isinstance(x, dict)]
        return []

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
