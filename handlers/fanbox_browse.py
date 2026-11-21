"""Fanbox 浏览/检索命令 Mixin。"""

from astrbot.api import logger
from astrbot.api.event import AstrMessageEvent

from ..infra.help import get_help_message


class FanboxBrowseMixin:
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
                    " 建议配置 fanbox_sessid；若仍 403，再配置 fanbox_cf_clearance 与 fanbox_user_agent。"
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
                " 建议配置 fanbox_sessid；若仍 403，再配置 fanbox_cf_clearance 与 fanbox_user_agent。"
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
