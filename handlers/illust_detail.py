"""插画详情/评论/相关作品的处理器 Mixin。"""

import asyncio

from astrbot.api import logger
from astrbot.api.event import AstrMessageEvent

from ..domain.tag import (
    FilterConfig,
    build_detail_message,
    filter_illusts_with_reason,
)
from ..infra.help import get_help_message
from ..media.pixiv_utils import send_forward_message, send_pixiv_image
from ..services.delivery import process_and_send_illusts


class IllustDetailMixin:
    async def pixiv_msg_url(self, event: AstrMessageEvent, msg: str = ""):
        """处理接受的消息，查看是否为 https://www.pixiv.net/artworks/xxxx 形式的 URL，并获取作品信息"""
        # 检查是否启用了 Pixiv URL 搜索功能
        if not self.pixiv_config.pixiv_urlsearch_enabled:
            return
        msg = event.message_str.strip()  # 去除首尾空白字符
        # 检查是否为 Pixiv 插画 URL
        if msg.startswith("https://www.pixiv.net/artworks/"):
            try:
                # 获取作品ID，使用 rstrip("/") 避免末尾斜杠导致取到空字符串
                illust_id = msg.rstrip("/").split("/")[-1]
                # 简单验证 ID 是否为数字，防止类似 /artworks/abc 的无效输入
                if not illust_id.isdigit():
                    yield event.plain_result("无效的 Pixiv 插画 ID。")
                    return

                # 调用已有的 pixiv_specific 方法获取作品信息并发送
                async for result in self.pixiv_specific(event, illust_id):
                    yield result
            except Exception as e:
                logger.error(f"获取插画信息失败: {e}")
                yield event.plain_result("获取插画信息失败，请稍后再试。")

    async def pixiv_specific(self, event: AstrMessageEvent, illust_id: str = ""):
        """根据作品 ID 获取特定作品详情"""
        # 检查是否提供了作品 ID
        if not illust_id:
            yield event.plain_result(
                "请输入要查询的作品 ID。使用 `/pixiv_help` 查看帮助。"
            )
            return

        # 验证作品 ID 是否为数字
        if not illust_id.isdigit():
            yield event.plain_result("作品 ID 必须为数字。")
            return

        # 验证是否已认证
        if not await self.client_wrapper.authenticate():
            yield event.plain_result(self.pixiv_config.get_auth_error_message())
            return

        # 调用 Pixiv API 获取作品详情
        try:
            illust_detail = await self.client_wrapper.call_pixiv_api(
                self.client.illust_detail, illust_id
            )

            # 检查 illust_detail 和 illust 是否存在
            if (
                not illust_detail
                or not hasattr(illust_detail, "illust")
                or not illust_detail.illust
            ):
                yield event.plain_result("未找到该作品，请检查作品 ID 是否正确。")
                return

            illust = illust_detail.illust

            # 统一使用 filter_illusts_with_reason 进行过滤和提示
            config = FilterConfig(
                r18_mode=self.pixiv_config.r18_mode,
                filter_r18g_only=self.pixiv_config.filter_r18g_only,
                ai_filter_mode=self.pixiv_config.ai_filter_mode,
                ai_detection_mode=self.pixiv_config.ai_detection_mode,
                display_tag_str=f"ID:{illust_id}",
                return_count=self.pixiv_config.return_count,
                logger=logger,
                show_filter_result=self.pixiv_config.show_filter_result,
                single_response_mode=self.pixiv_config.single_response_mode,
                show_details=self.pixiv_config.show_details,
                excluded_tags=[],
            )
            filtered_illusts, filter_msgs = filter_illusts_with_reason([illust], config)
            if self.pixiv_config.show_filter_result:
                for msg in filter_msgs:
                    yield event.plain_result(msg)
            if not filtered_illusts:
                return

            # 根据转发消息设置决定发送方式
            if self.pixiv_config.forward_threshold:
                # 启用转发时使用转发消息发送
                async for result in send_forward_message(
                    self.client,
                    event,
                    filtered_illusts,
                    lambda illust: build_detail_message(illust, is_novel=False),
                    send_all_pages=True,
                ):
                    yield result
            else:
                # 未启用转发时逐张发送
                detail_message = build_detail_message(
                    filtered_illusts[0], is_novel=False
                )
                async for result in send_pixiv_image(
                    self.client,
                    event,
                    filtered_illusts[0],
                    detail_message,
                    show_details=self.pixiv_config.show_details,
                    send_all_pages=True,  # 发送特定作品的所有页面
                ):
                    yield result

        except Exception as e:
            logger.error(f"Pixiv 插件：获取作品详情时发生错误 - {e}")
            yield event.plain_result(f"获取作品详情时发生错误: {str(e)}")
            import traceback

            logger.error(traceback.format_exc())

    async def pixiv_related(self, event: AstrMessageEvent, illust_id: str = ""):
        """获取与指定作品相关的其他作品"""
        # 检查参数是否为空或为 help
        if not illust_id.strip() or illust_id.strip().lower() == "help":
            help_text = get_help_message(
                "pixiv_related", "相关作品帮助消息加载失败，请检查配置文件。"
            )
            yield event.plain_result(help_text)
            return

        # 验证作品ID是否为数字
        if not illust_id.isdigit():
            yield event.plain_result(f"作品ID必须是数字: {illust_id}")
            return

        # 验证是否已认证
        if not await self.client_wrapper.authenticate():
            yield event.plain_result(self.pixiv_config.get_auth_error_message())
            return

        logger.info(f"Pixiv 插件：获取相关作品 - ID: {illust_id}")
        try:
            # 调用 API 获取相关作品
            related_result = await self.client_wrapper.call_pixiv_api(
                self.client.illust_related, int(illust_id)
            )
            initial_illusts = related_result.illusts if related_result.illusts else []

            if not initial_illusts:
                yield event.plain_result(f"未能找到与作品 ID {illust_id} 相关的作品。")
                return

            # 使用统一的作品处理和发送函数
            config = FilterConfig(
                r18_mode=self.pixiv_config.r18_mode,
                filter_r18g_only=self.pixiv_config.filter_r18g_only,
                ai_filter_mode=self.pixiv_config.ai_filter_mode,
                ai_detection_mode=self.pixiv_config.ai_detection_mode,
                display_tag_str=f"相关:{illust_id}",
                return_count=self.pixiv_config.return_count,
                logger=logger,
                show_filter_result=self.pixiv_config.show_filter_result,
                single_response_mode=self.pixiv_config.single_response_mode,
                excluded_tags=[],
                forward_threshold=self.pixiv_config.forward_threshold,
                show_details=self.pixiv_config.show_details,
            )

            async for result in process_and_send_illusts(
                initial_illusts,  # 传入所有初始作品，让process_and_send_illusts内部处理过滤和选择
                config,
                self.client,
                event,
                build_detail_message,
                send_pixiv_image,
                send_forward_message,
                is_novel=False,
            ):
                yield result

        except Exception as e:
            logger.error(f"Pixiv 插件：获取相关作品时发生错误 - {e}")
            yield event.plain_result(f"获取相关作品时发生错误: {str(e)}")

    async def pixiv_illust_comments(
        self, event: AstrMessageEvent, illust_id: str = "", offset: str = ""
    ):
        """获取指定作品的评论"""
        # 检查是否提供了作品 ID
        if not illust_id.strip() or illust_id.strip().lower() == "help":
            help_text = get_help_message(
                "pixiv_illust_comments", "作品评论帮助消息加载失败，请检查配置文件。"
            )
            yield event.plain_result(help_text)
            return

        # 验证作品 ID 是否为数字
        if not illust_id.isdigit():
            yield event.plain_result("作品 ID 必须为数字。")
            return

        # 验证偏移量是否为数字（如果提供）
        if offset and not offset.isdigit():
            yield event.plain_result("偏移量必须为数字。")
            return

        # 验证是否已认证
        if not await self.client_wrapper.authenticate():
            yield event.plain_result(self.pixiv_config.get_auth_error_message())
            return

        logger.info(
            f"Pixiv 插件：正在获取作品评论 - ID: {illust_id}, 偏移量: {offset or '0'}"
        )

        try:
            # 使用 asyncio.to_thread 包装同步 API 调用
            try:
                comments_result = await self.client_wrapper.call_pixiv_api(
                    self.client.illust_comments,
                    illust_id=int(illust_id),
                    offset=int(offset) if offset else None,
                    include_total_comments=True,
                )
            except Exception as api_error:
                # 捕获API调用本身的错误，特别是JSON解析错误
                error_msg = str(api_error)
                if "parse_json() error" in error_msg:
                    logger.error(f"Pixiv 插件：API返回空响应或非JSON格式 - {error_msg}")

                    # 添加调试代码：尝试直接获取原始响应
                    try:
                        import requests

                        url = f"{self.client.hosts}/v1/illust/comments"
                        params = {
                            "illust_id": illust_id,
                            "include_total_comments": "true",
                        }
                        if offset:
                            params["offset"] = offset

                        headers = {
                            "User-Agent": "PixivAndroidApp/5.0.64 (Android 6.0)",
                            "Authorization": f"Bearer {self.client.access_token}",
                        }

                        debug_response = await asyncio.to_thread(
                            requests.get, url, params=params, headers=headers
                        )
                        logger.error(
                            f"Pixiv 插件：调试信息 - 原始响应状态码: {debug_response.status_code}"
                        )
                        logger.error(
                            f"Pixiv 插件：调试信息 - 原始响应内容: {debug_response.text[:500]}"
                        )

                        yield event.plain_result(
                            f"获取作品评论时发生错误: API返回空响应，可能是该作品没有评论或API限制\n调试信息: 状态码 {debug_response.status_code}"
                        )
                    except Exception as debug_e:
                        logger.error(f"Pixiv 插件：调试请求失败 - {debug_e}")
                        yield event.plain_result(
                            "获取作品评论时发生错误: API返回空响应，可能是该作品没有评论或API限制"
                        )
                    return
                    yield event.plain_result(
                        "获取作品评论时发生错误: API返回空响应，可能是该作品没有评论或API限制"
                    )
                    return
                else:
                    # 重新抛出其他类型的错误
                    raise api_error

            # 检查返回结果是否有效
            if not comments_result:
                yield event.plain_result(f"未找到作品 ID {illust_id} 的评论。")
                return

            # 检查返回结果的结构
            comments = None
            total_comments = 0

            # 尝试不同的方式获取评论数据
            if hasattr(comments_result, "comments"):
                comments = comments_result.comments
                total_comments = getattr(comments_result, "total_comments", 0)
            elif hasattr(comments_result, "body"):
                if hasattr(comments_result.body, "comments"):
                    comments = comments_result.body.comments
                    total_comments = getattr(comments_result.body, "total_comments", 0)
            elif isinstance(comments_result, dict):
                # 如果返回的是字典，尝试从字典中获取数据
                if "comments" in comments_result:
                    comments = comments_result["comments"]
                    total_comments = comments_result.get("total_comments", 0)
                elif "body" in comments_result and isinstance(
                    comments_result["body"], dict
                ):
                    if "comments" in comments_result["body"]:
                        comments = comments_result["body"]["comments"]
                        total_comments = comments_result["body"].get(
                            "total_comments", 0
                        )

            # 如果仍然无法获取评论，记录详细信息并返回错误
            if comments is None:
                logger.error(
                    f"Pixiv 插件：评论API返回结构异常 - 类型: {type(comments_result)}, 内容: {str(comments_result)[:200]}"
                )
                yield event.plain_result("获取作品评论时发生错误: API返回结构异常")
                return

            if not comments:
                yield event.plain_result(f"作品 ID {illust_id} 暂无评论。")
                return

            # 构建评论信息
            comment_info = f"作品 ID: {illust_id} 的评论 (共 {total_comments} 条)\n\n"

            # 限制显示的评论数量
            max_comments = 10
            displayed_comments = comments[:max_comments]

            for i, comment in enumerate(displayed_comments, 1):
                # 处理不同类型的评论对象
                author = None
                author_name = "匿名用户"
                comment_text = ""
                date = ""

                if hasattr(comment, "user"):
                    author = comment.user
                elif isinstance(comment, dict) and "user" in comment:
                    author = comment["user"]

                if author:
                    if hasattr(author, "name"):
                        author_name = author.name
                    elif isinstance(author, dict) and "name" in author:
                        author_name = author["name"]

                if hasattr(comment, "comment"):
                    comment_text = comment.comment
                elif isinstance(comment, dict) and "comment" in comment:
                    comment_text = comment["comment"]

                if hasattr(comment, "date"):
                    date = comment.date
                elif isinstance(comment, dict) and "date" in comment:
                    date = comment["date"]

                comment_info += f"#{i} {author_name}\n"
                comment_info += f"{comment_text}\n"
                if date:
                    comment_info += f"时间: {date}\n"
                comment_info += "---\n"

            # 如果评论数量超过显示限制，提示用户
            if len(comments) > max_comments:
                next_offset = (int(offset) if offset else 0) + max_comments
                comment_info += f"\n已显示前 {max_comments} 条评论，使用 /pixiv_illust_comments {illust_id} {next_offset} 查看更多。"

            yield event.plain_result(comment_info)

        except Exception as e:
            logger.error(f"Pixiv 插件：获取作品评论时发生错误 - {e}")
            import traceback

            logger.error(traceback.format_exc())
            yield event.plain_result(f"获取作品评论时发生错误: {str(e)}")

    async def pixiv_showcase_article(
        self, event: AstrMessageEvent, showcase_id: str = ""
    ):
        """获取特辑详情"""
        # 检查是否提供了特辑 ID
        if not showcase_id.strip() or showcase_id.strip().lower() == "help":
            help_text = get_help_message(
                "pixiv_showcase_article", "特辑详情帮助消息加载失败，请检查配置文件。"
            )
            yield event.plain_result(help_text)
            return

        # 验证特辑 ID 是否为数字
        if not showcase_id.isdigit():
            yield event.plain_result("特辑 ID 必须为数字。")
            return

        logger.info(f"Pixiv 插件：正在获取特辑详情 - ID: {showcase_id}")

        try:
            # 调用 API 获取特辑详情（无需登录）
            showcase_result = await self.client_wrapper.call_pixiv_api(
                self.client.showcase_article, showcase_id=int(showcase_id)
            )

            if not showcase_result:
                yield event.plain_result(f"未找到特辑 ID {showcase_id}。")
                return

            # 检查返回结果的结构，处理不同的数据格式
            title = None
            description = None
            article_url = None
            publish_date = None
            artworks = []

            # 尝试从对象属性获取数据
            if hasattr(showcase_result, "title"):
                title = showcase_result.title
            elif hasattr(showcase_result, "body") and hasattr(
                showcase_result.body, "title"
            ):
                title = showcase_result.body.title
            elif isinstance(showcase_result, dict):
                if "title" in showcase_result:
                    title = showcase_result["title"]
                elif (
                    "body" in showcase_result
                    and isinstance(showcase_result["body"], dict)
                    and "title" in showcase_result["body"]
                ):
                    title = showcase_result["body"]["title"]

            # 类似地处理其他字段
            if hasattr(showcase_result, "description"):
                description = showcase_result.description
            elif hasattr(showcase_result, "body") and hasattr(
                showcase_result.body, "description"
            ):
                description = showcase_result.body.description
            elif isinstance(showcase_result, dict):
                if "description" in showcase_result:
                    description = showcase_result["description"]
                elif (
                    "body" in showcase_result
                    and isinstance(showcase_result["body"], dict)
                    and "description" in showcase_result["body"]
                ):
                    description = showcase_result["body"]["description"]

            if hasattr(showcase_result, "article_url"):
                article_url = showcase_result.article_url
            elif hasattr(showcase_result, "body") and hasattr(
                showcase_result.body, "article_url"
            ):
                article_url = showcase_result.body.article_url
            elif isinstance(showcase_result, dict):
                if "article_url" in showcase_result:
                    article_url = showcase_result["article_url"]
                elif (
                    "body" in showcase_result
                    and isinstance(showcase_result["body"], dict)
                    and "article_url" in showcase_result["body"]
                ):
                    article_url = showcase_result["body"]["article_url"]

            if hasattr(showcase_result, "publish_date"):
                publish_date = showcase_result.publish_date
            elif hasattr(showcase_result, "body") and hasattr(
                showcase_result.body, "publish_date"
            ):
                publish_date = showcase_result.body.publish_date
            elif isinstance(showcase_result, dict):
                if "publish_date" in showcase_result:
                    publish_date = showcase_result["publish_date"]
                elif (
                    "body" in showcase_result
                    and isinstance(showcase_result["body"], dict)
                    and "publish_date" in showcase_result["body"]
                ):
                    publish_date = showcase_result["body"]["publish_date"]

            # 处理作品列表
            if hasattr(showcase_result, "artworks"):
                artworks = showcase_result.artworks
            elif hasattr(showcase_result, "body") and hasattr(
                showcase_result.body, "artworks"
            ):
                artworks = showcase_result.body.artworks
            elif isinstance(showcase_result, dict):
                if "artworks" in showcase_result:
                    artworks = showcase_result["artworks"]
                elif (
                    "body" in showcase_result
                    and isinstance(showcase_result["body"], dict)
                    and "artworks" in showcase_result["body"]
                ):
                    artworks = showcase_result["body"]["artworks"]

            # 如果仍然无法获取数据，记录详细信息并返回错误
            if not title and not description and not artworks:
                logger.error(
                    f"Pixiv 插件：特辑API返回结构异常 - 类型: {type(showcase_result)}, 内容: {str(showcase_result)[:200]}"
                )
                yield event.plain_result(
                    "获取特辑详情时发生错误: API返回结构异常或特辑不存在"
                )
                return

            # 构建特辑信息
            title = title or "未知特辑"
            description = description or "无描述"
            article_url = article_url or ""
            publish_date = publish_date or "未知日期"

            showcase_info = f"特辑标题: {title}\n"
            showcase_info += f"特辑ID: {showcase_id}\n"
            showcase_info += f"发布日期: {publish_date}\n"

            if description:
                # 限制描述长度
                if len(description) > 500:
                    description = description[:500] + "..."
                showcase_info += f"描述: {description}\n"

            if article_url:
                showcase_info += f"链接: {article_url}\n"

            # 获取特辑中的作品
            if artworks:
                showcase_info += f"\n包含作品 ({len(artworks)}件):\n"
                for i, artwork in enumerate(artworks[:10], 1):  # 限制显示前10个
                    # 处理不同类型的作品对象
                    artwork_title = None
                    artwork_id = None
                    author_name = "未知作者"

                    if hasattr(artwork, "title"):
                        artwork_title = artwork.title
                    elif isinstance(artwork, dict) and "title" in artwork:
                        artwork_title = artwork["title"]

                    if hasattr(artwork, "id"):
                        artwork_id = artwork.id
                    elif isinstance(artwork, dict) and "id" in artwork:
                        artwork_id = artwork["id"]

                    # 处理作者信息
                    author = None
                    if hasattr(artwork, "user"):
                        author = artwork.user
                    elif isinstance(artwork, dict) and "user" in artwork:
                        author = artwork["user"]

                    if author:
                        if hasattr(author, "name"):
                            author_name = author.name
                        elif isinstance(author, dict) and "name" in author:
                            author_name = author["name"]

                    artwork_title = artwork_title or "未知标题"
                    artwork_id = artwork_id or "未知ID"

                    showcase_info += (
                        f"{i}. {artwork_title} - {author_name} (ID: {artwork_id})\n"
                    )

                if len(artworks) > 10:
                    showcase_info += f"... 还有 {len(artworks) - 10} 个作品\n"

            yield event.plain_result(showcase_info)

        except Exception as e:
            logger.error(f"Pixiv 插件：获取特辑详情时发生错误 - {e}")
            import traceback

            logger.error(traceback.format_exc())
            yield event.plain_result(f"获取特辑详情时发生错误: {str(e)}")
