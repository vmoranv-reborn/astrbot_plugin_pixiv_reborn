from pathlib import Path
from astrbot.api import logger
from astrbot.api.event import AstrMessageEvent
from ..utils.pixiv_utils import send_pixiv_image, send_forward_message
from ..utils.help import get_help_message
from ..utils.tag import (
    build_detail_message,
    FilterConfig,
    validate_and_process_tags,
    process_and_send_illusts,
)
import asyncio
import io
import base64
import hashlib
from astrbot.api.message_components import File
from fpdf import FPDF


class NovelHandler:
    """
    Pixiv 小说功能处理器
    负责处理 Pixiv 小说搜索、推荐、新小说、系列详情、评论获取和下载为 PDF 等功能
    """

    def __init__(self, client_wrapper, pixiv_config):
        self.client_wrapper = client_wrapper
        self.client = client_wrapper.client_api
        self.pixiv_config = pixiv_config
        # 字体相关初始化
        self.font_path = Path(__file__).parent / "data" / "SmileySans-Oblique.ttf"

    async def pixiv_novel(self, event: AstrMessageEvent, tags: str = ""):
        """处理 /pixiv_novel 命令，搜索 Pixiv 小说"""
        cleaned_tags = tags.strip()

        # Handle help and empty cases
        if not cleaned_tags or cleaned_tags.lower() == "help":
            help_text = get_help_message(
                "pixiv_novel", "小说搜索帮助消息加载失败，请检查配置文件。"
            )
            yield event.plain_result(help_text)
            return

        # 验证是否已认证
        if not await self.client_wrapper.authenticate():
            yield event.plain_result(self.pixiv_config.get_auth_error_message())
            return

        # 使用统一的标签处理函数
        tag_result = validate_and_process_tags(cleaned_tags)
        if not tag_result["success"]:
            yield event.plain_result(tag_result["error_message"])
            return

        exclude_tags = tag_result["exclude_tags"]
        search_tags = tag_result["search_tags"]
        display_tags = tag_result["display_tags"]

        logger.info(
            f"Pixiv 插件：正在搜索小说 - 标签: {search_tags}，排除标签: {exclude_tags}"
        )

        try:
            # 调用 Pixiv API 搜索小说
            search_result = await self.client_wrapper.call_pixiv_api(
                self.client.search_novel,
                search_tags,
                search_target="partial_match_for_tags",
            )
            initial_novels = search_result.novels if search_result.novels else []
            if not initial_novels:
                yield event.plain_result(f"未找到相关小说: {search_tags}")
                return

            # 使用统一的作品处理和发送函数
            config = FilterConfig(
                r18_mode=self.pixiv_config.r18_mode,
                ai_filter_mode=self.pixiv_config.ai_filter_mode,
                display_tag_str=display_tags,
                return_count=self.pixiv_config.return_count,
                logger=logger,
                show_filter_result=self.pixiv_config.show_filter_result,
                excluded_tags=exclude_tags or [],
                forward_threshold=self.pixiv_config.forward_threshold,
                show_details=self.pixiv_config.show_details,
            )

            async for result in process_and_send_illusts(
                initial_novels,  # 传入所有初始小说，让process_and_send_illusts内部处理过滤和选择
                config,
                self.client,
                event,
                build_detail_message,
                send_pixiv_image,
                send_forward_message,
                is_novel=True,
            ):
                yield result

        except Exception as e:
            logger.error(f"Pixiv 插件：搜索小说时发生错误 - {e}")
            yield event.plain_result(f"搜索小说时发生错误: {str(e)}")

    async def pixiv_novel_recommended(self, event: AstrMessageEvent):
        """获取 Pixiv 推荐小说"""
        logger.info("Pixiv 插件：正在获取推荐小说")

        # 验证是否已认证
        if not await self.client_wrapper.authenticate():
            yield event.plain_result(self.pixiv_config.get_auth_error_message())
            return

        try:
            # 调用 API 获取推荐小说
            recommend_result = await self.client_wrapper.call_pixiv_api(
                self.client.novel_recommended,
                include_ranking_label=True,
                filter="for_ios",
            )
            initial_novels = recommend_result.novels if recommend_result.novels else []

            if not initial_novels:
                yield event.plain_result("未能获取到推荐小说。")
                return

            # 使用统一的作品处理和发送函数
            config = FilterConfig(
                r18_mode=self.pixiv_config.r18_mode,
                ai_filter_mode=self.pixiv_config.ai_filter_mode,
                display_tag_str="推荐小说",
                return_count=self.pixiv_config.return_count,
                logger=logger,
                show_filter_result=self.pixiv_config.show_filter_result,
                excluded_tags=[],
                forward_threshold=self.pixiv_config.forward_threshold,
                show_details=self.pixiv_config.show_details,
            )

            async for result in process_and_send_illusts(
                initial_novels,
                config,
                self.client,
                event,
                build_detail_message,
                send_pixiv_image,
                send_forward_message,
                is_novel=True,
            ):
                yield result

        except Exception as e:
            logger.error(f"Pixiv 插件：获取推荐小说时发生错误 - {e}")
            yield event.plain_result(f"获取推荐小说时发生错误: {str(e)}")

    async def pixiv_novel_new(self, event: AstrMessageEvent, max_novel_id: str = ""):
        """获取大家的新小说"""
        # 检查是否为帮助请求
        if max_novel_id.strip().lower() == "help":
            help_text = get_help_message(
                "pixiv_novel_new", "新小说帮助消息加载失败，请检查配置文件。"
            )
            yield event.plain_result(help_text)
            return

        # 验证最大小说ID（如果提供）
        if max_novel_id and not max_novel_id.isdigit():
            yield event.plain_result("最大小说ID必须为数字。")
            return

        # 验证是否已认证
        if not await self.client_wrapper.authenticate():
            yield event.plain_result(self.pixiv_config.get_auth_error_message())
            return

        logger.info(f"Pixiv 插件：正在获取新小说 - 最大ID: {max_novel_id or '最新'}")

        try:
            # 调用 API 获取新小说
            new_novels_result = await self.client_wrapper.call_pixiv_api(
                self.client.novel_new,
                filter="for_ios",
                max_novel_id=int(max_novel_id) if max_novel_id else None,
            )

            if not new_novels_result or not hasattr(new_novels_result, "novels"):
                yield event.plain_result("未能获取到新小说。")
                return

            initial_novels = (
                new_novels_result.novels if new_novels_result.novels else []
            )

            if not initial_novels:
                yield event.plain_result("暂无新小说。")
                return

            # 使用统一的作品处理和发送函数
            config = FilterConfig(
                r18_mode=self.pixiv_config.r18_mode,
                ai_filter_mode=self.pixiv_config.ai_filter_mode,
                display_tag_str="新小说",
                return_count=self.pixiv_config.return_count,
                logger=logger,
                show_filter_result=self.pixiv_config.show_filter_result,
                excluded_tags=[],
                forward_threshold=self.pixiv_config.forward_threshold,
                show_details=self.pixiv_config.show_details,
            )

            async for result in process_and_send_illusts(
                initial_novels,
                config,
                self.client,
                event,
                build_detail_message,
                send_pixiv_image,
                send_forward_message,
                is_novel=True,
            ):
                yield result

        except Exception as e:
            logger.error(f"Pixiv 插件：获取新小说时发生错误 - {e}")
            yield event.plain_result(f"获取新小说时发生错误: {str(e)}")

    async def pixiv_novel_series(self, event: AstrMessageEvent, series_id: str = ""):
        """获取小说系列详情"""
        # 检查是否提供了系列 ID
        if not series_id.strip() or series_id.strip().lower() == "help":
            help_text = get_help_message(
                "pixiv_novel_series", "小说系列帮助消息加载失败，请检查配置文件。"
            )
            yield event.plain_result(help_text)
            return

        # 验证系列 ID 是否为数字
        if not series_id.isdigit():
            yield event.plain_result("小说系列 ID 必须为数字。")
            return

        # 验证是否已认证
        if not await self.client_wrapper.authenticate():
            yield event.plain_result(self.pixiv_config.get_auth_error_message())
            return

        logger.info(f"Pixiv 插件：正在获取小说系列详情 - ID: {series_id}")

        try:
            # 调用 API 获取小说系列详情
            series_result = await self.client_wrapper.call_pixiv_api(
                self.client.novel_series, series_id=int(series_id), filter="for_ios"
            )

            if not series_result:
                yield event.plain_result(f"未找到小说系列 ID {series_id}。")
                return

            # 构建系列信息
            series_title = getattr(series_result, "title", "未知系列")
            series_description = getattr(series_result, "description", "无描述")
            novels = getattr(series_result, "novels", [])

            series_info = f"小说系列: {series_title}\n"
            series_info += f"系列ID: {series_id}\n"
            series_info += f"描述: {series_description}\n"
            series_info += f"作品数量: {len(novels)}\n\n"

            if novels:
                series_info += "系列作品列表:\n"
                for i, novel in enumerate(novels[:10], 1):  # 限制显示前10部
                    novel_title = getattr(novel, "title", "未知标题")
                    novel_id = getattr(novel, "id", "未知ID")
                    series_info += f"{i}. {novel_title} (ID: {novel_id})\n"

                if len(novels) > 10:
                    series_info += f"... 还有 {len(novels) - 10} 部作品\n"

            yield event.plain_result(series_info)

        except Exception as e:
            logger.error(f"Pixiv 插件：获取小说系列详情时发生错误 - {e}")
            yield event.plain_result(f"获取小说系列详情时发生错误: {str(e)}")

    async def pixiv_novel_comments(
        self, event: AstrMessageEvent, novel_id: str = "", offset: str = ""
    ):
        """获取指定小说的评论"""
        # 检查是否提供了小说 ID
        if not novel_id.strip() or novel_id.strip().lower() == "help":
            help_text = get_help_message(
                "pixiv_novel_comments", "小说评论帮助消息加载失败，请检查配置文件。"
            )
            yield event.plain_result(help_text)
            return

        # 验证小说 ID 是否为数字
        if not novel_id.isdigit():
            yield event.plain_result("小说 ID 必须为数字。")
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
            f"Pixiv 插件：正在获取小说评论 - ID: {novel_id}, 偏移量: {offset or '0'}"
        )

        try:
            # 使用 asyncio.to_thread 包装同步 API 调用
            try:
                comments_result = await self.client_wrapper.call_pixiv_api(
                    self.client.novel_comments,
                    novel_id=int(novel_id),
                    offset=int(offset) if offset else None,
                    include_total_comments=True,
                )
            except Exception as api_error:
                # 捕获API调用本身的错误，特别是JSON解析错误
                error_msg = str(api_error)
                if "parse_json() error" in error_msg:
                    logger.error(
                        f"Pixiv 插件：小说评论API返回空响应或非JSON格式 - {error_msg}"
                    )

                    # 添加调试代码：尝试直接获取原始响应
                    try:
                        import requests

                        url = f"{self.client.hosts}/v1/novel/comments"
                        params = {
                            "novel_id": novel_id,
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
                            f"Pixiv 插件：调试信息 - 小说评论原始响应状态码: {debug_response.status_code}"
                        )
                        logger.error(
                            f"Pixiv 插件：调试信息 - 小说评论原始响应内容: {debug_response.text[:500]}"
                        )

                        yield event.plain_result(
                            f"获取小说评论时发生错误: API返回空响应，可能是该小说没有评论或API限制\n调试信息: 状态码 {debug_response.status_code}"
                        )
                    except Exception as debug_e:
                        logger.error(f"Pixiv 插件：小说评论调试请求失败 - {debug_e}")
                        yield event.plain_result(
                            "获取小说评论时发生错误: API返回空响应，可能是该小说没有评论或API限制"
                        )
                    return
                    yield event.plain_result(
                        "获取小说评论时发生错误: API返回空响应，可能是该小说没有评论或API限制"
                    )
                    return
                else:
                    # 重新抛出其他类型的错误
                    raise api_error

            # 检查返回结果是否有效
            if not comments_result:
                yield event.plain_result(f"未找到小说 ID {novel_id} 的评论。")
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
                    f"Pixiv 插件：小说评论API返回结构异常 - 类型: {type(comments_result)}, 内容: {str(comments_result)[:200]}"
                )
                yield event.plain_result("获取小说评论时发生错误: API返回结构异常")
                return

            if not comments:
                yield event.plain_result(f"小说 ID {novel_id} 暂无评论。")
                return

            # 构建评论信息
            comment_info = f"小说 ID: {novel_id} 的评论 (共 {total_comments} 条)\n\n"

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
                comment_info += f"\n已显示前 {max_comments} 条评论，使用 /pixiv_novel_comments {novel_id} {next_offset} 查看更多。"

            yield event.plain_result(comment_info)

        except Exception as e:
            logger.error(f"Pixiv 插件：获取小说评论时发生错误 - {e}")
            import traceback

            logger.error(traceback.format_exc())
            yield event.plain_result(f"获取小说评论时发生错误: {str(e)}")

    async def pixiv_novel_download(self, event: AstrMessageEvent, novel_id: str = ""):
        """根据ID下载Pixiv小说为pdf文件"""
        cleaned_id = novel_id.strip()
        if not cleaned_id or not cleaned_id.isdigit():
            yield event.plain_result(
                "请输入有效的小说ID。用法: /pixiv_novel_download <小说ID>"
            )
            return

        if not await self.client_wrapper.authenticate():
            yield event.plain_result(self.pixiv_config.get_auth_error_message())
            return

        logger.info(f"Pixiv 插件：正在准备下载小说并转换为PDF - ID: {cleaned_id}")

        try:
            # 获取小说详情和内容
            novel_detail_result = await asyncio.to_thread(
                self.client.novel_detail, cleaned_id
            )
            if not novel_detail_result or not novel_detail_result.novel:
                yield event.plain_result(f"未找到ID为 {cleaned_id} 的小说。")
                return
            novel_title = novel_detail_result.novel.title

            novel_content_result = await asyncio.to_thread(
                self.client.webview_novel, cleaned_id
            )
            if not novel_content_result or not hasattr(novel_content_result, "text"):
                yield event.plain_result(f"无法获取ID为 {cleaned_id} 的小说内容。")
                return
            novel_text = novel_content_result.text

            novel_text = novel_content_result.text

            # 生成 PDF 字节流
            pdf_bytes = await asyncio.to_thread(
                self.create_pdf_from_text, novel_title, novel_text
            )
            logger.info("Pixiv 插件：小说内容已成功转换为 PDF 字节流。")

            # 清理文件名
            safe_title = "".join(
                c for c in novel_title if c.isalnum() or c in (" ", "_")
            ).rstrip()
            if not safe_title:
                safe_title = "novel"
            file_name = f"{safe_title}_{cleaned_id}.pdf"

            # --- PDF 内存加密逻辑 ---
            password = hashlib.md5(cleaned_id.encode()).hexdigest()
            final_pdf_bytes = None
            password_notice = ""

            try:
                from PyPDF2 import PdfReader, PdfWriter

                reader = PdfReader(io.BytesIO(pdf_bytes))
                writer = PdfWriter()
                for page in reader.pages:
                    writer.add_page(page)
                writer.encrypt(password)

                # 使用内存流保存加密后的PDF
                with io.BytesIO() as bytes_stream:
                    writer.write(bytes_stream)
                    final_pdf_bytes = bytes_stream.getvalue()

                logger.info("Pixiv 插件：PDF 已成功在内存中加密。")
                password_notice = f"PDF已加密，密码为小说ID的MD5值: {password}"

            except ImportError:
                logger.warning("PyPDF2 未安装，无法加密PDF。将发送未加密的文件。")
                final_pdf_bytes = pdf_bytes  # 回退到未加密版本
                password_notice = "【注意】PyPDF2库未安装，本次发送的PDF未加密。"

            # 将文件内容编码为 Base64 URI
            file_base64 = base64.b64encode(final_pdf_bytes).decode("utf-8")
            base64_uri = f"base64://{file_base64}"

            logger.info("Pixiv 插件：PDF 内容已编码为 Base64，准备发送。")

            # 检查平台并发送文件
            if event.get_platform_name() == "aiocqhttp" and event.get_group_id():
                from astrbot.core.platform.sources.aiocqhttp.aiocqhttp_message_event import (
                    AiocqhttpMessageEvent,
                )

                if isinstance(event, AiocqhttpMessageEvent):
                    client = event.bot
                    group_id = event.get_group_id()
                    try:
                        logger.info(
                            f"Pixiv 插件：使用 aiocqhttp API (Base64) 上传群文件 {file_name} 到群组 {group_id}"
                        )
                        await client.upload_group_file(
                            group_id=group_id, file=base64_uri, name=file_name
                        )
                        logger.info(
                            "Pixiv 插件：成功调用 aiocqhttp API (Base64) 发送PDF。"
                        )
                        # 发送密码提示
                        if password_notice:
                            yield event.plain_result(password_notice)
                        return
                    except Exception as api_e:
                        logger.error(
                            f"Pixiv 插件：调用 aiocqhttp API (Base64) 发送文件失败: {api_e}"
                        )
                        yield event.plain_result(
                            f"通过高速接口发送文件失败: {api_e}。请联系管理员检查后端配置。"
                        )
                        return

            logger.info(
                "非 aiocqhttp 平台或私聊，尝试使用标准 File 组件 (Base64) 发送。"
            )
            yield event.chain_result([File(name=file_name, file=base64_uri)])
            if password_notice:
                yield event.plain_result(password_notice)

        except FileNotFoundError as e:
            logger.error(f"无法生成PDF: {e}")
            yield event.plain_result(
                "无法生成PDF：所需的中文字体文件下载失败或不存在。请检查网络连接或联系管理员。"
            )
        except Exception as e:
            logger.error(f"Pixiv 插件：下载或转换小说为PDF时发生错误 - {e}")
            yield event.plain_result(f"处理小说时发生错误: {str(e)}")

    def create_pdf_from_text(self, title: str, text: str) -> bytes:
        """使用 fpdf2 将文本转换为 PDF 字节流"""
        if not self.font_path.exists():
            logger.error(f"字体文件不存在，无法创建PDF: {self.font_path}")
            raise FileNotFoundError(f"字体文件不存在: {self.font_path}")

        pdf = FPDF()
        pdf.add_page()

        # 添加并使用我们自己下载的字体
        pdf.add_font("SmileySans", "", str(self.font_path), uni=True)
        pdf.set_font("SmileySans", size=20)

        # 添加标题
        pdf.multi_cell(0, 10, title, align="C")
        pdf.ln(10)

        # 设置正文样式
        pdf.set_font_size(12)

        # 添加正文
        pdf.multi_cell(0, 10, text)

        # 返回 PDF 内容的字节
        return pdf.output(dest="S")
