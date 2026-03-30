from typing import Any, List
import hashlib
import io
import base64
from pathlib import Path
from pydantic import Field
from pydantic.dataclasses import dataclass
from fpdf import FPDF

from astrbot.core.agent.run_context import ContextWrapper
from astrbot.core.agent.tool import FunctionTool, ToolExecResult
from astrbot.core.astr_agent_context import AstrAgentContext
from astrbot.api import logger

from .tag import (
    build_detail_message,
    FilterConfig,
    filter_illusts_with_reason,
    process_and_send_illusts_sorted,
)
from .pixiv_utils import (
    send_pixiv_image,
    send_forward_message,
    generate_safe_filename,
)


@dataclass
class PixivIllustSearchTool(FunctionTool[AstrAgentContext]):
    """
    Pixiv插画搜索工具
    """

    pixiv_client: Any = None
    pixiv_config: Any = None
    pixiv_client_wrapper: Any = None
    name: str = "pixiv_search_illust"
    description: str = (
        "【图片/插画搜索专用工具】用于在Pixiv上搜索二次元插画、动漫图片、壁纸等。"
        "当用户想要：搜图、找图、来张图、发张图、看图、要壁纸、找插画、"
        "搜索某个角色/作品的图片（如'初音未来的图'、'原神壁纸'）时，必须使用此工具。"
        "此工具专门返回图片，不是网页搜索。任何涉及图片、插画、二次元图的请求都应优先使用本工具。"
    )
    parameters: dict = Field(
        default_factory=lambda: {
            "type": "object",
            "properties": {
                "query": {
                    "type": "string",
                    "description": "搜索关键词或标签，直接使用用户输入的原文。例如：初音ミク、原神、可爱女孩等",
                },
                "count": {
                    "type": "integer",
                    "description": (
                        "【必填】返回图片数量。"
                        "必须根据用户请求的数量填写！"
                        "例如：'来两张图'→count=2，'给我三张'→count=3，'来点图'→count=3。"
                        "如果用户没有明确说数量，默认设为1。最小1，最大5。"
                    ),
                    "minimum": 1,
                    "maximum": 5,
                    "default": 1,
                },
                "filters": {
                    "type": "string",
                    "description": "过滤条件：'safe'(全年龄)、'r18'(限制级)。默认为safe",
                },
            },
            "required": ["query"],
        }
    )

    async def call(
        self, context: ContextWrapper[AstrAgentContext], **kwargs
    ) -> ToolExecResult:
        try:
            query = kwargs.get("query", "")
            count = min(max(int(kwargs.get("count", 1)), 1), 5)
            logger.info(f"Pixiv插画搜索工具：搜索 '{query}'，数量: {count}")

            if not self.pixiv_client:
                return "错误: Pixiv客户端未初始化"

            if (
                self.pixiv_client_wrapper
                and not await self.pixiv_client_wrapper.authenticate()
            ):
                if self.pixiv_config and hasattr(
                    self.pixiv_config, "get_auth_error_message"
                ):
                    return self.pixiv_config.get_auth_error_message()
                return "Pixiv API 认证失败，请检查配置中的凭据信息。"

            tags = query.strip()
            return await self._search_illust(tags, query, context, count)

        except Exception as e:
            logger.error(f"Pixiv插画搜索失败: {e}")
            return f"搜索失败: {str(e)}"

    async def _search_illust(self, tags, query, context, count=1):
        """按热度（收藏数）搜索插画 - 一周内"""
        import asyncio

        all_illusts = []
        page_count = 0
        next_params = None
        pages_to_fetch = 5

        while page_count < pages_to_fetch:
            try:
                if page_count == 0:
                    search_result = await asyncio.to_thread(
                        self.pixiv_client.search_illust,
                        tags,
                        search_target="partial_match_for_tags",
                        sort="date_desc",
                        filter="for_ios",
                        duration="within_last_week",  # 一周内
                    )
                else:
                    if not next_params:
                        break
                    search_result = await asyncio.to_thread(
                        self.pixiv_client.search_illust, **next_params
                    )

                if not search_result or not hasattr(search_result, "illusts"):
                    break

                if search_result.illusts:
                    all_illusts.extend(search_result.illusts)
                    page_count += 1
                else:
                    break

                if hasattr(search_result, "next_url") and search_result.next_url:
                    next_params = self.pixiv_client.parse_qs(search_result.next_url)
                else:
                    break

                await asyncio.sleep(0.2)
            except Exception as e:
                logger.error(f"热度搜索第 {page_count + 1} 页出错: {e}")
                break

        if not all_illusts:
            return f"未找到关于 '{query}' 的插画。"

        sorted_illusts = sorted(
            all_illusts, key=lambda x: getattr(x, "total_bookmarks", 0), reverse=True
        )

        event = self._get_event(context)
        if event:
            return await self._send_pixiv_result(
                event, sorted_illusts, query, tags, count
            )
        else:
            return self._format_text_results(sorted_illusts, query, tags)

    async def _send_pixiv_result(self, event, items, query, tags, count=1):
        """发送按热度排序的结果"""
        logger.info(f"PixivIllustSearchTool: 准备发送 {count} 张图片")
        config = FilterConfig(
            r18_mode=self.pixiv_config.r18_mode if self.pixiv_config else "过滤 R18",
            filter_r18g_only=self.pixiv_config.filter_r18g_only
            if self.pixiv_config
            else False,
            ai_filter_mode=self.pixiv_config.ai_filter_mode
            if self.pixiv_config
            else "过滤 AI 作品",
            display_tag_str=f"搜索:{query}",
            return_count=count,
            logger=logger,
            show_filter_result=False,
            excluded_tags=[],
            forward_threshold=self.pixiv_config.forward_threshold
            if self.pixiv_config
            else False,
            show_details=self.pixiv_config.show_details if self.pixiv_config else True,
        )

        filtered_items, _ = filter_illusts_with_reason(items, config)
        if not filtered_items:
            return "找到插画但被过滤了 (可能是R18或AI作品)。"

        if not hasattr(event, "send"):
            return self._format_text_results(filtered_items, query, tags)

        expected_count = min(len(filtered_items), config.return_count)
        sent_batches = 0

        try:
            async for result in process_and_send_illusts_sorted(
                items,
                config,
                self.pixiv_client,
                event,
                build_detail_message,
                send_pixiv_image,
                send_forward_message,
                is_novel=False,
            ):
                try:
                    await event.send(result)
                    sent_batches += 1
                except Exception as e:
                    logger.warning(f"发送图片失败: {e}")

            if sent_batches > 0:
                mode = "转发消息" if config.forward_threshold else "普通消息"
                return (
                    f"🔥 找到了！为您发送了「{query}」一周内最热门的"
                    f" {expected_count} 张作品（{mode}）。"
                )

            return "找到插画但发送失败，请稍后再试。"
        except Exception as e:
            logger.error(f"发送失败: {e}")
            return "找到插画但发送过程中出现异常。"

    def _get_event(self, context):
        try:
            agent_context = context.context if hasattr(context, "context") else context
            if hasattr(context, "event") and context.event:
                return context.event
            elif hasattr(agent_context, "event") and agent_context.event:
                return agent_context.event
        except Exception:
            pass
        return None

    def _format_text_results(self, items, query, tags):
        result = "找到以下插画:\n"
        for i, item in enumerate(items[:5], 1):
            title = getattr(item, "title", "未知标题")
            result += f"{i}. {title} (ID: {item.id})\n"
        return result


@dataclass
class PixivNovelSearchTool(FunctionTool[AstrAgentContext]):
    """
    Pixiv小说搜索工具
    """

    pixiv_client: Any = None
    pixiv_config: Any = None
    pixiv_client_wrapper: Any = None

    name: str = "pixiv_search_novel"
    description: str = "Pixiv小说搜索工具。用于搜索Pixiv上的小说，或者通过ID直接下载小说。支持输入关键词或纯数字ID。"
    parameters: dict = Field(
        default_factory=lambda: {
            "type": "object",
            "properties": {
                "query": {
                    "type": "string",
                    "description": "搜索关键词或小说ID（纯数字）。",
                },
                "filters": {
                    "type": "string",
                    "description": "过滤条件，如 'safe', 'r18' 等",
                },
            },
            "required": ["query"],
        }
    )

    async def call(
        self, context: ContextWrapper[AstrAgentContext], **kwargs
    ) -> ToolExecResult:
        try:
            query = kwargs.get("query", "")
            logger.info(f"Pixiv小说搜索工具：搜索 '{query}'")

            if not self.pixiv_client:
                return "错误: Pixiv客户端未初始化"

            if (
                self.pixiv_client_wrapper
                and not await self.pixiv_client_wrapper.authenticate()
            ):
                if self.pixiv_config and hasattr(
                    self.pixiv_config, "get_auth_error_message"
                ):
                    return self.pixiv_config.get_auth_error_message()
                return "Pixiv API 认证失败，请检查配置中的凭据信息。"

            tags = query.strip()
            return await self._search_novel(tags, query, context)

        except Exception as e:
            logger.error(f"Pixiv小说搜索失败: {e}")
            return f"搜索失败: {str(e)}"

    async def _search_novel(self, tags, query, context):
        import asyncio

        # ID 检查
        if query.isdigit():
            logger.info(f"检测到小说ID {query}")
            try:
                novel_detail = await asyncio.to_thread(
                    self.pixiv_client.novel_detail, int(query)
                )
                if novel_detail and novel_detail.novel:
                    event = self._get_event(context)
                    if event:
                        return await self._send_novel_result(
                            event, [novel_detail.novel], query, tags
                        )
                    else:
                        return f"找到小说: {novel_detail.novel.title} (ID: {query})，但无法发送文件(无事件上下文)。"
                else:
                    return f"未找到ID为 {query} 的小说。"
            except Exception as e:
                return f"获取小说详情失败: {str(e)}"

        # 标签搜索
        try:
            search_result = await asyncio.to_thread(
                self.pixiv_client.search_novel,
                tags,
                search_target="partial_match_for_tags",
            )

            if search_result and search_result.novels:
                event = self._get_event(context)
                if event:
                    return await self._send_novel_result(
                        event, search_result.novels, query, tags
                    )
                else:
                    return self._format_text_results(search_result.novels, query, tags)
            else:
                return f"未找到关于 '{query}' 的小说。"
        except Exception as e:
            return f"API调用错误: {str(e)}"

    async def _send_novel_result(self, event, items, query, tags):
        import asyncio

        if not items:
            return "未找到小说。"

        selected_item = items[0]  # 取第一个
        novel_id = str(selected_item.id)
        novel_title = selected_item.title

        logger.info(f"准备下载小说 {novel_title} (ID: {novel_id})")

        try:
            novel_content_result = await asyncio.to_thread(
                self.pixiv_client.webview_novel, novel_id
            )
            if not novel_content_result or not hasattr(novel_content_result, "text"):
                return f"无法获取小说内容 (ID: {novel_id})。"

            novel_text = novel_content_result.text

            try:
                pdf_bytes = await asyncio.to_thread(
                    self._create_pdf_from_text, novel_title, novel_text
                )
            except FileNotFoundError:
                return "无法生成PDF：字体文件丢失。"
            except Exception as e:
                return f"生成PDF失败: {str(e)}"

            # 加密
            password = hashlib.md5(novel_id.encode()).hexdigest()
            final_pdf_bytes = pdf_bytes
            password_notice = ""
            try:
                from PyPDF2 import PdfReader, PdfWriter

                reader = PdfReader(io.BytesIO(pdf_bytes))
                writer = PdfWriter()
                for page in reader.pages:
                    writer.add_page(page)
                writer.encrypt(password)
                with io.BytesIO() as bs:
                    writer.write(bs)
                    final_pdf_bytes = bs.getvalue()
                password_notice = f"PDF已加密，密码: {password}"
            except Exception:
                password_notice = "PDF未加密。"

            # 发送
            safe_title = generate_safe_filename(novel_title, "novel")
            file_name = f"{safe_title}_{novel_id}.pdf"

            file_sent = False
            if event.get_platform_name() == "aiocqhttp" and event.get_group_id():
                try:
                    from astrbot.core.platform.sources.aiocqhttp.aiocqhttp_message_event import (
                        AiocqhttpMessageEvent,
                    )

                    if isinstance(event, AiocqhttpMessageEvent):
                        client_bot = event.bot
                        group_id = event.get_group_id()
                        file_base64 = base64.b64encode(final_pdf_bytes).decode("utf-8")
                        await client_bot.upload_group_file(
                            group_id=group_id,
                            file=f"base64://{file_base64}",
                            name=file_name,
                        )
                        file_sent = True
                except Exception as e:
                    logger.error(f"群文件上传失败: {e}")

            author = (
                getattr(selected_item.user, "name", "未知作者")
                if hasattr(selected_item, "user")
                else "未知作者"
            )

            if file_sent:
                return f"已下载小说：\n**{novel_title}** - {author}\nID: {novel_id}\n文件已上传到群文件。\n{password_notice}\n(任务完成)"
            else:
                return f"已找到小说：\n**{novel_title}** - {author}\nID: {novel_id}\n无法发送文件，请尝试手动下载。\n(任务完成)"

        except Exception as e:
            logger.error(f"处理小说失败: {e}")
            return f"处理小说失败: {str(e)}"

    def _create_pdf_from_text(self, title: str, text: str) -> bytes:
        font_path = Path(__file__).parent.parent / "data" / "SmileySans-Oblique.ttf"
        if not font_path.exists():
            raise FileNotFoundError(f"字体文件不存在: {font_path}")

        pdf = FPDF()
        pdf.add_page()
        pdf.add_font("SmileySans", "", str(font_path), uni=True)
        pdf.set_font("SmileySans", size=20)
        pdf.multi_cell(0, 10, title, align="C")
        pdf.ln(10)
        pdf.set_font_size(12)
        pdf.multi_cell(0, 10, text)
        return pdf.output(dest="S")

    def _get_event(self, context):
        try:
            agent_context = context.context if hasattr(context, "context") else context
            if hasattr(context, "event") and context.event:
                return context.event
            elif hasattr(agent_context, "event") and agent_context.event:
                return agent_context.event
        except Exception:
            pass
        return None

    def _format_text_results(self, items, query, tags):
        result = "找到以下小说:\n"
        for i, item in enumerate(items[:5], 1):
            title = getattr(item, "title", "未知标题")
            result += f"{i}. {title} (ID: {item.id})\n"
        return result


def create_pixiv_llm_tools(
    pixiv_client=None, pixiv_config=None, pixiv_client_wrapper=None
) -> List[FunctionTool]:
    """
    创建Pixiv相关的LLM工具列表
    """
    logger.info(
        "创建Pixiv LLM工具，pixiv_client: %s, wrapper: %s"
        % (
            "已设置" if pixiv_client else "未设置",
            "已设置" if pixiv_client_wrapper else "未设置",
        )
    )

    tools = [
        PixivIllustSearchTool(
            pixiv_client=pixiv_client,
            pixiv_config=pixiv_config,
            pixiv_client_wrapper=pixiv_client_wrapper,
        ),
        PixivNovelSearchTool(
            pixiv_client=pixiv_client,
            pixiv_config=pixiv_config,
            pixiv_client_wrapper=pixiv_client_wrapper,
        ),
    ]
    logger.info(f"已创建 {len(tools)} 个LLM工具")
    return tools
