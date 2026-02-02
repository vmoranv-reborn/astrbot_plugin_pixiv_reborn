from astrbot.api.event import AstrMessageEvent
from astrbot.api import logger
from ..utils.help import get_help_message


class MiscHandler:
    """
    Pixiv 杂项功能处理器
    负责处理 Pixiv 插画趋势标签获取和 AI 作品显示设置等功能
    """

    def __init__(self, client_wrapper, pixiv_config):
        self.client_wrapper = client_wrapper
        self.client = client_wrapper.client_api
        self.pixiv_config = pixiv_config

    async def pixiv_trending_tags(self, event: AstrMessageEvent):
        """获取 Pixiv 插画趋势标签"""
        logger.info("Pixiv 插件：正在获取插画趋势标签...")

        # 验证是否已认证 (调用 wrapper)
        if not await self.client_wrapper.authenticate():
            yield event.plain_result(self.pixiv_config.get_auth_error_message())
            return

        try:
            # 调用 API (调用 wrapper)
            result = await self.client_wrapper.call_pixiv_api(
                self.client.trending_tags_illust, filter="for_ios"
            )

            if not result or not result.trend_tags:
                yield event.plain_result("未能获取到趋势标签，可能是 API 暂无数据。")
                return

            # 格式化标签信息
            tags_list = []
            for tag_info in result.trend_tags:
                tag_name = tag_info.get("tag", "未知标签")
                translated_name = tag_info.get("translated_name")
                if translated_name and translated_name != tag_name:
                    tags_list.append(f"- {tag_name} ({translated_name})")
                else:
                    tags_list.append(f"- {tag_name}")

            if not tags_list:
                yield event.plain_result("未能解析任何趋势标签。")
                return

            # 构建最终消息
            message = "# Pixiv 插画趋势标签\n\n"
            message += "\n".join(tags_list)

            yield event.plain_result(message)

        except Exception as e:
            logger.error(f"Pixiv 插件：获取趋势标签时发生错误 - {e}")
            yield event.plain_result(f"获取趋势标签时发生错误: {str(e)}")

    async def pixiv_ai_show_settings(self, event: AstrMessageEvent, setting: str = ""):
        """设置是否展示AI生成作品"""
        # 检查是否为帮助请求
        if not setting.strip() or setting.strip().lower() == "help":
            help_text = get_help_message(
                "pixiv_ai_show_settings", "AI作品设置帮助消息加载失败，请检查配置文件。"
            )
            yield event.plain_result(help_text)
            return

        # 验证设置参数
        valid_settings = ["true", "false", "1", "0", "yes", "no", "on", "off"]
        if setting.lower() not in valid_settings:
            yield event.plain_result(
                f"无效的设置值: {setting}\n可用值: {', '.join(valid_settings)}"
            )
            return

        # 转换为字符串 "true" 或 "false" (API要求)
        setting_str = (
            "true" if setting.lower() in ["true", "1", "yes", "on"] else "false"
        )

        # 验证是否已认证
        if not await self.client_wrapper.authenticate():
            yield event.plain_result(self.pixiv_config.get_auth_error_message())
            return

        logger.info(f"Pixiv 插件：正在设置AI作品显示 - 设置: {setting_str}")

        try:
            # 调用 API
            result = await self.client_wrapper.call_pixiv_api(
                self.client.user_edit_ai_show_settings, setting=setting_str
            )

            if result and hasattr(result, "error") and result.error:
                yield event.plain_result(
                    f"设置AI作品显示失败: {result.error.get('message', '未知错误')}"
                )
                return

            # 同时更新本地配置
            if setting_str == "true":
                self.pixiv_config.ai_filter_mode = "显示 AI 作品"
                mode_desc = "显示AI作品"
            else:
                self.pixiv_config.ai_filter_mode = "过滤 AI 作品"
                mode_desc = "过滤AI作品"

            # 保存配置
            self.pixiv_config.save_config()

            yield event.plain_result(
                f"AI作品设置已更新为: {mode_desc}\n本地配置已同步更新。"
            )

        except Exception as e:
            logger.error(f"Pixiv 插件：设置AI作品显示时发生错误 - {e}")
            import traceback

            logger.error(traceback.format_exc())
            yield event.plain_result(f"设置AI作品显示时发生错误: {str(e)}")
