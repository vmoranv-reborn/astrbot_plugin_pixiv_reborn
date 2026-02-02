import asyncio
from astrbot.api.event import AstrMessageEvent
from astrbot.api import logger

from ..utils.tag import (
    build_detail_message,
    FilterConfig,
    validate_and_process_tags,
    process_and_send_illusts,
    filter_illusts_with_reason,
    process_and_send_illusts_sorted,
)
from ..utils.pixiv_utils import send_pixiv_image, send_forward_message

from ..utils.help import get_help_message


class IllustHandler:
    def __init__(self, client_wrapper, pixiv_config):
        """
        初始化插画处理器
        :param client_wrapper: 封装好的 PixivClientWrapper 实例 (Core)
        :param config: PixivConfig 实例 (Config)
        """

        self.client_wrapper = client_wrapper
        self.client = client_wrapper.client_api
        self.pixiv_config = pixiv_config

    async def pixiv_search_illust(self, event: AstrMessageEvent, tags: str = ""):
        """处理 /pixiv 命令，默认为标签搜索功能"""
        # 清理标签字符串，并检查是否为空或为 "help"
        cleaned_tags = tags.strip()

        if cleaned_tags.lower() == "help":
            yield self.pixiv_help(event)
            return

        if not cleaned_tags:
            logger.info("Pixiv 插件：用户未提供搜索标签或标签为空，返回帮助信息。")
            yield event.plain_result(
                "请输入要搜索的标签。使用 `/pixiv_help` 查看帮助。\n"
                + self.pixiv_config.get_auth_error_message()
            )
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

        # 标签搜索处理
        logger.info(
            f"Pixiv 插件：正在搜索标签 - {search_tags}，排除标签 - {exclude_tags}"
        )
        try:
            # 包装同步搜索调用
            search_result = await self.client_wrapper.call_pixiv_api(
                self.client.search_illust,
                search_tags,
                search_target="partial_match_for_tags",
            )
            initial_illusts = search_result.illusts if search_result.illusts else []

            if not initial_illusts:
                yield event.plain_result("未找到相关插画。")
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
            logger.error(f"Pixiv 插件：搜索插画时发生错误 - {e}")
            yield event.plain_result(f"搜索插画时发生错误: {str(e)}")

    async def pixiv_illust_new(
        self,
        event: AstrMessageEvent,
        content_type: str = "illust",
        max_illust_id: str = "",
    ):
        """获取大家的新插画作品"""
        # 检查是否为帮助请求
        if content_type.strip().lower() == "help":
            help_text = get_help_message(
                "pixiv_illust_new", "新插画作品帮助消息加载失败，请检查配置文件。"
            )
            yield event.plain_result(help_text)
            return

        # 验证内容类型
        valid_content_types = ["illust", "manga"]
        if content_type not in valid_content_types:
            yield event.plain_result(
                f"无效的内容类型: {content_type}\n可用类型: {', '.join(valid_content_types)}"
            )
            return

        # 验证最大作品ID（如果提供）
        if max_illust_id and not max_illust_id.isdigit():
            yield event.plain_result("最大作品ID必须为数字。")
            return

        # 验证是否已认证
        if not await self.client_wrapper.authenticate():
            yield event.plain_result(self.pixiv_config.get_auth_error_message())
            return

        logger.info(
            f"Pixiv 插件：正在获取新插画作品 - 类型: {content_type}, 最大ID: {max_illust_id or '最新'}"
        )

        try:
            # 调用 API 获取新插画作品
            new_illusts_result = await self.client_wrapper.call_pixiv_api(
                self.client.illust_new,
                content_type=content_type,
                filter="for_ios",
                max_illust_id=int(max_illust_id) if max_illust_id else None,
            )

            if not new_illusts_result or not hasattr(new_illusts_result, "illusts"):
                yield event.plain_result("未能获取到新插画作品。")
                return

            initial_illusts = (
                new_illusts_result.illusts if new_illusts_result.illusts else []
            )

            if not initial_illusts:
                yield event.plain_result("暂无新插画作品。")
                return

            # 使用统一的作品处理和发送函数
            config = FilterConfig(
                r18_mode=self.pixiv_config.r18_mode,
                ai_filter_mode=self.pixiv_config.ai_filter_mode,
                display_tag_str=f"新{content_type}",
                return_count=self.pixiv_config.return_count,
                logger=logger,
                show_filter_result=self.pixiv_config.show_filter_result,
                excluded_tags=[],
                forward_threshold=self.pixiv_config.forward_threshold,
                show_details=self.pixiv_config.show_details,
            )

            async for result in process_and_send_illusts(
                initial_illusts,
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
            logger.error(f"Pixiv 插件：获取新插画作品时发生错误 - {e}")
            yield event.plain_result(f"获取新插画作品时发生错误: {str(e)}")

    async def pixiv_recommended(self, event: AstrMessageEvent, args: str = ""):
        """获取 Pixiv 推荐作品"""

        # 验证是否已认证
        if not await self.client_wrapper.authenticate():
            yield event.plain_result(self.pixiv_config.get_auth_error_message())
            return

        logger.info("Pixiv 插件：获取推荐作品")
        try:
            # 调用 API 获取推荐
            recommend_result = await self.client_wrapper.call_pixiv_api(
                self.client.illust_recommended
            )
            initial_illusts = (
                recommend_result.illusts if recommend_result.illusts else []
            )

            if not initial_illusts:
                yield event.plain_result("未能获取到推荐作品。")
                return

            # 使用统一的作品处理和发送函数
            config = FilterConfig(
                r18_mode=self.pixiv_config.r18_mode,
                ai_filter_mode=self.pixiv_config.ai_filter_mode,
                display_tag_str="推荐",
                return_count=self.pixiv_config.return_count,
                logger=logger,
                show_filter_result=self.pixiv_config.show_filter_result,
                excluded_tags=[],
                forward_threshold=self.pixiv_config.forward_threshold,
                show_details=self.pixiv_config.show_details,
            )

            async for result in process_and_send_illusts(
                initial_illusts,
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
            logger.error(f"Pixiv 插件：获取推荐作品时发生错误 - {e}")
            yield event.plain_result(f"获取推荐作品时发生错误: {str(e)}")

    async def pixiv_and(self, event: AstrMessageEvent, tags: str = ""):
        """处理 /pixiv_and 命令，进行 AND 逻辑深度搜索"""
        # 清理标签字符串
        cleaned_tags = tags.strip()

        if not cleaned_tags:
            logger.info(
                "Pixiv 插件 (AND)：用户未提供搜索标签或标签为空，返回帮助信息。"
            )
            yield event.plain_result(
                "请输入要进行 AND 搜索的标签 (用逗号分隔)。使用 `/pixiv_help` 查看帮助。\n"
                "支持排除标签功能，使用 -<标签> 来排除特定标签。\n\n"
                "**配置说明**:\n1. 先配置代理->[Astrbot代理配置教程](https://astrbot.app/config/astrbot-config.html#http-proxy);\n2. 再填入 `refresh_token`->**Pixiv Refresh Token**: 必填，用于 API 认证。获取方法请参考 [pixivpy3 文档](https://pypi.org/project/pixivpy3/) 或[这里](https://gist.github.com/karakoo/5e7e0b1f3cc74cbcb7fce1c778d3709e)。"
            )
            return

        # 使用统一的标签处理函数
        tag_result = validate_and_process_tags(cleaned_tags)
        if not tag_result["success"]:
            yield event.plain_result(tag_result["error_message"])
            return

        include_tags = tag_result["include_tags"]
        exclude_tags = tag_result["exclude_tags"]
        display_tag_str = tag_result["display_tags"]

        # AND 搜索至少需要两个包含标签
        if len(include_tags) < 2:
            yield event.plain_result(
                "AND 搜索至少需要两个包含标签，请用英文逗号 `,` 分隔。"
            )
            return

        # 验证是否已认证
        if not await self.client_wrapper.authenticate():
            yield event.plain_result(self.pixiv_config.get_auth_error_message())
            return

        # 获取翻页深度配置
        deepth = self.pixiv_config.deep_search_depth

        # 处理标签：分离第一个标签和其他标签
        first_tag = include_tags[0]
        other_tags = include_tags[1:]

        logger.info(
            f"Pixiv 插件：正在进行 AND 深度搜索。策略：先用标签 '{first_tag}' 深度搜索 (翻页深度: {deepth})，然后本地过滤要求同时包含: {','.join(include_tags)}，排除标签: {exclude_tags}"
        )

        # 搜索前发送提示消息
        search_phase_msg = f"正在深度搜索与标签「{first_tag}」相关的作品"
        filter_phase_msg = (
            f"稍后将筛选出同时包含「{','.join(include_tags)}」所有标签的结果。"
        )
        page_limit_msg = (
            f"将获取 {deepth} 页结果" if deepth != -1 else "将获取所有页面的结果"
        )
        yield event.plain_result(
            f"{search_phase_msg}，{filter_phase_msg} {page_limit_msg}，这可能需要一些时间..."
        )

        try:
            all_illusts_from_first_tag = []
            page_count = 0
            next_params = {}

            while deepth == -1 or page_count < deepth:
                current_page_num = page_count + 1
                try:
                    if page_count == 0:
                        # 第一次搜索: 传入标签和搜索目标
                        logger.debug(
                            f"Pixiv API Call (Page 1): search_illust(word='{first_tag}', search_target='partial_match_for_tags')"
                        )
                        json_result = await self.client_wrapper.call_pixiv_api(
                            self.client.search_illust,
                            first_tag,
                            search_target="partial_match_for_tags",
                        )
                    else:
                        # 后续翻页: 使用从 next_url 解析出的参数再次调用 search_illust
                        if not next_params:
                            logger.warning(
                                f"Pixiv 插件：尝试为 '{first_tag}' 翻页至第 {current_page_num} 页，但 next_params 为空，中止翻页。"
                            )
                            break
                        logger.debug(
                            f"Pixiv API Call (Page {current_page_num}): search_illust(**{next_params})"
                        )
                        json_result = await self.client_wrapper.call_pixiv_api(
                            self.client.search_illust, **next_params
                        )

                    # 检查 API 返回结果是否有错误字段
                    if hasattr(json_result, "error") and json_result.error:
                        logger.error(
                            f"Pixiv API 返回错误 (页码 {current_page_num}): {json_result.error}"
                        )
                        yield event.plain_result(
                            f"搜索 '{first_tag}' 的第 {current_page_num} 页时 API 返回错误: {json_result.error.get('message', '未知错误')}"
                        )
                        break

                    # 处理有效结果
                    if json_result.illusts:
                        logger.info(
                            f"Pixiv 插件：AND 搜索 (阶段1: '{first_tag}') 第 {current_page_num} 页找到 {len(json_result.illusts)} 个插画。"
                        )
                        all_illusts_from_first_tag.extend(json_result.illusts)
                    else:
                        logger.info(
                            f"Pixiv 插件：AND 搜索 (阶段1: '{first_tag}') 第 {current_page_num} 页没有找到插画。"
                        )

                    # 获取下一页参数
                    if hasattr(json_result, "next_url") and json_result.next_url:
                        next_params = self.client.parse_qs(json_result.next_url)
                        page_count += 1
                    else:
                        logger.info(
                            f"Pixiv 插件：AND 搜索 (阶段1: '{first_tag}') 在第 {current_page_num} 页后没有获取到下一页链接或达到深度限制，API 搜索结束。"
                        )
                        break

                except Exception as api_e:
                    # 捕获更具体的 API 调用异常或属性访问异常
                    logger.error(
                        f"Pixiv 插件：调用 search_illust API 时出错 (基于 '{first_tag}', 页码 {current_page_num}) - {type(api_e).__name__}: {api_e}"
                    )
                    yield event.plain_result(
                        f"搜索 '{first_tag}' 的第 {current_page_num} 页时遇到 API 错误，搜索中止。"
                    )
                    import traceback

                    logger.error(traceback.format_exc())
                    break

            logger.info(
                f"Pixiv 插件：AND 搜索 (阶段1: '{first_tag}') 完成，共获取 {len(all_illusts_from_first_tag)} 个插画，现在开始本地 AND 过滤..."
            )

            # 本地 AND 过滤
            and_filtered_illusts = []
            if all_illusts_from_first_tag:
                required_other_tags_lower = {tag.lower() for tag in other_tags}
                for illust in all_illusts_from_first_tag:
                    illust_tags_lower = {tag.name.lower() for tag in illust.tags}
                    # 检查是否包含所有其他必需标签 (第一个标签已通过 API 搜索保证存在)
                    if required_other_tags_lower.issubset(illust_tags_lower):
                        and_filtered_illusts.append(illust)

            initial_count = len(and_filtered_illusts)
            logger.info(
                f"Pixiv 插件：本地 AND 过滤完成，找到 {initial_count} 个同时包含「{','.join(include_tags)}」所有标签的作品。"
            )

            # 使用统一的作品处理和发送函数
            config = FilterConfig(
                r18_mode=self.pixiv_config.r18_mode,
                ai_filter_mode=self.pixiv_config.ai_filter_mode,
                display_tag_str=display_tag_str,
                return_count=self.pixiv_config.return_count,
                logger=logger,
                show_filter_result=self.pixiv_config.show_filter_result,
                excluded_tags=exclude_tags or [],
                forward_threshold=self.pixiv_config.forward_threshold,
                show_details=self.pixiv_config.show_details,
            )

            async for result in process_and_send_illusts(
                and_filtered_illusts,  # 传入所有过滤后的作品，让process_and_send_illusts内部处理选择
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
            logger.error(f"Pixiv 插件：AND 深度搜索时发生未预料的错误 - {e}")
            yield event.plain_result(f"AND 深度搜索时发生错误: {str(e)}")
            import traceback

            logger.error(traceback.format_exc())

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
                ai_filter_mode=self.pixiv_config.ai_filter_mode,
                display_tag_str=f"ID:{illust_id}",
                return_count=self.pixiv_config.return_count,
                logger=logger,
                show_filter_result=self.pixiv_config.show_filter_result,
                show_details=self.pixiv_config.show_details,
                excluded_tags=[],
            )
            filtered_illusts, filter_msgs = filter_illusts_with_reason([illust], config)
            if self.pixiv_config.show_filter_result:
                for msg in filter_msgs:
                    yield event.plain_result(msg)
            if not filtered_illusts:
                return

            # 统一使用build_detail_message生成详情信息
            detail_message = build_detail_message(filtered_illusts[0], is_novel=False)
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

    async def pixiv_ranking(self, event: AstrMessageEvent, args: str = ""):
        """获取 Pixiv 排行榜作品"""
        args_list = args.strip().split() if args.strip() else []

        # 如果没有传入参数或者第一个参数是 'help'，显示帮助信息
        if not args_list or args_list[0].lower() == "help":
            help_text = get_help_message(
                "pixiv_ranking", "排行榜帮助消息加载失败，请检查配置文件。"
            )
            yield event.plain_result(help_text)
            return

        # 解析参数
        mode = args_list[0] if len(args_list) > 0 else "day"
        date = args_list[1] if len(args_list) > 1 else None

        # 验证模式参数
        valid_modes = [
            "day",
            "week",
            "month",
            "day_male",
            "day_female",
            "week_original",
            "week_rookie",
            "day_manga",
            "day_r18",
            "day_male_r18",
            "day_female_r18",
            "week_r18",
            "week_r18g",
        ]

        if mode not in valid_modes:
            yield event.plain_result(
                f"无效的排行榜模式: {mode}\n请使用 `/pixiv_ranking help` 查看支持的模式"
            )
            return

        # 验证日期格式
        if date:
            try:
                # 简单验证日期格式
                year, month, day = date.split("-")
                if len(year) != 4 or len(month) != 2 or len(day) != 2:
                    raise ValueError("日期格式不正确")
            except Exception:
                yield event.plain_result(
                    f"无效的日期格式: {date}\n日期应为 YYYY-MM-DD 格式"
                )
                return

        # 检查 R18 权限
        if "r18" in mode and self.pixiv_config.r18_mode == "过滤 R18":
            yield event.plain_result(
                "当前 R18 模式设置为「过滤 R18」，无法使用 R18 相关排行榜。"
            )
            return

        logger.info(
            f"Pixiv 插件：正在获取排行榜 - 模式: {mode}, 日期: {date if date else '最新'}"
        )

        # 验证是否已认证
        if not await self.client_wrapper.authenticate():
            yield event.plain_result(self.pixiv_config.get_auth_error_message())
            return

        try:
            # 调用 Pixiv API 获取排行榜
            ranking_result = await self.client_wrapper.call_pixiv_api(
                self.client.illust_ranking, mode=mode, date=date
            )
            initial_illusts = ranking_result.illusts if ranking_result.illusts else []

            if not initial_illusts:
                yield event.plain_result(f"未能获取到 {date} 的 {mode} 排行榜数据。")
                return

            # Pixiv 排行榜接口在非 manga 模式下也可能混入 type=manga 的作品，这里主动过滤掉
            if mode and "manga" not in str(mode).lower():
                before_count = len(initial_illusts)
                initial_illusts = [
                    i for i in initial_illusts if getattr(i, "type", None) != "manga"
                ]
                filtered_count = before_count - len(initial_illusts)
                if filtered_count:
                    logger.info(
                        f"Pixiv 插件：排行榜 {mode} 已过滤 {filtered_count} 个漫画作品(manga)。"
                    )

                if not initial_illusts:
                    yield event.plain_result(
                        f"{mode} 排行榜结果均为漫画作品(manga)，已按非 manga 模式过滤。"
                    )
                    return

            # 使用统一的作品处理和发送函数
            config = FilterConfig(
                r18_mode=self.pixiv_config.r18_mode,
                ai_filter_mode=self.pixiv_config.ai_filter_mode,
                display_tag_str=f"排行榜:{mode}",
                return_count=self.pixiv_config.return_count,
                logger=logger,
                show_filter_result=self.pixiv_config.show_filter_result,
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
            logger.error(f"Pixiv 插件：获取排行榜时发生错误 - {e}")
            yield event.plain_result(f"获取排行榜时发生错误: {str(e)}")

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
                ai_filter_mode=self.pixiv_config.ai_filter_mode,
                display_tag_str=f"相关:{illust_id}",
                return_count=self.pixiv_config.return_count,
                logger=logger,
                show_filter_result=self.pixiv_config.show_filter_result,
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

    async def pixiv_deepsearch(self, event: AstrMessageEvent, tags: str):
        """
        深度搜索 Pixiv 插画，通过翻页获取多页结果
        用法: /pixiv_deepsearch <标签1>,<标签2>,...
        注意: 翻页深度由配置中的 deep_search_depth 参数控制
        """
        # 验证用户输入
        if not tags or tags.strip().lower() == "help":
            yield event.plain_result(
                "用法: /pixiv_deepsearch <标签1>,<标签2>,...\n"
                "深度搜索 Pixiv 插画，将遍历多个结果页面。\n"
                "支持排除标签功能，使用 -<标签> 来排除特定标签。\n"
                f"当前翻页深度设置: {self.pixiv_config.deep_search_depth} 页 (-1 表示获取所有页面)"
            )
            return

        # 验证是否已认证
        if not await self.client_wrapper.authenticate():
            yield event.plain_result(
                "Pixiv API 认证失败，请检查配置中的凭据信息。\n"
                + self.pixiv_config.get_auth_error_message()
            )
            return

        # 使用统一的标签处理函数
        tag_result = validate_and_process_tags(tags.strip())
        if not tag_result["success"]:
            yield event.plain_result(tag_result["error_message"])
            return

        include_tags = tag_result["include_tags"]
        exclude_tags = tag_result["exclude_tags"]
        search_tags_list = include_tags
        display_tags = tag_result["display_tags"]
        deep_search_depth = self.pixiv_config.deep_search_depth

        # 日志记录
        tag_str = ", ".join(search_tags_list)
        logger.info(
            f"Pixiv 插件：正在深度搜索标签 - {tag_str}，排除标签 - {exclude_tags}，翻页深度: {deep_search_depth}"
        )

        # 搜索前发送提示消息
        if deep_search_depth == -1:
            yield event.plain_result(
                f"正在深度搜索标签「{tag_str}」，将获取所有页面的结果，这可能需要一些时间..."
            )
        else:
            yield event.plain_result(
                f"正在深度搜索标签「{tag_str}」，将获取 {deep_search_depth} 页结果，这可能需要一些时间..."
            )

        try:
            # 准备搜索参数
            search_params = {
                "word": " ".join(search_tags_list),
                "search_target": "partial_match_for_tags",
                "sort": "popular_desc",
                "filter": "for_ios",
                "req_auth": True,
            }

            # 执行初始搜索
            all_illusts = []
            page_count = 0
            next_params = search_params.copy()

            # 循环获取多页结果
            while next_params:
                # 限制页数
                if deep_search_depth > 0 and page_count >= deep_search_depth:
                    break

                # 搜索当前页
                json_result = await self.client_wrapper.call_pixiv_api(
                    self.client.search_illust, **next_params
                )
                if not json_result or not hasattr(json_result, "illusts"):
                    break

                # 收集当前页的插画
                current_illusts = json_result.illusts
                if current_illusts:
                    all_illusts.extend(current_illusts)
                    page_count += 1
                    logger.info(
                        f"Pixiv 插件：已获取第 {page_count} 页，找到 {len(current_illusts)} 个插画"
                    )

                    # 发送进度更新
                    if page_count % 3 == 0:
                        yield event.plain_result(
                            f"搜索进行中：已获取 {page_count} 页，共 {len(all_illusts)} 个结果..."
                        )
                else:
                    break

                # 获取下一页参数
                next_url = json_result.next_url
                next_params = self.client.parse_qs(next_url) if next_url else None

                # 避免请求过于频繁
                if next_params:
                    await asyncio.sleep(0.5)  # 添加延迟，避免请求过快

            # 检查是否有结果
            if not all_illusts:
                yield event.plain_result(f"深度搜索未找到与「{tag_str}」相关的插画。")
                return

            # 记录找到的总数量
            initial_count = len(all_illusts)
            logger.info(
                f"Pixiv 插件：深度搜索完成，共找到 {initial_count} 个插画，开始过滤处理..."
            )
            yield event.plain_result(
                f"搜索完成！共获取 {page_count} 页，找到 {initial_count} 个结果，正在处理..."
            )

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
                all_illusts,  # 传入所有初始作品，让process_and_send_illusts内部处理过滤和选择
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
            logger.error(f"Pixiv 插件：深度搜索时发生错误 - {e}")
            yield event.plain_result(f"深度搜索时发生错误: {str(e)}")
            import traceback

            logger.error(traceback.format_exc())

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

    async def pixiv_hot(
        self, event: AstrMessageEvent, tags: str = "", duration: str = "week"
    ):
        """
        按热度（收藏数）搜索特定标签的作品
        用法: /pixiv_hot <标签> [时间范围] [页数]
        时间范围: day(一天内), week(一周内,默认), month(一月内), all(全部)
        """
        cleaned_tags = tags.strip()
        args_list = cleaned_tags.split() if cleaned_tags else []

        # 帮助信息
        if not args_list or args_list[0].lower() == "help":
            help_text = (
                "🔥 **热度搜索** - 按收藏数排序搜索作品\n\n"
                "**用法**: `/pixiv_hot <标签> [时间范围] [页数]`\n\n"
                "**时间范围**: day/week(默认)/month/all\n\n"
                "**示例**:\n"
                "- `/pixiv_hot 可莉` - 搜索一周内可莉的热门图\n"
                "- `/pixiv_hot クレー(原神) month` - 一个月内的热门图\n"
                "- `/pixiv_hot 甘雨 week 10` - 一周内，抓取10页\n"
                "- `/pixiv_hot 可莉,-R18` - 排除R18内容\n\n"
                "💡 本功能通过抓取多页后按收藏数排序，无需会员"
            )
            yield event.plain_result(help_text)
            return

        search_tag = args_list[0]
        duration_param = args_list[1] if len(args_list) > 1 else "week"
        pages_to_fetch = (
            int(args_list[2]) if len(args_list) > 2 and args_list[2].isdigit() else 5
        )

        duration_map = {
            "day": "within_last_day",
            "week": "within_last_week",
            "month": "within_last_month",
            "all": None,
        }

        if duration_param not in duration_map:
            yield event.plain_result(
                f"无效的时间范围: {duration_param}\n"
                f"可用选项: day(一天), week(一周), month(一月), all(全部)"
            )
            return

        if not await self.client_wrapper.authenticate():
            yield event.plain_result(self.pixiv_config.get_auth_error_message())
            return

        tag_result = validate_and_process_tags(search_tag)
        if not tag_result["success"]:
            yield event.plain_result(tag_result["error_message"])
            return

        exclude_tags = tag_result["exclude_tags"]
        search_tags = tag_result["search_tags"]
        display_tags = tag_result["display_tags"]

        duration_display = {
            "day": "一天内",
            "week": "一周内",
            "month": "一个月内",
            "all": "全部时间",
        }

        logger.info(
            f"Pixiv热度搜索 - 标签: {search_tags}, 时间: {duration_param}, 页数: {pages_to_fetch}"
        )

        yield event.plain_result(
            f"🔥 正在搜索「{display_tags}」{duration_display[duration_param]}的热门作品...\n"
            f"将抓取 {pages_to_fetch} 页数据并按收藏数排序，请稍候..."
        )

        try:
            all_illusts = []
            page_count = 0
            next_params = None

            while page_count < pages_to_fetch:
                try:
                    if page_count == 0:
                        search_kwargs = {
                            "word": search_tags,
                            "search_target": "partial_match_for_tags",
                            "sort": "date_desc",
                            "filter": "for_ios",
                        }
                        if duration_map[duration_param]:
                            search_kwargs["duration"] = duration_map[duration_param]

                        json_result = await self.client_wrapper.call_pixiv_api(
                            self.client.search_illust, **search_kwargs
                        )
                    else:
                        if not next_params:
                            break
                        json_result = await self.client_wrapper.call_pixiv_api(
                            self.client.search_illust, **next_params
                        )

                    if not json_result or not hasattr(json_result, "illusts"):
                        break

                    current_illusts = json_result.illusts
                    if current_illusts:
                        all_illusts.extend(current_illusts)
                        page_count += 1
                        logger.info(
                            f"热度搜索：已获取第 {page_count} 页，本页 {len(current_illusts)} 个"
                        )
                    else:
                        break

                    if hasattr(json_result, "next_url") and json_result.next_url:
                        next_params = self.client.parse_qs(json_result.next_url)
                    else:
                        break

                    await asyncio.sleep(0.3)

                except Exception as e:
                    logger.error(f"热度搜索第 {page_count + 1} 页出错: {e}")
                    break

            if not all_illusts:
                yield event.plain_result(
                    f"未找到与「{display_tags}」相关的{duration_display[duration_param]}作品。"
                )
                return

            # 按收藏数降序排序
            sorted_illusts = sorted(
                all_illusts,
                key=lambda x: getattr(x, "total_bookmarks", 0),
                reverse=True,
            )

            logger.info(
                f"热度搜索完成，共 {len(sorted_illusts)} 个作品，已按收藏数排序"
            )

            top_bookmark = getattr(sorted_illusts[0], "total_bookmarks", 0)
            yield event.plain_result(
                f"✅ 搜索完成！共找到 {len(sorted_illusts)} 个作品\n"
                f"🏆 最高收藏数: {top_bookmark}\n正在发送热门作品..."
            )

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

            async for result in process_and_send_illusts_sorted(
                sorted_illusts,
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
            logger.error(f"热度搜索错误: {e}")
            import traceback

            logger.error(traceback.format_exc())
            yield event.plain_result(f"热度搜索时发生错误: {str(e)}")
