"""
tag.py
统一Pixiv标签格式化、详情信息构建与R18/AI过滤工具模块
"""

from dataclasses import dataclass
from typing import List, Optional, Callable
import random

# R18 与 AI 敏感词列表
R18_BADWORDS = [s.lower() for s in ["R-18", "R18", "R18+"]]
R18G_BADWORDS = [s.lower() for s in ["R-18G", "R18G", "R18+G"]]
AI_BADWORDS = [s.lower() for s in ["AI", "AI生成", "AI-generated", "AI辅助"]]


@dataclass
class FilterConfig:
    """过滤配置类"""

    r18_mode: str
    ai_filter_mode: str
    ai_detection_mode: str = "field_or_tag"
    display_tag_str: Optional[str] = None
    first_tag: Optional[str] = None
    all_illusts_from_first_tag: Optional[List] = None
    return_count: int = 1
    logger: Optional[Callable] = None
    show_filter_result: bool = True
    excluded_tags: Optional[List[str]] = None
    filter_r18g_only: bool = False
    single_response_mode: bool = False
    forward_threshold: bool = False
    show_details: bool = True


def _get_value(source, *keys):
    """Read a field from dict-like or object-like Pixiv data."""
    if isinstance(source, dict):
        for key in keys:
            if key in source:
                return source.get(key)
        return None

    for key in keys:
        if hasattr(source, key):
            return getattr(source, key)
    return None


def _to_int(value):
    """Best-effort int conversion for Pixiv flags."""
    if isinstance(value, bool):
        return int(value)
    if isinstance(value, int):
        return value
    if isinstance(value, str):
        stripped = value.strip()
        if stripped.lstrip("-").isdigit():
            return int(stripped)
    return None


def _extract_tag_name(tag) -> str:
    """Extract a tag name from str/dict/object payloads."""
    if isinstance(tag, str):
        return tag.strip()

    name = _get_value(tag, "name")
    if isinstance(name, str):
        return name.strip()
    return ""


def _extract_tag_translated_name(tag) -> str:
    """Extract translated tag name from str/dict/object payloads."""
    translated_name = _get_value(tag, "translated_name", "translatedName")
    if isinstance(translated_name, str):
        return translated_name.strip()
    return ""


def _extract_tag_names(tags) -> List[str]:
    """Normalize Pixiv tags into a plain name list."""
    if not tags:
        return []

    if isinstance(tags, (list, tuple, set)):
        return [name for name in (_extract_tag_name(tag) for tag in tags) if name]

    name = _extract_tag_name(tags)
    return [name] if name else []


def is_r18(item):
    """检查作品是否为R18内容（包含R18G）"""
    x_restrict = _to_int(_get_value(item, "x_restrict", "xRestrict"))
    if x_restrict is not None and x_restrict > 0:
        return True

    for name in _extract_tag_names(_get_value(item, "tags") or []):
        lname = name.lower()
        # 精确匹配或作为独立词匹配
        all_r18_words = R18_BADWORDS + R18G_BADWORDS
        if lname in all_r18_words or any(
            bad
            for bad in all_r18_words
            if f" {bad} " in f" {lname} "
            or lname.startswith(f"{bad} ")
            or lname.endswith(f" {bad}")
        ):
            return True
    return False


def is_r18g(item):
    """检查作品是否为R18G内容"""
    x_restrict = _to_int(_get_value(item, "x_restrict", "xRestrict"))
    if x_restrict is not None and x_restrict >= 2:
        return True

    for name in _extract_tag_names(_get_value(item, "tags") or []):
        lname = name.lower()
        # 精确匹配或作为独立词匹配
        if lname in R18G_BADWORDS or any(
            bad
            for bad in R18G_BADWORDS
            if f" {bad} " in f" {lname} "
            or lname.startswith(f"{bad} ")
            or lname.endswith(f" {bad}")
        ):
            return True
    return False


def _is_ai_by_field(item):
    """根据 Pixiv 字段判断 AI。"""
    ai_type = _to_int(
        _get_value(item, "illust_ai_type", "illustAiType", "ai_type", "aiType")
    )
    return ai_type is not None and ai_type > 0


def _is_ai_by_tag(item):
    """根据标签判断 AI。"""
    for name in _extract_tag_names(_get_value(item, "tags") or []):
        lname = name.lower()
        # 精确匹配或作为独立词匹配
        if lname in AI_BADWORDS or any(
            bad
            for bad in AI_BADWORDS
            if f" {bad} " in f" {lname} "
            or lname.startswith(f"{bad} ")
            or lname.endswith(f" {bad}")
        ):
            return True
    return False


def is_ai(item, detection_mode: str = "field_or_tag"):
    """检查作品是否为AI生成内容。"""
    mode = (detection_mode or "field_or_tag").strip().lower()
    if mode == "field_only":
        return _is_ai_by_field(item)
    if mode == "tag_only":
        return _is_ai_by_tag(item)
    # 默认：field_or_tag
    return _is_ai_by_field(item) or _is_ai_by_tag(item)


def is_ugoira(item):
    """检查作品是否为动图（ugoira）"""
    return getattr(item, "type", None) == "ugoira"


def _apply_filters(item, config: FilterConfig) -> bool:
    """应用所有过滤条件"""
    # 单独开关：额外过滤 R18G（不覆盖 r18_mode 逻辑）。
    if config.filter_r18g_only and is_r18g(item):
        return False

    if config.r18_mode == "过滤 R18" and is_r18(item):
        return False
    if config.r18_mode == "仅 R18" and not is_r18(item):
        return False
    if config.ai_filter_mode == "过滤 AI 作品" and is_ai(
        item, config.ai_detection_mode
    ):
        return False
    if config.ai_filter_mode == "仅 AI 作品" and not is_ai(
        item, config.ai_detection_mode
    ):
        return False
    if config.excluded_tags and has_excluded_tags(item, config.excluded_tags):
        return False
    return True


def _generate_filter_messages(
    initial_count: int, filtered_count: int, config: FilterConfig, illusts: List
) -> List[str]:
    """生成过滤结果消息"""
    filter_msgs = []

    if not config.show_filter_result:
        return filter_msgs

    # 有作品被过滤的情况
    if filtered_count < initial_count:
        filter_reasons = []
        if config.r18_mode in ["过滤 R18", "仅 R18"]:
            filter_reasons.append("R18")
        elif config.filter_r18g_only:
            filter_reasons.append("R18G")
        if config.ai_filter_mode in ["过滤 AI 作品", "仅 AI 作品"]:
            filter_reasons.append("AI")
        if config.excluded_tags:
            filter_reasons.append("排除标签")

        if filter_reasons:
            filter_msgs.append(
                f"部分作品因 {'/'.join(filter_reasons)} 设置被过滤 "
                f"(找到 {initial_count} 个符合所有标签的作品，最终剩 {filtered_count} 个可发送)。"
            )
    elif initial_count > 0:
        filter_msgs.append(
            f"筛选完成，共找到 {initial_count} 个符合所有标签「{config.display_tag_str or ''}」的作品。"
            f"正在发送最多 {config.return_count} 张..."
        )

    # 处理无结果的情况
    if filtered_count == 0:
        filter_msgs.extend(_generate_no_result_messages(initial_count, config, illusts))

    return filter_msgs


def _generate_no_result_messages(
    initial_count: int, config: FilterConfig, illusts: List
) -> List[str]:
    """生成无结果时的详细消息"""
    msgs = []
    no_result_reason = []

    if config.filter_r18g_only and any(is_r18g(i) for i in illusts):
        no_result_reason.append("R18G 内容")
    if config.r18_mode == "过滤 R18" and any(is_r18(i) for i in illusts):
        no_result_reason.append("R18 内容")
    if config.ai_filter_mode == "过滤 AI 作品" and any(
        is_ai(i, config.ai_detection_mode) for i in illusts
    ):
        no_result_reason.append("AI 作品")
    if config.r18_mode == "仅 R18" and not any(is_r18(i) for i in illusts):
        no_result_reason.append("非 R18 内容")
    if config.ai_filter_mode == "仅 AI 作品" and not any(
        is_ai(i, config.ai_detection_mode) for i in illusts
    ):
        no_result_reason.append("非 AI 作品")
    if config.excluded_tags and any(
        has_excluded_tags(i, config.excluded_tags) for i in illusts
    ):
        no_result_reason.append("包含排除标签")

    if no_result_reason and initial_count > 0:
        msgs.append(
            f"所有找到的作品均为 {' 或 '.join(no_result_reason)}，根据当前设置已被过滤。"
        )
    elif (
        initial_count == 0
        and config.all_illusts_from_first_tag is not None
        and len(config.all_illusts_from_first_tag) > 0
    ):
        msgs.append(
            f"找到了与「{config.first_tag}」相关的作品，但没有作品同时包含所有标签「{config.display_tag_str}」。"
        )
    elif (
        initial_count == 0
        and config.all_illusts_from_first_tag is not None
        and len(config.all_illusts_from_first_tag) == 0
    ):
        msgs.append(f"未找到任何与标签「{config.first_tag}」相关的作品。")
    else:
        if config.logger:
            config.logger.warning(
                "AND 深度搜索后没有符合条件的插画可供发送，但过滤原因不明确。"
            )
        msgs.append("筛选后没有符合条件的作品可发送。")

    return msgs


def filter_illusts_with_reason(illusts, config: FilterConfig):
    """统一R18/AI/排除标签过滤逻辑，返回过滤后的插画列表和详细过滤提示"""
    initial_count = len(illusts)
    filtered_list = [item for item in illusts if _apply_filters(item, config)]
    filtered_count = len(filtered_list)

    filter_msgs = _generate_filter_messages(
        initial_count, filtered_count, config, illusts
    )

    return filtered_list, filter_msgs


def _build_single_response_summary(
    initial_count: int, filtered_count: int, send_count: int, filter_msgs: List[str]
) -> str:
    """构建单消息模式下的汇总文本。"""
    summary_lines = [
        f"搜索完成：初始结果 {initial_count} 个，过滤后 {filtered_count} 个，准备发送 {send_count} 个。"
    ]
    if filter_msgs:
        summary_lines.extend(filter_msgs)
    return "\n".join(summary_lines)


def format_tags(tags) -> str:
    """
    将Pixiv标签结构（支持list/dict/str）格式化为:
    R-18, 尘白禁区(Snowbreak), snowbreak, スノウブレイク(Snowbreak), ...
    """
    result = []
    if isinstance(tags, (list, tuple, set)):
        for tag in tags:
            name = _extract_tag_name(tag)
            trans = _extract_tag_translated_name(tag)
            if name:
                result.append(f"{name}({trans})" if trans else name)
    else:
        name = _extract_tag_name(tags)
        trans = _extract_tag_translated_name(tags)
        if name:
            result.append(f"{name}({trans})" if trans else name)
    return ", ".join([t for t in result if t]) if result else "无"


def build_detail_message(item, is_novel=False):
    """
    构建Pixiv作品详情信息：
    - 插画：标题/作者/标签/链接
    - 小说：小说标题/作者/标签/字数/系列/链接（缺失字段自动省略）
    """
    if is_novel:
        title = getattr(item, "title", "")
        author = getattr(item, "user", None)
        if author and hasattr(author, "name"):
            author = author.name
        else:
            author = getattr(item, "author", "未知")
        tags_str = format_tags(getattr(item, "tags", []))
        text_length = getattr(item, "text_length", None)
        if text_length is None:
            text_length = getattr(item, "word_count", "未知")
        series = getattr(item, "series", None)
        if series and hasattr(series, "title"):
            series_title = series.title
        elif isinstance(series, dict):
            series_title = series.get("title", "未知")
        elif isinstance(series, str) and series:
            series_title = series
        elif series:
            series_title = str(series)
        else:
            series_title = "未知"
        link = f"https://www.pixiv.net/novel/show.php?id={item.id}"
        detail_message = (
            f"小说标题: {title}\n"
            f"作者: {author}\n"
            f"标签: {tags_str}\n"
            f"字数: {text_length}\n"
            f"系列: {series_title}\n"
            f"链接: {link}"
        )
        return detail_message
    else:
        title = getattr(item, "title", "")
        author = getattr(item, "user", None)
        if author and hasattr(author, "name"):
            author = author.name
        else:
            author = getattr(item, "author", "")
        tags_str = format_tags(getattr(item, "tags", []))
        link = f"https://www.pixiv.net/artworks/{item.id}"
        return f"标题: {title}\n作者: {author}\n标签: {tags_str}\n链接: {link}"


def has_excluded_tags(item, excluded_tags):
    """
    检查作品是否包含需要排除的标签

    Args:
        item: Pixiv作品对象
        excluded_tags: 需要排除的标签列表（已转换为小写）

    Returns:
        bool: 如果包含排除标签返回True，否则返回False
    """
    if not excluded_tags:
        return False

    for name in _extract_tag_names(_get_value(item, "tags") or []):
        lname = name.lower()
        if any(excluded_tag in lname for excluded_tag in excluded_tags):
            return True
    return False


async def process_and_send_illusts(
    initial_illusts,
    config: FilterConfig,
    client,
    event,
    build_detail_message_func,
    send_pixiv_image_func,
    send_forward_message_func,
    is_novel=False,
    include_related_ids=False,
):
    """
    统一处理作品过滤和发送的逻辑

    Args:
        initial_illusts: 初始作品列表
        config: 过滤配置
        client: Pixiv API 客户端
        event: 消息事件
        build_detail_message_func: 构建详情消息的函数
        send_pixiv_image_func: 发送图片的函数
        send_forward_message_func: 发送转发消息的函数
        is_novel: 是否为小说（默认为False）

    Returns:
        AsyncGenerator:
            - include_related_ids=False 时，仅生成消息对象
            - include_related_ids=True 时，生成 (message_content, related_illust_ids)
    """

    def _get_illust_id(item):
        try:
            item_id = getattr(item, "id", None)
            if item_id is not None:
                return int(item_id)
        except Exception:
            pass
        try:
            if isinstance(item, dict) and "id" in item:
                return int(item["id"])
        except Exception:
            pass
        return None

    def _wrap_result(message_content, related_ids):
        if include_related_ids:
            return message_content, related_ids
        return message_content

    # 应用过滤
    filtered_illusts, filter_msgs = filter_illusts_with_reason(initial_illusts, config)
    initial_count = len(initial_illusts)
    filtered_count = len(filtered_illusts)

    if config.single_response_mode:
        if not filtered_illusts:
            no_result_msg = (
                "\n".join(filter_msgs)
                if filter_msgs
                else "筛选后没有符合条件的作品可发送。"
            )
            yield _wrap_result(event.plain_result(no_result_msg), [])
            return

        illusts_to_send = sample_illusts(
            filtered_illusts, config.return_count, shuffle=True
        )
        if not illusts_to_send:
            yield _wrap_result(event.plain_result("筛选后没有符合条件的作品可发送。"), [])
            return

        related_ids = []
        for illust in illusts_to_send:
            illust_id = _get_illust_id(illust)
            if illust_id is not None:
                related_ids.append(illust_id)

        summary_text = _build_single_response_summary(
            initial_count,
            filtered_count,
            len(illusts_to_send),
            filter_msgs if config.show_filter_result else [],
        )

        async for result in send_forward_message_func(
            client,
            event,
            illusts_to_send,
            lambda illust: build_detail_message_func(illust, is_novel=is_novel),
            summary_text=summary_text,
            single_batch=True,
        ):
            yield _wrap_result(result, related_ids)
        return

    # 发送过滤消息
    if config.show_filter_result:
        for msg in filter_msgs:
            yield _wrap_result(event.plain_result(msg), [])

    if not filtered_illusts:
        # 如果没有符合条件的作品，发送一个提示消息
        if config.show_filter_result:
            # 如果显示过滤结果，但过滤消息为空，发送一个默认消息
            if not filter_msgs:
                yield _wrap_result(
                    event.plain_result("筛选后没有符合条件的作品可发送。"), []
                )
        else:
            # 如果不显示过滤结果，直接发送一个简单的提示消息
            yield _wrap_result(event.plain_result("没有找到符合条件的作品。"), [])
        return

    # 随机选择作品
    illusts_to_send = sample_illusts(
        filtered_illusts, config.return_count, shuffle=True
    )

    if not illusts_to_send:
        return

    # 根据配置决定发送方式
    if config.forward_threshold:
        # 启用转发时使用转发消息（无论图片数量多少）
        related_ids = []
        for illust in illusts_to_send:
            illust_id = _get_illust_id(illust)
            if illust_id is not None:
                related_ids.append(illust_id)

        async for result in send_forward_message_func(
            client,
            event,
            illusts_to_send,
            lambda illust: build_detail_message_func(illust, is_novel=is_novel),
        ):
            yield _wrap_result(result, related_ids)
    else:
        # 未启用转发时逐张发送
        for illust in illusts_to_send:
            illust_id = _get_illust_id(illust)
            detail_message = build_detail_message_func(illust, is_novel=is_novel)
            async for result in send_pixiv_image_func(
                client, event, illust, detail_message, show_details=config.show_details
            ):
                yield _wrap_result(
                    result, ([illust_id] if illust_id is not None else [])
                )


def parse_tags_with_exclusion(tags_str):
    """
    解析标签字符串，分离包含标签和排除标签

    Args:
        tags_str: 标签字符串，如 "萝莉,-R18,可爱"

    Returns:
        tuple: (包含标签列表, 排除标签列表, 冲突标签列表)
    """
    if not tags_str:
        return [], [], []

    normalized_tags = (
        tags_str.replace("，", ",")
        .replace("、", ",")
        .replace("；", ",")
        .replace(";", ",")
    )
    all_tags = [tag.strip() for tag in normalized_tags.split(",") if tag.strip()]
    include_tags = []
    exclude_tags = []

    negative_prefixes = ("-", "－", "—", "–")
    for tag in all_tags:
        if tag.startswith(negative_prefixes):
            excluded_tag = tag[1:].strip().lower()
            if excluded_tag:
                exclude_tags.append(excluded_tag)
        else:
            include_tags.append(tag)

    # 去重，保持用户输入顺序
    exclude_tags = list(dict.fromkeys(exclude_tags))

    # 检查冲突标签
    include_tags_lower = [tag.lower() for tag in include_tags]
    conflict_tags = []

    for exclude_tag in exclude_tags:
        if exclude_tag in include_tags_lower:
            conflict_tags.append(exclude_tag)

    return include_tags, exclude_tags, conflict_tags


def validate_and_process_tags(cleaned_tags):
    """
    验证和处理标签，返回处理结果或错误消息

    Args:
        cleaned_tags: 清理后的标签字符串

    Returns:
        dict: 包含处理结果的字典，格式为:
            {
                'success': bool,  # 是否成功
                'error_message': str,  # 错误消息（如果有）
                'include_tags': list,  # 包含标签列表
                'exclude_tags': list,  # 排除标签列表
                'search_tags': str,  # 搜索标签字符串
                'display_tags': str  # 显示标签字符串
            }
    """
    # 解析包含和排除标签，检查冲突
    include_tags, exclude_tags, conflict_tags = parse_tags_with_exclusion(cleaned_tags)

    # 检查是否存在冲突标签
    if conflict_tags:
        conflict_list = "、".join(conflict_tags)
        return {
            "success": False,
            "error_message": f"标签冲突：以下标签同时出现在包含和排除列表中：{conflict_list}\n你药剂把干啥",
            "include_tags": [],
            "exclude_tags": [],
            "search_tags": "",
            "display_tags": cleaned_tags,
        }

    if not include_tags:
        return {
            "success": False,
            "error_message": "请至少提供一个包含标签（不以 - 开头的标签）。",
            "include_tags": [],
            "exclude_tags": [],
            "search_tags": "",
            "display_tags": cleaned_tags,
        }

    # Pixiv API expects multi-tag queries joined by spaces rather than commas.
    search_tags = " ".join(include_tags)
    display_tags = cleaned_tags

    return {
        "success": True,
        "error_message": "",
        "include_tags": include_tags,
        "exclude_tags": exclude_tags,
        "search_tags": search_tags,
        "display_tags": display_tags,
    }


def sample_illusts(illusts, count, shuffle=False):
    """
    从作品列表中随机选择指定数量的作品

    Args:
        illusts: 作品列表
        count: 要选择的数量
        shuffle: 是否先打乱顺序再选择（默认为False）

    Returns:
        list: 随机选择的作品列表
    """
    if not illusts:
        return []

    count_to_send = min(len(illusts), count)
    if count_to_send > 0:
        if shuffle:
            random.shuffle(illusts)
            return illusts[:count_to_send]
        else:
            return random.sample(illusts, count_to_send)
    else:
        return []


async def process_and_send_illusts_sorted(
    sorted_illusts,
    config: FilterConfig,
    client,
    event,
    build_detail_message_func,
    send_pixiv_image_func,
    send_forward_message_func,
    is_novel=False,
):
    """
    处理已排序的作品列表并发送
    """
    filtered_illusts, filter_msgs = filter_illusts_with_reason(sorted_illusts, config)
    initial_count = len(sorted_illusts)
    filtered_count = len(filtered_illusts)

    if config.single_response_mode:
        if not filtered_illusts:
            no_result_msg = (
                "\n".join(filter_msgs)
                if filter_msgs
                else "筛选后没有符合条件的作品可发送。"
            )
            yield event.plain_result(no_result_msg)
            return

        count_to_send = min(len(filtered_illusts), config.return_count)
        illusts_to_send = filtered_illusts[:count_to_send]
        if not illusts_to_send:
            yield event.plain_result("筛选后没有符合条件的作品可发送。")
            return

        summary_text = _build_single_response_summary(
            initial_count,
            filtered_count,
            len(illusts_to_send),
            filter_msgs if config.show_filter_result else [],
        )
        async for result in send_forward_message_func(
            client,
            event,
            illusts_to_send,
            lambda illust: build_detail_message_func(illust, is_novel=is_novel),
            summary_text=summary_text,
            single_batch=True,
        ):
            yield result
        return

    if config.show_filter_result:
        for msg in filter_msgs:
            yield event.plain_result(msg)

    if not filtered_illusts:
        if config.show_filter_result and not filter_msgs:
            yield event.plain_result("筛选后没有符合条件的作品可发送。")
        elif not config.show_filter_result:
            yield event.plain_result("没有找到符合条件的作品。")
        return

    count_to_send = min(len(filtered_illusts), config.return_count)
    illusts_to_send = filtered_illusts[:count_to_send]

    if not illusts_to_send:
        return

    if config.forward_threshold:
        async for result in send_forward_message_func(
            client,
            event,
            illusts_to_send,
            lambda illust: build_detail_message_func(illust, is_novel=is_novel),
        ):
            yield result
    else:
        for illust in illusts_to_send:
            detail_message = build_detail_message_func(illust, is_novel=is_novel)
            async for result in send_pixiv_image_func(
                client, event, illust, detail_message, show_details=config.show_details
            ):
                yield result
