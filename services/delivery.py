"""作品筛选后的发送编排（应用服务层）。

领域层只负责过滤/格式化；本模块负责“选哪些、怎么发”，并通过参数注入
发送函数，避免 services 反向依赖 handlers。
"""

import random
from typing import List

from ..domain.tag import FilterConfig, filter_illusts_with_reason


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
            yield _wrap_result(
                event.plain_result("筛选后没有符合条件的作品可发送。"), []
            )
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
