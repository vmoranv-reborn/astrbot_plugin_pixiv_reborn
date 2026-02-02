from astrbot.api.event import AstrMessageEvent
from astrbot.api import logger
from ..utils.database import (
    add_subscription,
    remove_subscription,
    list_subscriptions,
)


class SubscribeHandler:
    """
    Pixiv 订阅功能处理器
    负责处理画师订阅的添加、删除和查看功能
    """

    def __init__(self, client_wrapper, pixiv_config):
        self.client_wrapper = client_wrapper
        self.client = client_wrapper.client_api
        self.pixiv_config = pixiv_config

    async def pixiv_subscribe_add(self, event: AstrMessageEvent, artist_id: str = ""):
        """订阅画师"""
        if not self.pixiv_config.subscription_enabled:
            yield event.plain_result("订阅功能未启用。")
            return

        if not artist_id or not artist_id.isdigit():
            yield event.plain_result(
                "请输入有效的画师ID。用法: /pixiv_subscribe_add <画师ID>"
            )
            return

        platform_name = event.platform_meta.id
        message_type = event.get_message_type().value
        session_id = f"{platform_name}:{message_type}:{event.get_group_id() or event.get_sender_id()}"

        sub_type = "artist"
        target_name = artist_id

        try:
            if not await self.client_wrapper.authenticate():
                yield event.plain_result(self.pixiv_config.get_auth_error_message())
                return

            # 获取画师信息
            user_detail = await self.client_wrapper.call_pixiv_api(
                self.client.user_detail, int(artist_id)
            )
            if user_detail and user_detail.user:
                target_name = user_detail.user.name

            # 获取画师最新作品ID作为初始值
            latest_illust_id = 0
            try:
                user_illusts = await self.client_wrapper.call_pixiv_api(
                    self.client.user_illusts, int(artist_id)
                )
                if user_illusts and user_illusts.illusts:
                    latest_illust_id = user_illusts.illusts[0].id
                    logger.info(
                        f"获取到画师 {artist_id} 的最新作品ID: {latest_illust_id}"
                    )
            except Exception as e:
                logger.warning(
                    f"获取画师 {artist_id} 最新作品ID失败: {e}，将使用默认值 0"
                )

        except Exception as e:
            logger.error(f"获取画师 {artist_id} 信息失败: {e}")
            yield event.plain_result(
                f"无法获取画师ID {artist_id} 的信息，但仍会使用该ID进行订阅。"
            )

        success, message = add_subscription(
            event.get_group_id() or event.get_sender_id(),
            session_id,
            sub_type,
            artist_id,
            target_name,
            latest_illust_id,
        )
        yield event.plain_result(message)

    async def pixiv_subscribe_remove(
        self, event: AstrMessageEvent, artist_id: str = ""
    ):
        """取消订阅画师"""
        if not self.pixiv_config.subscription_enabled:
            yield event.plain_result("订阅功能未启用。")
            return

        if not artist_id or not artist_id.isdigit():
            yield event.plain_result(
                "请输入有效的画师ID。用法: /pixiv_subscribe_remove <画师ID>"
            )
            return

        chat_id = event.get_group_id() or event.get_sender_id()
        sub_type = "artist"

        success, message = remove_subscription(chat_id, sub_type, artist_id)
        yield event.plain_result(message)

    async def pixiv_subscribe_list(self, event: AstrMessageEvent, args: str = ""):
        """查看当前订阅列表"""
        if not self.pixiv_config.subscription_enabled:
            yield event.plain_result("订阅功能未启用。")
            return

        chat_id = event.get_group_id() or event.get_sender_id()
        subs = list_subscriptions(chat_id)

        if not subs:
            yield event.plain_result("您还没有任何订阅。")
            return

        msg = "您的订阅列表：\n"
        for sub in subs:
            msg += f"- [画师] {sub.target_name} ({sub.target_id})\n"
        yield event.plain_result(msg)
