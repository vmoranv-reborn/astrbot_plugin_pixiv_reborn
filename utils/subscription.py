import asyncio
from datetime import datetime, timedelta
from apscheduler.schedulers.asyncio import AsyncIOScheduler
from astrbot.api import logger
from pixivpy3 import AppPixivAPI
from ..utils.pixiv_utils import (
    filter_items,
    send_pixiv_image,
)

from .database import get_all_subscriptions, update_last_notified_id
from .tag import build_detail_message


class SubscriptionService:
    def __init__(self, client_wrapper, pixiv_config, context):
        self.client_wrapper = client_wrapper
        self.client = client_wrapper.client_api
        self.pixiv_config = pixiv_config
        self.context = context
        self.scheduler = AsyncIOScheduler(timezone="Asia/Shanghai")
        self.job = None

    def start(self):
        """启动后台任务"""
        if not self.scheduler.running:
            self.job = self.scheduler.add_job(
                self.check_subscriptions,
                "interval",
                minutes=self.pixiv_config.subscription_check_interval_minutes,
                next_run_time=datetime.now()
                + timedelta(seconds=10),  # 10秒后第一次运行
            )
            self.scheduler.start()

    def stop(self):
        """停止后台任务"""
        if self.scheduler.running:
            self.scheduler.shutdown()
            logger.info("订阅检查服务已停止。")

    async def check_subscriptions(self):
        """检查所有订阅并推送更新"""
        if not await self.client_wrapper.authenticate():
            logger.error("订阅检查失败：Pixiv API 认证失败。")
            return

        subscriptions = get_all_subscriptions()
        if not subscriptions:
            return

        for sub in subscriptions:
            try:
                if sub.sub_type == "artist":
                    await self.check_artist_updates(sub)
            except Exception as e:
                logger.error(
                    f"检查订阅 {sub.sub_type}: {sub.target_id} 时发生错误: {e}"
                )
            await asyncio.sleep(5)

    async def check_artist_updates(self, sub):
        """检查画师更新"""
        api: AppPixivAPI = self.client
        json_result = await asyncio.to_thread(api.user_illusts, sub.target_id)

        if not json_result or not json_result.illusts:
            return

        new_illusts = []
        for illust in json_result.illusts:
            if illust.id > sub.last_notified_illust_id:
                new_illusts.append(illust)
            else:
                break

        if new_illusts:
            new_illusts.reverse()
            for illust in new_illusts:
                filtered_illusts, _ = filter_items(
                    [illust], f"画师订阅: {sub.target_name}"
                )
                if filtered_illusts:
                    sent_ok = await self.send_update(sub, filtered_illusts[0])
                    if sent_ok:
                        update_last_notified_id(
                            sub.chat_id, sub.sub_type, sub.target_id, illust.id
                        )
                    else:
                        logger.warning(
                            f"订阅发送失败，保留 last_notified_illust_id 不变，"
                            f"下次将重试。artist={sub.target_id}, illust={illust.id}"
                        )
                        break
                else:
                    update_last_notified_id(
                        sub.chat_id, sub.sub_type, sub.target_id, illust.id
                    )
                await asyncio.sleep(2)

    async def send_update(self, sub, illust):
        """发送更新通知，返回图片是否发送成功。"""
        image_sent = False
        try:
            # 导入 MessageChain 类
            from astrbot.core.message.message_event_result import MessageChain
            from astrbot.api.message_components import Image, Node, Nodes, Plain

            # 创建模拟事件对象（用于捕获消息链）
            class MockEvent:
                def chain_result(self, chain):
                    message_chain = MessageChain()
                    message_chain.chain = chain
                    return message_chain

                def plain_result(self, text):
                    message_chain = MessageChain()
                    message_chain.message(text)
                    return message_chain

            mock_event = MockEvent()

            session_id_str = sub.session_id
            detail_message = (
                f"您订阅的 {sub.sub_type} [{sub.target_name}] 有新作品啦！\n"
            )
            detail_message += build_detail_message(illust, is_novel=False)

            # 使用 async for 循环来驱动 send_pixiv_image 生成器
            # 并通过 mock_event 捕获其 yield 的结果
            async for message_content in send_pixiv_image(
                self.client,
                mock_event,
                illust,
                detail_message,
                self.pixiv_config.show_details,
            ):
                if message_content:
                    if hasattr(message_content, "chain"):
                        if self.pixiv_config.subscription_force_forward:
                            # 订阅消息统一以合并转发发送（即便只有一条），避免图片直接出现在群聊中
                            node_content = list(message_content.chain or [])
                            forward_chain = mock_event.chain_result(
                                [Nodes(nodes=[Node(name="Pixiv订阅", content=node_content)])]
                            )
                            await self.context.send_message(session_id_str, forward_chain)
                        else:
                            await self.context.send_message(session_id_str, message_content)
                        # 只有包含 Image 组件时才视为图片发送成功（文本节点不推进游标）
                        if any(
                            isinstance(component, Image)
                            for component in (message_content.chain or [])
                        ):
                            image_sent = True
                    else:
                        plain_text = str(message_content)
                        if self.pixiv_config.subscription_force_forward:
                            # 如果不是 MessageChain，对文本也走单节点合并消息
                            forward_chain = mock_event.chain_result(
                                [
                                    Nodes(
                                        nodes=[
                                            Node(
                                                name="Pixiv订阅",
                                                content=[Plain(plain_text)],
                                            )
                                        ]
                                    )
                                ]
                            )
                            await self.context.send_message(session_id_str, forward_chain)
                        else:
                            message_chain = MessageChain()
                            message_chain.message(plain_text)
                            await self.context.send_message(
                                session_id_str, message_chain
                            )
            return image_sent

        except Exception as e:
            logger.error(f"发送订阅更新时出错: {e}")
            import traceback

            logger.error(traceback.format_exc())
            return False
