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
        """检查所有订阅并推送更新，按 (sub_type, target_id) 聚合，避免同一画师重复拉取 API。"""
        if not await self.client_wrapper.authenticate():
            logger.error("订阅检查失败：Pixiv API 认证失败。")
            return

        subscriptions = get_all_subscriptions()
        if not subscriptions:
            return

        # 按 (sub_type, target_id) 分组，每组只调用一次 API
        groups: dict[tuple[str, str], list] = {}
        for sub in subscriptions:
            key = (sub.sub_type, sub.target_id)
            groups.setdefault(key, []).append(sub)

        artists = list(groups.items())

        for (sub_type, target_id), subs in artists:
            try:
                if sub_type == "artist":
                    await self.check_artist_updates_aggregated(
                        int(target_id), subs
                    )
            except Exception as e:
                logger.error(
                    f"检查订阅 {sub_type}: {target_id} 时发生错误: {e}"
                )
            # 画师之间保留短暂间隔，避免 API 频率限制
            await asyncio.sleep(3)

    async def check_artist_updates_aggregated(self, artist_id: int, subs: list):
        """聚合检查画师更新：拉取一次 API，然后并发向所有订阅群推送。"""
        api: AppPixivAPI = self.client
        json_result = await asyncio.to_thread(api.user_illusts, artist_id)

        if not json_result or not json_result.illusts:
            return

        # 找出本次拉取中所有新作品（取所有订阅中 last_notified_illust_id 的最大值作为阈值，避免遗漏）
        # 但各群的 last_notified_illust_id 可能不同，需要为每个群独立过滤
        # 先找出全局最新作品（ID 最大的），以此为上限
        all_illusts = sorted(json_result.illusts, key=lambda i: i.id, reverse=True)
        global_latest_id = all_illusts[0].id if all_illusts else 0

        # 并发为各群推送
        tasks = []
        for sub in subs:
            tasks.append(
                self._send_artist_updates_to_sub(sub, all_illusts, global_latest_id)
            )

        if tasks:
            await asyncio.gather(*tasks)

    async def _send_artist_updates_to_sub(
        self, sub, all_illusts: list, global_latest_id: int
    ):
        """向单个订阅推送画师的新作品。"""
        # 按该群的 last_notified_illust_id 过滤新作品
        new_illusts = []
        for illust in all_illusts:
            if illust.id > sub.last_notified_illust_id:
                new_illusts.append(illust)
            else:
                break

        if not new_illusts:
            return

        # 按 ID 升序排列，最新的在最后
        new_illusts.reverse()

        # 更新该群的 last_notified_illust_id 为当前全局最新
        update_last_notified_id(
            sub.chat_id, sub.sub_type, sub.target_id, global_latest_id
        )

        for illust in new_illusts:
            filtered_illusts, _ = filter_items(
                [illust], f"画师订阅: {sub.target_name}"
            )
            if filtered_illusts:
                await self.send_update(sub, filtered_illusts[0])
                # 同一群内多张作品之间短暂间隔
                await asyncio.sleep(1.5)

    async def send_update(self, sub, illust):
        """发送更新通知"""
        try:
            # 导入 MessageChain 类
            from astrbot.core.message.message_event_result import MessageChain

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
                        await self.context.send_message(session_id_str, message_content)
                    else:
                        # 如果不是 MessageChain 对象，创建一个
                        message_chain = MessageChain()
                        message_chain.message(str(message_content))
                        await self.context.send_message(session_id_str, message_chain)

        except Exception as e:
            logger.error(f"发送订阅更新时出错: {e}")
            import traceback

            logger.error(traceback.format_exc())