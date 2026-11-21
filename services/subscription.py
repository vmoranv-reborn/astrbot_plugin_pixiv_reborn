import asyncio
from datetime import datetime, timedelta

from apscheduler.schedulers.asyncio import AsyncIOScheduler
from astrbot.api import logger

from ..domain.tag import build_detail_message
from ..infra.database import get_all_subscriptions, update_last_notified_id
from ..infra.message import CaptureEvent, chain_contains_image
from ..media.pixiv_utils import (
    filter_items,
    send_forward_message,
    send_pixiv_image,
)


class SubscriptionService:
    """画师订阅检查与推送服务。"""

    def __init__(self, client_wrapper, pixiv_config, context):
        self.client_wrapper = client_wrapper
        self.client = client_wrapper.client_api
        self.pixiv_config = pixiv_config
        self.context = context
        self.scheduler = AsyncIOScheduler(timezone="Asia/Shanghai")
        self.job = None

    def start(self):
        """启动后台任务。"""
        if not self.scheduler.running:
            self.job = self.scheduler.add_job(
                self.check_subscriptions,
                "interval",
                minutes=self.pixiv_config.subscription_check_interval_minutes,
                next_run_time=datetime.now() + timedelta(seconds=10),
            )
            self.scheduler.start()

    def stop(self):
        """停止后台任务。"""
        if self.scheduler.running:
            self.scheduler.shutdown()
            logger.info("订阅检查服务已停止。")

    async def check_subscriptions(self):
        """检查所有订阅并按 (sub_type, target_id) 聚合，避免重复拉取 API。"""
        if not await self.client_wrapper.authenticate():
            logger.debug("订阅检查跳过：Pixiv API 当前未认证。")
            return

        subscriptions = get_all_subscriptions()
        if not subscriptions:
            return

        groups: dict[tuple[str, str], list] = {}
        for sub in subscriptions:
            groups.setdefault((sub.sub_type, sub.target_id), []).append(sub)

        for (sub_type, target_id), subs in groups.items():
            try:
                if sub_type == "artist":
                    await self.check_artist_updates_aggregated(int(target_id), subs)
            except Exception as e:
                logger.error(f"检查订阅 {sub_type}: {target_id} 时发生错误: {e}")
            await asyncio.sleep(3)

    async def check_artist_updates_aggregated(self, artist_id: int, subs: list):
        """拉取一次画师作品，然后并发向所有订阅推送。"""
        json_result = await asyncio.to_thread(self.client.user_illusts, artist_id)
        if not json_result or not json_result.illusts:
            return

        all_illusts = sorted(json_result.illusts, key=lambda i: i.id, reverse=True)
        tasks = [self._send_artist_updates_to_sub(sub, all_illusts) for sub in subs]
        if tasks:
            results = await asyncio.gather(*tasks, return_exceptions=True)
            for result in results:
                if isinstance(result, Exception):
                    logger.error(f"订阅推送任务异常: {result}")

    async def _send_artist_updates_to_sub(self, sub, all_illusts: list):
        """向单个订阅推送新作品；仅在发送成功后推进游标。"""
        new_illusts = []
        for illust in all_illusts:
            if illust.id > sub.last_notified_illust_id:
                new_illusts.append(illust)
            else:
                break

        if not new_illusts:
            return

        new_illusts.reverse()  # 最新作品在最后发送

        for illust in new_illusts:
            filtered_illusts, _ = filter_items([illust], f"画师订阅: {sub.target_name}")
            if filtered_illusts:
                sent_ok = await self.send_update(sub, filtered_illusts[0])
                if not sent_ok:
                    logger.warning(
                        "订阅发送失败，保留 last_notified_illust_id 不变，"
                        f"下次将重试。artist={sub.target_id}, illust={illust.id}"
                    )
                    return
            update_last_notified_id(sub.chat_id, sub.sub_type, sub.target_id, illust.id)
            await asyncio.sleep(1.5)

    async def _ensure_full_pages(self, illust):
        """user_illusts 未返回 meta_pages 时，补拉 illust_detail 以拿到全部页面。"""
        pages = list(getattr(illust, "meta_pages", None) or [])
        page_count = int(getattr(illust, "page_count", 1) or 1)
        if page_count <= 1 or pages or not self.client:
            return illust
        try:
            detail = await asyncio.to_thread(
                self.client.illust_detail, getattr(illust, "id", None)
            )
            full = getattr(detail, "illust", None) if detail else None
            if full and (getattr(full, "meta_pages", None) or []):
                return full
        except Exception as exc:
            logger.warning(
                f"补拉作品详情失败，将退回首图: illust={getattr(illust, 'id', None)} - {exc}"
            )
        return illust

    async def send_update(self, sub, illust) -> bool:
        """发送更新通知；多图优先合并转发，失败时回退逐页发送。"""
        try:
            mock_event = CaptureEvent()
            illust = await self._ensure_full_pages(illust)
            detail_message = (
                f"您订阅的 {sub.sub_type} [{sub.target_name}] 有新作品啦！\n"
            )
            detail_message += build_detail_message(illust, is_novel=False)

            # Issue #53: 订阅始终发送全部页面，不再提供“仅首图”开关。
            send_all_pages = True
            max_pages = int(
                getattr(self.pixiv_config, "subscription_max_pages", 0) or 0
            )
            page_count = int(getattr(illust, "page_count", 1) or 1)
            # 多图必须经过转发聚合路径；单图沿用现有订阅转发配置。
            use_forward = (
                bool(getattr(self.pixiv_config, "subscription_force_forward", True))
                or page_count > 1
            )

            if use_forward:
                forward_messages = 0
                forward_ok = 0
                async for message_content in send_forward_message(
                    self.client,
                    mock_event,
                    [illust],
                    lambda item: build_detail_message(item, is_novel=False),
                    send_all_pages=send_all_pages,
                    max_pages=max_pages,
                    summary_text=detail_message,
                    single_batch=True,
                ):
                    if not message_content:
                        continue
                    forward_messages += 1
                    delivered = await self.context.send_message(
                        sub.session_id, message_content
                    )
                    if bool(delivered) and chain_contains_image(
                        getattr(message_content, "chain", None)
                    ):
                        forward_ok += 1

                if forward_messages and forward_ok == forward_messages:
                    return True
                if forward_ok:
                    # 部分转发已送达，回退逐页会造成重复，交由下一轮重试。
                    return False
                logger.warning(
                    "订阅合并转发未送达图片，回退逐页发送。"
                    f"chat={sub.chat_id}, illust={illust.id}"
                )

            delivered_all = True
            sent_any = False
            async for message_content in send_pixiv_image(
                self.client,
                mock_event,
                illust,
                detail_message,
                self.pixiv_config.show_details,
                send_all_pages=send_all_pages,
                max_pages=max_pages,
            ):
                if not message_content:
                    continue
                delivered = await self.context.send_message(
                    sub.session_id, message_content
                )
                if bool(delivered) and chain_contains_image(
                    getattr(message_content, "chain", None)
                ):
                    sent_any = True
                else:
                    delivered_all = False
            return sent_any and delivered_all

        except Exception as e:
            logger.error(f"发送订阅更新时出错: {e}")
            import traceback

            logger.error(traceback.format_exc())
            return False
