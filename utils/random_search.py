import asyncio
import random
from datetime import datetime, timedelta
from apscheduler.schedulers.asyncio import AsyncIOScheduler
from astrbot.api import logger
from astrbot.core.message.message_event_result import MessageChain

from .database import (
    get_all_random_search_groups,
    get_random_tags,
    filter_sent_illusts,
    add_sent_illust,
    cleanup_old_sent_illusts,
    get_schedule_time,
    set_schedule_time,
    remove_schedule_time,
    get_all_schedule_times,
    get_all_random_ranking_groups,
    get_random_rankings,
)
from .tag import (
    build_detail_message,
    FilterConfig,
    validate_and_process_tags,
    process_and_send_illusts,
)
from .pixiv_utils import send_pixiv_image, send_forward_message


class RandomSearchService:
    def __init__(self, client_wrapper, pixiv_config, context):
        self.client_wrapper = client_wrapper
        self.client = client_wrapper.client_api
        self.pixiv_config = pixiv_config
        self.context = context

        self.scheduler = AsyncIOScheduler(timezone="Asia/Shanghai")
        self.job = None
        # 使用数据库存储调度时间，不再使用内存字典
        # 防止并发执行的锁: {chat_id: bool}
        self.execution_locks = {}

        # 新增：全局执行锁和任务队列
        self.global_execution_lock = asyncio.Lock()  # 全局执行锁
        self.task_queue = asyncio.Queue()  # 任务队列
        self.is_queue_processor_running = False  # 队列处理器运行状态

    def start(self):
        """启动后台任务"""
        if not self.scheduler.running:
            self.job = self.scheduler.add_job(
                self._scheduler_tick,
                "interval",
                minutes=1,  # 心跳检查间隔：每分钟检查一次是否有群组达到随机推送时间
                next_run_time=datetime.now() + timedelta(seconds=10),
            )
            # 添加定期清理任务，每天清理一次过期记录
            self.scheduler.add_job(
                self._cleanup_task,
                "cron",
                hour=2,
                minute=0,  # 每天凌晨2点执行
            )

            self.scheduler.start()
            logger.info("Pixiv 随机搜索服务已启动。")

            # 服务启动时，从数据库加载所有调度时间
            self._load_existing_schedules()

    def _load_existing_schedules(self):
        """从数据库加载现有的调度时间"""
        try:
            schedules = get_all_schedule_times()
            logger.info(f"从数据库加载了 {len(schedules)} 个群组的调度时间")
        except Exception as e:
            logger.error(f"加载调度时间失败: {e}")

    def stop(self):
        """停止后台任务"""
        if self.scheduler.running:
            self.scheduler.shutdown()
            # 注意：队列处理器会在服务停止时自动结束，因为它们是守护任务
            self.is_queue_processor_running = False
            logger.info("Pixiv 随机搜索服务已停止。")

    async def _scheduler_tick(self):
        """
        检查是否有群组需要执行搜索，并将其加入队列。
        """
        if not self.client:
            return

        try:
            # 启动队列处理器（如果尚未运行）
            if not self.is_queue_processor_running:
                asyncio.create_task(self._task_queue_processor())
                self.is_queue_processor_running = True
                logger.info("RandomSearchService 队列处理器已启动")

            # 获取所有配置了标签的群组
            # groups = get_all_random_search_groups()
            tag_groups = get_all_random_search_groups()
            ranking_groups = get_all_random_ranking_groups()
            groups = list(set(tag_groups + ranking_groups))

            now = datetime.now()

            pending_groups = []

            for chat_id in groups:
                # 初始化执行锁
                if chat_id not in self.execution_locks:
                    self.execution_locks[chat_id] = False

                # 从数据库获取下次执行时间
                next_execution_time = get_schedule_time(chat_id)

                # 如果是第一次看到这个群组，立即或稍后调度
                if next_execution_time is None:
                    # 初始延迟，避免同时启动，使用用户配置的间隔范围
                    min_interval = self.pixiv_config.random_search_min_interval
                    max_interval = self.pixiv_config.random_search_max_interval
                    # 基本验证确保 max >= min
                    if max_interval < min_interval:
                        max_interval = min_interval

                    delay_minutes = random.randint(min_interval, max_interval)
                    next_execution_time = now + timedelta(minutes=delay_minutes)
                    set_schedule_time(chat_id, next_execution_time)
                    logger.info(
                        f"群组 {chat_id}: 首次调度随机搜索，将在 {delay_minutes} 分钟后执行"
                    )
                    continue

                # 检查是否到了运行时间且当前没有执行任务
                if now >= next_execution_time and not self.execution_locks[chat_id]:
                    pending_groups.append(chat_id)

            # 将所有待执行的群组加入队列
            for chat_id in pending_groups:
                try:
                    await self.task_queue.put(chat_id)
                    logger.info(f"群组 {chat_id}: 已加入随机搜索队列")
                except Exception as e:
                    logger.error(f"将群组 {chat_id} 加入队列失败: {e}")

        except Exception as e:
            logger.error(f"RandomSearchService 调度器 tick 出错: {e}")

    async def _task_queue_processor(self):
        """
        任务队列处理器，按顺序执行队列中的搜索任务。
        """
        logger.info("RandomSearchService 任务队列处理器开始运行")

        while True:
            try:
                # 从队列中获取群组ID（阻塞等待）
                chat_id = await self.task_queue.get()

                # 使用全局锁确保同时只有一个任务执行
                async with self.global_execution_lock:
                    # 再次检查群组是否仍在执行状态
                    if self.execution_locks.get(chat_id, False):
                        logger.warning(f"群组 {chat_id} 已在执行状态，跳过本次任务")
                        self.task_queue.task_done()
                        continue

                    # 设置执行锁
                    self.execution_locks[chat_id] = True

                    try:
                        logger.info(f"开始执行群组 {chat_id} 的随机搜索")
                        await self.execute_search_for_group(chat_id)

                        # 调度下次运行
                        now = datetime.now()
                        min_interval = self.pixiv_config.random_search_min_interval
                        max_interval = self.pixiv_config.random_search_max_interval
                        # 基本验证确保 max >= min
                        if max_interval < min_interval:
                            max_interval = min_interval

                        next_interval = random.randint(min_interval, max_interval)
                        new_execution_time = now + timedelta(minutes=next_interval)
                        set_schedule_time(chat_id, new_execution_time)
                        logger.info(
                            f"群组 {chat_id}: 随机搜索已执行。下次运行在 {next_interval} 分钟后。"
                        )

                    except Exception as e:
                        logger.error(f"执行群组 {chat_id} 的随机搜索时出错: {e}")
                    finally:
                        # 释放执行锁
                        self.execution_locks[chat_id] = False
                        self.task_queue.task_done()

            except asyncio.CancelledError:
                logger.info("RandomSearchService 任务队列处理器被取消")
                break
            except Exception as e:
                logger.error(f"RandomSearchService 任务队列处理器出错: {e}")
                # 短暂延迟后继续处理下一个任务
                await asyncio.sleep(5)

    async def _cleanup_task(self):
        """定期清理过期记录的任务"""
        try:
            logger.info("开始清理过期的已发送作品记录...")
            # 获取配置
            days = self.pixiv_config.random_sent_illust_retention_days

            # 使用 to_thread 防止数据库操作阻塞异步循环
            await asyncio.to_thread(cleanup_old_sent_illusts, days=days)
            logger.info("清理过期记录任务完成。")
        except Exception as e:
            logger.error(f"清理过期记录任务出错: {e}")

    async def execute_search_for_group(self, chat_id: str):
        """为特定群组执行随机搜索（标签或排行榜）"""
        tags = get_random_tags(chat_id)
        rankings = get_random_rankings(chat_id)

        if not tags and not rankings:
            return

        # 随机选择执行标签搜索或排行榜搜索
        all_options = []
        for tag in tags:
            all_options.append(("tag", tag))
        for ranking in rankings:
            all_options.append(("ranking", ranking))

        selected = random.choice(all_options)

        if selected[0] == "tag":
            await self._execute_tag_search(chat_id, selected[1])
        else:
            await self._execute_ranking_search(chat_id, selected[1])

    async def _execute_tag_search(self, chat_id: str, selected_tag_entry):
        """执行标签搜索"""
        raw_tag = selected_tag_entry.tag
        session_id = selected_tag_entry.session_id

        logger.info(f"正在为群组 {chat_id} 执行随机标签搜索，标签: {raw_tag}")

        # 如果需要则认证
        if not await self.client_wrapper.authenticate():
            logger.error(f"群组 {chat_id} 的随机搜索失败: 认证失败。")
            return

        # 处理标签
        tag_result = validate_and_process_tags(raw_tag)
        if not tag_result["success"]:
            logger.warning(
                f"标签 {raw_tag} 的随机搜索验证失败: {tag_result['error_message']}"
            )
            return

        search_tags = tag_result["search_tags"]
        exclude_tags = tag_result["exclude_tags"]
        display_tags = tag_result["display_tags"]

        try:
            # 准备搜索参数，参考 pixiv_deepsearch 的实现
            search_params = {
                "word": search_tags,
                "search_target": "partial_match_for_tags",
                "sort": "popular_desc",
                "filter": "for_ios",
                "req_auth": True,
            }

            # 执行深度搜索，完全参考 pixiv_deepsearch 的实现
            all_illusts = []
            page_count = 0
            deep_search_depth = self.pixiv_config.deep_search_depth
            next_params = search_params.copy()

            # 循环获取多页结果
            while next_params:
                # 限制页数
                if deep_search_depth > 0 and page_count >= deep_search_depth:
                    break

                # 搜索当前页，使用与 pixiv_deepsearch 相同的方式
                json_result = await asyncio.to_thread(
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
                        f"标签 {raw_tag} 的随机搜索：已获取第 {page_count} 页，找到 {len(current_illusts)} 个插画"
                    )

                    # 发送进度更新（每3页更新一次，与 pixiv_deepsearch 保持一致）
                    if page_count % 3 == 0:
                        logger.info(
                            f"标签 {raw_tag} 搜索进行中：已获取 {page_count} 页，共 {len(all_illusts)} 个结果..."
                        )
                else:
                    break

                # 获取下一页参数，使用与 pixiv_deepsearch 相同的方式
                next_url = json_result.next_url
                next_params = self.client.parse_qs(next_url) if next_url else None

                # 避免请求过于频繁，与 pixiv_deepsearch 保持一致的延迟
                if next_params:
                    await asyncio.sleep(0.5)  # 添加延迟，避免请求过快

            if not all_illusts:
                logger.info(f"标签 {raw_tag} 的随机搜索未返回结果。")
                return

            # 记录找到的总数量，与 pixiv_deepsearch 保持一致
            initial_count = len(all_illusts)
            logger.info(
                f"标签 {raw_tag} 的随机搜索完成，共获取 {page_count} 页，找到 {initial_count} 个插画，开始过滤处理..."
            )

            # 过滤已发送的作品
            initial_illusts = filter_sent_illusts(all_illusts, chat_id)

            if not initial_illusts:
                logger.info(f"标签 {raw_tag} 的随机搜索过滤后无可用作品。")
                return

            # 发送配置
            config = FilterConfig(
                r18_mode=self.pixiv_config.r18_mode,
                ai_filter_mode=self.pixiv_config.ai_filter_mode,
                display_tag_str=f"随机:{display_tags}",
                return_count=self.pixiv_config.return_count,
                logger=logger,
                show_filter_result=self.pixiv_config.show_filter_result,
                excluded_tags=exclude_tags or [],
                forward_threshold=self.pixiv_config.forward_threshold,
                show_details=self.pixiv_config.show_details,
            )

            # 创建模拟事件以捕获输出
            class MockEvent:
                def __init__(self):
                    self.bot = None  # 模拟 bot 属性

                def chain_result(self, chain):
                    message_chain = MessageChain()
                    message_chain.chain = chain
                    return message_chain

                def plain_result(self, text):
                    message_chain = MessageChain()
                    message_chain.message(text)
                    return message_chain

                def get_platform_name(self):
                    return "unknown"

                def get_group_id(self):
                    return None

            mock_event = MockEvent()

            # 复用 process_and_send_illusts
            sent_illust_ids = set()  # 记录已发送的作品ID

            async for message_content in process_and_send_illusts(
                initial_illusts,
                config,
                self.client,
                mock_event,
                build_detail_message,
                send_pixiv_image,
                send_forward_message,
                is_novel=False,
            ):
                if message_content:
                    logger.info(f"准备向 session_id: {session_id} 发送消息")
                    if hasattr(message_content, "chain"):
                        logger.info(f"消息链长度: {len(message_content.chain)}")

                    try:
                        if hasattr(message_content, "chain"):
                            # 检查是否为转发消息
                            chain = message_content.chain
                            if chain and len(chain) > 0 and hasattr(chain[0], "nodes"):
                                logger.info(
                                    f"检测到转发消息，节点数量: {len(chain[0].nodes)}"
                                )
                                # 转发消息中包含多个作品，需要提取作品ID
                                for node in chain[0].nodes:
                                    if hasattr(node, "content") and node.content:
                                        for content_item in node.content:
                                            if (
                                                hasattr(content_item, "plain")
                                                and "作品ID:" in content_item.plain
                                            ):
                                                # 从详情消息中提取作品ID
                                                lines = content_item.plain.split("\n")
                                                for line in lines:
                                                    if line.startswith(
                                                        "链接: https://www.pixiv.net/artworks/"
                                                    ):
                                                        illust_id = int(
                                                            line.split("/")[-1]
                                                        )
                                                        sent_illust_ids.add(illust_id)
                            await self.context.send_message(session_id, message_content)
                        else:
                            # 纯文本或列表的回退
                            if isinstance(message_content, list):
                                logger.warning(
                                    "在 random_search 中收到列表而不是 MessageChain"
                                )
                                pass
                            elif isinstance(message_content, MessageChain):
                                await self.context.send_message(
                                    session_id, message_content
                                )
                            else:
                                # 尝试字符串转换
                                chain = MessageChain().message(str(message_content))
                                await self.context.send_message(session_id, chain)
                        logger.info(f"消息已发送至 {session_id}")
                    except Exception as e:
                        logger.error(f"向 {session_id} 发送消息失败: {e}")

            # 记录已发送的作品ID到数据库
            for illust_id in sent_illust_ids:
                add_sent_illust(illust_id, chat_id)
            if sent_illust_ids:
                logger.info(
                    f"群组 {chat_id}: 已记录 {len(sent_illust_ids)} 个作品的发送记录"
                )

        except Exception as e:
            logger.error(f"为群组 {chat_id} 执行随机标签搜索时出错: {e}")

    async def _execute_ranking_search(self, chat_id: str, ranking_config):
        """执行排行榜搜索"""
        mode = ranking_config.mode
        date = ranking_config.date
        session_id = ranking_config.session_id

        logger.info(
            f"正在为群组 {chat_id} 执行随机排行榜搜索，模式: {mode}, 日期: {date}"
        )

        if not await self.client_wrapper.authenticate():
            logger.error(f"群组 {chat_id} 的随机排行榜搜索失败: 认证失败。")
            return

        try:
            ranking_result = await asyncio.to_thread(
                self.client.illust_ranking, mode=mode, date=date
            )
            initial_illusts = ranking_result.illusts if ranking_result.illusts else []

            if not initial_illusts:
                logger.info(f"排行榜 {mode} 的随机搜索未返回结果。")
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
                        f"排行榜 {mode}：已过滤 {filtered_count} 个漫画作品(manga)。"
                    )

            # 过滤已发送的作品
            initial_illusts = filter_sent_illusts(initial_illusts, chat_id)

            if not initial_illusts:
                logger.info(f"排行榜 {mode} 的随机搜索过滤后无可用作品。")
                return

            config = FilterConfig(
                r18_mode=self.pixiv_config.r18_mode,
                ai_filter_mode=self.pixiv_config.ai_filter_mode,
                display_tag_str=f"随机排行榜:{mode}",
                return_count=self.pixiv_config.return_count,
                logger=logger,
                show_filter_result=self.pixiv_config.show_filter_result,
                excluded_tags=[],
                forward_threshold=self.pixiv_config.forward_threshold,
                show_details=self.pixiv_config.show_details,
            )

            class MockEvent:
                def __init__(self):
                    self.bot = None

                def chain_result(self, chain):
                    message_chain = MessageChain()
                    message_chain.chain = chain
                    return message_chain

                def plain_result(self, text):
                    message_chain = MessageChain()
                    message_chain.message(text)
                    return message_chain

                def get_platform_name(self):
                    return "unknown"

                def get_group_id(self):
                    return None

            mock_event = MockEvent()
            sent_illust_ids = set()

            async for message_content in process_and_send_illusts(
                initial_illusts,
                config,
                self.client,
                mock_event,
                build_detail_message,
                send_pixiv_image,
                send_forward_message,
                is_novel=False,
            ):
                if message_content:
                    try:
                        if hasattr(message_content, "chain"):
                            chain = message_content.chain
                            if chain and len(chain) > 0 and hasattr(chain[0], "nodes"):
                                for node in chain[0].nodes:
                                    if hasattr(node, "content") and node.content:
                                        for content_item in node.content:
                                            if (
                                                hasattr(content_item, "plain")
                                                and "作品ID:" in content_item.plain
                                            ):
                                                lines = content_item.plain.split("\n")
                                                for line in lines:
                                                    if line.startswith(
                                                        "链接: https://www.pixiv.net/artworks/"
                                                    ):
                                                        illust_id = int(
                                                            line.split("/")[-1]
                                                        )
                                                        sent_illust_ids.add(illust_id)
                            await self.context.send_message(session_id, message_content)
                        elif isinstance(message_content, MessageChain):
                            await self.context.send_message(session_id, message_content)
                        else:
                            chain = MessageChain().message(str(message_content))
                            await self.context.send_message(session_id, chain)
                        logger.info(f"排行榜消息已发送至 {session_id}")
                    except Exception as e:
                        logger.error(f"向 {session_id} 发送排行榜消息失败: {e}")

            for illust_id in sent_illust_ids:
                add_sent_illust(illust_id, chat_id)
            if sent_illust_ids:
                logger.info(
                    f"群组 {chat_id}: 已记录 {len(sent_illust_ids)} 个排行榜作品的发送记录"
                )

        except Exception as e:
            logger.error(f"为群组 {chat_id} 执行随机排行榜搜索时出错: {e}")

    def suspend_group_search(self, chat_id: str):
        """暂停指定群组的随机搜索"""
        try:
            # 移除该群组的调度时间
            remove_schedule_time(chat_id)
            logger.info(f"已移除群组 {chat_id} 的调度时间")
        except Exception as e:
            logger.error(f"移除群组 {chat_id} 调度时间失败: {e}")

    def resume_group_search(self, chat_id: str):
        """恢复指定群组的随机搜索"""
        try:
            # 重新设置调度时间，使用用户配置的间隔范围
            now = datetime.now()
            min_interval = self.pixiv_config.random_search_min_interval
            max_interval = self.pixiv_config.random_search_max_interval
            # 基本验证确保 max >= min
            if max_interval < min_interval:
                max_interval = min_interval

            # 恢复时使用较短的延迟，但仍在用户配置范围内
            delay_minutes = random.randint(min_interval, max_interval)
            next_time = now + timedelta(minutes=delay_minutes)
            set_schedule_time(chat_id, next_time)
            logger.info(
                f"群组 {chat_id} 随机搜索已恢复，将在 {delay_minutes} 分钟后执行"
            )
        except Exception as e:
            logger.error(f"恢复群组 {chat_id} 调度时间失败: {e}")

    def get_queue_status(self) -> dict:
        """获取队列状态信息，用于调试和监控"""
        return {
            "queue_size": self.task_queue.qsize(),
            "is_queue_processor_running": self.is_queue_processor_running,
            "execution_locks": dict(self.execution_locks),
            "active_groups": [
                chat_id for chat_id, locked in self.execution_locks.items() if locked
            ],
        }

    async def force_execute_group(self, chat_id: str) -> bool:
        """强制执行指定群组的随机搜索（用于调试）"""
        if chat_id not in self.execution_locks:
            self.execution_locks[chat_id] = False

        if self.execution_locks[chat_id]:
            logger.warning(f"群组 {chat_id} 已在执行状态，无法强制执行")
            return False

        try:
            await self.task_queue.put(chat_id)
            logger.info(f"群组 {chat_id} 已强制加入执行队列")
            return True
        except Exception as e:
            logger.error(f"强制执行群组 {chat_id} 失败: {e}")
            return False
