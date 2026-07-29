import asyncio
from typing import Dict, Any
import aiohttp

from astrbot.api.event import AstrMessageEvent, filter
from astrbot.api.star import Context, Star, StarTools
from astrbot.api import logger

from .utils.database import initialize_database
from .utils.subscription import SubscriptionService
from .utils.pixiv_utils import init_pixiv_utils
from .utils.help import init_help_manager, get_help_message
from .utils.llm_tool import create_pixiv_llm_tools
from .utils.tag import set_filter_config_source

from .utils.config import PixivConfig, PixivConfigManager

from .core.client import PixivClientWrapper
from .handlers.illust import IllustHandler
from .handlers.user import UserHandler
from .handlers.novel import NovelHandler
from .handlers.subscribe import SubscribeHandler
from .handlers.random_illust import RandomIllustHandler
from .handlers.misc import MiscHandler
from .handlers.fanbox import FanboxHandler


class PixivSearchPlugin(Star):
    """
    AstrBot 插件，用于通过 Pixiv API 搜索插画。
    配置通过 AstrBot WebUI 进行管理。
    用法:
        /pixiv search <标签1>,<标签2>,...  搜索 Pixiv 插画
        /pixiv help                 查看帮助信息
    可在配置中设置认证信息、返回数量和 R18 过滤模式。
    """

    def __init__(self, context: Context, config: Dict[str, Any]):
        """初始化 Pixiv 插件"""
        super().__init__(context)
        self.config = config

        # 1.初始化配置管理器

        self.pixiv_config = PixivConfig(self.config)
        self.config_manager = PixivConfigManager(self.pixiv_config)

        # 2. 初始化核心客户端 (Facade 持有核心组件)
        self.client_wrapper = PixivClientWrapper(self.pixiv_config)
        self.client = self.client_wrapper.client_api

        # 3. 初始化各个子系统 (Handlers)，把工具给它们
        self.illust_handler = IllustHandler(self.client_wrapper, self.pixiv_config)
        self.user_handler = UserHandler(self.client_wrapper, self.pixiv_config)
        self.novel_handler = NovelHandler(self.client_wrapper, self.pixiv_config)
        self.subscribe_handler = SubscribeHandler(
            self.client_wrapper, self.pixiv_config
        )
        self.random_illust_handler = RandomIllustHandler(
            self.client_wrapper, self.pixiv_config, context
        )
        self.misc_handler = MiscHandler(self.client_wrapper, self.pixiv_config)
        self.fanbox_handler = FanboxHandler(self.pixiv_config, context=context)

        self._refresh_task: asyncio.Task = None
        self._http_session = None
        self.sub_service = None
        self.random_search_service = None

        # 使用 StarTools 获取标准数据目录
        data_dir = StarTools.get_data_dir("pixiv_search")
        self.temp_dir = data_dir / "temp"
        self.temp_dir.mkdir(parents=True, exist_ok=True)
        self.fanbox_handler.temp_dir = self.temp_dir

        # 初始化 PixivUtils 模块
        init_pixiv_utils(self.client, self.pixiv_config, self.temp_dir)
        set_filter_config_source(self.pixiv_config)

        # 初始化帮助消息管理器
        init_help_manager(data_dir)

        # 初始化数据库
        initialize_database()

        # 记录初始化信息
        logger.info(f"Pixiv 插件配置加载：{self.pixiv_config.get_config_info()}")

        # 启动后台刷新任务
        self._refresh_task = self.client_wrapper.start_refresh_task()

        # 启动订阅服务
        if self.pixiv_config.subscription_enabled:
            self.sub_service = SubscriptionService(
                self.client_wrapper, self.pixiv_config, context
            )
            self.sub_service.start()
        else:
            logger.info("Pixiv 插件：订阅功能已禁用。")

        # 启动随机搜索服务
        self.random_search_service = self.random_illust_handler.random_search_service
        self.random_search_service.start()

        # 初始化LLM工具
        logger.info(
            f"Pixiv 插件：准备初始化LLM工具，client: {'已设置' if self.client else '未设置'}"
        )
        self.llm_tools = create_pixiv_llm_tools(
            self.client, self.pixiv_config, self.client_wrapper
        )
        logger.info("Pixiv 插件：LLM工具已初始化。")

        # 注册LLM工具到AstrBot
        try:
            self.context.add_llm_tools(*self.llm_tools)
            logger.info(
                f"Pixiv 插件：已注册 {len(self.llm_tools)} 个LLM工具到AstrBot系统。"
            )
        except Exception as e:
            logger.error(f"Pixiv 插件：注册LLM工具失败 - {e}")

    @staticmethod
    def info() -> Dict[str, Any]:
        """返回插件元数据"""
        return {
            "name": "pixiv_search",
            "author": "vmoranv",
            "description": "Pixiv 图片搜索",
            "version": "1.7.4",
            "homepage": "https://github.com/vmoranv-reborn/astrbot_plugin_pixiv_search",
        }

    @filter.command_group("pixiv")
    def pixiv(self):
        """Pixiv 功能指令组"""
        pass

    @pixiv.command("search")
    async def pixiv_search_illust(self, event: AstrMessageEvent, tags: str = ""):
        """按标签搜索 Pixiv 插画"""
        async for result in self.illust_handler.pixiv_search_illust(event, tags):
            yield result

    @pixiv.command("deep")
    async def pixiv_deepsearch(self, event: AstrMessageEvent, tags: str):
        """深度搜索 Pixiv 插画"""
        async for result in self.illust_handler.pixiv_deepsearch(event, tags):
            yield result

    @pixiv.command("and")
    async def pixiv_and(self, event: AstrMessageEvent, tags: str = ""):
        """搜索同时包含所有指定标签的插画"""
        async for result in self.illust_handler.pixiv_and(event, tags):
            yield result

    @pixiv.command("hot")
    async def pixiv_hot(
        self,
        event: AstrMessageEvent,
        tag: str = "",
        duration: str = "",
        pages: str = "",
    ):
        """按热度（收藏数）搜索作品"""
        async for result in self.illust_handler.pixiv_hot(event, tag, duration, pages):
            yield result

    @pixiv.command("help")
    async def pixiv_help(self, event: AstrMessageEvent, args: str = ""):
        """生成并返回帮助信息"""

        help_text = get_help_message("pixiv_help", "帮助消息加载失败，请检查配置文件。")
        yield event.plain_result(help_text)

    @pixiv.command("ai")
    async def pixiv_ai_show_settings(self, event: AstrMessageEvent, setting: str = ""):
        """设置是否展示AI生成作品"""
        async for result in self.misc_handler.pixiv_ai_show_settings(event, setting):
            yield result

    @pixiv.command("config")
    async def pixiv_config(
        self, event: AstrMessageEvent, arg1: str = "", arg2: str = ""
    ):
        """查看或动态设置 Pixiv 插件参数（除 refresh_token）。"""
        result = await self.config_manager.handle_config_command(event, arg1, arg2)
        if result:
            yield event.plain_result(result)

    # --------插画类

    @pixiv.group("illust")
    def pixiv_illust_group(self):
        """插画查询指令组"""
        pass

    @pixiv_illust_group.command("new")
    async def pixiv_illust_new(
        self,
        event: AstrMessageEvent,
        content_type: str = "illust",
        max_illust_id: str = "",
    ):
        """获取大家的新插画作品"""
        async for result in self.illust_handler.pixiv_illust_new(
            event, content_type, max_illust_id
        ):
            yield result

    @pixiv_illust_group.command("recommended")
    async def pixiv_recommended(self, event: AstrMessageEvent, args: str = ""):
        """获取 Pixiv 推荐作品"""
        async for result in self.illust_handler.pixiv_recommended(event, args):
            yield result

    @filter.event_message_type(filter.EventMessageType.ALL)
    async def pixiv_url_all(self, event: AstrMessageEvent):
        """处理url消息事件,判断是否为p站插画链接,并发送图片"""
        async for result in self.illust_handler.pixiv_msg_url(event, event.message_str):
            yield result

    @pixiv_illust_group.command("get")
    async def pixiv_specific(self, event: AstrMessageEvent, illust_id: str = ""):
        """根据作品 ID 获取特定作品详情"""
        async for result in self.illust_handler.pixiv_specific(event, illust_id):
            yield result

    @pixiv_illust_group.command("ranking")
    async def pixiv_ranking(
        self, event: AstrMessageEvent, mode: str = "", date: str = ""
    ):
        """获取 Pixiv 排行榜作品"""
        args = " ".join([x for x in [mode, date] if x])
        async for result in self.illust_handler.pixiv_ranking(event, args):
            yield result

    @pixiv_illust_group.command("related")
    async def pixiv_related(self, event: AstrMessageEvent, illust_id: str = ""):
        """获取与指定作品相关的其他作品"""
        async for result in self.illust_handler.pixiv_related(event, illust_id):
            yield result

    @pixiv_illust_group.command("comments")
    async def pixiv_illust_comments(
        self, event: AstrMessageEvent, illust_id: str = "", offset: str = ""
    ):
        """获取指定作品的评论"""
        async for result in self.illust_handler.pixiv_illust_comments(
            event, illust_id, offset
        ):
            yield result

    @pixiv_illust_group.command("showcase")
    async def pixiv_showcase_article(
        self, event: AstrMessageEvent, showcase_id: str = ""
    ):
        """获取特辑详情"""
        async for result in self.illust_handler.pixiv_showcase_article(
            event, showcase_id
        ):
            yield result

    @pixiv_illust_group.command("trending")
    async def pixiv_trending_tags(self, event: AstrMessageEvent):
        """获取 Pixiv 插画趋势标签"""
        async for result in self.misc_handler.pixiv_trending_tags(event):
            yield result

    # ----用户类

    @pixiv.group("user")
    def pixiv_user_group(self):
        """用户查询指令组"""
        pass

    @pixiv_user_group.command("search")
    async def pixiv_user_search(self, event: AstrMessageEvent, username: str = ""):
        """搜索 Pixiv 用户"""
        async for result in self.user_handler.pixiv_user_search(event, username):
            yield result

    @pixiv_user_group.command("detail")
    async def pixiv_user_detail(self, event: AstrMessageEvent, user_id: str = ""):
        """获取 Pixiv 用户详情"""
        async for result in self.user_handler.pixiv_user_detail(event, user_id):
            yield result

    @pixiv_user_group.command("works")
    async def pixiv_user_illusts(self, event: AstrMessageEvent, user_id: str = ""):
        """获取指定用户的作品"""
        async for result in self.user_handler.pixiv_user_illusts(event, user_id):
            yield result

    # --------小说类

    @pixiv.group("novel")
    def pixiv_novel_group(self):
        """小说查询指令组"""
        pass

    @pixiv_novel_group.command("search")
    async def pixiv_novel(self, event: AstrMessageEvent, tags: str = ""):
        """按标签搜索 Pixiv 小说"""
        async for result in self.novel_handler.pixiv_novel(event, tags):
            yield result

    @pixiv_novel_group.command("recommended")
    async def pixiv_novel_recommended(self, event: AstrMessageEvent):
        """获取 Pixiv 推荐小说"""
        async for result in self.novel_handler.pixiv_novel_recommended(event):
            yield result

    @pixiv_novel_group.command("new")
    async def pixiv_novel_new(self, event: AstrMessageEvent, max_novel_id: str = ""):
        """获取大家的新小说"""
        async for result in self.novel_handler.pixiv_novel_new(event, max_novel_id):
            yield result

    @pixiv_novel_group.command("series")
    async def pixiv_novel_series(self, event: AstrMessageEvent, series_id: str = ""):
        """获取小说系列详情"""
        async for result in self.novel_handler.pixiv_novel_series(event, series_id):
            yield result

    @pixiv_novel_group.command("comments")
    async def pixiv_novel_comments(
        self, event: AstrMessageEvent, novel_id: str = "", offset: str = ""
    ):
        """获取指定小说的评论"""
        async for result in self.novel_handler.pixiv_novel_comments(
            event, novel_id, offset
        ):
            yield result

    @pixiv_novel_group.command("download")
    async def pixiv_novel_download(self, event: AstrMessageEvent, novel_id: str = ""):
        """根据ID下载Pixiv小说为pdf文件"""
        async for result in self.novel_handler.pixiv_novel_download(event, novel_id):
            yield result

    # ----订阅类

    @pixiv.group("subscribe")
    def pixiv_subscribe_group(self):
        """画师订阅指令组"""
        pass

    @pixiv_subscribe_group.command("add")
    async def pixiv_subscribe_add(self, event: AstrMessageEvent, artist_id: str = ""):
        """订阅画师"""
        async for result in self.subscribe_handler.pixiv_subscribe_add(
            event, artist_id
        ):
            yield result

    @pixiv_subscribe_group.command("remove")
    async def pixiv_subscribe_remove(
        self, event: AstrMessageEvent, artist_id: str = ""
    ):
        """取消订阅画师"""
        async for result in self.subscribe_handler.pixiv_subscribe_remove(
            event, artist_id
        ):
            yield result

    @pixiv_subscribe_group.command("list")
    async def pixiv_subscribe_list(self, event: AstrMessageEvent, args: str = ""):
        """查看当前订阅列表"""
        async for result in self.subscribe_handler.pixiv_subscribe_list(event, args):
            yield result

    # ----随机搜索类

    @pixiv.group("random")
    def pixiv_random_group(self):
        """随机搜索指令组"""
        pass

    @pixiv_random_group.command("add")
    async def pixiv_random_add(self, event: AstrMessageEvent, tags: str = ""):
        """添加随机搜索标签"""
        async for result in self.random_illust_handler.pixiv_random_add(event, tags):
            yield result

    @pixiv_random_group.command("del")
    async def pixiv_random_del(self, event: AstrMessageEvent, index: str = ""):
        """删除随机搜索标签"""
        async for result in self.random_illust_handler.pixiv_random_del(event, index):
            yield result

    @pixiv_random_group.command("list")
    async def pixiv_random_list(self, event: AstrMessageEvent, args: str = ""):
        """列出当前群聊/用户的随机搜索标签"""
        async for result in self.random_illust_handler.pixiv_random_list(event, args):
            yield result

    @pixiv_random_group.command("suspend")
    async def pixiv_random_suspend(self, event: AstrMessageEvent):
        """暂停当前群聊的随机搜索功能"""
        async for result in self.random_illust_handler.pixiv_random_suspend(event):
            yield result

    @pixiv_random_group.command("resume")
    async def pixiv_random_resume(self, event: AstrMessageEvent):
        """恢复当前群聊的随机搜索功能"""
        async for result in self.random_illust_handler.pixiv_random_resume(event):
            yield result

    @pixiv_random_group.command("status")
    async def pixiv_random_status(self, event: AstrMessageEvent):
        """查看随机搜索队列状态"""
        async for result in self.random_illust_handler.pixiv_random_status(event):
            yield result

    @pixiv_random_group.command("force")
    async def pixiv_random_force(self, event: AstrMessageEvent):
        """强制执行当前群聊的随机搜索（调试用）"""
        async for result in self.random_illust_handler.pixiv_random_force(event):
            yield result

    @pixiv_random_group.command("ranking-add")
    async def pixiv_random_ranking_add(
        self, event: AstrMessageEvent, mode: str = "", date: str = ""
    ):
        """添加随机排行榜配置"""
        args = " ".join([x for x in [mode, date] if x])
        async for result in self.random_illust_handler.pixiv_random_ranking_add(
            event, args
        ):
            yield result

    @pixiv_random_group.command("ranking-del")
    async def pixiv_random_ranking_del(self, event: AstrMessageEvent, index: str = ""):
        """删除随机排行榜配置"""
        async for result in self.random_illust_handler.pixiv_random_ranking_del(
            event, index
        ):
            yield result

    @pixiv_random_group.command("ranking-list")
    async def pixiv_random_ranking_list(self, event: AstrMessageEvent, args: str = ""):
        """列出当前群聊的随机排行榜配置"""
        async for result in self.random_illust_handler.pixiv_random_ranking_list(
            event, args
        ):
            yield result

    # ----Fanbox

    @pixiv.group("fanbox")
    def pixiv_fanbox_group(self):
        """Fanbox 指令组"""
        pass

    @pixiv_fanbox_group.command("creator")
    async def pixiv_fanbox_creator(
        self,
        event: AstrMessageEvent,
        creator_input: str = "",
        limit: str = "",
    ):
        """获取 Fanbox 创作者信息和最近帖子"""
        args = " ".join([x for x in [creator_input, limit] if x])
        async for result in self.fanbox_handler.pixiv_fanbox_creator(event, args):
            yield result

    @pixiv_fanbox_group.command("post")
    async def pixiv_fanbox_post(self, event: AstrMessageEvent, args: str = ""):
        """获取 Fanbox 帖子详情"""
        async for result in self.fanbox_handler.pixiv_fanbox_post(event, args):
            yield result

    @pixiv_fanbox_group.command("recommended")
    async def pixiv_fanbox_recommended(self, event: AstrMessageEvent, args: str = "5"):
        """获取 Fanbox 推荐创作者"""
        async for result in self.fanbox_handler.pixiv_fanbox_recommended(event, args):
            yield result

    @pixiv_fanbox_group.command("artist")
    async def pixiv_fanbox_artist(
        self,
        event: AstrMessageEvent,
        keyword: str = "",
        limit: str = "",
    ):
        """按 Nekohouse artists 搜索 Fanbox 创作者"""
        args = " ".join([x for x in [keyword, limit] if x])
        async for result in self.fanbox_handler.pixiv_fanbox_artist(event, args):
            yield result

    @pixiv_fanbox_group.command("download")
    async def pixiv_fanbox_dl(self, event: AstrMessageEvent, args: str = ""):
        """批量下载创作者 Fanbox 帖子"""
        async for result in self.fanbox_handler.pixiv_fanbox_dl(event, args):
            yield result

    @pixiv_fanbox_group.command("status")
    async def pixiv_fanbox_dl_status(self, event: AstrMessageEvent):
        """查看 Fanbox 下载任务进度"""
        async for result in self.fanbox_handler.pixiv_fanbox_dl_status(event):
            yield result

    @pixiv_fanbox_group.command("stop")
    async def pixiv_fanbox_dl_stop(self, event: AstrMessageEvent):
        """停止 Fanbox 下载任务"""
        async for result in self.fanbox_handler.pixiv_fanbox_dl_stop(event):
            yield result

    @pixiv_fanbox_group.command("view")
    async def pixiv_fanbox_dl_view(self, event: AstrMessageEvent, args: str = ""):
        """查看/发送/打包已下载的 Fanbox 内容"""
        async for result in self.fanbox_handler.pixiv_fanbox_dl_view(event, args):
            yield result

    async def terminate(self):
        """插件终止时调用的清理函数"""
        logger.info("Pixiv 搜索插件正在停用...")
        # 停止订阅服务
        if self.sub_service:
            self.sub_service.stop()
        # 停止随机搜索服务
        if self.random_search_service:
            await self.random_search_service.stop()
        # 取消后台刷新任务
        await self.client_wrapper.stop_refresh_task()
        self._refresh_task = self.client_wrapper._refresh_task

        logger.info("Pixiv 搜索插件已停用。")
        # 关闭HTTP会话
        if self._http_session and not self._http_session.closed:
            await self._http_session.close()

    async def _get_http_session(self):
        if self._http_session is None or self._http_session.closed:
            self._http_session = aiohttp.ClientSession()
        return self._http_session

    async def pixiv_llm_search(self, query: str, search_type: str = "illust") -> str:
        """
        使用LLM工具进行智能搜索

        Args:
            query: 搜索查询，可以是自然语言描述
            search_type: 搜索类型，如 'illust', 'novel', 'user' 等

        Returns:
            str: 搜索结果
        """
        try:
            # 验证是否已认证
            if not await self.client_wrapper.authenticate():
                return self.pixiv_config.get_auth_error_message()

            logger.info(
                f"Pixiv 插件：使用LLM工具搜索 - 查询: {query}, 类型: {search_type}"
            )

            # 使用PixivSearchTool进行搜索
            normalized_type = (search_type or "illust").strip().lower()
            target_tool_name = (
                "pixiv_search_novel"
                if normalized_type in {"novel", "小说"}
                else "pixiv_search_illust"
            )

            search_tool = None
            for tool in self.llm_tools:
                if hasattr(tool, "name") and tool.name == target_tool_name:
                    search_tool = tool
                    break

            if not search_tool:
                return "LLM搜索工具未初始化"

            # 创建模拟的上下文
            from astrbot.core.agent.run_context import ContextWrapper
            from astrbot.core.astr_agent_context import AstrAgentContext

            mock_context = ContextWrapper(AstrAgentContext())

            # 调用搜索工具
            result = await search_tool.call(mock_context, query=query)

            logger.info("Pixiv 插件：LLM搜索完成")
            return result

        except Exception as e:
            error_msg = f"LLM搜索时发生错误: {str(e)}"
            logger.error(error_msg)
            return error_msg
