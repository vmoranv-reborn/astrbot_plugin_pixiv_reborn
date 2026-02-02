import asyncio
from astrbot.api import logger
from pixivpy3 import ByPassSniApi, PixivError


class PixivClientWrapper:
    """Pixiv API 客户端包装器，处理认证和定期刷新 Token"""

    def __init__(self, pixiv_config):
        self.pixiv_config = pixiv_config

        # 根据是否配置代理选择不同的 API 客户端
        if pixiv_config.proxy:
            # 有代理时使用标准 AppPixivAPI
            from pixivpy3 import AppPixivAPI

            self.client_api = AppPixivAPI(**pixiv_config.get_requests_kwargs())
            logger.info("Pixiv 插件：使用代理模式 (AppPixivAPI)")
        else:
            # 无代理时使用 ByPassSniApi (大陆直连)
            self.client_api = ByPassSniApi()
            self.client_api.require_appapi_hosts()
            logger.info("Pixiv 插件：使用大陆直连模式 (ByPassSniApi)")

    async def authenticate(self) -> bool:
        """尝试使用配置的凭据进行 Pixiv API 认证"""
        # 每次调用都尝试认证，让 pixivpy3 处理 token 状态
        try:
            if self.pixiv_config.refresh_token:
                # 调用 auth()，pixivpy3 会在需要时刷新 token
                await asyncio.to_thread(
                    self.client_api.auth, refresh_token=self.pixiv_config.refresh_token
                )
                return True
            else:
                logger.error("Pixiv 插件：未提供有效的 Refresh Token，无法进行认证。")
                return False

        except Exception as e:
            logger.error(
                f"Pixiv 插件：认证/刷新时发生错误 - 异常类型: {type(e)}, 错误信息: {e}"
            )
            return False

    async def periodic_token_refresh(self):
        """定期尝试使用 refresh_token 进行认证以保持其活性"""
        while True:
            try:
                # 先等待指定间隔
                wait_seconds = self.pixiv_config.refresh_interval * 60
                logger.debug(
                    f"Pixiv Token 刷新任务：等待 {self.pixiv_config.refresh_interval} 分钟 ({wait_seconds} 秒)..."
                )
                await asyncio.sleep(wait_seconds)

                # 检查 refresh_token 是否已配置
                current_refresh_token = self.pixiv_config.refresh_token
                if not current_refresh_token:
                    logger.warning(
                        "Pixiv Token 刷新任务：未配置 Refresh Token，跳过本次刷新。"
                    )
                    continue

                logger.info("Pixiv Token 刷新任务：尝试使用 Refresh Token 进行认证...")
                try:
                    self.client_api.auth(refresh_token=current_refresh_token)
                    logger.info("Pixiv Token 刷新任务：认证调用成功。")

                except PixivError as pe:
                    logger.error(
                        f"Pixiv Token 刷新任务：认证时发生 Pixiv API 错误 - {pe}"
                    )
                except Exception as e:
                    logger.error(
                        f"Pixiv Token 刷新任务：认证时发生未知错误 - {type(e).__name__}: {e}"
                    )
                    import traceback

                    logger.error(traceback.format_exc())

            except asyncio.CancelledError:
                logger.info("Pixiv Token 刷新任务：任务被取消，停止刷新。")
                break
            except Exception as loop_e:
                logger.error(
                    f"Pixiv Token 刷新任务：循环中发生意外错误 - {loop_e}，将在下次间隔后重试。"
                )
                import traceback

                logger.error(traceback.format_exc())

    async def start_refresh_task(self):
        # 启动后台刷新任务
        if self.pixiv_config.refresh_interval > 0:
            self._refresh_task = asyncio.create_task(self.periodic_token_refresh())
            logger.info(
                f"Pixiv 插件：已启动 Refresh Token 自动刷新任务，间隔 {self.pixiv_config.refresh_interval} 分钟。"
            )
        else:
            logger.info("Pixiv 插件：Refresh Token 自动刷新已禁用。")

    async def call_pixiv_api(self, func, *args, **kwargs):
        """异步调用 Pixiv API 的辅助方法"""
        return await asyncio.to_thread(func, *args, **kwargs)
