import asyncio
import random
import re
import socket
import time

import requests
from astrbot.api import logger
from pixivpy3 import ByPassSniApi, AppPixivAPI


ACCESS_TOKEN_DEFAULT_TTL_SECONDS = 3600
ACCESS_TOKEN_REFRESH_MARGIN_SECONDS = 300
AUTH_RETRY_DELAYS_SECONDS = (1.0,)
AUTH_TRANSIENT_COOLDOWN_SECONDS = 60
AUTH_REJECTED_COOLDOWN_SECONDS = 900
AUTH_ERROR_LOG_COOLDOWN_SECONDS = 3600


class PixivClientWrapper:
    """Pixiv API 客户端包装器，处理认证和定期刷新 Token"""

    def __init__(self, pixiv_config):
        self.pixiv_config = pixiv_config
        self._refresh_task: asyncio.Task | None = None
        self._auth_lock = asyncio.Lock()
        self._access_token_usable_until = 0.0
        self._auth_retry_not_before = 0.0
        self._last_auth_error_key = ""
        self._last_auth_error_logged_at = 0.0
        self._auth_had_failure = False

        # 根据是否配置代理选择不同的 API 客户端
        if pixiv_config.proxy:
            # 有代理时使用标准 AppPixivAPI
            self.client_api = AppPixivAPI(**pixiv_config.get_requests_kwargs())
            logger.info("Pixiv 插件：使用代理模式 (AppPixivAPI)")
        elif pixiv_config.api_proxy_host:
            # 使用 API 反代服务器
            self.client_api = AppPixivAPI()
            self.client_api.hosts = f"https://{pixiv_config.api_proxy_host}"
            logger.info(
                f"Pixiv 插件：使用 API 反代模式 ({pixiv_config.api_proxy_host})"
            )
        else:
            # 尝试多种直连方案
            self.client_api = self._create_direct_client()

    def _create_direct_client(self):
        """创建直连客户端，尝试多种方案"""
        # 方案1: 尝试标准 API 直连（部分网络环境可用）
        try:
            # 快速测试 DNS 解析
            socket.gethostbyname("oauth.secure.pixiv.net")
            logger.info("Pixiv 插件：DNS 解析成功，尝试直连模式")
            # 先测试连接
            try:
                requests.head(
                    "https://oauth.secure.pixiv.net/", timeout=5, allow_redirects=False
                )
                logger.info("Pixiv 插件：直连测试成功，使用标准 AppPixivAPI")
                return AppPixivAPI()
            except (requests.exceptions.Timeout, requests.exceptions.ConnectionError):
                logger.info("Pixiv 插件：直连测试超时，尝试 ByPassSniApi 模式")
        except socket.gaierror:
            logger.info("Pixiv 插件：DNS 解析失败，尝试 ByPassSniApi 模式")

        # 方案2: ByPassSniApi（使用国内可用 DoH）
        client_api = ByPassSniApi()
        hosts_result = self._require_appapi_hosts_with_cn_doh(client_api)

        if hosts_result:
            logger.info(f"Pixiv 插件：使用 ByPassSniApi 模式, hosts={hosts_result}")
            return client_api

        # 方案3: 最后回退到标准直连
        logger.warning("Pixiv 插件：所有直连方案失败，回退到标准模式（可能无法连接）")
        return AppPixivAPI()

    def _require_appapi_hosts_with_cn_doh(
        self, api, hostname: str = "app-api.secure.pixiv.net", timeout: int = 10
    ) -> str | bool:
        """使用国内可用的 DoH 服务器解析 Pixiv hosts"""
        # 优先使用国内 DoH 服务器
        doh_urls = [
            "https://doh.pub/dns-query",  # 腾讯 DoH（国内可用）
            "https://dns.alidns.com/dns-query",  # 阿里 DoH（可能可用）
            "https://1.0.0.1/dns-query",  # Cloudflare 备选
            "https://1.1.1.1/dns-query",  # Cloudflare 主
            "https://doh.dns.sb/dns-query",  # DNS.sb
        ]

        headers = {"Accept": "application/dns-json"}
        params = {
            "name": hostname,
            "type": "A",
            "do": "false",
            "cd": "false",
        }

        for url in doh_urls:
            try:
                response = requests.get(
                    url, headers=headers, params=params, timeout=timeout
                )
                if response.status_code == 200:
                    data = response.json()
                    if "Answer" in data and data["Answer"]:
                        ip = data["Answer"][0]["data"]
                        api.hosts = f"https://{ip}"
                        return api.hosts
            except Exception:
                continue

        return False

    def _has_usable_access_token(self) -> bool:
        """只在已知有效期内复用 access token，避免每次 API 调用都刷新。"""
        return bool(getattr(self.client_api, "access_token", None)) and (
            time.monotonic() < self._access_token_usable_until
        )

    def _current_refresh_token(self) -> str | None:
        """优先复用 Pixiv 最近返回的 refresh token，不写入日志或磁盘。"""
        return (
            getattr(self.client_api, "refresh_token", None)
            or self.pixiv_config.refresh_token
        )

    @staticmethod
    def _token_ttl_seconds(auth_result) -> int:
        response = getattr(auth_result, "response", None)
        raw_ttl = getattr(response, "expires_in", ACCESS_TOKEN_DEFAULT_TTL_SECONDS)
        try:
            ttl = int(raw_ttl)
        except (TypeError, ValueError):
            ttl = ACCESS_TOKEN_DEFAULT_TTL_SECONDS
        return max(60, ttl)

    def _mark_auth_success(self, auth_result) -> None:
        ttl = self._token_ttl_seconds(auth_result)
        margin = min(
            ACCESS_TOKEN_REFRESH_MARGIN_SECONDS,
            max(30, ttl // 10),
        )
        self._access_token_usable_until = time.monotonic() + max(30, ttl - margin)
        self._auth_retry_not_before = 0.0

    @staticmethod
    def _http_status_from_error(exc: Exception) -> int | None:
        match = re.search(r"\bHTTP\s+(\d{3})\b", str(exc))
        return int(match.group(1)) if match else None

    @staticmethod
    def _header_value(headers, name: str) -> str:
        if not headers:
            return ""
        for key, value in headers.items():
            if str(key).lower() == name.lower():
                return str(value)
        return ""

    def _auth_error_details(self, exc: Exception) -> tuple[str, str, bool, int]:
        """生成不含令牌和响应正文的诊断摘要。"""
        status = self._http_status_from_error(exc)
        headers = getattr(exc, "header", None)
        content_type = self._header_value(headers, "content-type").split(";", 1)[0]
        body = getattr(exc, "body", None)
        if isinstance(body, bytes):
            body_bytes = body
        elif body is None:
            body_bytes = b""
        else:
            body_bytes = str(body).encode("utf-8", errors="replace")

        stripped = body_bytes.lstrip().lower()
        if not body_bytes:
            body_kind = "empty"
        elif stripped.startswith((b"<!doctype html", b"<html")):
            body_kind = "html"
        elif stripped.startswith((b"{", b"[")):
            body_kind = "json-like"
        else:
            body_kind = "text-or-binary"

        message = str(exc)
        request_failed = "requests " in message.lower() and " error:" in message.lower()
        if "Get access_token error" in message:
            reason = "OAuth 响应不是有效 JSON"
        elif status in {400, 401}:
            reason = "Refresh Token 被 Pixiv 拒绝"
        elif status == 403:
            reason = "OAuth 请求被拒绝"
        elif status == 429:
            reason = "OAuth 请求触发限流"
        elif status is not None and status >= 500:
            reason = "Pixiv 或中间网关服务异常"
        elif request_failed or isinstance(
            exc, (requests.exceptions.RequestException, TimeoutError)
        ):
            reason = "OAuth 网络请求异常"
        else:
            reason = "OAuth 认证调用异常"

        transient = (
            "Get access_token error" in message
            or request_failed
            or isinstance(exc, (requests.exceptions.RequestException, TimeoutError))
            or status == 429
            or (status is not None and status >= 500)
        )
        cooldown = (
            AUTH_TRANSIENT_COOLDOWN_SECONDS
            if transient
            else AUTH_REJECTED_COOLDOWN_SECONDS
        )
        error_key = "|".join(
            [
                type(exc).__name__,
                str(status or "unknown"),
                content_type or "unknown",
                body_kind,
                reason,
            ]
        )
        details = (
            f"原因={reason}, 异常类型={type(exc).__name__}, "
            f"HTTP={status or 'unknown'}, Content-Type={content_type or 'unknown'}, "
            f"响应类型={body_kind}, 响应字节数={len(body_bytes)}, "
            f"冷却={cooldown}s"
        )
        return details, error_key, transient, cooldown

    def _log_final_auth_error(self, details: str, error_key: str) -> None:
        now = time.monotonic()
        repeated_recently = (
            error_key == self._last_auth_error_key
            and now - self._last_auth_error_logged_at < AUTH_ERROR_LOG_COOLDOWN_SECONDS
        )
        if repeated_recently:
            logger.debug(f"Pixiv 插件：认证仍失败（重复日志已抑制）- {details}")
            return

        logger.error(f"Pixiv 插件：认证失败 - {details}")
        self._last_auth_error_key = error_key
        self._last_auth_error_logged_at = now

    async def authenticate(self, *, reason: str = "on-demand") -> bool:
        """复用仍有效的 access token，并在必要时安全刷新。"""
        if self._has_usable_access_token():
            return True

        refresh_token = self._current_refresh_token()
        if not refresh_token:
            logger.error("Pixiv 插件：未提供有效的 Refresh Token，无法进行认证。")
            return False

        async with self._auth_lock:
            # 等锁期间其他调用可能已经完成刷新，避免刷新风暴。
            if self._has_usable_access_token():
                return True

            now = time.monotonic()
            if now < self._auth_retry_not_before:
                return self._has_usable_access_token()

            attempts = 1 + len(AUTH_RETRY_DELAYS_SECONDS)
            for attempt in range(1, attempts + 1):
                try:
                    auth_result = await asyncio.to_thread(
                        self.client_api.auth,
                        refresh_token=self._current_refresh_token(),
                    )
                    self._mark_auth_success(auth_result)
                    if self._auth_had_failure or attempt > 1:
                        logger.info(
                            "Pixiv 插件：OAuth 认证已恢复 "
                            f"(触发原因={reason}, 尝试次数={attempt})"
                        )
                    else:
                        logger.debug(
                            "Pixiv 插件：OAuth 认证成功 "
                            f"(触发原因={reason}, access token 已缓存)"
                        )
                    self._auth_had_failure = False
                    self._last_auth_error_key = ""
                    self._last_auth_error_logged_at = 0.0
                    return True
                except asyncio.CancelledError:
                    raise
                except Exception as exc:
                    details, error_key, transient, cooldown = self._auth_error_details(
                        exc
                    )
                    self._auth_had_failure = True
                    if transient and attempt < attempts:
                        delay = AUTH_RETRY_DELAYS_SECONDS[attempt - 1]
                        delay += random.uniform(0.0, 0.5)
                        logger.debug(
                            "Pixiv 插件：OAuth 临时异常，将进行一次退避重试 "
                            f"(等待={delay:.1f}s, {details})"
                        )
                        await asyncio.sleep(delay)
                        continue

                    self._auth_retry_not_before = time.monotonic() + cooldown
                    self._access_token_usable_until = 0.0
                    self._log_final_auth_error(details, error_key)
                    return False

    async def periodic_token_refresh(self):
        """按配置周期检查；仅在 access token 不可复用时刷新。"""
        while True:
            try:
                # 先等待指定间隔
                wait_seconds = self.pixiv_config.refresh_interval * 60
                logger.debug(
                    f"Pixiv Token 刷新任务：等待 {self.pixiv_config.refresh_interval} 分钟 ({wait_seconds} 秒)..."
                )
                await asyncio.sleep(wait_seconds)

                # 检查 refresh_token 是否已配置
                current_refresh_token = self._current_refresh_token()
                if not current_refresh_token:
                    logger.warning(
                        "Pixiv Token 刷新任务：未配置 Refresh Token，跳过本次刷新。"
                    )
                    continue

                logger.debug("Pixiv Token 刷新任务：开始检查令牌状态。")
                await self.authenticate(reason="scheduled")

            except asyncio.CancelledError:
                logger.info("Pixiv Token 刷新任务：任务被取消，停止刷新。")
                break
            except Exception as loop_e:
                logger.error(
                    f"Pixiv Token 刷新任务：循环中发生意外错误 - {loop_e}，将在下次间隔后重试。"
                )
                import traceback

                logger.error(traceback.format_exc())

    def start_refresh_task(self) -> asyncio.Task | None:
        """启动后台刷新任务并返回任务句柄（若已启动则复用原任务）。"""
        if self.pixiv_config.refresh_interval <= 0:
            logger.info("Pixiv 插件：Refresh Token 自动刷新已禁用。")
            return None

        if self._refresh_task and not self._refresh_task.done():
            return self._refresh_task

        self._refresh_task = asyncio.create_task(self.periodic_token_refresh())
        logger.info(
            f"Pixiv 插件：已启动 Refresh Token 自动刷新任务，间隔 {self.pixiv_config.refresh_interval} 分钟。"
        )
        return self._refresh_task

    async def stop_refresh_task(self) -> None:
        """停止后台刷新任务。"""
        if not self._refresh_task or self._refresh_task.done():
            return

        self._refresh_task.cancel()
        try:
            await self._refresh_task
        except asyncio.CancelledError:
            logger.info("Pixiv Token 刷新任务已成功取消。")
        except Exception as e:
            logger.error(f"等待 Pixiv Token 刷新任务取消时发生错误: {e}")

    async def call_pixiv_api(self, func, *args, **kwargs):
        """异步调用 Pixiv API 的辅助方法"""
        return await asyncio.to_thread(func, *args, **kwargs)
