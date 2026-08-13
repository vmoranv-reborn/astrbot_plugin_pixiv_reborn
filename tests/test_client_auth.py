import asyncio
import sys
import unittest
from types import ModuleType, SimpleNamespace
from unittest.mock import Mock, patch

try:
    import astrbot.api  # noqa: F401
except ImportError:
    astrbot_module = ModuleType("astrbot")
    astrbot_api_module = ModuleType("astrbot.api")
    astrbot_api_module.logger = SimpleNamespace(
        debug=Mock(),
        info=Mock(),
        warning=Mock(),
        error=Mock(),
    )
    astrbot_module.api = astrbot_api_module
    sys.modules["astrbot"] = astrbot_module
    sys.modules["astrbot.api"] = astrbot_api_module

from pixivpy3 import PixivError

from core.client import PixivClientWrapper


class FakeClient:
    def __init__(self, outcomes):
        self.access_token = None
        self.refresh_token = None
        self.outcomes = list(outcomes)
        self.auth_calls = 0

    def auth(self, *, refresh_token):
        self.auth_calls += 1
        outcome = self.outcomes.pop(0)
        if isinstance(outcome, Exception):
            raise outcome
        self.access_token = "access-token-for-test"
        self.refresh_token = "rotated-refresh-token-for-test"
        return outcome


def auth_result(expires_in=3600):
    return SimpleNamespace(response=SimpleNamespace(expires_in=expires_in))


async def run_inline(func, *args, **kwargs):
    await asyncio.sleep(0)
    return func(*args, **kwargs)


def make_wrapper(client):
    config = SimpleNamespace(
        proxy="http://proxy.invalid:8080",
        api_proxy_host="",
        refresh_token="configured-refresh-token-for-test",
        refresh_interval=180,
        get_requests_kwargs=lambda: {},
    )
    with patch("core.client.AppPixivAPI", return_value=client):
        return PixivClientWrapper(config)


class ClientAuthenticationTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.to_thread_patcher = patch("core.client.asyncio.to_thread", new=run_inline)
        self.to_thread_patcher.start()

    async def asyncTearDown(self):
        self.to_thread_patcher.stop()

    async def test_reuses_access_token_until_refresh_margin(self):
        client = FakeClient([auth_result()])
        wrapper = make_wrapper(client)

        self.assertTrue(await wrapper.authenticate())
        self.assertTrue(await wrapper.authenticate())

        self.assertEqual(client.auth_calls, 1)

    async def test_concurrent_calls_share_one_refresh(self):
        client = FakeClient([auth_result()])
        wrapper = make_wrapper(client)

        results = await asyncio.gather(
            wrapper.authenticate(),
            wrapper.authenticate(),
            wrapper.authenticate(),
        )

        self.assertEqual(results, [True, True, True])
        self.assertEqual(client.auth_calls, 1)

    async def test_retries_invalid_json_response_once(self):
        temporary_error = PixivError(
            "Get access_token error! Response: None",
            header={"Content-Type": "text/html"},
            body="<html>temporary gateway response</html>",
        )
        client = FakeClient([temporary_error, auth_result()])
        wrapper = make_wrapper(client)

        with (
            patch("core.client.AUTH_RETRY_DELAYS_SECONDS", (0.0,)),
            patch("core.client.random.uniform", return_value=0.0),
        ):
            self.assertTrue(await wrapper.authenticate())

        self.assertEqual(client.auth_calls, 2)

    async def test_rejected_refresh_token_enters_cooldown(self):
        rejected_error = PixivError(
            "[ERROR] auth() failed! check refresh_token.\nHTTP 400",
            header={"Content-Type": "application/json"},
            body='{"error":"invalid_grant"}',
        )
        client = FakeClient([rejected_error])
        wrapper = make_wrapper(client)

        self.assertFalse(await wrapper.authenticate())
        self.assertFalse(await wrapper.authenticate())

        self.assertEqual(client.auth_calls, 1)

    async def test_concurrent_failures_share_cooldown(self):
        rejected_error = PixivError(
            "[ERROR] auth() failed! check refresh_token.\nHTTP 401",
            header={"Content-Type": "application/json"},
            body='{"error":"invalid_grant"}',
        )
        client = FakeClient([rejected_error])
        wrapper = make_wrapper(client)

        results = await asyncio.gather(
            wrapper.authenticate(),
            wrapper.authenticate(),
            wrapper.authenticate(),
        )

        self.assertEqual(results, [False, False, False])
        self.assertEqual(client.auth_calls, 1)

    async def test_auth_log_does_not_include_response_body(self):
        secret_body = '{"refresh_token":"secret-refresh-token"}'
        rejected_error = PixivError(
            "[ERROR] auth() failed! check refresh_token.\nHTTP 400",
            header={"Content-Type": "application/json"},
            body=secret_body,
        )
        client = FakeClient([rejected_error])
        wrapper = make_wrapper(client)

        with patch("core.client.logger.error") as log_error:
            self.assertFalse(await wrapper.authenticate())

        logged_message = " ".join(
            str(arg) for call in log_error.call_args_list for arg in call.args
        )
        self.assertNotIn("secret-refresh-token", logged_message)
        self.assertNotIn(secret_body, logged_message)


if __name__ == "__main__":
    unittest.main()
