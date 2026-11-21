"""AstrBot 消息适配器。

集中封装后台任务中“模拟事件 → MessageChain”的桥接逻辑，避免各服务
重复定义 MockEvent，并为订阅/随机搜索提供一致的成功判定。
"""

from __future__ import annotations

from typing import Any, Iterable

from astrbot.api.event import MessageEventResult
from astrbot.api.message_components import Image, Nodes


class CaptureEvent:
    """最小化事件对象：把生成器 yield 的组件捕获为 MessageChain。

    AstrBot 的发送函数要求 event.chain_result/plain_result，但后台任务没有
    真实事件。该适配器只实现发送路径需要的方法，不伪装成完整 AstrMessageEvent。
    """

    def __init__(
        self,
        *,
        bot: Any = None,
        platform_name: str = "unknown",
        group_id: str | None = None,
    ) -> None:
        self.bot = bot
        self._platform_name = platform_name
        self._group_id = group_id

    def chain_result(self, chain: Iterable[Any]) -> MessageEventResult:
        return MessageEventResult(chain=list(chain))

    def plain_result(self, text: str) -> MessageEventResult:
        return MessageEventResult().message(text)

    def get_platform_name(self) -> str:
        return self._platform_name

    def get_group_id(self) -> str | None:
        return self._group_id


def chain_contains_image(chain: Iterable[Any] | None) -> bool:
    """递归判断消息链是否包含图片（支持 Nodes 合并转发）。"""

    for component in chain or []:
        if isinstance(component, Image):
            return True
        if isinstance(component, Nodes):
            for node in component.nodes:
                if chain_contains_image(getattr(node, "content", None)):
                    return True
    return False
