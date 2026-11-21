"""帮助消息管理模块。"""

import json
from pathlib import Path
from typing import Dict, Optional

from astrbot.api import logger

HELP_FILE = Path(__file__).resolve().parent.parent / "data" / "helpmsg.json"


class HelpManager:
    """从插件内置 data/helpmsg.json 读取帮助文本。"""

    def __init__(self) -> None:
        self._help_messages: Dict[str, str] = {}
        self._load_help_messages()

    def _load_help_messages(self) -> None:
        try:
            if HELP_FILE.exists():
                with open(HELP_FILE, "r", encoding="utf-8") as f:
                    self._help_messages = json.load(f)
                logger.info(f"Pixiv 插件：成功加载帮助消息文件 {HELP_FILE}")
            else:
                logger.warning(f"Pixiv 插件：帮助消息文件不存在: {HELP_FILE}")
                self._help_messages = {}
        except Exception as e:
            logger.error(f"Pixiv 插件：加载帮助消息文件失败 - {e}")
            self._help_messages = {}

    def get_help_message(self, key: str, default: Optional[str] = None) -> str:
        if key in self._help_messages:
            return self._help_messages[key]
        logger.warning(f"Pixiv 插件：未找到帮助消息键: {key}")
        return default or f"帮助消息 '{key}' 未找到"


_help_manager: Optional[HelpManager] = None


def init_help_manager() -> None:
    """初始化帮助管理器（幂等）。"""
    global _help_manager
    _help_manager = HelpManager()


def get_help_message(key: str, default: Optional[str] = None) -> str:
    if _help_manager is None:
        return default or f"帮助管理器未初始化，无法获取消息 '{key}'"
    return _help_manager.get_help_message(key, default)
