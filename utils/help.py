"""
help.py
帮助消息管理模块
"""

import json
from pathlib import Path
from typing import Dict, Optional
from astrbot.api import logger


class HelpManager:
    """帮助消息管理器"""

    def __init__(self, data_dir: Path):
        """初始化帮助管理器

        Args:
            data_dir: 数据目录路径
        """
        self.data_dir = data_dir
        # 使用插件目录下的帮助文件
        self.help_file = Path(__file__).parent.parent / "data" / "helpmsg.json"
        self._help_messages: Dict[str, str] = {}
        self._load_help_messages()

    def _load_help_messages(self):
        """加载帮助消息"""
        try:
            if self.help_file.exists():
                with open(self.help_file, "r", encoding="utf-8") as f:
                    self._help_messages = json.load(f)
                logger.info(f"Pixiv 插件：成功加载帮助消息文件 {self.help_file}")
            else:
                logger.warning(f"Pixiv 插件：帮助消息文件不存在: {self.help_file}")
                self._help_messages = {}
        except Exception as e:
            logger.error(f"Pixiv 插件：加载帮助消息文件失败 - {e}")
            self._help_messages = {}

    def get_help_message(self, key: str, default: Optional[str] = None) -> str:
        """获取帮助消息

        Args:
            key: 帮助消息的键
            default: 默认消息（如果键不存在）

        Returns:
            str: 帮助消息
        """
        if key in self._help_messages:
            return self._help_messages[key]
        else:
            logger.warning(f"Pixiv 插件：未找到帮助消息键: {key}")
            return default or f"帮助消息 '{key}' 未找到"

    def reload_help_messages(self):
        """重新加载帮助消息"""
        self._load_help_messages()


# 全局帮助管理器实例
_help_manager: Optional[HelpManager] = None


def init_help_manager(data_dir: Path):
    """初始化帮助管理器

    Args:
        data_dir: 数据目录路径
    """
    global _help_manager
    _help_manager = HelpManager(data_dir)


def get_help_message(key: str, default: Optional[str] = None) -> str:
    """获取帮助消息

    Args:
        key: 帮助消息的键
        default: 默认消息（如果键不存在）

    Returns:
        str: 帮助消息
    """
    if _help_manager is None:
        return default or f"帮助管理器未初始化，无法获取消息 '{key}'"
    return _help_manager.get_help_message(key, default)
