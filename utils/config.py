import os
import asyncio
from astrbot.api import logger
from pathlib import Path
from typing import Dict, Any
from dataclasses import dataclass


async def clean_temp_dir(temp_dir: Path, max_files: int = 20) -> None:
    """
    异步清理临时目录，保持文件数量在指定限制内。

    Args:
        temp_dir: 要清理的目录的 Path 对象。
        max_files: 最大保留文件数量。
    """
    if not temp_dir.exists():
        return

    try:
        # 使用 asyncio.to_thread 进行异步文件操作
        files = await asyncio.to_thread(_get_temp_files, temp_dir)

        if len(files) > max_files:
            # 按创建时间排序，删除最旧的文件
            files_to_delete = await asyncio.to_thread(_sort_files_by_ctime, files)
            num_to_delete = len(files_to_delete) - max_files

            for i in range(num_to_delete):
                try:
                    await asyncio.to_thread(os.remove, files_to_delete[i])
                    logger.debug(f"[PixivPlugin] 已删除临时文件: {files_to_delete[i]}")
                except OSError as e:
                    logger.warning(
                        f"[PixivPlugin] 删除临时图片失败: {files_to_delete[i]}，原因: {e}"
                    )

            logger.info(
                f"[PixivPlugin] 临时目录清理完成，删除了 {num_to_delete} 个文件"
            )

    except Exception as e:
        logger.error(f"[PixivPlugin] 清理临时目录时发生错误: {e}", exc_info=True)


def _get_temp_files(temp_dir: Path) -> list[str]:
    """获取临时目录中的所有文件路径"""
    return [str(f) for f in temp_dir.iterdir() if f.is_file()]


def _sort_files_by_ctime(files: list[str]) -> list[str]:
    """按创建时间排序文件列表"""
    return sorted(files, key=lambda x: os.path.getctime(x))


async def smart_clean_temp_dir(
    temp_dir: Path, probability: float = 0.1, max_files: int = 20
) -> None:
    """
    智能清理临时目录，使用概率性触发以减少频繁的文件系统操作。

    Args:
        temp_dir: 要清理的目录的 Path 对象。
        probability: 触发清理的概率 (0.0-1.0)。
        max_files: 最大保留文件数量。
    """
    import random

    if random.random() < probability:
        await clean_temp_dir(temp_dir, max_files)


@dataclass
class PixivConfig:
    """Pixiv 插件配置管理类"""

    def __init__(self, config: Dict[str, Any]):
        """初始化配置"""
        self.config = config
        self._load_config()

    def _load_config(self):
        """加载配置项"""
        self.proxy = self.config.get("proxy", "").strip()
        self.refresh_token = self.config.get("refresh_token", None)
        self.return_count = self.config.get("return_count", 1)
        self.r18_mode = self.config.get("r18_mode", "过滤 R18")
        self.ai_filter_mode = self.config.get("ai_filter_mode", "过滤 AI 作品")
        self.show_filter_result = self.config.get("show_filter_result", True)
        self.show_details = self.config.get("show_details", True)
        self.deep_search_depth = self.config.get("deep_search_depth", 3)
        self.forward_threshold = self.config.get("forward_threshold", False)
        self.is_fromfilesystem = self.config.get("is_fromfilesystem", False)
        self.image_quality = self.config.get("image_quality", "original")
        self.refresh_interval = self.config.get("refresh_token_interval_minutes", 180)
        self.subscription_enabled = self.config.get("subscription_enabled", True)
        self.subscription_check_interval_minutes = self.config.get(
            "subscription_check_interval_minutes", 30
        )
        self.random_search_min_interval = self.config.get(
            "random_search_min_interval", 60
        )
        self.random_search_max_interval = self.config.get(
            "random_search_max_interval", 120
        )
        self.random_sent_illust_retention_days = self.config.get(
            "random_sent_illust_retention_days", 7
        )
        # 新增：图片反代配置
        self.image_proxy_host = self.config.get("image_proxy_host", "i.pixiv.re")
        self.use_image_proxy = self.config.get("use_image_proxy", True)

    def get_auth_error_message(self) -> str:
        """获取认证错误消息"""
        return (
            "Pixiv API 认证失败，请检查配置中的凭据信息。\n"
            "先带脑子配置代理->[Astrbot代理配置教程](https://astrbot.app/config/astrbot-config.html#http-proxy);\n"
            "再填入refresh_token->**Pixiv Refresh Token**: 必填，用于 API 认证。获取方法请参考 "
            "[pixivpy3 文档](https://pypi.org/project/pixivpy3/) 或[这里](https://gist.github.com/karakoo/5e7e0b1f3cc74cbcb7fce1c778d3709e)。"
        )

    def get_config_info(self) -> str:
        """获取配置信息字符串"""
        return (
            f"refresh_token={'已设置' if self.refresh_token else '未设置'}, "
            f"return_count={self.return_count}, r18_mode='{self.r18_mode}', "
            f"ai_filter_mode='{self.ai_filter_mode}', show_details={self.show_details}, "
            f"refresh_interval={self.refresh_interval} 分钟, "
            f"subscription_enabled={self.subscription_enabled}, "
            f"proxy='{self.proxy or '未使用'}'"
        )

    def get_requests_kwargs(self) -> Dict[str, Any]:
        """获取请求参数"""
        kwargs = {}
        if self.proxy:
            kwargs["proxies"] = {"http": self.proxy, "https": self.proxy}
        return kwargs

    def save_config(self):
        """保存配置"""
        if hasattr(self.config, "save_config"):
            self.config.save_config()


class PixivConfigManager:
    """Pixiv 配置管理器，用于动态配置"""

    def __init__(self, config: PixivConfig):
        self.config = config
        self.schema = {
            "r18_mode": {"type": "enum", "choices": ["过滤 R18", "允许 R18", "仅 R18"]},
            "ai_filter_mode": {
                "type": "enum",
                "choices": ["显示 AI 作品", "过滤 AI 作品", "仅 AI 作品"],
            },
            "return_count": {"type": "int", "min": 1, "max": 30},
            "show_filter_result": {"type": "bool"},
            "show_details": {"type": "bool"},
            "deep_search_depth": {"type": "int", "min": -1, "max": 50},
            "forward_threshold": {"type": "bool"},
            "image_quality": {
                "type": "enum",
                "choices": ["original", "large", "medium"],
            },
            "subscription_enabled": {"type": "bool"},
            # 隐藏的配置项，不显示给用户但仍然可以设置
            "is_fromfilesystem": {"type": "bool", "hidden": True},
            "refresh_token_interval_minutes": {
                "type": "int",
                "min": 0,
                "max": 10080,
                "hidden": True,
            },
            "subscription_check_interval_minutes": {
                "type": "int",
                "min": 5,
                "max": 1440,
                "hidden": True,
            },
            "random_search_min_interval": {"type": "int", "min": 1, "max": 1440},
            "random_search_max_interval": {"type": "int", "min": 1, "max": 1440},
            "proxy": {"type": "string", "hidden": True},
            "random_sent_illust_retention_days": {"type": "int", "min": 1, "max": 365},
        }

    def get_help_text(self) -> str:
        """获取帮助文本"""
        try:
            from .help import get_help_message

            return get_help_message("pixiv_config", "配置帮助信息未找到")
        except ImportError:
            return "# Pixiv 配置命令帮助\n\n配置帮助信息加载失败，请检查帮助文件。"

    def get_current_config(self) -> Dict[str, Any]:
        """获取当前配置（只显示常用配置项，隐藏敏感信息）"""
        # 只显示用户常用的配置项，隐藏敏感和不常用的配置
        display_keys = [
            "return_count",
            "r18_mode",
            "ai_filter_mode",
            "show_filter_result",
            "show_details",
            "deep_search_depth",
            "forward_threshold",
            "image_quality",
            "subscription_enabled",
            "random_search_min_interval",
            "random_search_max_interval",
            "random_sent_illust_retention_days",
        ]

        current = {}
        for k in display_keys:
            if k in self.schema.keys():
                current[k] = getattr(self.config, k, None)
        return current

    def validate_and_set_config(self, key: str, value: str) -> tuple[bool, str]:
        """验证并设置配置"""
        if key not in self.schema:
            # 只显示非隐藏的参数
            visible_keys = [
                k for k, v in self.schema.items() if not v.get("hidden", False)
            ]
            return False, f"不支持的参数: {key}\n可用参数: {', '.join(visible_keys)}"

        schema_item = self.schema[key]
        typ = schema_item["type"]

        try:
            if typ == "enum":
                value_normalized = value.replace("_", " ")
                choices_map = {c.replace(" ", "_"): c for c in schema_item["choices"]}
                if value in choices_map:
                    value_normalized = choices_map[value]
                if value_normalized not in schema_item["choices"]:
                    return (
                        False,
                        f"无效值: {value}\n可选值: {', '.join(schema_item['choices'])}\n可用下划线代替空格，如: 允许_R18",
                    )
                setattr(self.config, key, value_normalized)
            elif typ == "bool":
                v = value.lower()
                if v in ("true", "1", "yes", "on"):
                    v = True
                elif v in ("false", "0", "no", "off"):
                    v = False
                else:
                    return False, "布尔值仅支持: true/false/yes/no/on/off/1/0"
                setattr(self.config, key, v)
            elif typ == "int":
                try:
                    v = int(value)
                    # 应用标准的 min/max 检查
                    minv, maxv = (
                        schema_item.get("min", None),
                        schema_item.get("max", None),
                    )
                    if (minv is not None and v < minv) or (
                        maxv is not None and v > maxv
                    ):
                        return False, f"配置项 {key} 的值必须在 {minv} 到 {maxv} 之间。"

                    # 特殊处理映射关系
                    if key == "refresh_token_interval_minutes":
                        setattr(self.config, "refresh_interval", v)
                    else:
                        setattr(self.config, key, v)
                except ValueError:
                    return False, f"配置项 {key} 的值 '{value}' 不是有效的整数。"
            elif typ == "string":
                setattr(self.config, key, value)

            self.config.save_config()
            # 获取实际设置的值
            if key == "refresh_token_interval_minutes":
                actual_value = getattr(self.config, "refresh_interval")
            else:
                actual_value = getattr(self.config, key)
            return True, f"{key} 已更新为: {actual_value}"
        except Exception as e:
            return False, f"设置失败: {e}"

    def get_param_info(self, key: str) -> str:
        """获取参数信息"""
        if key not in self.schema:
            # 只显示非隐藏的参数
            visible_keys = [
                k for k, v in self.schema.items() if not v.get("hidden", False)
            ]
            return f"不支持的参数: {key}\n可用参数: {', '.join(visible_keys)}"

        # 检查是否为隐藏参数
        schema_item = self.schema[key]
        if schema_item.get("hidden", False):
            visible_keys = [
                k for k, v in self.schema.items() if not v.get("hidden", False)
            ]
            return f"参数 {key} 不可查看\n可用参数: {', '.join(visible_keys)}"

        # 获取当前值，处理映射关系
        if key == "refresh_token_interval_minutes":
            current_value = getattr(self.config, "refresh_interval", 720)
        else:
            current_value = getattr(self.config, key, "未设置")

        msg = f"{key} 当前值: {current_value}\n"
        if schema_item["type"] == "enum":
            msg += f"可选值: {', '.join(schema_item['choices'])}"
        elif schema_item["type"] == "bool":
            msg += "可选值: true, false"
        elif schema_item["type"] == "int":
            minv, maxv = schema_item.get("min", None), schema_item.get("max", None)
            msg += f"可选范围: {minv} ~ {maxv}"
        elif schema_item["type"] == "string":
            msg += "可选值: 任意字符串"

        return msg

    async def handle_config_command(self, event, arg1: str = "", arg2: str = ""):
        """处理配置命令"""
        args = []
        if arg1:
            args.append(arg1)
        if arg2:
            args.append(arg2)

        if not args or (args and args[0].strip().lower() == "help"):
            return self.get_help_text()

        if args[0].strip().lower() == "show":
            current = self.get_current_config()
            msg = "# 当前 Pixiv 配置\n"
            for k, v in current.items():
                msg += f"{k}: {v}\n"
            return msg

        # 1参数：显示某项及可选项
        key = args[0]
        if len(args) == 1:
            return self.get_param_info(key)

        # 2参数：设置
        value = args[1]
        success, message = self.validate_and_set_config(key, value)

        if success:
            # 设置成功后，返回当前配置
            current = self.get_current_config()
            msg = f"{message}\n\n# 当前 Pixiv 配置\n"
            for k, v in current.items():
                msg += f"{k}: {v}\n"
            return msg
        else:
            return message
