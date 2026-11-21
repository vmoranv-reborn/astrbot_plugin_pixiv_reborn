"""插件数据目录定位。

保留历史目录名 ``pixiv_search``：改名会迁移/丢失已有订阅数据库与临时文件。
"""

from pathlib import Path

LEGACY_DATA_DIR_NAME = "pixiv_search"


def get_plugin_data_dir() -> Path:
    from astrbot.api.star import StarTools

    return StarTools.get_data_dir(LEGACY_DATA_DIR_NAME)
