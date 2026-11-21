"""Pixiv Fanbox 功能处理器：组合公共、抓取、浏览与下载 Mixin。"""

from .fanbox_common import FanboxCommonMixin
from .fanbox_fetch import FanboxFetchMixin
from .fanbox_browse import FanboxBrowseMixin
from .fanbox_download import FanboxDownloadMixin


class FanboxHandler(
    FanboxCommonMixin,
    FanboxFetchMixin,
    FanboxBrowseMixin,
    FanboxDownloadMixin,
):
    """Pixiv Fanbox 功能处理器。"""
