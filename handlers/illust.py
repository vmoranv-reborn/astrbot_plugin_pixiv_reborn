"""插画命令处理器：组合搜索与详情 Mixin。"""

from .illust_detail import IllustDetailMixin
from .illust_search import IllustSearchMixin


class IllustHandler(IllustDetailMixin, IllustSearchMixin):
    def __init__(self, client_wrapper, pixiv_config):
        """
        初始化插画处理器
        :param client_wrapper: 封装好的 PixivClientWrapper 实例 (Core)
        :param config: PixivConfig 实例 (Config)
        """

        self.client_wrapper = client_wrapper
        self.client = client_wrapper.client_api
        self.pixiv_config = pixiv_config
