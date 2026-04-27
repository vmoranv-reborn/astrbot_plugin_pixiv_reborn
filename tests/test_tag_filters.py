import unittest
from types import SimpleNamespace

from utils.tag import FilterConfig, filter_illusts_with_reason


def make_illust(
    *,
    illust_id: int,
    total_bookmarks: int = 0,
    total_view: int = 0,
    like_count=None,
):
    payload = {
        "id": illust_id,
        "title": f"illust-{illust_id}",
        "user": SimpleNamespace(name="tester"),
        "tags": [],
        "x_restrict": 0,
        "illust_ai_type": 0,
        "total_bookmarks": total_bookmarks,
        "total_view": total_view,
    }
    if like_count is not None:
        payload["likeCount"] = like_count
    return SimpleNamespace(**payload)


def make_novel(*, novel_id: int):
    return SimpleNamespace(
        id=novel_id,
        title=f"novel-{novel_id}",
        user=SimpleNamespace(name="tester"),
        tags=[],
        x_restrict=0,
        illust_ai_type=0,
        text_length=1200,
    )


class TagFilterThresholdTests(unittest.TestCase):
    def test_filters_bookmarks_views_and_likes(self):
        config = FilterConfig(
            r18_mode="允许 R18",
            ai_filter_mode="显示 AI 作品",
            display_tag_str="阈值测试",
            min_bookmarks=100,
            min_views=1000,
            min_likes=30,
            show_filter_result=False,
        )
        illusts = [
            make_illust(
                illust_id=1, total_bookmarks=200, total_view=5000, like_count=60
            ),
            make_illust(
                illust_id=2, total_bookmarks=80, total_view=5000, like_count=60
            ),
            make_illust(
                illust_id=3, total_bookmarks=200, total_view=800, like_count=60
            ),
            make_illust(
                illust_id=4, total_bookmarks=200, total_view=5000, like_count=10
            ),
        ]

        filtered, messages = filter_illusts_with_reason(illusts, config)

        self.assertEqual([item.id for item in filtered], [1])
        self.assertEqual(messages, [])

    def test_like_threshold_ignores_missing_like_field(self):
        config = FilterConfig(
            r18_mode="允许 R18",
            ai_filter_mode="显示 AI 作品",
            display_tag_str="无点赞字段",
            min_bookmarks=100,
            min_views=1000,
            min_likes=30,
            show_filter_result=False,
        )

        filtered, _ = filter_illusts_with_reason(
            [make_illust(illust_id=1, total_bookmarks=200, total_view=5000)], config
        )

        self.assertEqual([item.id for item in filtered], [1])

    def test_no_result_message_mentions_threshold_reasons(self):
        config = FilterConfig(
            r18_mode="允许 R18",
            ai_filter_mode="显示 AI 作品",
            display_tag_str="无结果提示",
            min_bookmarks=100,
            min_views=1000,
            min_likes=30,
            show_filter_result=True,
        )
        illusts = [
            make_illust(illust_id=1, total_bookmarks=20, total_view=500, like_count=5)
        ]

        filtered, messages = filter_illusts_with_reason(illusts, config)

        self.assertEqual(filtered, [])
        self.assertTrue(any("书签数低于 100" in msg for msg in messages))
        self.assertTrue(any("阅读量低于 1000" in msg for msg in messages))
        self.assertTrue(any("点赞数低于 30" in msg for msg in messages))

    def test_novel_filters_skip_stat_thresholds(self):
        config = FilterConfig(
            r18_mode="允许 R18",
            ai_filter_mode="显示 AI 作品",
            display_tag_str="小说",
            min_bookmarks=1000,
            min_views=10000,
            min_likes=500,
            show_filter_result=False,
            enable_stat_filters=False,
        )

        filtered, _ = filter_illusts_with_reason([make_novel(novel_id=1)], config)

        self.assertEqual([item.id for item in filtered], [1])


if __name__ == "__main__":
    unittest.main()
