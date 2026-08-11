"""fanbox 包解析与断点去重逻辑单测（payload 取自 fanbox-dl PR#104 测试用例）。"""

import asyncio
import json
import sys
import tempfile
import time
import unittest
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock

# 本地无 astrbot 环境时打桩，使 fanbox.downloader 可导入
sys.modules.setdefault("astrbot", MagicMock())
sys.modules.setdefault("astrbot.api", MagicMock())

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from fanbox.models import (
    FanboxFile,
    FanboxImage,
    FanboxPost,
    parse_page_urls,
    parse_post_info,
    parse_post_list,
)


# fanbox-dl PR#104 官方测试 payload
PAGINATION_LEGACY = '{"body":["https://api.fanbox.cc/post.listCreator?creatorId=example&limit=10","https://api.fanbox.cc/post.listCreator?creatorId=example&limit=10&page=2"]}'
PAGINATION_CURRENT = '{"body":{"pageUrls":["https://api.fanbox.cc/post.listCreator?creatorId=example&limit=10","https://api.fanbox.cc/post.listCreator?creatorId=example&limit=10&page=2"]}}'
LIST_LEGACY = '{"body":[{"id":"1001","title":"First post"},{"id":"1002","title":"Second post"}]}'
LIST_CURRENT = '{"body":{"posts":[{"id":"1001","title":"First post"},{"id":"1002","title":"Second post"}]}}'
POST_INFO_LEGACY = '{"body":{"id":"1001","title":"Example post","creatorId":"example"}}'
POST_INFO_CURRENT = '{"body":{"post":{"id":"1001","title":"Example post","creatorId":"example"}}}'
EXPECTED_PAGE_URLS = [
    "https://api.fanbox.cc/post.listCreator?creatorId=example&limit=10",
    "https://api.fanbox.cc/post.listCreator?creatorId=example&limit=10&page=2",
]


def _make_post(body):
    return FanboxPost(id="1", title="t", creator_id="c", body=body)


class TestPR104Compat(unittest.TestCase):
    def test_pagination_legacy_and_current(self):
        self.assertEqual(parse_page_urls(json.loads(PAGINATION_LEGACY)), EXPECTED_PAGE_URLS)
        self.assertEqual(parse_page_urls(json.loads(PAGINATION_CURRENT)), EXPECTED_PAGE_URLS)

    def test_list_creator_legacy_and_current(self):
        for raw in (LIST_LEGACY, LIST_CURRENT):
            posts, next_page = parse_post_list(json.loads(raw))
            self.assertEqual([p.id for p in posts], ["1001", "1002"])
            self.assertEqual(posts[0].title, "First post")
            self.assertIsNone(next_page)

    def test_list_creator_next_page(self):
        payload = json.loads(
            '{"body":{"posts":[{"id":"1","title":"a"}],"nextPage":"https://api.fanbox.cc/post.listCreator?cursor=x"}}'
        )
        posts, next_page = parse_post_list(payload)
        self.assertEqual(len(posts), 1)
        self.assertEqual(next_page, "https://api.fanbox.cc/post.listCreator?cursor=x")

    def test_post_info_legacy_and_current(self):
        for raw in (POST_INFO_LEGACY, POST_INFO_CURRENT):
            post = parse_post_info(json.loads(raw))
            self.assertIsNotNone(post)
            self.assertEqual(post.id, "1001")
            self.assertEqual(post.title, "Example post")
            self.assertEqual(post.creator_id, "example")

    def test_post_info_empty_body(self):
        self.assertIsNone(parse_post_info(json.loads('{"body":null}')))
        self.assertIsNone(parse_post_info(json.loads('{"body":{"post":null}}')))


class TestListDownloadable(unittest.TestCase):
    def test_image_post(self):
        post = _make_post(
            {
                "images": [
                    {"id": "i1", "extension": "jpg", "originalUrl": "https://x/1.jpg"},
                    {"id": "i2", "extension": "png", "originalUrl": "https://x/2.png"},
                ]
            }
        )
        assets = post.list_downloadable()
        self.assertEqual(len(assets), 2)
        self.assertTrue(all(isinstance(a, FanboxImage) for a in assets))
        self.assertEqual(assets[0].url, "https://x/1.jpg")

    def test_file_post(self):
        post = _make_post(
            {
                "files": [
                    {"id": "f1", "name": "pack", "extension": "zip", "url": "https://x/p.zip"}
                ]
            }
        )
        assets = post.list_downloadable()
        self.assertEqual(len(assets), 1)
        self.assertIsInstance(assets[0], FanboxFile)
        self.assertEqual(assets[0].name, "pack")

    def test_blog_post_blocks_order(self):
        post = _make_post(
            {
                "blocks": [
                    {"type": "p", "text": "第一段"},
                    {"type": "image", "imageId": "i1"},
                    {"type": "file", "fileId": "f1"},
                    {"type": "image", "imageId": "i2"},
                ],
                "imageMap": {
                    "i1": {"id": "i1", "extension": "jpg", "originalUrl": "https://x/1.jpg"},
                    "i2": {"id": "i2", "extension": "jpg", "originalUrl": "https://x/2.jpg"},
                },
                "fileMap": {
                    "f1": {"id": "f1", "name": "a", "extension": "zip", "url": "https://x/a.zip"}
                },
            }
        )
        assets = post.list_downloadable()
        # 顺序应与 blocks 一致：图1 → 文件 → 图2
        self.assertEqual(
            [(type(a).__name__, a.id) for a in assets],
            [("FanboxImage", "i1"), ("FanboxFile", "f1"), ("FanboxImage", "i2")],
        )
        self.assertEqual(post.body_text(), "第一段")

    def test_no_body(self):
        self.assertEqual(_make_post(None).list_downloadable(), [])


class TestDownloadedStore(unittest.TestCase):
    def test_resume_skip(self):
        from fanbox.downloader import DownloadedStore

        with tempfile.TemporaryDirectory() as tmp:
            store = DownloadedStore(Path(tmp))
            self.assertFalse(store.contains("1001"))
            store.add("1001")
            store.add("1001")  # 重复添加不重复记录
            store.add("1002")

            # 重新加载模拟断点续跑
            store2 = DownloadedStore(Path(tmp))
            self.assertTrue(store2.contains("1001"))
            self.assertTrue(store2.contains("1002"))
            self.assertFalse(store2.contains("1003"))

            data = json.loads((Path(tmp) / "downloaded.json").read_text(encoding="utf-8"))
            self.assertEqual(data["downloaded"], ["1001", "1002"])
            self.assertIn("updated_at", data)

    def test_corrupt_file_treated_as_empty(self):
        from fanbox.downloader import DownloadedStore

        with tempfile.TemporaryDirectory() as tmp:
            (Path(tmp) / "downloaded.json").write_text("not-json", encoding="utf-8")
            store = DownloadedStore(Path(tmp))
            self.assertFalse(store.contains("1001"))

    def test_dir_name_validation(self):
        from fanbox.downloader import validate_dir_name

        self.assertEqual(validate_dir_name("harusono"), "harusono")
        self.assertEqual(validate_dir_name("我的目录-01"), "我的目录-01")
        for bad in ("../etc", "a/b", "a\\b", "..", ""):
            with self.assertRaises(ValueError):
                validate_dir_name(bad)


class TestDownloadOneSkip(unittest.IsolatedAsyncioTestCase):
    """文件级断点：已存在的完整文件跳过不重复下载。"""

    async def test_skips_existing_file(self):
        from fanbox.downloader import FanboxDownloadManager

        with tempfile.TemporaryDirectory() as tmp:
            post_dir = Path(tmp)
            (post_dir / "001.jpg").write_bytes(b"done")
            mgr = FanboxDownloadManager(Path(tmp))
            client = MagicMock()
            client.download_asset = AsyncMock(return_value=100)
            asset = FanboxImage(id="i1", extension="jpg", original_url="https://x/1.jpg")

            result = await mgr._download_one(
                client, asyncio.Semaphore(1), post_dir, 1, asset
            )
            self.assertEqual(result, 0)
            client.download_asset.assert_not_called()

    async def test_force_redownloads_existing_file(self):
        from fanbox.downloader import FanboxDownloadManager

        with tempfile.TemporaryDirectory() as tmp:
            post_dir = Path(tmp)
            (post_dir / "001.jpg").write_bytes(b"old")
            mgr = FanboxDownloadManager(Path(tmp))
            client = MagicMock()
            client.download_asset = AsyncMock(return_value=100)
            asset = FanboxImage(id="i1", extension="jpg", original_url="https://x/1.jpg")

            result = await mgr._download_one(
                client, asyncio.Semaphore(1), post_dir, 1, asset, force=True
            )
            self.assertEqual(result, 100)
            client.download_asset.assert_called_once()

    async def test_downloads_missing_file_and_clears_progress(self):
        from fanbox.downloader import FanboxDownloadManager

        with tempfile.TemporaryDirectory() as tmp:
            mgr = FanboxDownloadManager(Path(tmp))
            client = MagicMock()
            client.download_asset = AsyncMock(return_value=100)
            asset = FanboxImage(id="i1", extension="jpg", original_url="https://x/1.jpg")

            result = await mgr._download_one(
                client, asyncio.Semaphore(1), Path(tmp), 1, asset
            )
            self.assertEqual(result, 100)
            client.download_asset.assert_called_once()
            # 传入了进度回调
            self.assertIn("on_progress", client.download_asset.call_args.kwargs)
            # 完成后活动文件表已清空
            self.assertEqual(mgr.progress.active_files, {})


class TestProgressRender(unittest.TestCase):
    def test_running_shows_speed_and_file_progress(self):
        from fanbox.downloader import DownloadProgress

        p = DownloadProgress(
            creator_id="c",
            dir_name="d",
            state="running",
            planned=10,
            processed=3,
            speed_bps=2 * 1024 * 1024,
            started_at=time.time(),
        )
        p.active_files["003.jpg"] = (1024 * 1024, 2 * 1024 * 1024)
        text = p.render()
        self.assertIn("速度: 2.00 MB/s", text)
        self.assertIn("003.jpg: 1.0/2.0 MB (50%)", text)

    def test_done_hides_speed(self):
        from fanbox.downloader import DownloadProgress

        p = DownloadProgress(
            creator_id="c", dir_name="d", state="done", speed_bps=1024 * 1024
        )
        self.assertNotIn("速度:", p.render())

    def test_speed_window(self):
        from fanbox.downloader import FanboxDownloadManager

        with tempfile.TemporaryDirectory() as tmp:
            mgr = FanboxDownloadManager(Path(tmp))
            mgr._note_file_progress("a.jpg", 1000, 2000)
            mgr._note_file_progress("a.jpg", 2000, 2000)
            self.assertEqual(mgr.progress.active_files["a.jpg"], (2000, 2000))
            # 窗口内两样本同刻，span<0.5 时速度计 0，不除零
            self.assertGreaterEqual(mgr.progress.speed_bps, 0.0)


if __name__ == "__main__":
    unittest.main()
