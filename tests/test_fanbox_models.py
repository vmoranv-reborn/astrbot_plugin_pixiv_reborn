"""fanbox 包解析与断点去重逻辑单测（payload 取自 fanbox-dl PR#104 测试用例）。"""

import json
import sys
import tempfile
import unittest
from pathlib import Path

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


if __name__ == "__main__":
    unittest.main()
