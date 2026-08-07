"""Fanbox 帖子/文件数据结构与响应解析（兼容 fanbox-dl PR#104 新旧两种 body 格式）。"""

from dataclasses import dataclass
from typing import Any


@dataclass
class FanboxImage:
    id: str
    extension: str
    original_url: str
    thumbnail_url: str = ""

    @property
    def url(self) -> str:
        return self.original_url


@dataclass
class FanboxFile:
    id: str
    name: str
    extension: str
    url: str


# 可下载对象统一接口：url / extension / id
Downloadable = FanboxImage | FanboxFile


@dataclass
class FanboxPost:
    id: str
    title: str
    creator_id: str
    published_datetime: str = ""
    fee_required: int = 0
    is_restricted: bool = False
    is_pinned: bool = False
    body: dict[str, Any] | None = None

    def list_downloadable(self) -> list[Downloadable]:
        """按 fanbox-dl 顺序提取媒体：images > files > blocks+imageMap/fileMap。"""
        body = self.body
        if not isinstance(body, dict):
            return []

        images = body.get("images")
        if isinstance(images, list) and images:
            return [img for img in (_parse_image(x) for x in images) if img is not None]

        files = body.get("files")
        if isinstance(files, list) and files:
            return [f for f in (_parse_file(x) for x in files) if f is not None]

        blocks = body.get("blocks")
        if isinstance(blocks, list) and blocks:
            image_map = body.get("imageMap") if isinstance(body.get("imageMap"), dict) else {}
            file_map = body.get("fileMap") if isinstance(body.get("fileMap"), dict) else {}
            result: list[Downloadable] = []
            for block in blocks:
                if not isinstance(block, dict):
                    continue
                image_id = block.get("imageId")
                if image_id and image_id in image_map:
                    img = _parse_image(image_map[image_id])
                    if img is not None:
                        result.append(img)
                file_id = block.get("fileId")
                if file_id and file_id in file_map:
                    f = _parse_file(file_map[file_id])
                    if f is not None:
                        result.append(f)
            return result

        return []

    def body_text(self) -> str:
        """提取正文纯文本（text 或 blocks 拼接），用于 content.md。"""
        body = self.body
        if not isinstance(body, dict):
            return ""
        if isinstance(body.get("text"), str):
            return body["text"]
        blocks = body.get("blocks")
        if isinstance(blocks, list):
            texts = [
                b["text"].strip()
                for b in blocks
                if isinstance(b, dict) and isinstance(b.get("text"), str) and b["text"].strip()
            ]
            if texts:
                return "\n\n".join(texts)
        return ""


def _parse_image(data: Any) -> FanboxImage | None:
    if not isinstance(data, dict):
        return None
    url = data.get("originalUrl")
    if not isinstance(url, str) or not url:
        return None
    return FanboxImage(
        id=str(data.get("id", "")),
        extension=str(data.get("extension", "") or "").lstrip("."),
        original_url=url,
        thumbnail_url=str(data.get("thumbnailUrl", "") or ""),
    )


def _parse_file(data: Any) -> FanboxFile | None:
    if not isinstance(data, dict):
        return None
    url = data.get("url")
    if not isinstance(url, str) or not url:
        return None
    return FanboxFile(
        id=str(data.get("id", "")),
        name=str(data.get("name", "") or ""),
        extension=str(data.get("extension", "") or "").lstrip("."),
        url=url,
    )


def parse_post_summary(data: Any) -> FanboxPost | None:
    """解析列表页中的帖子摘要（body 为空或无媒体字段）。"""
    if not isinstance(data, dict):
        return None
    post_id = data.get("id")
    if post_id is None:
        return None
    return FanboxPost(
        id=str(post_id),
        title=str(data.get("title", "") or ""),
        creator_id=str(data.get("creatorId", "") or ""),
        published_datetime=str(data.get("publishedDatetime", "") or ""),
        fee_required=int(data.get("feeRequired", 0) or 0),
        is_restricted=bool(data.get("isRestricted")),
        is_pinned=bool(data.get("isPinned")),
        body=data.get("body") if isinstance(data.get("body"), dict) else None,
    )


def _unwrap_body(payload: Any) -> Any:
    if isinstance(payload, dict):
        return payload.get("body")
    return payload


def parse_page_urls(payload: Any) -> list[str]:
    """post.paginateCreator 响应：body 为 URL 列表（旧）或 {pageUrls: [...]}（新）。"""
    body = _unwrap_body(payload)
    if isinstance(body, dict):
        body = body.get("pageUrls")
    if not isinstance(body, list):
        return []
    return [u for u in body if isinstance(u, str) and u]


def parse_post_list(payload: Any) -> tuple[list[FanboxPost], str | None]:
    """post.listCreator 响应：返回 (帖子列表, nextPage)。兼容 body 数组与 {posts, nextPage}。"""
    body = _unwrap_body(payload)
    next_page: str | None = None
    if isinstance(body, dict):
        raw_next = body.get("nextPage")
        if isinstance(raw_next, str) and raw_next:
            next_page = raw_next
        body = body.get("posts")
    if not isinstance(body, list):
        return [], next_page
    posts = [p for p in (parse_post_summary(x) for x in body) if p is not None]
    return posts, next_page


def parse_post_info(payload: Any) -> FanboxPost | None:
    """post.info 响应：body 为帖子对象（旧）或 {post: {...}}（新）；空 body 返回 None。"""
    body = _unwrap_body(payload)
    if not isinstance(body, dict):
        return None
    if "post" in body:
        body = body.get("post")
        if not isinstance(body, dict):
            return None
    if body.get("id") is None:
        return None
    return parse_post_summary(body)
