"""Fanbox 下载任务管理：并发下载、落盘、downloaded.json 断点去重、打包。"""

import asyncio
import contextlib
import json
import re
import time
from collections import deque
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Awaitable, Callable

from astrbot.api import logger

from .client import FanboxAPIClient
from .models import FanboxFile, FanboxImage, FanboxPost
from .packer import pack_creator_encrypted
from .rate_limit import CookieInvalidError

DOWNLOAD_CONCURRENCY = 4  # 文件下载并发
DETAIL_PREFETCH_QUEUE = 4  # 帖子详情预取队列深度
SPEED_WINDOW_SECONDS = 10.0  # 当前速度采样窗口
DIR_NAME_RE = re.compile(r"^[\w一-鿿-]{1,64}$", re.UNICODE)
_UNSAFE_FILENAME_CHARS = re.compile(r'[\\/:*?"<>|\x00-\x1f]')


def validate_dir_name(name: str) -> str:
    """校验 --dir 目录名，拒绝路径穿越。"""
    name = name.strip()
    if not name or not DIR_NAME_RE.match(name) or ".." in name:
        raise ValueError(f"目录名无效: {name!r}（仅允许字母/数字/中文/_/-，不超过 64 字符）")
    return name


def sanitize_filename(name: str, max_len: int = 80) -> str:
    """文件名 OS 安全转义与截断。"""
    cleaned = _UNSAFE_FILENAME_CHARS.sub("-", name).strip().strip(".")
    cleaned = re.sub(r"\s+", " ", cleaned)
    if len(cleaned) > max_len:
        cleaned = cleaned[:max_len].rstrip()
    return cleaned or "untitled"


class DownloadedStore:
    """downloaded.json 读写：postId 集合是唯一去重真相，原子写支持断点续跑。"""

    def __init__(self, creator_dir: Path):
        self.path = creator_dir / "downloaded.json"
        self._downloaded: list[str] = []
        self.load()

    def load(self):
        self._downloaded = []
        if not self.path.exists():
            return
        try:
            data = json.loads(self.path.read_text(encoding="utf-8"))
            ids = data.get("downloaded") if isinstance(data, dict) else data
            if isinstance(ids, list):
                self._downloaded = [str(x) for x in ids]
        except (OSError, json.JSONDecodeError) as exc:
            logger.warning(f"Pixiv 插件：downloaded.json 读取失败，按空记录处理 - {exc}")

    def contains(self, post_id: str) -> bool:
        return post_id in set(self._downloaded)

    def add(self, post_id: str):
        if post_id not in set(self._downloaded):
            self._downloaded.append(post_id)
        self._save()

    def _save(self):
        self.path.parent.mkdir(parents=True, exist_ok=True)
        payload = {
            "downloaded": self._downloaded,
            "updated_at": time.strftime("%Y-%m-%dT%H:%M:%S%z"),
        }
        tmp = self.path.with_suffix(".json.tmp")
        tmp.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")
        tmp.replace(self.path)  # 原子替换


@dataclass
class DownloadProgress:
    creator_id: str = ""
    dir_name: str = ""
    state: str = "idle"  # running / stopping / done / stopped / error
    planned: int = 0
    processed: int = 0
    succeeded: int = 0
    skipped_downloaded: int = 0
    skipped_restricted: int = 0
    failed: int = 0
    bytes_downloaded: int = 0
    current_post: str = ""
    speed_bps: float = 0.0  # 当前下载速度（滑动窗口）
    active_files: dict[str, tuple[int, int]] = field(default_factory=dict)  # 文件名 → (已下载, 总大小)
    errors: list[str] = field(default_factory=list)
    started_at: float = 0.0
    message: str = ""

    def render(self) -> str:
        """状态文本，供 status 命令展示。"""
        elapsed = int(time.time() - self.started_at) if self.started_at else 0
        mb = self.bytes_downloaded / 1024 / 1024
        lines = [
            f"# Fanbox 下载任务：{self.creator_id}",
            "",
            f"状态: {self.state} | 目录: fanbox/{self.dir_name}",
            f"进度: {self.processed}/{self.planned or '?'} 篇"
            f"（成功 {self.succeeded} / 已下载跳过 {self.skipped_downloaded}"
            f" / 受限跳过 {self.skipped_restricted} / 失败 {self.failed}）",
            f"已下载: {mb:.1f} MB | 用时: {elapsed}s",
        ]
        if self.state == "running":
            speed_mb = self.speed_bps / 1024 / 1024
            lines.append(f"速度: {speed_mb:.2f} MB/s")
        if self.current_post:
            lines.append(f"当前: {self.current_post}")
        if self.state == "running" and self.active_files:
            for fname, (done, total) in self.active_files.items():
                done_mb = done / 1024 / 1024
                if total:
                    total_mb = total / 1024 / 1024
                    lines.append(
                        f"  {fname}: {done_mb:.1f}/{total_mb:.1f} MB ({done * 100 // total}%)"
                    )
                else:
                    lines.append(f"  {fname}: {done_mb:.1f} MB")
        if self.message:
            lines.append(f"说明: {self.message}")
        if self.errors:
            lines.append("最近错误:")
            lines.extend(f"- {e}" for e in self.errors[-3:])
        return "\n".join(lines)


class FanboxDownloadManager:
    """下载任务管理器：全局同时仅一个任务，协作式停止。"""

    def __init__(
        self,
        data_dir: Path,
        concurrency: int = DOWNLOAD_CONCURRENCY,
        prefetch_queue: int = DETAIL_PREFETCH_QUEUE,
        speed_window: float = SPEED_WINDOW_SECONDS,
    ):
        self.root_dir = data_dir / "fanbox"
        self.progress = DownloadProgress()
        self._task: asyncio.Task | None = None
        self._cancel_event: asyncio.Event | None = None
        self._speed_window: deque[tuple[float, int]] = deque()
        # 策略参数由 config 层注入（默认即上方常量，非必要不修改）
        self._concurrency = concurrency
        self._prefetch_queue = prefetch_queue
        self._speed_window_seconds = speed_window
    @property
    def running(self) -> bool:
        return self._task is not None and not self._task.done()

    def creator_dir(self, dir_name: str) -> Path:
        return self.root_dir / dir_name

    def start(
        self,
        client: FanboxAPIClient,
        creator_id: str,
        dir_name: str,
        limit: int | None = None,
        since: str | None = None,
        dl_type: str = "all",
        force: bool = False,
        on_done: Callable[[str], Awaitable[None]] | None = None,
    ) -> str | None:
        """启动后台任务；已有任务运行时返回冲突提示。"""
        if self.running:
            return (
                f"已有下载任务进行中（{self.progress.creator_id}），"
                "请先 /pixiv_fanbox_dl_status 查看或 /pixiv_fanbox_dl_stop 停止。"
            )
        self._cancel_event = asyncio.Event()
        client.set_cancel_event(self._cancel_event)
        self._speed_window.clear()
        self.progress = DownloadProgress(
            creator_id=creator_id,
            dir_name=dir_name,
            state="running",
            started_at=time.time(),
        )
        self._task = asyncio.create_task(
            self._run(client, creator_id, dir_name, limit, since, dl_type, force, on_done)
        )
        return None

    def stop(self) -> str:
        if not self.running or self._cancel_event is None:
            return "当前没有进行中的 Fanbox 下载任务。"
        self._cancel_event.set()
        self.progress.state = "stopping"
        return "已发送停止信号，任务将在当前文件下载完成后终止。"

    def status_text(self) -> str:
        if self.progress.state == "idle":
            return "当前没有 Fanbox 下载任务记录。"
        return self.progress.render()

    async def _run(
        self,
        client: FanboxAPIClient,
        creator_id: str,
        dir_name: str,
        limit: int | None,
        since: str | None,
        dl_type: str,
        force: bool,
        on_done: Callable[[str], Awaitable[None]] | None,
    ):
        p = self.progress
        creator_dir = self.creator_dir(dir_name)
        posts_root = creator_dir / "posts"
        posts_root.mkdir(parents=True, exist_ok=True)
        store = DownloadedStore(creator_dir)
        semaphore = asyncio.Semaphore(self._concurrency)

        try:
            # 先收集符合条件的帖子摘要（分页拉取阶段也受限流保护）
            targets: list[FanboxPost] = []
            async for summary in client.iter_creator_posts(creator_id):
                if not force and store.contains(summary.id):
                    p.skipped_downloaded += 1
                    continue
                if summary.is_restricted:
                    p.skipped_restricted += 1
                    continue
                if since and summary.published_datetime[:10] < since:
                    continue
                targets.append(summary)
                if limit is not None and len(targets) >= limit:
                    break
            p.planned = len(targets)
            logger.info(
                f"Pixiv 插件：Fanbox 下载任务开始 - creator={creator_id} 待下载 {p.planned} 篇"
            )

            consecutive_auth_errors = 0  # 连续 403 计数，区分单帖无权限与 Cookie 整体失效
            detail_queue: asyncio.Queue = asyncio.Queue(maxsize=self._prefetch_queue)
            prefetch_task = asyncio.create_task(
                self._prefetch_details(client, targets, detail_queue)
            )
            try:
                while True:
                    if self._cancel_event and self._cancel_event.is_set():
                        break
                    item = await detail_queue.get()
                    if item is None:
                        break
                    summary, post, fetch_error = item
                    p.current_post = f"{summary.id} {summary.title[:40]}"
                    p.processed += 1
                    try:
                        if fetch_error is not None:
                            raise fetch_error
                        if post is None:
                            p.skipped_restricted += 1
                            continue
                        assets = post.list_downloadable()
                        if dl_type == "image":
                            assets = [a for a in assets if isinstance(a, FanboxImage)]
                        elif dl_type == "file":
                            assets = [a for a in assets if isinstance(a, FanboxFile)]

                        post_dir = posts_root / f"{post.id}_{sanitize_filename(post.title)}"
                        post_dir.mkdir(parents=True, exist_ok=True)
                        self._write_content_md(post_dir, post, creator_id)

                        results = await asyncio.gather(
                            *(
                                self._download_one(
                                    client, semaphore, post_dir, idx, asset, force=force
                                )
                                for idx, asset in enumerate(assets, start=1)
                            ),
                            return_exceptions=True,
                        )
                        failures = [r for r in results if isinstance(r, Exception)]
                        for exc in failures:
                            if isinstance(exc, asyncio.CancelledError):
                                raise exc
                        if failures:
                            raise RuntimeError(
                                f"{len(failures)}/{len(assets)} 个文件失败: {failures[0]}"
                            )

                        p.bytes_downloaded += sum(r for r in results if isinstance(r, int))
                        store.add(post.id)  # 每帖全部成功才记录，支持断点续跑
                        p.succeeded += 1
                    except asyncio.CancelledError:
                        break
                    except Exception as exc:
                        # 单帖 403 多为未订阅方案或缺 cf_clearance，按受限跳过；连续 5 次才判定整体失效
                        if isinstance(exc, CookieInvalidError):
                            p.skipped_restricted += 1
                            consecutive_auth_errors += 1
                            p.errors.append(f"{summary.id}: 无访问权限（未订阅方案或缺少 cf_clearance）")
                            if consecutive_auth_errors >= 5:
                                p.message = str(exc)
                                break
                            continue
                        consecutive_auth_errors = 0
                        p.failed += 1
                        p.errors.append(f"{summary.id}: {exc}")
                        logger.warning(
                            f"Pixiv 插件：Fanbox 帖子下载失败 - {summary.id} - {exc}"
                        )
            finally:
                prefetch_task.cancel()
                with contextlib.suppress(asyncio.CancelledError):
                    await prefetch_task

            stopped = self._cancel_event is not None and self._cancel_event.is_set()
            p.state = "stopped" if stopped else "done"
            p.current_post = ""
            if p.state == "done" and not p.message:
                p.message = "任务完成。"
        except Exception as exc:
            p.state = "error"
            p.message = str(exc)
            p.errors.append(str(exc))
            logger.error(f"Pixiv 插件：Fanbox 下载任务异常终止 - {exc}")
        finally:
            await client.close()  # 释放复用的 HTTP 会话

        summary_text = self._build_summary()
        logger.info(f"Pixiv 插件：Fanbox 下载任务结束\n{summary_text}")
        if on_done is not None:
            try:
                await on_done(summary_text)
            except Exception as exc:
                # 推送失败兜底：结果保留在 status 中可查
                logger.warning(f"Pixiv 插件：Fanbox 下载结果推送失败 - {exc}")

    async def _prefetch_details(
        self,
        client: FanboxAPIClient,
        targets: list[FanboxPost],
        queue: asyncio.Queue,
    ):
        """详情预取流水线：限流的详情请求与文件下载并行，缩短总耗时。

        队列元素为 (摘要, 详情, 错误)，None 为结束哨兵。
        """
        try:
            for summary in targets:
                if self._cancel_event and self._cancel_event.is_set():
                    break
                try:
                    post = await client.get_post_detail(summary.id)
                    await queue.put((summary, post, None))
                except asyncio.CancelledError:
                    raise
                except Exception as exc:
                    await queue.put((summary, None, exc))
        finally:
            with contextlib.suppress(asyncio.CancelledError):
                await queue.put(None)

    async def _download_one(
        self,
        client: FanboxAPIClient,
        semaphore: asyncio.Semaphore,
        post_dir: Path,
        index: int,
        asset: FanboxImage | FanboxFile,
        force: bool = False,
    ) -> int:
        async with semaphore:
            if isinstance(asset, FanboxImage):
                ext = asset.extension or "jpg"
                dest = post_dir / f"{index:03d}.{ext}"
                fallback = asset.thumbnail_url or None
            else:
                name = sanitize_filename(asset.name, max_len=60) or asset.id or "file"
                ext = f".{asset.extension}" if asset.extension else ""
                dest = post_dir / f"file_{name}{ext}"
                fallback = None
            if dest.exists() and not force:
                # 已下载文件跳过；中断残文件由 client._remove_partial 清除，存在即完整
                return 0
            fname = dest.name
            try:
                return await client.download_asset(
                    asset.url,
                    dest,
                    fallback_url=fallback,
                    on_progress=lambda done, total: self._note_file_progress(
                        fname, done, total
                    ),
                )
            finally:
                self.progress.active_files.pop(fname, None)

    def _note_file_progress(self, fname: str, downloaded: int, total: int):
        """更新文件进度并维护速度滑动窗口。"""
        prev = self.progress.active_files.get(fname, (0, 0))[0]
        self.progress.active_files[fname] = (downloaded, total)
        delta = downloaded - prev
        if delta <= 0:
            return
        now = time.monotonic()
        self._speed_window.append((now, delta))
        cutoff = now - self._speed_window_seconds
        while self._speed_window and self._speed_window[0][0] < cutoff:
            self._speed_window.popleft()
        span = now - self._speed_window[0][0] if self._speed_window else 0.0
        total_bytes = sum(b for _, b in self._speed_window)
        self.progress.speed_bps = total_bytes / span if span > 0.5 else 0.0

    @staticmethod
    def _write_content_md(post_dir: Path, post: FanboxPost, creator_id: str):
        """写入帖子元信息与正文。"""
        lines = [
            f"# {post.title or '无标题'}",
            "",
            f"- postId: {post.id}",
            f"- creatorId: {post.creator_id or creator_id}",
            f"- 发布时间: {post.published_datetime or '未知'}",
            f"- 门槛: {post.fee_required} 日元",
            f"- 链接: https://{post.creator_id or creator_id}.fanbox.cc/posts/{post.id}",
            "",
            "---",
            "",
        ]
        text = post.body_text()
        if text:
            lines.append(text)
        (post_dir / "content.md").write_text(
            "\n".join(lines), encoding="utf-8"
        )

    def _build_summary(self) -> str:
        p = self.progress
        state_text = {"done": "✅ 完成", "stopped": "⏹ 已停止", "error": "❌ 异常终止"}.get(
            p.state, p.state
        )
        lines = [
            f"# Fanbox 批量下载{state_text}：{p.creator_id}",
            "",
            f"成功 {p.succeeded} 篇 / 已下载跳过 {p.skipped_downloaded}"
            f" / 受限跳过 {p.skipped_restricted} / 失败 {p.failed}",
            f"下载量: {p.bytes_downloaded / 1024 / 1024:.1f} MB",
            f"存储: {self.creator_dir(p.dir_name)}",
        ]
        if p.message and p.state != "done":
            lines.append(f"说明: {p.message}")
        if p.errors:
            lines.append("失败原因（最近 3 条）:")
            lines.extend(f"- {e}" for e in p.errors[-3:])
        return "\n".join(lines)

    # -------- 下载内容查看 / 打包 --------

    def list_downloaded_posts(self, dir_name: str) -> list[dict[str, Any]]:
        """扫描已下载帖子目录，返回 postId/标题/文件数/大小。"""
        creator_dir = self.creator_dir(dir_name)
        posts_root = creator_dir / "posts"
        if not posts_root.is_dir():
            return []
        store_ids = set(DownloadedStore(creator_dir)._downloaded)
        result = []
        for post_dir in sorted(posts_root.iterdir()):
            if not post_dir.is_dir():
                continue
            dir_name_part = post_dir.name
            post_id, _, title = dir_name_part.partition("_")
            if store_ids and post_id not in store_ids:
                continue
            files = [f for f in post_dir.iterdir() if f.is_file()]
            size = sum(f.stat().st_size for f in files)
            result.append(
                {
                    "post_id": post_id,
                    "title": title,
                    "files": len(files),
                    "size": size,
                    "path": post_dir,
                }
            )
        return result

    def find_post_dir(self, dir_name: str, post_id: str) -> Path | None:
        """按 postId 前缀定位帖子目录。"""
        posts_root = self.creator_dir(dir_name) / "posts"
        if not posts_root.is_dir():
            return None
        for post_dir in posts_root.iterdir():
            if post_dir.is_dir() and post_dir.name.startswith(f"{post_id}_"):
                return post_dir
        return None

    def pack_creator(
        self, dir_name: str, temp_dir: Path, part_limit: int | None = None
    ) -> tuple[list[Path], str]:
        """AES 加密打包 creator 目录（分卷逻辑见 fanbox/packer.py）。"""
        kwargs = {"part_limit": part_limit} if part_limit else {}
        return pack_creator_encrypted(
            self.creator_dir(dir_name), temp_dir, dir_name, **kwargs
        )
