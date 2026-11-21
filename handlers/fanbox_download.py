"""Fanbox 下载/打包/查看命令的处理器 Mixin。"""

import asyncio
import re
import shlex
from pathlib import Path
from typing import Any

from astrbot.api import logger
from astrbot.api.event import AstrMessageEvent, MessageChain
import astrbot.api.message_components as Comp

from ..fanbox.client import FanboxAPIClient
from ..fanbox.downloader import validate_dir_name
from ..fanbox.packer import cleanup_stale_packs
from ..infra.help import get_help_message
from ..infra.paths import get_plugin_data_dir


class FanboxDownloadMixin:
    def _create_dl_client(self) -> FanboxAPIClient:
        """创建批量下载客户端，复用本类的 Cookie/UA/代理。"""
        cfg = self.pixiv_config
        return FanboxAPIClient(
            cookie_getter=self._fanbox_cookie_header,
            ua_getter=self._fanbox_user_agent,
            proxy_getter=self._get_proxy,
            api_host=getattr(cfg, "fanbox_api_proxy_host", ""),
            impersonate=getattr(cfg, "fanbox_dl_impersonate", ""),
            page_limit=getattr(cfg, "fanbox_dl_page_limit", 300),
            max_429_retries=getattr(cfg, "fanbox_dl_max_429_retries", 4),
            max_cf_consecutive=getattr(cfg, "fanbox_dl_max_cf_consecutive", 3),
            max_download_retries=getattr(cfg, "fanbox_dl_max_retries", 5),
        )

    def _make_dl_done_callback(self, event: AstrMessageEvent):
        """任务结束推送：复用订阅模块的 context.send_message 模式。"""
        session_id = event.unified_msg_origin

        async def on_done(summary: str):
            if self.context is None:
                return

            chain = MessageChain()
            chain.message(summary)
            await self.context.send_message(session_id, chain)

        return on_done

    def _raw_command_args(event: AstrMessageEvent) -> str:
        """从原始消息取命令名后的完整参数串。

        AstrBot 按空格向 handler 注入参数，单参数签名会丢弃多余 token
        （如 /pixiv_fanbox_dl foo --type file 只注入 foo），故从原文重取。
        """
        raw = re.sub(r"\s+", " ", event.get_message_str().strip())
        parts = raw.split(" ", 1)
        return parts[1].strip() if len(parts) > 1 else ""

    def _parse_dl_options(self, tokens: list[str]):
        """解析下载选项，返回 (creator_input, options_dict)；出错抛 ValueError。"""
        creator_input = None
        options: dict[str, Any] = {
            "limit": None,
            "since": None,
            "dl_type": "all",
            "dir_name": None,
            "force": False,
        }
        i = 0
        while i < len(tokens):
            tok = tokens[i]
            if tok == "--force":
                options["force"] = True
                i += 1
            elif tok == "--limit" and i + 1 < len(tokens):
                if not tokens[i + 1].isdigit():
                    raise ValueError("--limit 需要正整数")
                options["limit"] = max(1, int(tokens[i + 1]))
                i += 2
            elif tok == "--since" and i + 1 < len(tokens):
                import datetime

                try:
                    datetime.datetime.strptime(tokens[i + 1], "%Y-%m-%d")
                except ValueError:
                    raise ValueError("--since 需要 YYYY-MM-DD 格式日期")
                options["since"] = tokens[i + 1]
                i += 2
            elif tok == "--type" and i + 1 < len(tokens):
                if tokens[i + 1] not in {"image", "file", "all"}:
                    raise ValueError("--type 仅支持 image|file|all")
                options["dl_type"] = tokens[i + 1]
                i += 2
            elif tok == "--dir" and i + 1 < len(tokens):
                options["dir_name"] = validate_dir_name(tokens[i + 1])
                i += 2
            elif tok.startswith("--"):
                raise ValueError(f"未知选项: {tok}")
            elif creator_input is None:
                creator_input = tok
                i += 1
            else:
                raise ValueError(f"多余参数: {tok}")
        return creator_input, options

    async def pixiv_fanbox_dl(self, event: AstrMessageEvent, args: str = ""):
        """批量下载创作者 Fanbox 帖子（后台任务）。"""
        text = self._raw_command_args(event)
        if not text or text.lower() == "help":
            yield event.plain_result(
                get_help_message(
                    "pixiv_fanbox_dl",
                    "用法: /pixiv_fanbox_dl <creatorId|链接> [--limit N] [--since YYYY-MM-DD] [--type image|file|all] [--dir 名称] [--force]",
                )
            )
            return

        try:
            tokens = shlex.split(text)
            creator_input, options = self._parse_dl_options(tokens)
        except ValueError as e:
            yield event.plain_result(f"参数错误: {e}")
            return
        if not creator_input:
            yield event.plain_result(
                "缺少 creatorId 参数。发送 /pixiv_fanbox_dl help 查看用法。"
            )
            return

        try:
            creator_id = await self._resolve_creator_id(creator_input)
        except Exception as e:
            yield event.plain_result(f"creatorId 解析失败: {e}")
            return

        dir_name = options["dir_name"] or creator_id
        try:
            dir_name = validate_dir_name(dir_name)
        except ValueError as e:
            yield event.plain_result(f"{e}，可用 --dir 指定合法目录名。")
            return

        conflict = self.dl_manager.start(
            self._create_dl_client(),
            creator_id,
            dir_name,
            limit=options["limit"],
            since=options["since"],
            dl_type=options["dl_type"],
            force=options["force"],
            on_done=self._make_dl_done_callback(event),
        )
        if conflict:
            yield event.plain_result(conflict)
            return

        opt_parts = [
            f"limit={options['limit'] or '不限'}",
            f"since={options['since'] or '不限'}",
            f"type={options['dl_type']}",
        ]
        if options["force"]:
            opt_parts.append("force=是")
        yield event.plain_result(
            f"Fanbox 批量下载任务已启动：{creator_id}\n"
            f"保存目录: fanbox/{dir_name}/ | {' | '.join(opt_parts)}\n"
            "已下载过的帖子会自动跳过。\n"
            "/pixiv_fanbox_dl_status 查看进度 | /pixiv_fanbox_dl_stop 停止"
        )

    async def pixiv_fanbox_dl_status(self, event: AstrMessageEvent, args: str = ""):
        """查看当前 Fanbox 下载任务进度。"""
        yield event.plain_result(self.dl_manager.status_text())

    async def pixiv_fanbox_dl_stop(self, event: AstrMessageEvent, args: str = ""):
        """停止当前 Fanbox 下载任务。"""
        yield event.plain_result(self.dl_manager.stop())

    def _resolve_dl_dir_name(self, raw: str) -> str:
        """view 命令的目录参数：支持 fanbox 域名链接或直接目录名。"""
        domain_match = self.FANBOX_DOMAIN_RE.search(raw.strip())
        if domain_match:
            return domain_match.group(1)
        return validate_dir_name(raw)

    async def pixiv_fanbox_dl_view(self, event: AstrMessageEvent, args: str = ""):
        """查看已下载内容：列表 / 发送单帖 / 打包发送。"""
        text = self._raw_command_args(event)
        if not text or text.lower() == "help":
            yield event.plain_result(
                get_help_message(
                    "pixiv_fanbox_dl_view",
                    "用法: /pixiv_fanbox_dl_view <creatorId|目录名> [postId|--pack]",
                )
            )
            return

        try:
            tokens = shlex.split(text)
        except ValueError as e:
            yield event.plain_result(f"参数解析失败: {e}")
            return
        try:
            dir_name = self._resolve_dl_dir_name(tokens[0])
        except ValueError as e:
            yield event.plain_result(str(e))
            return
        second = tokens[1] if len(tokens) > 1 else None

        if second == "--pack":
            async for result in self._dl_view_pack(event, dir_name):
                yield result
        elif second is None:
            yield event.plain_result(self._dl_view_list(dir_name))
        elif second.isdigit():
            async for result in self._dl_view_post(event, dir_name, second):
                yield result
        else:
            yield event.plain_result(
                f"无法识别的参数: {second}（应为 postId 或 --pack）"
            )

    def _dl_view_list(self, dir_name: str) -> str:
        posts = self.dl_manager.list_downloaded_posts(dir_name)
        lines = [f"# Fanbox 已下载内容：{dir_name}", ""]
        if not posts:
            lines.append("暂无已下载的帖子。")
            return "\n".join(lines)
        total_size = sum(p["size"] for p in posts)
        lines.append(f"共 {len(posts)} 篇 | 总大小 {total_size / 1024 / 1024:.1f} MB")
        lines.append("")
        for idx, post in enumerate(posts[:50], start=1):
            size_mb = post["size"] / 1024 / 1024
            lines.append(
                f"{idx}. {post['title'] or '无标题'} (ID: {post['post_id']})"
                f" | {post['files']} 个文件 | {size_mb:.1f} MB"
            )
        if len(posts) > 50:
            lines.append(f"... 其余 {len(posts) - 50} 篇省略")
        lines.append("")
        lines.append(f"发送单帖: /pixiv_fanbox_dl_view {dir_name} <postId>")
        lines.append(f"打包发送: /pixiv_fanbox_dl_view {dir_name} --pack")
        return "\n".join(lines)

    async def _dl_view_post(self, event: AstrMessageEvent, dir_name: str, post_id: str):
        post_dir = self.dl_manager.find_post_dir(dir_name, post_id)
        if post_dir is None:
            yield event.plain_result(
                f"未找到帖子 {post_id} 的下载目录，先用 /pixiv_fanbox_dl_view {dir_name} 查看列表。"
            )
            return

        content_path = post_dir / "content.md"
        text = ""
        if content_path.exists():
            try:
                text = content_path.read_text(encoding="utf-8")
            except OSError:
                text = ""
        if len(text) > 3000:
            text = text[:3000] + "\n...（正文过长已截断，完整内容见 content.md）"

        files = sorted(f for f in post_dir.iterdir() if f.is_file())
        images = [f for f in files if f.suffix.lower() in self.IMAGE_SUFFIXES]
        attachments = [
            f
            for f in files
            if f.suffix.lower() not in self.IMAGE_SUFFIXES and f.name != "content.md"
        ]

        image_components = []
        for img_path in images[:10]:
            try:
                image_components.append(Comp.Image.fromFileSystem(str(img_path)))
            except Exception as e:
                logger.warning(
                    f"Pixiv 插件：Fanbox 本地图片构建失败 - {img_path} - {e}"
                )

        tail_parts = []
        if len(images) > 10:
            tail_parts.append(f"图片仅发送前 10 张（共 {len(images)} 张）")
        if attachments:
            names = "、".join(f.name for f in attachments[:5])
            more = f" 等 {len(attachments)} 个" if len(attachments) > 5 else ""
            tail_parts.append(f"附件不在消息中发送: {names}{more}，位于 {post_dir}")
        if tail_parts:
            text += "\n\n" + "\n".join(tail_parts)

        if image_components:
            yield event.chain_result(
                [*image_components, Comp.Plain(text or "（无正文）")]
            )
        else:
            yield event.plain_result(text or "该帖子没有可发送的内容。")

    async def _dl_view_pack(self, event: AstrMessageEvent, dir_name: str):
        temp_dir = Path(self.temp_dir or get_plugin_data_dir() / "temp")
        # 打包前清理过期残留，防止 temp_dir 磁盘堆积
        removed = cleanup_stale_packs(temp_dir)
        if removed:
            logger.info(f"Pixiv 插件：清理 {removed} 个过期 Fanbox 打包文件")

        # 发送上限预估：源目录总大小超限直接拒绝，防止误操作打爆队列
        send_limit = (
            getattr(self.pixiv_config, "fanbox_dl_send_limit_mb", 1024) * 1024 * 1024
        )  # 0 表示不拦截
        try:
            # rglob+stat 在大目录上不轻，放线程池避免阻塞事件循环
            total_bytes = await asyncio.to_thread(
                self.dl_manager.creator_size_bytes, dir_name
            )
        except FileNotFoundError as e:
            yield event.plain_result(str(e))
            return
        if send_limit > 0 and total_bytes > send_limit:
            logger.warning(
                f"Pixiv 插件：Fanbox 打包发送被上限拦截 {dir_name}，"
                f"{total_bytes / 1024 / 1024:.1f} MB > {send_limit / 1024 / 1024:.0f} MB"
            )
            yield event.plain_result(
                f"目录总大小 {total_bytes / 1024 / 1024:.1f} MB，超过发送上限"
                f"（{send_limit / 1024 / 1024:.0f}MB，配置项 fanbox_dl_send_limit_mb），"
                f"已取消打包。\n目录路径: {self.dl_manager.creator_dir(dir_name)}"
            )
            return

        pack_limit = (
            getattr(self.pixiv_config, "fanbox_dl_pack_size_mb", 100) * 1024 * 1024
        )
        # packer 为惰性生成器，目录不存在/为空的异常要到首次 next() 才抛出，
        # 由下方逐卷循环捕获
        parts_iter = self.dl_manager.pack_creator(
            dir_name, temp_dir, part_limit=pack_limit
        )

        logger.info(f"Pixiv 插件：Fanbox 打包任务开始 {dir_name}")
        yield event.plain_result(
            f"开始打包 {dir_name}（{total_bytes / 1024 / 1024:.1f} MB），"
            f"按 {pack_limit / 1024 / 1024:.0f}MB 分卷，压好一卷发一卷…"
        )
        sent_parts: list[Path] = []
        part_total = 0
        _EXHAUSTED = object()
        while True:
            try:
                # 压缩是 CPU 密集操作，放工作线程逐卷驱动，不冻结事件循环
                item = await asyncio.to_thread(next, parts_iter, _EXHAUSTED)
            except FileNotFoundError as e:
                # 目录不存在/为空等打包前置异常，保留 packer 的原始提示
                yield event.plain_result(str(e))
                break
            except Exception as e:
                logger.error(f"Pixiv 插件：Fanbox 打包失败 - {e}")
                yield event.plain_result(f"打包失败: {e}")
                break
            if item is _EXHAUSTED:
                break
            zip_path, password, idx, part_total = item
            size_mb = zip_path.stat().st_size / 1024 / 1024
            part_text = f"（第 {idx}/{part_total} 卷）" if part_total > 1 else ""
            if zip_path.stat().st_size > pack_limit:
                logger.warning(
                    f"Pixiv 插件：Fanbox 第 {idx} 卷超单卷上限未发送 {zip_path}"
                )
                yield event.plain_result(
                    f"压缩包{part_text} {size_mb:.1f} MB，超过单卷发送上限"
                    f"（{pack_limit / 1024 / 1024:.0f}MB），未发送。"
                    f"\n文件路径: {zip_path}\n解压密码: {password}"
                )
                continue
            logger.info(
                f"Pixiv 插件：Fanbox 正在发送第 {idx}/{part_total} 卷，{size_mb:.1f} MB"
            )
            yield event.chain_result(
                [
                    Comp.File(name=zip_path.name, file=str(zip_path)),
                    Comp.Plain(
                        f"Fanbox 打包：{dir_name}{part_text}（{size_mb:.1f} MB）"
                        f"\n解压密码: {password}"
                    ),
                ]
            )
            sent_parts.append(zip_path)
        logger.info(
            f"Pixiv 插件：Fanbox 打包任务结束 {dir_name}，"
            f"共 {part_total} 卷，已发送 {len(sent_parts)} 卷"
        )
        if sent_parts:
            # 延迟删除已发送分卷，按卷数缩放避免上传中途被删
            asyncio.create_task(
                self._delete_pack_files_later(
                    sent_parts, delay=300 + 60 * len(sent_parts)
                )
            )

    async def _delete_pack_files_later(parts: list[Path], delay: float = 300):
        """发送后延迟清理分卷文件。"""
        logger.debug(
            f"Pixiv 插件：Fanbox 打包分卷将于 {delay:.0f}s 后清理，共 {len(parts)} 个"
        )
        await asyncio.sleep(delay)
        removed = 0
        for p in parts:
            try:
                p.unlink(missing_ok=True)
                removed += 1
            except OSError as exc:
                logger.warning(f"Pixiv 插件：删除打包分卷失败 {p} - {exc}")
        logger.info(f"Pixiv 插件：Fanbox 清理打包分卷 {removed}/{len(parts)} 个")
