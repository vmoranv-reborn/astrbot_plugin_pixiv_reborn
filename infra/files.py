"""跨平台文件发送适配（基于 AstrBot 公共 File 组件）。"""

from __future__ import annotations

import os
import tempfile
from pathlib import Path

from astrbot.api.event import AstrMessageEvent, MessageChain
from astrbot.api.message_components import File


async def send_bytes_as_file(event: AstrMessageEvent, data: bytes, name: str) -> bool:
    """把内存字节写成临时文件，并通过平台无关的 File 组件发送。"""

    suffix = Path(name).suffix or ".bin"
    fd, path = tempfile.mkstemp(suffix=suffix)
    try:
        with os.fdopen(fd, "wb") as handle:
            handle.write(data)
        await event.send(MessageChain(chain=[File(name=name, file=path)]))
        return True
    finally:
        try:
            os.unlink(path)
        except OSError:
            pass
