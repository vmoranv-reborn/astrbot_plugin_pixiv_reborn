"""Fanbox 打包发送：AES 加密 zip + 超限额分卷（防 TX 风控扫描）。

打包为生成器逐卷产出，配合 asyncio.to_thread 边压缩边发送，不冻结事件循环。
详细设计见 README「Fanbox 批量下载」一节。
"""

import random
import string
import time
from collections.abc import Iterator
from pathlib import Path

import pyzipper

from astrbot.api import logger

MAX_PACK_SIZE_BYTES = 100 * 1024 * 1024  # 单卷发送上限 100MB
PASSWORD_ALPHABET = string.ascii_letters + string.digits


def generate_password(length: int = 10) -> str:
    """生成 10 位字母数字随机密码。"""
    return "".join(random.choices(PASSWORD_ALPHABET, k=length))


def iter_encrypted_pack_parts(
    creator_dir: Path,
    temp_dir: Path,
    dir_name: str,
    part_limit: int = MAX_PACK_SIZE_BYTES,
) -> Iterator[tuple[Path, str, int, int]]:
    """将 creator 目录打成 AES 加密 zip，按 part_limit 贪心分卷，逐卷产出。

    每压完一卷 yield (分卷路径, 密码, 卷序号, 总卷数)。
    单文件超限额的独占一卷（发送方需自行拦截）。
    """
    if not creator_dir.is_dir():
        raise FileNotFoundError(f"目录不存在: {creator_dir}")

    files = sorted(p for p in creator_dir.rglob("*") if p.is_file())
    if not files:
        raise FileNotFoundError(f"目录为空: {creator_dir}")
    total_size = sum(f.stat().st_size for f in files)
    logger.info(
        f"Pixiv 插件：Fanbox 开始加密打包 {dir_name}，"
        f"共 {len(files)} 个文件 / {total_size / 1024 / 1024:.1f} MB"
    )

    # 贪心分组：累加体积不超限额的归一卷
    groups: list[list[Path]] = [[]]
    current_size = 0
    for f in files:
        fsize = f.stat().st_size
        if groups[-1] and current_size + fsize > part_limit:
            groups.append([])
            current_size = 0
            logger.debug(
                f"Pixiv 插件：Fanbox 打包分卷切分于 {f.name}，"
                f"当前卷 {current_size / 1024 / 1024:.1f} MB"
            )
        groups[-1].append(f)
        current_size += fsize

    password = generate_password()
    temp_dir.mkdir(parents=True, exist_ok=True)
    stamp = int(time.time())
    total = len(groups)
    logger.info(f"Pixiv 插件：Fanbox 打包分为 {total} 卷，密码已生成")
    for idx, group in enumerate(groups, start=1):
        suffix = f"_part{idx}of{total}" if total > 1 else ""
        zip_path = temp_dir / f"fanbox_pack_{dir_name}_{stamp}{suffix}.zip"
        logger.info(f"Pixiv 插件：Fanbox 正在压缩第 {idx}/{total} 卷（{len(group)} 个文件）")
        with pyzipper.AESZipFile(
            zip_path,
            "w",
            compression=pyzipper.ZIP_DEFLATED,
            encryption=pyzipper.WZ_AES,
        ) as zf:
            zf.setpassword(password.encode())
            zf.setencryption(pyzipper.WZ_AES, nbits=256)
            for f in group:
                zf.write(f, f.relative_to(creator_dir))
                logger.debug(f"Pixiv 插件：Fanbox 打包写入 {f.relative_to(creator_dir)}")
        logger.info(
            f"Pixiv 插件：Fanbox 第 {idx}/{total} 卷压缩完成，"
            f"{zip_path.stat().st_size / 1024 / 1024:.1f} MB"
        )
        yield zip_path, password, idx, total


def cleanup_stale_packs(temp_dir: Path, max_age_seconds: float = 3600) -> int:
    """清理 temp_dir 下超过 max_age_seconds 的 fanbox_pack_*.zip，返回删除数。"""
    if not temp_dir.is_dir():
        return 0
    now = time.time()
    removed = 0
    for f in temp_dir.glob("fanbox_pack_*.zip"):
        try:
            if now - f.stat().st_mtime > max_age_seconds:
                f.unlink()
                removed += 1
                logger.debug(f"Pixiv 插件：清理过期打包文件 {f.name}")
        except OSError as exc:
            logger.warning(f"Pixiv 插件：清理过期打包文件失败 {f} - {exc}")
    return removed
