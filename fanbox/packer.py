"""Fanbox 打包发送：AES 加密 zip + 超限额分卷（防 TX 风控扫描）。

详细设计见 README「Fanbox 批量下载」一节。
"""

import random
import string
import time
from pathlib import Path

import pyzipper

from astrbot.api import logger

MAX_PACK_SIZE_BYTES = 100 * 1024 * 1024  # 单卷发送上限 100MB
PASSWORD_ALPHABET = string.ascii_letters + string.digits


def generate_password(length: int = 10) -> str:
    """生成 10 位字母数字随机密码。"""
    return "".join(random.choices(PASSWORD_ALPHABET, k=length))


def pack_creator_encrypted(
    creator_dir: Path,
    temp_dir: Path,
    dir_name: str,
    part_limit: int = MAX_PACK_SIZE_BYTES,
) -> tuple[list[Path], str]:
    """将 creator 目录打成 AES 加密 zip，按 part_limit 贪心分卷。

    返回 (分卷路径列表, 密码)。单文件超限额的独占一卷（发送方需自行拦截）。
    """
    if not creator_dir.is_dir():
        raise FileNotFoundError(f"目录不存在: {creator_dir}")

    files = sorted(p for p in creator_dir.rglob("*") if p.is_file())
    if not files:
        raise FileNotFoundError(f"目录为空: {creator_dir}")

    # 贪心分组：累加体积不超限额的归一卷
    groups: list[list[Path]] = [[]]
    current_size = 0
    for f in files:
        fsize = f.stat().st_size
        if groups[-1] and current_size + fsize > part_limit:
            groups.append([])
            current_size = 0
        groups[-1].append(f)
        current_size += fsize

    password = generate_password()
    temp_dir.mkdir(parents=True, exist_ok=True)
    stamp = int(time.time())
    parts: list[Path] = []
    total = len(groups)
    for idx, group in enumerate(groups, start=1):
        suffix = f"_part{idx}of{total}" if total > 1 else ""
        zip_path = temp_dir / f"fanbox_pack_{dir_name}_{stamp}{suffix}.zip"
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
        parts.append(zip_path)
        logger.info(
            f"Pixiv 插件：Fanbox 加密打包第 {idx}/{total} 卷，"
            f"{len(group)} 个文件，{zip_path.stat().st_size / 1024 / 1024:.1f} MB"
        )
    return parts, password


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
        except OSError as exc:
            logger.warning(f"Pixiv 插件：清理过期打包文件失败 {f} - {exc}")
    return removed
