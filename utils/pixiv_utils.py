import asyncio
import aiohttp
import aiofiles
import base64
import subprocess
import zipfile
import tempfile
from pathlib import Path
from typing import Any, Optional
from astrbot.api import logger
from astrbot.api.message_components import Image, Plain, Node, Nodes
from pixivpy3 import AppPixivAPI

from .config import PixivConfig
from .tag import filter_illusts_with_reason, FilterConfig
from .config import smart_clean_temp_dir, clean_temp_dir


# 全局变量，需要在模块初始化时设置
_config = None
_temp_dir = None
PIXIV_IMAGE_PROXY = "i.pixiv.re"

def init_pixiv_utils(client: AppPixivAPI, config: PixivConfig, temp_dir: Path):
    """初始化 PixivUtils 模块的全局变量"""
    global _config, _temp_dir
    _config = config
    _temp_dir = temp_dir


def get_proxied_image_url(original_url: str, use_proxy: bool = True) -> str:
    """
    将原始 Pixiv 图片 URL 转换为反代 URL

    Args:
        original_url: 原始的 i.pximg.net URL
        use_proxy: 是否使用图片反代

    Returns:
        转换后的 URL
    """
    if not use_proxy or not original_url:
        return original_url

    if "i.pximg.net" in original_url:
        return original_url.replace("i.pximg.net", PIXIV_IMAGE_PROXY)

    return original_url


def filter_items(items, tag_label, excluded_tags=None):
    """
    统一过滤插画/小说的辅助方法，只需传入待过滤对象和标签描述。
    其他参数自动使用插件全局配置。
    """
    config = FilterConfig(
        r18_mode=_config.r18_mode,
        ai_filter_mode=_config.ai_filter_mode,
        display_tag_str=tag_label,
        return_count=_config.return_count,
        logger=logger,
        show_filter_result=_config.show_filter_result,
        excluded_tags=excluded_tags or []
    )
    
    return filter_illusts_with_reason(items, config)


def generate_safe_filename(title: str, default_name: str = "pixiv") -> str:
    """
    生成安全的文件名，移除特殊字符
    
    Args:
        title: 原始标题
        default_name: 默认名称，当标题为空或无效时使用
    
    Returns:
        安全的文件名
    """
    safe_title = "".join(c for c in title if c.isalnum() or c in (" ", "_", "-")).rstrip()
    return safe_title if safe_title else default_name


def build_ugoira_info_message(illust, metadata, gif_info, detail_message: str = None) -> str:
    """
    构建动图信息消息
    
    Args:
        illust: 插画对象
        metadata: 动图元数据
        gif_info: GIF信息字典
        detail_message: 详细消息，用于提取标签信息
    
    Returns:
        构建好的动图信息消息
    """
    ugoira_info = "🎬 动图作品\n"
    ugoira_info += f"标题: {illust.title}\n"
    ugoira_info += f"作者: {illust.user.name}\n"
    ugoira_info += f"帧数: {len(metadata.frames)}\n"
    ugoira_info += f"GIF大小: {gif_info.get('size', 0) / 1024 / 1024:.2f} MB\n"
    
    # 添加标签信息（如果有detail_message，从中提取标签信息）
    if detail_message:
        # 从detail_message中提取标签信息
        lines = detail_message.split('\n')
        for line in lines:
            if line.startswith('标签:'):
                ugoira_info += f"{line}\n"
                break
    
    ugoira_info += f"作品链接: https://www.pixiv.net/artworks/{illust.id}\n\n"
    
    return ugoira_info


async def download_image(session: aiohttp.ClientSession, url: str, headers: dict = None) -> Optional[bytes]:
    """
    下载图片数据，支持反代和超时控制
    """
    try:
        default_headers = {"Referer": "https://app-api.pixiv.net/"}
        if headers:
            default_headers.update(headers)
        # 如果没有配置代理，使用图片反代 URL
        use_image_proxy = not (_config.proxy if _config else None)
        actual_url = get_proxied_image_url(url, use_proxy=use_image_proxy)

        # 添加超时控制
        timeout = aiohttp.ClientTimeout(total=45, connect=10, sock_read=30)

        async with session.get(
                actual_url,
                headers=default_headers,
                proxy=_config.proxy or None,
                timeout=timeout
        ) as response:
            if response.status == 200:
                return await response.read()
            else:
                logger.warning(f"Pixiv 插件：图片下载失败，状态码: {response.status}, URL: {actual_url}")
                return None

    except asyncio.TimeoutError:
        logger.warning(f"Pixiv 插件：图片下载超时 - {url}")
        return None
    except Exception as e:
        logger.error(f"Pixiv 插件：图片下载异常 - {e}")
        return None


async def process_ugoira_for_content(client: AppPixivAPI, session: aiohttp.ClientSession,
                                   illust, detail_message: str = None) -> Optional[dict]:
    """
    处理动图并返回内容字典，包含GIF数据和信息文本
    
    Args:
        client: Pixiv API客户端
        session: aiohttp会话
        illust: 插画对象
        detail_message: 详细消息
    
    Returns:
        包含gif_data和ugoira_info的字典，失败时返回None
    """
    try:
        # 获取动图元数据
        ugoira_metadata = await asyncio.to_thread(client.ugoira_metadata, illust.id)
        if not ugoira_metadata or not hasattr(ugoira_metadata, 'ugoira_metadata'):
            return None
        
        metadata = ugoira_metadata.ugoira_metadata
        if not hasattr(metadata, 'zip_urls') or not metadata.zip_urls.medium:
            return None
        
        zip_url = metadata.zip_urls.medium
        
        # 下载ZIP文件
        zip_data = await download_image(session, zip_url)
        if not zip_data:
            return None
        
        # 生成安全的文件名
        safe_title = generate_safe_filename(illust.title, "ugoira")
        
        # 尝试转换为GIF
        gif_result = await _convert_ugoira_to_gif(zip_data, metadata, safe_title, illust.id)
        
        if gif_result:
            # GIF转换成功
            gif_data, gif_info = gif_result
            try:
                # 构建GIF信息消息
                ugoira_info = build_ugoira_info_message(illust, metadata, gif_info, detail_message)
                
                # 返回包含GIF数据和信息的字典
                return {
                    'gif_data': gif_data,
                    'ugoira_info': ugoira_info
                }
                
            except Exception as e:
                logger.error(f"Pixiv 插件：处理动图GIF时发生错误 - {e}")
                return None
        else:
            # GIF转换失败
            return None
            
    except Exception as e:
        logger.error(f"Pixiv 插件：处理动图时发生错误 - {e}")
        return None


async def authenticate(client: AppPixivAPI) -> bool:
    """尝试使用配置的凭据进行 Pixiv API 认证"""
    # 每次调用都尝试认证，让 pixivpy3 处理 token 状态
    try:
        if _config.refresh_token:
            # 调用 auth()，pixivpy3 会在需要时刷新 token
            await asyncio.to_thread(client.auth, refresh_token=_config.refresh_token)
            return True
        else:
            logger.error("Pixiv 插件：未提供有效的 Refresh Token，无法进行认证。")
            return False

    except Exception as e:
        logger.error(
            f"Pixiv 插件：认证/刷新时发生错误 - 异常类型: {type(e)}, 错误信息: {e}"
        )
        return False

async def send_pixiv_image(
    client: AppPixivAPI,
    event: Any,
    illust,
    detail_message: str = None,
    show_details: bool = True,
    send_all_pages: bool = False,
):
    """
    通用Pixiv图片下载与发送函数。
    根据`send_all_pages`参数决定是发送多页作品的所有页面还是仅发送第一页。
    自动选择最佳图片链接（original>large>medium），采用本地文件缓存，自动清理缓存目录，发送后删除临时文件。
    """
    # 检查是否为动图
    if hasattr(illust, 'type') and illust.type == 'ugoira':
        logger.info(f"Pixiv 插件：检测到动图作品 - ID: {illust.id}")
        async for result in send_ugoira(client, event, illust, detail_message):
            yield result
        return
    
    await smart_clean_temp_dir(_temp_dir, probability=0.1, max_files=20)

    url_sources = []  # 元组列表: (url_object, detail_message_for_page)

    # 辅助类，用于统一单页插画的URL结构
    class SinglePageUrls:
        def __init__(self, illust):
            self.original = getattr(
                illust.meta_single_page, "original_image_url", None
            )
            self.large = getattr(illust.image_urls, "large", None)
            self.medium = getattr(illust.image_urls, "medium", None)

    if send_all_pages and illust.page_count > 1:
        for i, page in enumerate(illust.meta_pages):
            page_detail = (
                f"第 {i + 1}/{illust.page_count} 页\n{detail_message or ''}"
            )
            # 对于多页作品，page.image_urls 包含 original, large, medium
            url_sources.append((page.image_urls, page_detail))
    else:
        if illust.page_count > 1:
            # 多页作品的第一页
            url_obj = illust.meta_pages[0].image_urls
        else:
            # 单页作品
            url_obj = SinglePageUrls(illust)
        url_sources.append((url_obj, detail_message))

    for url_obj, msg in url_sources:
        quality_preference = ["original", "large", "medium"]
        start_index = (
            quality_preference.index(_config.image_quality)
            if _config.image_quality in quality_preference
            else 0
        )
        qualities_to_try = quality_preference[start_index:]

        image_sent_for_source = False
        for quality in qualities_to_try:
            image_url = getattr(url_obj, quality, None)
            if not image_url:
                continue

            logger.info(f"Pixiv 插件：尝试发送图片，质量: {quality}, URL: {image_url}")
            try:
                async with aiohttp.ClientSession() as session:
                    img_data = await download_image(session, image_url)
                    if img_data:
                        # 直接使用字节数据发送图片，避免文件系统路径问题
                        if show_details and msg:
                            yield event.chain_result(
                                [Image.fromBytes(img_data), Plain(msg)]
                            )
                        else:
                            yield event.chain_result(
                                [Image.fromBytes(img_data)]
                            )

                        image_sent_for_source = True
                        break  # 此源成功，移动到下一个源
                    else:
                        logger.warning(
                            f"Pixiv 插件：图片下载失败 (质量: {quality})。尝试下一质量..."
                        )
            except Exception as e:
                logger.error(
                    f"Pixiv 插件：图片下载异常 (质量: {quality}) - {e}。尝试下一质量..."
                )

        if not image_sent_for_source:
            yield event.plain_result(f"图片下载失败，仅发送信息：\n{msg or ''}")

async def send_ugoira(client: AppPixivAPI, event: Any, illust, detail_message: str = None):
    """
    处理动图（ugoira）的下载和发送，优先转换为GIF格式
    """
    
    # 在处理新的动图之前，先清理可能存在的旧文件
    await smart_clean_temp_dir(_temp_dir, probability=0.1, max_files=20)
    
    try:
        async with aiohttp.ClientSession() as session:
            # 使用通用函数处理动图
            content = await process_ugoira_for_content(client, session, illust, detail_message)
            
            if content:
                # 成功获取到GIF内容
                gif_data = content['gif_data']
                ugoira_info = content['ugoira_info']
                
                # 1. 先尝试使用标准Image组件发送GIF
                logger.info(f"Pixiv 插件：使用标准Image组件发送GIF - ID: {illust.id}")
                
                yield event.chain_result([
                    Image.fromBytes(gif_data),
                    Plain(ugoira_info)
                ])
                
                # 2. 如果是群聊，再尝试上传为群文件
                if _config.is_fromfilesystem and event.get_platform_name() == "aiocqhttp" and event.get_group_id():
                    try:
                        from astrbot.core.platform.sources.aiocqhttp.aiocqhttp_message_event import AiocqhttpMessageEvent
                        if isinstance(event, AiocqhttpMessageEvent):
                            client_bot = event.bot
                            group_id = event.get_group_id()
                            safe_title = generate_safe_filename(illust.title, "ugoira")
                            file_name = f"{safe_title}_{illust.id}.gif"
                            
                            # 使用已有的GIF数据转换为Base64
                            gif_base64 = base64.b64encode(gif_data).decode('utf-8')
                            base64_uri = f"base64://{gif_base64}"
                            
                            logger.info(f"Pixiv 插件：尝试上传GIF到群文件 {file_name} - ID: {illust.id}")
                            await client_bot.upload_group_file(group_id=group_id, file=base64_uri, name=file_name)
                            logger.info(f"Pixiv 插件：成功上传GIF到群文件 - ID: {illust.id}")
                    except Exception as e:
                        logger.error(f"Pixiv 插件：上传群文件失败 - {e}")
                        # 群文件上传失败不影响主流程，不显示错误给用户
                
                logger.info(f"Pixiv 插件：动图GIF发送完成 - ID: {illust.id}")
            else:
                # 处理失败，发送错误信息
                yield event.plain_result("动图处理失败")

    except Exception as e:
        logger.error(f"Pixiv 插件：处理动图时发生错误 - {e}")
        yield event.plain_result(f"处理动图时发生错误: {str(e)}")

async def _convert_ugoira_to_gif(zip_data, metadata, safe_title, illust_id):
    """
    将动图ZIP文件转换为GIF格式
    """
    temp_dir = None
    try:
        # 检查ffmpeg是否可用
        try:
            subprocess.run(['ffmpeg', '-version'], capture_output=True, check=True, timeout=10)
        except (subprocess.CalledProcessError, FileNotFoundError, subprocess.TimeoutExpired):
            logger.warning("Pixiv 插件：ffmpeg不可用，无法转换动图为GIF")
            return None
        
        # 创建临时目录
        temp_dir = tempfile.mkdtemp(prefix=f"pixiv_ugoira_{illust_id}_", dir=_temp_dir)
        
        # 解压ZIP文件
        zip_path = Path(temp_dir) / f"{safe_title}_{illust_id}.zip"
        async with aiofiles.open(zip_path, "wb") as f:
            await f.write(zip_data)
        
        with zipfile.ZipFile(zip_path, 'r') as zip_ref:
            zip_ref.extractall(temp_dir)
        
        # 检查帧数据
        if not hasattr(metadata, 'frames') or not metadata.frames:
            logger.error("Pixiv 插件：动图元数据中缺少帧信息")
            return None
        
        # 创建帧列表文件
        frames_dir = Path(temp_dir)
        frame_files = []
        
        # 先列出解压后的所有文件，找出实际的帧文件
        list(frames_dir.glob("*.jpg")) + list(frames_dir.glob("*.png"))
        
        for i, frame in enumerate(metadata.frames):
            # 尝试多种可能的文件名格式
            possible_names = [
                f"frame_{i:06d}.jpg",
                f"frame_{i:06d}.png",
                f"{i:06d}.jpg",
                f"{i:06d}.png",
                f"frame_{i}.jpg",
                f"frame_{i}.png"
            ]
            
            frame_file = None
            for name in possible_names:
                potential_file = frames_dir / name
                if potential_file.exists():
                    frame_file = potential_file
                    break
            
            if frame_file:
                duration = getattr(frame, 'delay', 100)  # 默认100ms
                frame_files.append(f"file '{frame_file}'\nduration {duration/1000}")
            else:
                logger.warning(f"Pixiv 插件：找不到帧文件 {i} (尝试了: {possible_names})")
        
        if not frame_files:
            logger.error("Pixiv 插件：没有找到有效的帧文件")
            return None
        
        # 创建ffmpeg输入文件
        concat_file = Path(temp_dir) / "frames.txt"
        concat_content = "\n".join(frame_files)
        async with aiofiles.open(concat_file, "w", encoding='utf-8') as f:
            await f.write(concat_content)
        
        # 输出GIF路径
        output_gif = Path(temp_dir) / f"{safe_title}_{illust_id}.gif"
        
        # 使用ffmpeg转换GIF
        cmd = [
            'ffmpeg', '-y',  # 覆盖输出文件
            '-f', 'concat',  # 使用concat demuxer
            '-safe', '0',    # 允许不安全的路径
            '-i', str(concat_file),  # 输入文件列表
            '-vf', 'scale=trunc(iw/2)*2:trunc(ih/2)*2',  # 确保尺寸为偶数
            '-gifflags', '+transdiff',  # 优化GIF
            str(output_gif)  # 输出文件
        ]
        
        # 使用 asyncio.create_subprocess_exec 替代 subprocess.run
        process = await asyncio.create_subprocess_exec(
            *cmd,
            cwd=str(temp_dir),
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE
        )
        
        try:
            stdout, stderr = await asyncio.wait_for(process.communicate(), timeout=60)
        except asyncio.TimeoutError:
            process.kill()
            await process.communicate()
            logger.error("Pixiv 插件：ffmpeg转换超时")
            return None

        if process.returncode != 0:
            logger.error(f"Pixiv 插件：ffmpeg转换失败 - {stderr.decode()}")
            return None
        
        if not output_gif.exists():
            logger.error("Pixiv 插件：GIF文件未生成")
            return None
        
        # 读取GIF文件为字节数据
        try:
            with open(output_gif, 'rb') as f:
                gif_data = f.read()
            
            return gif_data, {
                'frames': len(metadata.frames),
                'size': len(gif_data)
            }
        except Exception as e:
            logger.error(f"Pixiv 插件：读取GIF文件失败 - {e}")
            return None
        
    except subprocess.TimeoutExpired:
        logger.error("Pixiv 插件：ffmpeg转换超时")
        return None
    except Exception as e:
        logger.error(f"Pixiv 插件：转换动图为GIF时发生错误 - {e}")
        return None
    
async def send_forward_message(client: AppPixivAPI, event, images, build_detail_message_func):
    """
    直接下载图片并组装 nodes，避免不兼容消息类型。
    自动检测动图并使用相应的处理方式。
    """
    batch_size = 10
    nickname = "PixivBot"
    # 在处理转发消息之前，先清理可能存在的旧文件
    await clean_temp_dir(_temp_dir, max_files=20)
    for i in range(0, len(images), batch_size):
        batch_imgs = images[i : i + batch_size]
        nodes_list = []
        async with aiohttp.ClientSession() as session:
            for img in batch_imgs:
                # 检查是否为动图
                if hasattr(img, 'type') and img.type == 'ugoira':
                    # 使用通用函数处理动图
                    detail_message = build_detail_message_func(img) if _config.show_details else None
                    content = await process_ugoira_for_content(client, session, img, detail_message)
                    if content:
                        # 成功获取到GIF内容
                        gif_data = content['gif_data']
                        ugoira_info = content['ugoira_info']
                        node_content = [Image.fromBytes(gif_data), Plain(ugoira_info)]
                    else:
                        node_content = [Plain("动图处理失败")]
                else:
                    # 处理普通图片
                    detail_message = build_detail_message_func(img)
                    
                    # 使用与普通消息相同的URL获取逻辑，包括SinglePageUrls处理
                    # 辅助类，用于统一单页插画的URL结构
                    class SinglePageUrls:
                        def __init__(self, illust):
                            self.original = getattr(
                                illust.meta_single_page, "original_image_url", None
                            )
                            self.large = getattr(illust.image_urls, "large", None)
                            self.medium = getattr(illust.image_urls, "medium", None)
                    
                    # 获取URL对象，与普通消息保持一致
                    if img.page_count > 1:
                        # 多页作品的第一页
                        url_obj = img.meta_pages[0].image_urls
                    else:
                        # 单页作品，使用SinglePageUrls获取original质量
                        url_obj = SinglePageUrls(img)
                    
                    # 使用与普通消息相同的质量降级逻辑
                    quality_preference = ["original", "large", "medium"]
                    start_index = (
                        quality_preference.index(_config.image_quality)
                        if _config.image_quality in quality_preference
                        else 0
                    )
                    qualities_to_try = quality_preference[start_index:]
                    
                    headers = {
                        "Referer": "https://www.pixiv.net/",
                        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
                    }
                    node_content = []
                    image_sent = False
                    
                    # 按质量优先级尝试下载图片，与普通消息保持一致
                    for quality in qualities_to_try:
                        image_url = getattr(url_obj, quality, None)
                        if not image_url:
                            continue
                            
                        logger.info(f"Pixiv 插件：转发消息尝试发送图片，质量: {quality}, URL: {image_url}")
                        img_data = await download_image(session, image_url, headers)
                        if img_data:
                            # 直接使用字节数据发送图片，避免文件系统路径问题
                            node_content.append(Image.fromBytes(img_data))
                            image_sent = True
                            break  # 成功下载，跳出质量循环
                        else:
                            logger.warning(f"Pixiv 插件：转发消息图片下载失败 (质量: {quality})。尝试下一质量...")
                    
                    if not image_sent:
                        node_content.append(Plain("图片下载失败，仅发送信息"))
                        
                    if _config.show_details:
                        node_content.append(Plain(detail_message))
                   
                node = Node(name=nickname, content=node_content)
                nodes_list.append(node)
        if nodes_list:
            nodes_obj = Nodes(nodes=nodes_list)
            yield event.chain_result([nodes_obj])