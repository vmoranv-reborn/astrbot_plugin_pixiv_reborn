import peewee as pw
from datetime import datetime, timedelta
from astrbot.api import logger
from astrbot.api.star import StarTools

# 使用 StarTools 获取标准数据目录
data_dir = StarTools.get_data_dir("pixiv_search")
data_dir.mkdir(parents=True, exist_ok=True)

# 数据库文件路径
db_path = data_dir / "subscriptions.db"
db = pw.SqliteDatabase(str(db_path))

class BaseModel(pw.Model):
    class Meta:
        database = db

class Subscription(BaseModel):
    """订阅模型"""
    chat_id = pw.CharField()  # 订阅来源的聊天ID (群号或用户QQ号)
    session_id = pw.TextField()  # 用于发送通知的完整会话ID (JSON字符串)
    sub_type = pw.CharField()  # 订阅类型: 'artist'
    target_id = pw.CharField()  # 订阅目标 ID (画师ID)
    target_name = pw.CharField(null=True) # 订阅目标的名称（画师名）
    last_notified_illust_id = pw.BigIntegerField(default=0)  # 最后通知的作品 ID
    
    class Meta:
        primary_key = pw.CompositeKey('chat_id', 'sub_type', 'target_id')

class RandomSearchTag(BaseModel):
    """随机搜索标签模型"""
    chat_id = pw.CharField() # 群号
    session_id = pw.TextField() # 用于发送消息
    tag = pw.CharField() # 搜索标签
    is_suspended = pw.BooleanField(default=False) # 是否暂停随机搜索

    class Meta:
        primary_key = pw.CompositeKey('chat_id', 'tag')

class SentIllust(BaseModel):
    """已发送的作品记录模型，用于去重"""
    illust_id = pw.BigIntegerField()  # 作品ID
    chat_id = pw.CharField()  # 群聊ID
    sent_at = pw.DateTimeField()  # 发送时间
    
    class Meta:
        primary_key = pw.CompositeKey('illust_id', 'chat_id')

class RandomRankingConfig(BaseModel):
    """随机排行榜配置模型"""
    chat_id = pw.CharField()  # 群号
    session_id = pw.TextField()  # 用于发送消息
    mode = pw.CharField()  # 排行榜模式
    date = pw.CharField(null=True)  # 可选的日期参数
    is_suspended = pw.BooleanField(default=False)  # 是否暂停
    
    class Meta:
        primary_key = pw.CompositeKey('chat_id', 'mode')

class RandomSearchSchedule(BaseModel):
    """随机搜索调度时间模型"""
    chat_id = pw.CharField()  # 群聊ID
    next_execution_time = pw.DateTimeField()  # 下次执行时间
    
    class Meta:
        primary_key = pw.CompositeKey('chat_id')

def initialize_database():
    """初始化数据库，创建表"""
    try:
        db.connect(reuse_if_open=True)
        if not Subscription.table_exists():
            db.create_tables([Subscription])
            logger.info("数据库初始化成功，数据表 subscription 已创建。")
        
        if not RandomSearchTag.table_exists():
            db.create_tables([RandomSearchTag])
            logger.info("数据库初始化成功，数据表 random_search_tag 已创建。")
        else:
            # 检查字段是否完整，如果不完整（比如开发过程中的残留），则重建表
            try:
                columns = [c.name for c in db.get_columns('randomsearchtag')]
                if 'tag' not in columns:
                    logger.warning("检测到 random_search_tag 表结构不完整，正在重建...")
                    db.drop_tables([RandomSearchTag])
                    db.create_tables([RandomSearchTag])
                    logger.info("random_search_tag 表重建完成。")
                elif 'is_suspended' not in columns:
                    # 添加新的 is_suspended 字段
                    logger.info("正在更新 random_search_tag 表结构，添加 is_suspended 字段...")
                    db.execute_sql('ALTER TABLE randomsearchtag ADD COLUMN is_suspended BOOLEAN DEFAULT FALSE')
                    logger.info("random_search_tag 表结构更新完成。")
            except Exception as e:
                 logger.warning(f"检查 random_search_tag 表结构时出错 (可能表名不匹配): {e}")

        if not SentIllust.table_exists():
            db.create_tables([SentIllust])
            logger.info("数据库初始化成功，数据表 sent_illust 已创建。")

        if not RandomSearchSchedule.table_exists():
            db.create_tables([RandomSearchSchedule])
            logger.info("数据库初始化成功，数据表 random_search_schedule 已创建。")

        if not RandomRankingConfig.table_exists():
            db.create_tables([RandomRankingConfig])
            logger.info("数据库初始化成功，数据表 random_ranking_config 已创建。")

        # 兼容旧版，检查并添加 chat_id 列
        if Subscription.table_exists():
            columns = [c.name for c in db.get_columns('subscription')]
            if 'chat_id' not in columns:
                 logger.info("正在更新数据库表结构，添加 chat_id 列...")
                 db.evolve(
                     pw.SQL('ALTER TABLE subscription ADD COLUMN chat_id VARCHAR(255) DEFAULT ""')
                 )
                 logger.info("数据库表结构更新完成。")

    except Exception as e:
        logger.error(f"数据库初始化或迁移失败: {e}")
    finally:
        if not db.is_closed():
            db.close()

def add_subscription(chat_id: str, session_id_json: str, sub_type: str, target_id: str, target_name: str = None, initial_illust_id: int = 0) -> (bool, str):
    """
    添加订阅

    :param chat_id: 订阅来源的聊天ID
    :param session_id_json: 订阅者的会话ID (JSON字符串)
    :param sub_type: 订阅类型 (当前仅支持 'artist')
    :param target_id: 目标 ID
    :param target_name: 目标名称
    :param initial_illust_id: 初始的最后通知作品ID
    :return: (是否成功, 消息)
    """
    try:
        with db.atomic():
            Subscription.create(
                chat_id=chat_id,
                session_id=session_id_json,
                sub_type=sub_type,
                target_id=target_id,
                target_name=target_name or target_id,
                last_notified_illust_id=initial_illust_id
            )
        logger.info(f"聊天 {chat_id} 成功添加对 artist: {target_id} 的订阅，初始作品ID: {initial_illust_id}。")
        return True, f"成功订阅画师: {target_name or target_id}！"
    except pw.IntegrityError:
        logger.warning(f"聊天 {chat_id} 尝试重复订阅 artist: {target_id}。")
        return False, f"您已经订阅过画师: {target_name or target_id}。"
    except Exception as e:
        logger.error(f"添加订阅时发生错误: {e}")
        return False, f"添加订阅时发生未知错误: {e}"

def remove_subscription(chat_id: str, sub_type: str, target_id: str) -> (bool, str):
    """
    移除订阅

    :param chat_id: 订阅来源的聊天ID
    :param sub_type: 订阅类型 (当前仅支持 'artist')
    :param target_id: 目标 ID
    :return: (是否成功, 消息)
    """
    try:
        query = Subscription.delete().where(
            (Subscription.chat_id == chat_id) &
            (Subscription.sub_type == sub_type) &
            (Subscription.target_id == target_id)
        )
        deleted_rows = query.execute()
        if deleted_rows > 0:
            logger.info(f"聊天 {chat_id} 成功移除了对 artist: {target_id} 的订阅。")
            return True, f"成功取消对画师: {target_id} 的订阅。"
        else:
            logger.warning(f"聊天 {chat_id} 尝试移除不存在的订阅 artist: {target_id}。")
            return False, f"您没有订阅画师: {target_id}。"
    except Exception as e:
        logger.error(f"移除订阅时发生错误: {e}")
        return False, f"移除订阅时发生未知错误: {e}"

def list_subscriptions(chat_id: str) -> list:
    """
    列出指定聊天的订阅

    :param chat_id: 订阅来源的聊天ID
    :return: 订阅列表
    """
    try:
        subscriptions = Subscription.select().where(Subscription.chat_id == chat_id)
        return list(subscriptions)
    except Exception as e:
        logger.error(f"列出订阅时发生错误: {e}")
        return []

def get_all_subscriptions() -> list:
    """
    获取所有订阅
    """
    try:
        return list(Subscription.select())
    except Exception as e:
        logger.error(f"获取所有订阅时发生错误: {e}")
        return []

def update_last_notified_id(chat_id: str, sub_type: str, target_id: str, new_id: int):
    """
    更新最后通知的作品ID
    """
    try:
        query = Subscription.update(last_notified_illust_id=new_id).where(
            (Subscription.chat_id == chat_id) &
            (Subscription.sub_type == sub_type) &
            (Subscription.target_id == target_id)
        )
        query.execute()
    except Exception as e:
        logger.error(f"更新 last_notified_illust_id 时出错: {e}")

def add_random_tag(chat_id: str, session_id: str, tag: str) -> (bool, str):
    """添加随机搜索标签"""
    try:
        with db.atomic():
            RandomSearchTag.create(
                chat_id=chat_id,
                session_id=session_id,
                tag=tag
            )
        return True, f"成功添加随机搜索标签: {tag}"
    except pw.IntegrityError:
        return False, f"该标签已存在: {tag}"
    except Exception as e:
        logger.error(f"添加随机标签失败: {e}")
        return False, f"添加失败: {e}"

def remove_random_tag(chat_id: str, tag_index: int) -> (bool, str):
    """删除随机搜索标签 (按索引)"""
    try:
        tags = list(RandomSearchTag.select().where(RandomSearchTag.chat_id == chat_id))
        if 0 <= tag_index < len(tags):
            tag_entry = tags[tag_index]
            tag_name = tag_entry.tag
            tag_entry.delete_instance()
            return True, f"成功删除标签: {tag_name}"
        else:
            return False, "无效的标签序号。"
    except Exception as e:
        logger.error(f"删除随机标签失败: {e}")
        return False, f"删除失败: {e}"

def get_random_tags(chat_id: str) -> list:
    """获取指定群聊的随机标签列表（只返回未暂停的标签）"""
    try:
        return list(RandomSearchTag.select().where(
            (RandomSearchTag.chat_id == chat_id) &
            (RandomSearchTag.is_suspended == False)
        ))
    except Exception as e:
        logger.error(f"获取随机标签失败: {e}")
        return []

def get_all_random_search_groups() -> list:
    """获取所有启用了随机搜索的群聊ID"""
    try:
        # 获取所有有随机搜索标签的群组
        all_groups_query = RandomSearchTag.select(RandomSearchTag.chat_id).distinct()
        all_groups = [row.chat_id for row in all_groups_query]
        
        # 过滤掉完全暂停的群组
        active_groups = []
        for chat_id in all_groups:
            # 检查该群组是否所有标签都被暂停
            tags = list(RandomSearchTag.select().where(RandomSearchTag.chat_id == chat_id))
            if tags:
                # 如果至少有一个标签未暂停，则认为群组是活跃的
                if any(not tag.is_suspended for tag in tags):
                    active_groups.append(chat_id)
        
        return active_groups
    except Exception as e:
        logger.error(f"获取随机搜索群聊列表失败: {e}")
        return []

def suspend_random_search(chat_id: str) -> (bool, str):
    """暂停指定群聊的随机搜索"""
    try:
        query = RandomSearchTag.update(is_suspended=True).where(
            RandomSearchTag.chat_id == chat_id
        )
        updated_rows = query.execute()
        if updated_rows > 0:
            logger.info(f"群聊 {chat_id} 的随机搜索已暂停。")
            return True, f"已暂停当前群聊的随机搜索功能。"
        else:
            return False, "当前群聊没有配置随机搜索标签。"
    except Exception as e:
        logger.error(f"暂停随机搜索失败: {e}")
        return False, f"暂停失败: {e}"

def resume_random_search(chat_id: str) -> (bool, str):
    """恢复指定群聊的随机搜索"""
    try:
        query = RandomSearchTag.update(is_suspended=False).where(
            RandomSearchTag.chat_id == chat_id
        )
        updated_rows = query.execute()
        if updated_rows > 0:
            logger.info(f"群聊 {chat_id} 的随机搜索已恢复。")
            return True, f"已恢复当前群聊的随机搜索功能。"
        else:
            return False, "当前群聊没有配置随机搜索标签。"
    except Exception as e:
        logger.error(f"恢复随机搜索失败: {e}")
        return False, f"恢复失败: {e}"

def get_random_search_status(chat_id: str) -> (bool, bool):
    """
    获取指定群聊的随机搜索状态
    :return: (是否有配置, 是否暂停)
    """
    try:
        tags = list(RandomSearchTag.select().where(RandomSearchTag.chat_id == chat_id))
        if not tags:
            return False, False
        
        # 如果所有标签都被暂停，则认为群组被暂停
        is_suspended = all(tag.is_suspended for tag in tags)
        return True, is_suspended
    except Exception as e:
        logger.error(f"获取随机搜索状态失败: {e}")
        return False, False

def add_sent_illust(illust_id: int, chat_id: str):
    """记录已发送的作品"""
    try:
        with db.atomic():
            SentIllust.create(
                illust_id=illust_id,
                chat_id=chat_id,
                sent_at=datetime.now()
            )
    except pw.IntegrityError:
        # 记录已存在，忽略
        pass
    except Exception as e:
        logger.error(f"添加已发送作品记录失败: {e}")

def is_illust_sent(illust_id: int, chat_id: str) -> bool:
    """检查作品是否已发送过"""
    try:
        return SentIllust.select().where(
            (SentIllust.illust_id == illust_id) &
            (SentIllust.chat_id == chat_id)
        ).exists()
    except Exception as e:
        logger.error(f"检查作品发送状态失败: {e}")
        return False

def cleanup_old_sent_illusts(days: int = 1):
    """清理指定天数前的已发送作品记录"""
    try:
        cutoff_date = datetime.now() - timedelta(days=days)
        query = SentIllust.delete().where(SentIllust.sent_at < cutoff_date)
        deleted_count = query.execute()
        if deleted_count > 0:
            logger.info(f"清理了 {deleted_count} 条超过 {days} 天的已发送作品记录")
    except Exception as e:
        logger.error(f"清理过期已发送作品记录失败: {e}")

def filter_sent_illusts(illusts, chat_id: str) -> list:
    """过滤掉已发送的作品"""
    try:
        # 获取所有已发送的作品ID
        sent_ids = set(
            record.illust_id for record in
            SentIllust.select(SentIllust.illust_id).where(SentIllust.chat_id == chat_id)
        )
        
        # 过滤掉已发送的作品
        filtered_illusts = []
        for illust in illusts:
            if illust.id not in sent_ids:
                filtered_illusts.append(illust)
        
        logger.info(f"群组 {chat_id}: 过滤前 {len(illusts)} 个作品，过滤后 {len(filtered_illusts)} 个作品")
        return filtered_illusts
    except Exception as e:
        logger.error(f"过滤已发送作品失败: {e}")
        return illusts  # 出错时返回原列表

def get_schedule_time(chat_id: str) -> datetime:
    """获取指定群聊的下次执行时间"""
    try:
        schedule = RandomSearchSchedule.get_or_none(RandomSearchSchedule.chat_id == chat_id)
        if schedule:
            return schedule.next_execution_time
        return None
    except Exception as e:
        logger.error(f"获取调度时间失败: {e}")
        return None

def set_schedule_time(chat_id: str, next_time: datetime):
    """设置指定群聊的下次执行时间"""
    try:
        with db.atomic():
            # 先尝试更新现有记录
            updated = RandomSearchSchedule.update(
                next_execution_time=next_time
            ).where(RandomSearchSchedule.chat_id == chat_id).execute()
            
            # 如果没有更新到记录，则插入新记录
            if updated == 0:
                RandomSearchSchedule.create(
                    chat_id=chat_id,
                    next_execution_time=next_time
                )
        logger.debug(f"已设置群组 {chat_id} 的下次执行时间为 {next_time}")
    except Exception as e:
        logger.error(f"设置调度时间失败: {e}")

def remove_schedule_time(chat_id: str):
    """移除指定群聊的调度时间"""
    try:
        query = RandomSearchSchedule.delete().where(RandomSearchSchedule.chat_id == chat_id)
        deleted_count = query.execute()
        if deleted_count > 0:
            logger.debug(f"已移除群组 {chat_id} 的调度时间")
    except Exception as e:
        logger.error(f"移除调度时间失败: {e}")

def get_all_schedule_times() -> dict:
    """获取所有群聊的调度时间"""
    try:
        schedules = RandomSearchSchedule.select()
        return {schedule.chat_id: schedule.next_execution_time for schedule in schedules}
    except Exception as e:
        logger.error(f"获取所有调度时间失败: {e}")
        return {}

# 随机排行榜相关函数
def add_random_ranking(chat_id: str, session_id: str, mode: str, date: str = None) -> (bool, str):
    """添加随机排行榜配置"""
    try:
        with db.atomic():
            RandomRankingConfig.create(
                chat_id=chat_id,
                session_id=session_id,
                mode=mode,
                date=date
            )
        return True, f"成功添加随机排行榜: {mode}" + (f" ({date})" if date else "")
    except pw.IntegrityError:
        return False, f"该排行榜模式已存在: {mode}"
    except Exception as e:
        logger.error(f"添加随机排行榜失败: {e}")
        return False, f"添加失败: {e}"

def remove_random_ranking(chat_id: str, index: int) -> (bool, str):
    """删除随机排行榜配置 (按索引)"""
    try:
        configs = list(RandomRankingConfig.select().where(RandomRankingConfig.chat_id == chat_id))
        if 0 <= index < len(configs):
            config = configs[index]
            mode = config.mode
            config.delete_instance()
            return True, f"成功删除排行榜: {mode}"
        else:
            return False, "无效的序号。"
    except Exception as e:
        logger.error(f"删除随机排行榜失败: {e}")
        return False, f"删除失败: {e}"

def get_random_rankings(chat_id: str) -> list:
    """获取指定群聊的随机排行榜配置列表（只返回未暂停的）"""
    try:
        return list(RandomRankingConfig.select().where(
            (RandomRankingConfig.chat_id == chat_id) &
            (RandomRankingConfig.is_suspended == False)
        ))
    except Exception as e:
        logger.error(f"获取随机排行榜配置失败: {e}")
        return []

def get_all_random_ranking_groups() -> list:
    """获取所有启用了随机排行榜的群聊ID"""
    try:
        all_groups_query = RandomRankingConfig.select(RandomRankingConfig.chat_id).distinct()
        all_groups = [row.chat_id for row in all_groups_query]
        
        active_groups = []
        for chat_id in all_groups:
            configs = list(RandomRankingConfig.select().where(RandomRankingConfig.chat_id == chat_id))
            if configs and any(not c.is_suspended for c in configs):
                active_groups.append(chat_id)
        
        return active_groups
    except Exception as e:
        logger.error(f"获取随机排行榜群聊列表失败: {e}")
        return []

def list_random_rankings(chat_id: str) -> list:
    """列出指定群聊的所有随机排行榜配置"""
    try:
        return list(RandomRankingConfig.select().where(RandomRankingConfig.chat_id == chat_id))
    except Exception as e:
        logger.error(f"列出随机排行榜配置失败: {e}")
        return []