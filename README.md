# AstrBot Pixiv 搜索插件

[![Ask DeepWiki](https://deepwiki.com/badge.svg)](https://deepwiki.com/vmoranv-reborn/astrbot_plugin_pixiv_search)
[![文档](https://img.shields.io/badge/AstrBot-%E6%96%87%E6%A1%A3-blue)](https://astrbot.app)
[![aiohttp](https://img.shields.io/pypi/v/aiohttp.svg)](https://pypi.org/project/aiohttp/)

![:@astrbot_plugin_pixiv_search](https://count.getloli.com/get/@astrbot_plugin_pixiv_search?theme=booru-lewd)

这是一个为 [AstrBot](https://astrbot.app) 开发的 Pixiv 搜索插件，让你可以在聊天中轻松搜索和获取 Pixiv 插画作品。

## ✨ 核心特性

- 🎨 **多种搜索方式**: 支持标签搜索、用户搜索、作品详情查询
- 📚 **内容多样化**: 插画、小说、排行榜、推荐作品一应俱全
- 🧩 **Fanbox 支持**: 可查询 Fanbox 创作者、帖子详情与推荐创作者
- 🎬 **动图支持**: 自动识别并转换 Pixiv 动图（ugoira）为GIF格式
- 🔍 **高级搜索**: 深度搜索、与搜索、相关作品推荐
- 🛡️ **内容控制**: 灵活的 R18 内容过滤配置
- ⚙️ **高度可配置**: 返回数量、显示详情、AI 作品过滤、最低书签/阅读量/点赞阈值等
- 🔐 **安全管理**: 通过 WebUI 安全管理 API 凭据

## 🎯 主要功能

所有功能统一收纳在 `/pixiv` 指令组。直接输入 `/pixiv` 可查看 AstrBot 自动生成的指令树。

### 搜索与设置

- `/pixiv search <标签>` - 标签搜索插画
- `/pixiv deep <标签>` - 深度搜索更多相关作品
- `/pixiv and <标签>` - 搜索同时包含所有标签的作品
- `/pixiv hot <标签> [时间范围] [页数]` - 按收藏数排序搜索
- `/pixiv ai <设置>` - 设置是否展示 AI 生成作品
- `/pixiv config [show|help|参数名] [值]` - 查看或修改配置
- `/pixiv help` - 显示完整帮助

### 功能分组

- `/pixiv illust get|new|recommended|ranking|related|comments|showcase|trending`
- `/pixiv user search|detail|works`
- `/pixiv novel search|new|recommended|series|comments|download`
- `/pixiv subscribe add|remove|list`
- `/pixiv random add|del|list|suspend|resume|status|force`
- `/pixiv random ranking-add|ranking-del|ranking-list`
- `/pixiv fanbox creator|post|recommended|artist|download|status|stop|view`

Fanbox 批量下载支持断点续跑、日期与类型过滤、强制重下、进度查询、停止任务、单帖发送和加密分卷打包。完整参数可通过 `/pixiv help` 查看。

### 排除 tag
- `-<tag>` - 排除包含 `<tag>` 的插画（支持多个负面标签）
- 示例：`/pixiv search 露露卡,光之美少女,-ntr,-futa`
- 同样支持随机搜索标签配置：`/pixiv random add 露露卡,光之美少女,-ntr,-futa`

### 从旧版指令迁移

本版本将原有 41 个顶层指令合并为一个 `/pixiv` 指令组。常用映射如下：

| 旧指令 | 新指令 |
|---|---|
| `/pixiv <标签>` | `/pixiv search <标签>` |
| `/pixiv_deepsearch`、`/pixiv_and`、`/pixiv_hot` | `/pixiv deep`、`/pixiv and`、`/pixiv hot` |
| `/pixiv_specific`、`/pixiv_recommended`、`/pixiv_ranking` | `/pixiv illust get`、`/pixiv illust recommended`、`/pixiv illust ranking` |
| `/pixiv_user_*` | `/pixiv user *`（`illusts` 改名为 `works`） |
| `/pixiv_novel_*` | `/pixiv novel *` |
| `/pixiv_subscribe_*` | `/pixiv subscribe *` |
| `/pixiv_random_*` | `/pixiv random *` |
| `/pixiv_random_ranking_*` | `/pixiv random ranking-*` |
| `/pixiv_fanbox_*` | `/pixiv fanbox *` |
| `/pixiv_config`、`/pixiv_ai_show_settings`、`/pixiv_help` | `/pixiv config`、`/pixiv ai`、`/pixiv help` |

Discord 原生指令组需要包含 [AstrBot PR #9445](https://github.com/AstrBotDevs/AstrBot/pull/9445) 的版本；在该核心支持合并前，本插件 PR 保持草稿状态。

## 🚀 快速开始

### 前置条件

- Python >= 3.10
- 已部署的 AstrBot 实例 (v3.x+)
- 有效的 Pixiv 账号和 `refresh_token`

### 配置插件

1. 打开 AstrBot WebUI
2. 进入 `插件管理` -> 找到 Pixiv 搜索插件
3. 点击 `插件配置`，填写以下信息：
   - **Refresh Token**: 必填，用于 Pixiv API 认证
   - **Fanbox Session (可选)**: `FANBOXSESSID`，用于受限 Fanbox 内容
   - **Fanbox 数据源模式**: `auto`（默认，官方优先失败回退 Nekohouse）/`official`（仅官方）/`nekohouse`（仅归档）
   - **R18 过滤模式**: 过滤R18/允许R18/仅R18
   - **额外过滤R18G**: 在允许 R18 时也可单独拦截 R18G
   - **单条合并消息**: 搜索完成后仅发送一条合并转发消息（默认开启）
   - **返回图片数量**: 1-10张，默认1张
   - **AI作品显示**: 是否显示AI生成作品
   - **质量阈值过滤**: 可选设置最小书签数 / 阅读量 / 点赞数
   - **质量过滤**: 可选发送原画|大图|缩略图
   - **其他选项**: 详情显示、文件转发等

4. 保存配置

### 获取 Refresh Token

参考以下资源获取 Pixiv `refresh_token`:
- [pixivpy3 官方文档](https://pypi.org/project/pixivpy3/)
- [Pixiv OAuth 教程](https://gist.github.com/ZipFile/c9ebedb224406f4f11845ab700124362)

### 部署反代服务（中国大陆用户）

若无法使用代理且直连 Pixiv API 失败，可自建 Cloudflare Workers 反向代理：

**仓库地址**: [vmoranv/pixiv-proxy](https://github.com/vmoranv/pixiv-proxy)

**部署步骤**：

1. 登录 [Cloudflare Dashboard](https://dash.cloudflare.com)
2. 进入 **Workers & Pages** → **Create Application** → **Create Worker**
3. 将 [pixiv-proxy.js](https://raw.githubusercontent.com/vmoranv/pixiv-proxy/main/pixiv-proxy.js) 的代码粘贴到编辑器中
4. 点击 **Deploy** 部署
5. 部署完成后复制 Worker 域名（如 `xxx.workers.dev`）
6. 在插件配置中设置：
   - `api_proxy_host` = `xxx.workers.dev`（用于 API 访问）
   - 或 `image_proxy_host` = `xxx.workers.dev`（用于图片下载）

> **提示**: 建议绑定自定义域名以避免 `workers.dev` 域名被墙

## 📝 使用示例

```bash
# 基础搜索
/pixiv search 初音ミク,VOCALOID
/pixiv search 茉莉安,-ntr

# 下载小说
/pixiv novel download 12345678

# 高级搜索  
/pixiv deep 原神,风景
/pixiv and 初音ミク,可爱

# 获取推荐和排行榜
/pixiv illust recommended
/pixiv illust ranking daily

# 获取最新作品
/pixiv illust new
/pixiv novel new

# 小说相关
/pixiv novel recommended
/pixiv novel series 123456

# 评论功能
/pixiv illust comments 12345678
/pixiv novel comments 12345678

# 特殊功能
/pixiv ai true

# 用户相关
/pixiv user search 某个画师名
/pixiv user detail 123456

# 特辑功能
/pixiv illust showcase 123456

# 获取帮助
/pixiv help

# 订阅功能
/pixiv subscribe add 123456
/pixiv subscribe remove 123456
/pixiv subscribe list

# 随机搜索功能
/pixiv random add 风景
/pixiv random list
/pixiv random del 1
/pixiv random suspend
/pixiv random resume
/pixiv random status
/pixiv random force

# 随机排行榜功能
/pixiv random ranking-add day
/pixiv random ranking-add week 2023-05-01
/pixiv random ranking-del 1
/pixiv random ranking-list

# 热度搜索
/pixiv hot 可莉 week 5

# Fanbox 功能
/pixiv fanbox creator harusono 5
/pixiv fanbox post 10451793
/pixiv fanbox recommended 8
/pixiv fanbox artist hannari 10

# Fanbox 批量下载
/pixiv fanbox download harusono --limit 50 --type image
/pixiv fanbox download harusono --since 2026-01-01 --dir harusono_2026
/pixiv fanbox status
/pixiv fanbox stop
/pixiv fanbox view harusono --pack

# 配置管理
/pixiv config show
/pixiv config r18_mode 仅_R18
/pixiv config min_bookmarks 500
/pixiv config min_views 5000
/pixiv config random_search_min_interval 30
```

## ⚙️ 配置选项

| 配置项 | 说明 | 默认值 |
|--------|------|--------|
| `refresh_token` | Pixiv API 认证令牌 | 必填 |
| `fanbox_sessid` | Fanbox 会话 Cookie（FANBOXSESSID，可选） | 留空 |
| `fanbox_cf_clearance` | Fanbox cf_clearance（仅官方 API 被 Cloudflare 拦截时填） | 留空 |
| `fanbox_user_agent` | Fanbox 请求 UA（建议与浏览器一致） | 留空 |
| `fanbox_data_source` | Fanbox 数据源：`auto`/`official`/`nekohouse` | auto |
| `fanbox_api_proxy_host` | Fanbox 批量下载 API 反代域名（被 Cloudflare 拦时用） | 留空 |
| `fanbox_dl_impersonate` | 批量下载 TLS 指纹伪装（如 `edge101`/`chrome131`，被拦时首选） | 留空 |
| `fanbox_dl_*` | 批量下载策略参数：`page_limit`(300) `max_429_retries`(4) `max_cf_consecutive`(3) `max_retries`(5) `concurrency`(4) `prefetch_queue`(4) `pack_size_mb`(100)，非必要不修改 | 括号内为默认值 |
| `return_count` | 每次搜索返回的图片数量 (1-10) | 1 |
| `r18_mode` | R18内容处理模式 | 过滤 R18 |
| `filter_r18g_only` | 是否额外过滤 R18G | false |
| `ai_filter_mode` | AI作品显示设置 | 显示 AI 作品 |
| `ai_detection_mode` | AI判定策略：`field_or_tag`/`field_only`/`tag_only` | field_or_tag |
| `min_bookmarks` | 过滤书签数小于该值的插画，0 表示关闭 | 0 |
| `min_views` | 过滤阅读量小于该值的插画，0 表示关闭 | 0 |
| `min_likes` | 过滤点赞数小于该值的插画，0 表示关闭；若 API 未返回点赞字段则自动忽略 | 0 |
| `deep_search_depth` | 深度搜索时搜索页数深度 (-1无限制, 0-50) | 3 |
| `show_details` | 是否在发送图片时附带详细信息 | true |
| `forward_threshold` | 是否启用消息转发功能 | false |
| `show_filter_result` | 是否显示过滤内容提示 | true |
| `single_response_mode` | 是否仅在搜索完成后发送一条合并消息 | true |
| `image_send_method` | 图片发送方式：`url`/`file`/`byte`（升级旧版本建议设为 `byte` 或 `file`） | url |
| `image_quality` | 默认发送的图片质量 (original/large/medium) | medium |
| `pil_compress_quality` | 本地 PIL 压缩百分比(1-100，仅file/byte生效，100为不压缩) | 100 |
| `pil_compress_target_kb` | 本地 PIL 目标大小KB(>0优先按大小压缩，仅file/byte生效) | 0 |
| `refresh_token_interval_minutes` | 自动刷新 Refresh Token 的间隔时间（分钟） | 180 |
| `subscription_enabled` | 是否启用订阅功能 | true |
| `subscription_force_forward` | 订阅消息是否强制使用合并转发（即便仅一条） | true |
| `subscription_check_interval_minutes` | 订阅更新检查间隔（分钟） | 30 |
| `proxy` | 网络代理地址，如 `http://127.0.0.1:7890` | 留空 |
| `image_proxy_host` | 图片反代服务器地址 | i.pixiv.re |
| `use_image_proxy` | 是否启用图片反代服务器（`url` 发送模式建议开启） | true |
| `random_search_min_interval` | 随机搜索最短间隔（分钟） | 60 |
| `random_search_max_interval` | 随机搜索最长间隔（分钟） | 120 |
| `random_sent_illust_retention_days` | 已发送作品保留天数 | 7 |

## 🔧 故障排除

**SSL 错误**: 如遇到 `SSLError`，请更新 DNS 解析设置。参考: [SSLError 解决方案](https://github.com/upbit/pixivpy/issues/244)

**模块未找到**: 重启 AstrBot 以确保依赖正确安装

**API 认证失败**: 检查 `refresh_token` 是否有效和正确配置

**无代理直连失败**: 若在中国大陆无法使用代理且 ByPassSniApi 模式失效，可自建 Cloudflare Workers 反向代理。详见 [vmoranv/pixiv-proxy](https://github.com/vmoranv/pixiv-proxy) 仓库，部署后在插件配置中设置 `api_proxy_host` 为你的 Worker 域名。

**Fanbox 帖子获取失败**: 可能触发 Cloudflare 或帖子受限。可先用 `/pixiv fanbox creator` 查看公开帖子，必要时配置 `fanbox_sessid`；若官方仍 403，建议同时配置 `fanbox_cookie`（完整 Cookie，含 `cf_clearance`）和 `fanbox_user_agent`（与浏览器一致）；也可切换 `fanbox_data_source=nekohouse` 仅走归档数据。

**Fanbox 批量下载 403（HTML 拦截页）**: 带 Cookie 请求 `post.info` 被 Cloudflare 拦（列表接口不受影响）。可将 `fanbox_dl_impersonate` 设置为与浏览器同族的指纹（Edge 如 `edge101`，Chrome 如 `chrome131`），并保持 `fanbox_user_agent`、Cookie 与浏览器一致。也可以自建以 `api.fanbox.cc` 为上游的 CF Workers 反代，再填写 `fanbox_api_proxy_host`。

**Fanbox 配置缺省提示**: 当 `fanbox_sessid` 未配置且访问受限内容时，会自动返回 `data/helpmsg.json` 的 `pixiv_fanbox_sessid_missing` 提示。

## 📖 更多信息

- [AstrBot 官方文档](https://astrbot.app/)
- [插件开发指南](https://astrbot.app/develop/plugin.html)
- [问题反馈](https://github.com/vmoranv-reborn/astrbot_plugin_pixiv_search/issues)

## ⭐ 项目统计

<div align="center">

[![Star History Chart](https://api.star-history.com/svg?repos=vmoranv-reborn/astrbot_plugin_pixiv_search&type=Date)](https://star-history.com/#vmoranv-reborn/astrbot_plugin_pixiv_search&Date)

![Analytics](https://repobeats.axiom.co/api/embed/9e6727cd94536119069eebccfe45b505ac499470.svg "Repobeats analytics image")

</div>

## 📄 许可证

本项目遵循开源许可证，具体许可证信息请查看项目根目录下的 LICENSE 文件。

---

**注意**: 使用本插件需遵守 Pixiv 服务条款和相关法律法规。请合理使用 API 避免频繁请求。
