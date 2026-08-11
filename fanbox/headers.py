"""Fanbox 相关 HTTP 头统一构建（client 与 handlers 复用）。"""

ACCEPT_LANGUAGE = "ja,en-US;q=0.9,en;q=0.8,zh-CN;q=0.7"
FANBOX_WWW_ORIGIN = "https://www.fanbox.cc"


def build_api_headers(
    ua: str, referer: str, cookie: str | None = None
) -> dict[str, str]:
    """官方 API JSON 请求头（浏览器 XHR 形态）。"""
    headers = {
        "Accept": "application/json, text/plain, */*",
        "Accept-Language": ACCEPT_LANGUAGE,
        "Origin": FANBOX_WWW_ORIGIN,
        "Referer": referer,
        "Sec-Fetch-Dest": "empty",
        "Sec-Fetch-Mode": "cors",
        "Sec-Fetch-Site": "same-site",
        "User-Agent": ua,
    }
    if cookie:
        headers["Cookie"] = cookie
    return headers


def build_html_headers(
    ua: str, referer: str | None = None, cookie: str | None = None
) -> dict[str, str]:
    """页面 HTML 请求头（浏览器导航形态）。"""
    headers = {
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        "Accept-Language": ACCEPT_LANGUAGE,
        "User-Agent": ua,
    }
    if referer:
        headers["Referer"] = referer
    if cookie:
        headers["Cookie"] = cookie
    return headers
