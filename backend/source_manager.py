"""source_manager.py —— 播报源管理服务

main.py 的 REST 路由和 agent.py 的工具都从这里取源，不再各写一份。
以前两边各有一份增删逻辑：HTTP 那份只查了 http:// 前缀，没过 SSRF 网关；
agent 那份过了。同一个功能两套安全口径，典型的双实现分叉 —— 这模块就是来
消灭这种分叉的。

对外三个函数：
  list_sources()          内置源 + 用户接入的源
  add_source(name, url)   接入或更新一个源（同名视为更新）
  remove_source(name)     移除一个用户接入的源

失败一律抛 SourceError，由调用方决定怎么表达：HTTP 层转 4xx，agent 层转
{"ok": false, "error": ...}。

注意：check_url 会真解析 DNS，接入源时要求域名当时能解析、解析出的 IP 是公网地址。
要接内网的私有源（比如自建论坛），用环境变量 AI_BAOBAO_ALLOW_PRIVATE=1 单独开口子。
"""
import logging

import config
import crawler
import security

logger = logging.getLogger("ai_bobao.source_manager")

MAX_NAME_LEN = 100       # 源名长度上限


class SourceError(Exception):
    """源管理失败。status 供 HTTP 层选状态码，message 是给用户看的说明。"""

    def __init__(self, message: str, status: int = 400):
        super().__init__(message)
        self.message = message
        self.status = status


def list_sources() -> dict:
    """内置源 + 用户接入的源。内置源标 builtin，只能看不能删。"""
    custom = config.get("sources", "custom") or []
    return {"builtin": [{"name": n, "url": u, "builtin": True}
                        for n, u in crawler.FEEDS],
            "custom": [{**s, "builtin": False} for s in custom]}


def add_source(name: str, url: str, enabled: bool = True) -> dict:
    """接入一个源。同名视为更新地址。

    地址过一遍 SSRF 网关：只放行 http/https，解析出来的 IP 不能是内网或
    云元数据地址。HTTP 接口以前只查了协议前缀，等于给攻击者留了个内网探测器。
    """
    name = security.clean_text(name, MAX_NAME_LEN)
    if not name:
        raise SourceError("源名称不能为空")
    raw = str(url or "").strip()
    if len(raw) > security.MAX_URL_LEN:
        raise SourceError(f"源地址过长（超过 {security.MAX_URL_LEN} 字符）")
    url = security.clean_text(raw, security.MAX_URL_LEN)
    if not url.startswith(("http://", "https://")):
        raise SourceError("源地址必须以 http:// 或 https:// 开头")
    try:
        url = security.check_url(url)
    except security.SecurityError as e:
        raise SourceError(f"源地址被安全网关拦下：{e}") from e

    custom = list(config.get("sources", "custom") or [])
    entry = {"name": name, "url": url, "enabled": bool(enabled)}
    for i, s in enumerate(custom):
        if s.get("name") == name:
            custom[i] = entry
            break
    else:
        custom.append(entry)
    try:
        config.update({"sources": {"custom": custom}})
    except (ValueError, TypeError, OSError) as e:
        raise SourceError(f"写入配置失败：{e}") from e
    logger.info("接入源 %s → %s", name, url)
    return {"ok": True, "sources": custom,
            "message": f"已接入 {name}，下一轮抓取生效"}


def remove_source(name: str) -> dict:
    """移除一个用户接入的源。内置源不在这里，删不掉。"""
    name = security.clean_text(name, MAX_NAME_LEN)
    custom = list(config.get("sources", "custom") or [])
    rest = [s for s in custom if s.get("name") != name]
    if len(rest) == len(custom):
        raise SourceError(f"未找到源：{name}", status=404)
    try:
        config.update({"sources": {"custom": rest}})
    except (ValueError, TypeError, OSError) as e:
        raise SourceError(f"写入配置失败：{e}") from e
    logger.info("移除源 %s", name)
    return {"ok": True, "sources": rest, "message": f"已移除 {name}"}
