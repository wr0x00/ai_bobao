"""source_discovery.py —— 接入新漏洞社区：探测 feed 地址 + AI 判断能不能用。

用户在设置页填一个社区首页（https://xz.aliyun.com 这种），这里分两步：

1. 探测：按常见路径逐个试 `/feed`、`/rss`、`/rss.xml`…… 能解析出条目的就是 feed。
   实测这条路够用——先知、seebug 都是这么挂着的，首页本身往往拿不到 feed 地址。
2. 判活：拿到 feed 之后交给 LLM 看一眼最新几条，凭内容判断这是不是漏洞技术社区、
   是不是 AI 灌水聚合站。这层判断是必要的，纯规则只能证明"是 XML"，
   证明不了"是漏洞文章"。

探测不写配置，确认后才落 sources 节，所以猜错了也不会污染既有源。

平台型 API（OSV / GitHub Advisory 这类 JSON 接口）暂未实现，
扩展点见文件末尾 _API_ADAPTERS。

出站安全：首页地址是用户填的，属于不可信输入。探测前先过 security.check_url，
把内网地址、回环地址、云元数据地址挡在门外；实际请求再由安全网关兜一层。
"""
import logging
import re

import llm
import security

logger = logging.getLogger("ai_bobao.source_discovery")

# 按命中率的常见 feed 路径。带 .xml 的放前面：同一站点常有多个别名，
# 猜错也只是多试一次，顺序无所谓，但先试更规范的名字。
_SUFFIXES = ("/feed", "/rss", "/rss.xml", "/atom.xml", "/feed.xml",
             "/index.xml", "/feeds/posts/default", "/rss/index.xml")

_ATOM = "{http://www.w3.org/2005/Atom}"


def _get(url: str, timeout: float = 12) -> bytes:
    import crawler
    return crawler._http_get(url, timeout=timeout)


def _count_entries(raw: bytes) -> tuple[int, list[str]]:
    """能解析成 feed 就返回 (条目数, 前几条标题)，不是 feed 返回 (0, [])。"""
    try:
        root = security.parse_xml(raw)
    except Exception:  # noqa: BLE001 —— 不是 XML、DTD 实体、格式错，都当"不是 feed"
        return 0, []
    items = list(root.iter("item")) + list(root.iter(f"{_ATOM}entry"))
    titles = []
    for it in items[:8]:
        t = it.findtext("title") or it.findtext(f"{_ATOM}title") or ""
        titles.append(re.sub(r"\s+", " ", t).strip()[:80])
    return len(items), titles


def _normalize(url: str) -> str:
    """用户可能只填了域名，补上 https:// 再往下走。"""
    base = url.strip().rstrip("/")
    if not base.startswith(("http://", "https://")):
        base = "https://" + base
    return base


def _candidates(url: str) -> list[str]:
    """待探测的 URL 列表：用户给的可能就是 feed，也可能只是首页。"""
    base = _normalize(url)
    return [base] + [base + s for s in _SUFFIXES]


def probe(url: str) -> list[dict]:
    """挨个试候选 URL，返回所有能解析出条目的地址。

    探测前先把用户给的地址校验一遍：只允许 http/https，域名解析出来的
    IP 不能是内网/回环/云元数据地址。挡不住的地址直接抛 SecurityError，
    上层转成 400 返回给前端。
    """
    security.check_url(_normalize(url))
    found = []
    for cand in _candidates(url):
        try:
            n, titles = _count_entries(_get(cand))
        except Exception:      # noqa: BLE001 —— 404/超时/非 XML 都很常见
            continue
        if n:
            found.append({"url": cand, "entries": n, "titles": titles})
    return found


_VERDICT_SYS = (
    "你是漏洞情报甄别助手。用户给一个网站 RSS/Atom 源解析出的最新文章标题，"
    "你要判断这个站点是不是「漏洞技术社区」——即内容以漏洞分析、漏洞复现、"
    "安全研究、攻防技术为主。只返回 JSON，不要解释。"
)
_VERDICT_KEYS = """返回这个 JSON：
{"is_vuln_source": true/false,
 "reason": "一句话理由",
 "suggested_name": "给这个源起个简短中文名，如「先知」「Seebug」"}"""


def judge(url: str, titles: list[str]) -> dict:
    """让 LLM 判断这个 feed 是不是漏洞社区。

    LLM 不可用时按「标题里有没有漏洞关键词」兜底，宁可放过也不误杀：
    判错成 false 会挡住用户接一个正常社区，代价不对称。
    """
    if not titles:
        return {"is_vuln_source": False, "reason": "未取到任何条目标题",
                "suggested_name": "", "by_llm": False}
    joined = "\n".join(f"- {t}" for t in titles)
    try:
        r = llm.get_llm().chat(_VERDICT_SYS, f"网站：{url}\n\n最新文章：\n{joined}\n\n{_VERDICT_KEYS}")
        return {"is_vuln_source": bool(r.get("is_vuln_source")),
                "reason": str(r.get("reason", ""))[:200],
                "suggested_name": str(r.get("suggested_name", ""))[:30],
                "by_llm": True}
    except Exception as e:      # noqa: BLE001
        hint = ("漏洞", "CVE", "漏洞利用", "复现", "0day", "RCE", "任意文件", "权限提升",
                "vulnerability", "exploit", "injection")
        hit = [h for h in hint if any(h.lower() in t.lower() for t in titles)]
        return {"is_vuln_source": bool(hit),
                "reason": f"LLM 不可用，按标题关键词判断：命中 {hit or '无'}",
                "suggested_name": "", "by_llm": False}


def discover(url: str, llm_judge: bool = True) -> dict:
    """一步到位：探测 + 判活。返回给设置页预览，不落配置。

    feed 一个都探不到时不急着宣判：用户给的页面本身可能就是能爬的
    HTML 列表页（补天这种没 feed 但列表是服务端渲染的站），按 HTML
    适配解析出标题，照样交给 AI 判活。
    """
    found = probe(url)
    if not found:
        base = _normalize(url)
        try:
            import crawler
            items = crawler._parse_html_list(_get(base), base, "probe")
        except Exception:  # noqa: BLE001 —— 拉不下页面/解析不出，走原失败话术
            items = []
        titles = [it["title"] for it in items[:8]]
        if not titles:
            return {"ok": False,
                    "message": "常见路径都没找到 feed，页面也解析不出文章链接；"
                               "该站可能是交互无法爬取的类型，可先在浏览器里"
                               "找它的 RSS 地址再填进来",
                    "tried": list(_SUFFIXES), "candidates": []}
        cand = {"url": base, "entries": len(items), "titles": titles, "kind": "html"}
        cand["verdict"] = judge(base, titles) if llm_judge else {
            "is_vuln_source": True, "reason": "未启用 AI 判活", "suggested_name": "",
            "by_llm": False}
        return {"ok": True, "candidates": [cand], "best": base,
                "message": "没找到 feed；已按 HTML 列表页解析（每轮直接抓页面）"}
    # 条目最多的那个最可能是主源，其余留给用户挑
    found.sort(key=lambda f: -f["entries"])
    for f in found:
        f["verdict"] = judge(f["url"], f["titles"]) if llm_judge else {
            "is_vuln_source": True, "reason": "未启用 AI 判活", "suggested_name": "",
            "by_llm": False}
    return {"ok": True, "candidates": found,
            "best": found[0]["url"], "message": f"找到 {len(found)} 个 feed"}


# ── 平台型 API 扩展点（暂未实现）────────────────────────────
#
# 目前只支持 RSS/Atom。要接 OSV / GitHub Advisory / NVD 这类 JSON 接口，
# 在这里加一个适配器即可，不必改 crawler：
#
#   def _fetch_osv(url, limit):
#       """返回 [{title, link, summary, published}, ...]，字段名与
#       crawler._mk 的入参对齐。key 若需鉴权，从 config.get("sources","api_key") 取。"""
#       ...
#
# 然后登记进 _API_ADAPTERS，discover() 会先试它给出的地址。
_API_ADAPTERS: dict[str, object] = {}
