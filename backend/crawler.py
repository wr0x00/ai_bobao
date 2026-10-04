"""crawler.py —— 漏洞文章爬虫模块（替代 NVD：直接爬全网漏洞文章）

流程：RSS 源聚合 → 文章正文抓取 → PoC 代码块提取
- 每个 feed / 每篇文章都有硬性墙钟死线（线程 + join），涓流响应拖不死流水线
- 单源失败只打告警，绝不影响其他源；正文爬不动返回空，绝不抛异常
- PoC 提取规则：页面里 <pre>/<code> 块长度>80 且含代码特征 → 视为现成 PoC
"""
import hashlib
import re
import ssl
import threading
import urllib.request
import xml.etree.ElementTree as ET
from email.utils import parsedate_to_datetime

import config

DEADLINE = 25      # 硬死线（秒）

# 免证书校验：部分站点（seebug 等）证书链在本地验证不过，demo 用途直接跳过校验
_SSL_CTX = ssl._create_unverified_context()

# freebuf 整站有阿里云 WAF JS 挑战，纯 HTTP 爬不动（需无头浏览器），故不列；
# packetstorm 的 feed 返回残缺 XML，也移除；
# 嘶吼（4hou）的 feed 最新一条已停在 2026-05-15，停更四个多月，继续留着
# 只会把一堆积压文章反复捞回来重译，浪费抓取和翻译额度，直接下掉。
FEEDS = [
    ("seebug", "https://paper.seebug.org/rss/"),
    ("先知", "https://xz.aliyun.com/feed"),
    ("exploit-db", "https://www.exploit-db.com/rss.xml"),
]

_TAG = re.compile(r"<[^>]+>")
_SCRIPT = re.compile(r"<(script|style)[^>]*>.*?</\1>", re.S | re.I)
_BLOCK = re.compile(r"<(pre|code)[^>]*>(.*?)</\1>", re.S | re.I)
_POC_HINT = ("import ", "curl ", "requests.", "get /", "post /", "payload",
             "http://", "https://", "popen", "socket", "nuclei", "${jndi", "select ")


def _with_deadline(fn, timeout: float = DEADLINE):
    result: dict = {}

    def worker():
        try:
            result["data"] = fn()
        except Exception as e:  # noqa: BLE001
            result["err"] = repr(e)

    t = threading.Thread(target=worker, daemon=True)
    t.start()
    t.join(timeout)
    if t.is_alive():
        raise TimeoutError(f"超过 {timeout}s 未完成")
    if "err" in result:
        raise RuntimeError(result["err"])
    return result["data"]


def _http_get(url: str, timeout: float = 20) -> bytes:
    req = urllib.request.Request(
        url, headers={"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/130.0.0.0"})
    with urllib.request.urlopen(req, timeout=timeout, context=_SSL_CTX) as r:
        return r.read()


def _mk(source: str, title: str, link: str, desc: str, pub: str) -> dict:
    title = _TAG.sub("", title or "").strip()
    desc = _TAG.sub(" ", desc or "").strip()
    date = ""
    if pub:
        try:
            date = parsedate_to_datetime(pub).date().isoformat()
        except Exception:
            date = pub[:10]
    vid = "art-" + hashlib.md5((link or title).encode()).hexdigest()[:12]
    return {"id": vid, "title": title[:120], "source": source,
            "summary": desc[:500], "refs": [link] if link else [],
            "cvss": None, "published": date, "link": link}


def _parse_feed(raw: bytes, source: str) -> list[dict]:
    root = ET.fromstring(raw)
    out = []
    for it in root.iter("item"):  # RSS 2.0
        out.append(_mk(source, it.findtext("title"), (it.findtext("link") or "").strip(),
                       it.findtext("description"), it.findtext("pubDate") or ""))
    ns = "{http://www.w3.org/2005/Atom}"
    for it in root.iter(f"{ns}entry"):  # Atom
        link = ""
        for l in it.findall(f"{ns}link"):
            link = l.get("href") or link
        out.append(_mk(source, it.findtext(f"{ns}title"), link,
                       it.findtext(f"{ns}summary") or it.findtext(f"{ns}content"),
                       it.findtext(f"{ns}updated") or ""))
    return out


def all_feeds() -> list[tuple[str, str]]:
    """内置源 + 用户在设置页接入的源。

    自定义源存在 config.yaml 的 sources.custom 里，enabled=False 的跳过。
    每次现读配置，接了源不用重启。
    """
    feeds = list(FEEDS)
    for s in (config.get("sources", "custom") or []):
        if s.get("enabled", True) and s.get("url"):
            feeds.append((s["name"], s["url"]))
    return feeds


def fetch_articles() -> list[dict]:
    """聚合所有 feed，按 id 去重。永不抛异常。"""
    limit = config.get("collect", "fetch_limit")
    items = []
    for name, url in all_feeds():
        try:
            got = _with_deadline(lambda u=url: _parse_feed(_http_get(u), name))
            print(f"[crawler] {name} → {len(got)} 篇")
            items.extend(got[:limit])
        except Exception as e:  # noqa: BLE001
            print(f"[crawler] {name} 失败: {e!r}")
    seen, uniq = set(), []
    for it in items:
        if it["id"] not in seen and it["title"]:
            seen.add(it["id"])
            uniq.append(it)
    return uniq


def fetch_article_content(link: str) -> tuple[str, str | None]:
    """抓文章正文 → (纯文本, 现成PoC或None)。爬不动返回 ("", None)。"""
    if not link:
        return "", None
    try:
        raw = _with_deadline(lambda: _http_get(link), timeout=DEADLINE)
    except Exception as e:  # noqa: BLE001
        print(f"[crawler] 正文失败 {link[:60]}: {e!r}")
        return "", None
    html = raw.decode("utf-8", "replace")
    blocks = [_TAG.sub("", m.group(2)) for m in _BLOCK.finditer(html)]
    poc_blocks = [b.strip() for b in blocks
                  if len(b.strip()) > 80 and any(h in b.lower() for h in _POC_HINT)]
    text = re.sub(r"\s+", " ", _TAG.sub(" ", _SCRIPT.sub(" ", html)))[:4000]
    poc = "\n\n".join(poc_blocks[:2]) or None
    return text, poc
