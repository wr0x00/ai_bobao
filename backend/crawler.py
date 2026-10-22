"""crawler.py —— 漏洞文章爬虫模块（替代 NVD：直接爬全网漏洞文章）

流程：RSS 源聚合 → 文章正文抓取 → PoC 代码块提取
- 每个 feed / 每篇文章都有硬性墙钟死线（线程 + join），涓流响应拖不死流水线
- 单源失败只打告警，绝不影响其他源；正文爬不动返回空，绝不抛异常
- PoC 提取规则：页面里 <pre>/<code> 块长度>80 且含代码特征 → 视为现成 PoC

出站安全：所有对外请求统一走 security.open_url。它负责拦内网地址、
逐跳校验重定向、限制响应体大小、校验服务器证书（默认开）。
文章正文地址来自 feed 内容，同样是不可信输入，一并由它挡。
"""
import hashlib
import logging
import re
import threading
from email.utils import parsedate_to_datetime
from urllib.parse import urljoin, urlparse

import config
import security

logger = logging.getLogger("ai_bobao.crawler")

DEADLINE = 25      # 硬死线（秒）
MAX_FEED = 4 * 1024 * 1024     # feed 响应上限 4MB
MAX_ARTICLE = 8 * 1024 * 1024  # 文章正文响应上限 8MB

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

# ── HTML 列表页适配 ────────────────────────────────────────
# 不是所有社区都提供 RSS（补天这种全站 JS 交互但列表页服务端渲染的不少见）。
# feed 探不到时把页面当通用列表页解析：<a> 里文字像文章标题的就收。
_ANCHOR = re.compile(r'<a\b[^>]*href=["\']([^"\']+)["\'][^>]*>(.*?)</a>', re.S | re.I)
_EXCERPT = re.compile(r"<p\b[^>]*>(.*?)</p>", re.S | re.I)
_DATE = re.compile(r"(\d{4}-\d{1,2}-\d{1,2})")
# 明显不是文章的链接形状：导航、账号、资源文件
_SKIP_PATH = re.compile(
    r"/(login|register|signin|signup|logout|about|contact|help|search|tag|tags|"
    r"category|user|users|people|member|topic-index|feed|rss|atom|api/|static/|"
    r"assets/|js/|css/|download|comment|setting)", re.I)


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


def _http_get(url: str, timeout: float = 20, max_bytes: int = MAX_FEED) -> bytes:
    """取一个 URL 的内容。走安全网关，内网地址、证书问题、超大响应都会被挡下。"""
    return security.open_url(
        url,
        timeout=timeout,
        max_bytes=max_bytes,
        headers={"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/130.0.0.0",
                 "Accept": "*/*"},
    )


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
    root = security.parse_xml(raw, MAX_FEED)
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


def _parse_html_list(raw: bytes, base: str, source: str) -> list[dict]:
    """通用 HTML 列表页解析：把页面里的文章链接挖出来。

    规则刻意放得宽松：标题文字 ≥8 字的站内链接都算候选，再靠
    _SKIP_PATH 挡导航/账号页、按 URL 去重、按出现顺序（通常最新在前）。
    摘要与日期是"顺手捡"：链接后面紧跟的 <p> 若不含链接就当摘要，
    正文里形如 2026-10-12 的日期取第一段。解析出的正经入库判定仍交给
    内容判层管，这里只管"这一页有哪些像文章的东西"。
    """
    out, seen = [], set()
    page = raw.decode("utf-8", "replace")
    for m in _ANCHOR.finditer(page):
        # 标题去掉括号补充（「首页 (current)」「UNITY(4)」这类）再判长度，
        # 排掉导航上肉眼是链接却不带信息的项
        href = m.group(1).strip()
        title = _TAG.sub("", m.group(2)).strip()
        bare = re.sub(r"[（(][^）)]*[）)]", "", title).strip()
        if len(bare) < 8 or len(title) > 160:
            continue
        if href.startswith(("#", "javascript:", "mailto:")):
            continue
        url = urljoin(base, href.split("#")[0])
        try:
            u = urlparse(url)
        except ValueError:
            continue
        if u.scheme not in ("http", "https") or _SKIP_PATH.search(u.path):
            continue
        if url.rstrip("#/ ").rstrip("/") == base.rstrip("/"):
            continue
        if url in seen:
            continue
        seen.add(url)
        # 顺手捡摘要（紧邻的 <p>）和日期（ Own 块一般在 1600 字符内），捡不到就留着空
        tail = page[m.end(): m.end() + 1600]
        pm = _EXCERPT.search(tail)
        desc = _TAG.sub(" ", pm.group(1)).strip() if (pm and "<a" not in pm.group(1)) else ""
        dm = _DATE.search(tail)
        out.append(_mk(source, title[:120], url, desc[:500], dm.group(1) if dm else ""))
        if len(out) >= 60:
            break
    return out


def fetch_articles() -> list[dict]:
    """聚合所有 feed，按 id 去重。永不抛异常。

    每个源先按 RSS/Atom 解析；解析不出条目（HTML 页面、纯交互站的不同
    URL 形状）就退到 HTML 列表页适配。两种走的是同一条入库流水线。
    """
    limit = config.get("collect", "fetch_limit")
    items = []
    for name, url in all_feeds():
        try:
            raw = _with_deadline(lambda u=url: _http_get(u))

            def _extract(r=raw, n=name, u=url):
                try:
                    return _parse_feed(r, n)
                except Exception:  # noqa: BLE001 —— 不是 XML 就当 HTML 列表
                    return _parse_html_list(r, u, n)

            got = _with_deadline(_extract)
            logger.info("%s → %d 篇", name, len(got))
            items.extend(got[:limit])
        except Exception as e:  # noqa: BLE001
            logger.warning("%s 抓取失败：%r", name, e)
    seen, uniq = set(), []
    for it in items:
        if it["id"] not in seen and it["title"]:
            seen.add(it["id"])
            uniq.append(it)
    return uniq


def fetch_article_content(link: str) -> tuple[str, str | None]:
    """抓文章正文 → (纯文本, 现成PoC或None)。爬不动返回 ("", None)。

    link 来自 feed 内容，站点作者写什么我们就得去什么，所以它是不可信输入。
    交给安全网关去挡：内网地址、带账号密码的地址、超大响应都拿不到。
    """
    if not link:
        return "", None
    try:
        raw = _with_deadline(lambda: _http_get(link, max_bytes=MAX_ARTICLE), timeout=DEADLINE)
    except Exception as e:  # noqa: BLE001
        logger.warning("正文抓取失败 %s：%r", link[:60], e)
        return "", None
    html = raw.decode("utf-8", "replace")
    blocks = [_TAG.sub("", m.group(2)) for m in _BLOCK.finditer(html)]
    poc_blocks = [b.strip() for b in blocks
                  if len(b.strip()) > 80 and any(h in b.lower() for h in _POC_HINT)]
    text = re.sub(r"\s+", " ", _TAG.sub(" ", _SCRIPT.sub(" ", html)))[:4000]
    poc = "\n\n".join(poc_blocks[:2]) or None
    return text, poc
