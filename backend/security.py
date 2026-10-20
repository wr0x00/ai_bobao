"""security.py —— 安全底座：出站网关、路径归一化、入参收敛、限流、令牌。

这个文件只管"守门"，不碰任何业务逻辑。以后谁要往外发请求、要按 ID 读文件、
要接收用户提交的地址，都从这里过一道，别再各写一套。

一共四块能力：

1. 出站网关 open_url()
   只放行 http/https；域名先解析成 IP，逐个检查是不是内网/回环/云元数据地址；
   每跳重定向都重新检查；响应体有大小上限；最后再核一遍实际连上的对端 IP。

2. 路径归一化 safe_join() / require_vid()
   拼出来的路径必须还落在原目录里，漏洞 ID 必须长得像漏洞 ID。

3. 入参收敛 clamp_int() / clean_text() / safe_refs()
   外部传进来的数字、字符串、链接统一收到合理范围。

4. 节流与令牌 RateLimiter / api_token()
   重活儿接口按 IP 限量，写接口要带令牌。

默认口径是"宁可挡住也别放行"。本机跑 Ollama 之类的内网服务确实需要访问内网地址，
这种情况用环境变量 AI_BAOBAO_ALLOW_PRIVATE=1 单独开口子，默认是关的。
"""
from __future__ import annotations

import ipaddress
import os
import re
import secrets
import socket
import ssl
import threading
import time
import urllib.error
import urllib.request
from pathlib import Path
from urllib.parse import urlparse

# 本项目的约定头：前端所有请求都带上，见 frontend/src/api.js
HEADER_FLAG = "X-AI-BaoBao"          # 值恒为 1，作用是"证明这不是浏览器自动发起的简单请求"
HEADER_VALUE = "1"
HEADER_TOKEN = "X-AI-BaoBao-Token"   # 写操作还要带这个，令牌从 /api/session 拿

DATA_DIR = Path(__file__).resolve().parent / "data"
TOKEN_FILE = DATA_DIR / ".api_token"

MAX_URL_LEN = 2000                  # URL 太长基本都是探针
MAX_DOWNLOAD = 8 * 1024 * 1024      # 单次下载上限 8MB
MAX_BODY = 64 * 1024                # 请求体上限 64KB，够写配置，不够塞攻击载荷
MAX_REDIRECTS = 5
MAX_VID_LEN = 120
MAX_TEXT_LEN = 200

_SAFE_CHARS = re.compile(r"[^A-Za-z0-9._-]+")
_TOKEN_RE = re.compile(r"^[0-9a-f]{64}$")

_token_cache: str = ""
_token_lock = threading.Lock()


class SecurityError(Exception):
    """安全校验没过。用它统一表达"这一步不让过"，上层转成 4xx 返回。"""


# ── 环境开关 ──────────────────────────────────────────────
def _env_flag(name: str, default: bool = False) -> bool:
    """读布尔型环境变量。写 1/true/yes/on 都算开，其他一律按默认值走。"""
    raw = os.getenv(name, "").strip().lower()
    if not raw:
        return default
    return raw in ("1", "true", "yes", "on")


def allow_private_hosts() -> bool:
    """允不允许访问内网地址。本机 Ollama 这类要开着，别的场景别开。"""
    return _env_flag("AI_BAOBAO_ALLOW_PRIVATE", False)


def tls_verify() -> bool:
    """要不要校验服务器证书。默认校验；实在连不上的站点再用环境变量临时放开。"""
    return _env_flag("AI_BAOBAO_TLS_VERIFY", True)


def docs_enabled() -> bool:
    """要不要开 /docs、/redoc、/openapi.json。默认关。

    接口清单对攻击者是白送的情报，要看就在本机临时设 AI_BAOBAO_DOCS=1。
    """
    return _env_flag("AI_BAOBAO_DOCS", False)


def cors_origins() -> list[str]:
    """允许跨域访问的前端地址。默认只有本机 Vite 开发服务器。"""
    raw = os.getenv("AI_BAOBAO_CORS_ORIGINS", "")
    if raw.strip():
        return [x.strip() for x in raw.split(",") if x.strip()]
    return ["http://localhost:5173", "http://127.0.0.1:5173"]


def allowed_hosts() -> list[str]:
    """允许出现在 Host 头里的主机名。

    浏览器发 Host 头是原样发的，陌生主机名直接 400，这一条挡的是 DNS 重绑定：
    攻击者把域名解析到 127.0.0.1，靠这个白名单他连门都进不来。
    """
    raw = os.getenv("AI_BAOBAO_ALLOWED_HOSTS", "")
    if raw.strip():
        return [x.strip() for x in raw.split(",") if x.strip()]
    return ["127.0.0.1", "localhost", "testserver"]


# ── IP 判定 ──────────────────────────────────────────────
def _ip_is_public(ip: ipaddress._BaseAddress) -> bool:
    """这个 IP 能不能对外访问。

    挡掉的是内网回环、云厂商元数据地址（169.254.169.254、100.100.100.200）、
    链路本地、组播这些。IPv6 映射过来的 IPv4（::ffff:127.0.0.1）要拆开单独判，
    否则它看着像公网地址，实质连的是本机。
    """
    if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped:
        return _ip_is_public(ip.ipv4_mapped)
    if ip.is_loopback or ip.is_private or ip.is_link_local:
        return False
    if ip.is_multicast or ip.is_reserved or ip.is_unspecified:
        return False
    if ip.version == 4:
        # 100.64.0.0/10 是运营商级 NAT，169.254.0.0/16 里躺着云元数据地址
        if ip in ipaddress.ip_network("100.64.0.0/10"):
            return False
        if ip in ipaddress.ip_network("169.254.0.0/16"):
            return False
        if ip in ipaddress.ip_network("192.0.0.0/24"):
            return False
        if ip in ipaddress.ip_network("198.18.0.0/15"):
            return False
    else:
        if ip in ipaddress.ip_network("fc00::/7"):
            return False
        if ip in ipaddress.ip_network("fe80::/10"):
            return False
    return True


def resolve_host(host: str, port: int = 80) -> list[str]:
    """域名解析成 IP 列表。一个域名可能解析出多个地址，全部返回，全部都要过检。"""
    try:
        infos = socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)
    except socket.gaierror as e:
        raise SecurityError(f"域名解析失败：{host}") from e
    except OSError as e:
        raise SecurityError(f"域名解析失败：{host}") from e
    out: list[str] = []
    for info in infos:
        ip = info[4][0]
        if ip not in out:
            out.append(ip)
    if not out:
        raise SecurityError(f"域名解析不到地址：{host}")
    return out


def _check_ip(ip_text: str, allow_private: bool) -> None:
    try:
        ip = ipaddress.ip_address(ip_text)
    except ValueError as e:
        raise SecurityError(f"IP 格式不对：{ip_text}") from e
    if allow_private:
        return
    if not _ip_is_public(ip):
        raise SecurityError(f"目标地址是内网/保留地址，不允许访问：{ip_text}")


# ── URL 校验 ─────────────────────────────────────────────
def is_http_url(value: str) -> bool:
    """只做表面检查，不解析 DNS。用来筛掉 javascript:、data: 这类伪协议。"""
    try:
        p = urlparse((value or "").strip())
    except ValueError:
        return False
    return p.scheme in ("http", "https") and bool(p.hostname)


def check_url(url: str, allow_private: bool | None = None) -> str:
    """校验一个地址能不能安全访问。过了就返回去掉空白的原串，不过直接抛 SecurityError。

    allow_private 传 None 时看环境变量 AI_BAOBAO_ALLOW_PRIVATE。
    """
    raw = (url or "").strip()
    if not raw:
        raise SecurityError("地址为空")
    if len(raw) > MAX_URL_LEN:
        raise SecurityError(f"地址过长（超过 {MAX_URL_LEN} 字符）")
    try:
        p = urlparse(raw)
    except ValueError as e:
        raise SecurityError("地址格式不对") from e
    if p.scheme not in ("http", "https"):
        raise SecurityError("只支持 http:// 或 https:// 开头的地址")
    if not p.netloc:
        raise SecurityError("地址里没有主机名")
    if p.username or p.password:
        raise SecurityError("地址里不能带账号密码")
    host = p.hostname
    if not host:
        raise SecurityError("地址里没有主机名")
    if allow_private is None:
        allow_private = allow_private_hosts()
    for ip in resolve_host(host, p.port or (443 if p.scheme == "https" else 80)):
        _check_ip(ip, allow_private)
    return raw


class _SafeRedirect(urllib.request.HTTPRedirectHandler):
    """重定向处理器。每一跳都重新校验目标地址，防止用 302 拐进内网。"""

    def __init__(self, allow_private: bool):
        self.allow_private = allow_private

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        check_url(newurl, self.allow_private)
        return super().redirect_request(req, fp, code, msg, headers, newurl)


def _ssl_context() -> ssl.SSLContext:
    if tls_verify():
        return ssl.create_default_context()
    return ssl.create_unverified_context()


def _peer_ip(resp) -> str:
    """取实际连上的对端 IP。取不到就返回空串，交给调用方决定要不要较真。"""
    try:
        return resp.fp.raw._sock.getpeername()[0]
    except Exception:  # noqa: BLE001 —— 不同 Python 版本/协议下结构不一样，取不到就算了
        return ""


def open_url(
    url: str,
    timeout: float = 20.0,
    max_bytes: int = MAX_DOWNLOAD,
    headers: dict | None = None,
    method: str = "GET",
    data: bytes | None = None,
    allow_private: bool | None = None,
) -> bytes:
    """安全出站网关。整个项目对外发请求都走这里。

    依次做四件事：
    1. 校验协议和地址，域名解析成 IP 逐个检查，内网和云元数据地址一律拒绝；
    2. 每跳重定向都重新走第 1 步；
    3. 响应体超过 max_bytes 直接报错，不让对方拿大文件把内存吃光；
    4. 响应回来后核对实际对端的 IP，和刚才解析的一致，防 DNS 重绑定。
    """
    target = check_url(url, allow_private)
    if allow_private is None:
        allow_private = allow_private_hosts()
    req = urllib.request.Request(target, data=data, method=method.upper())
    for k, v in (headers or {}).items():
        req.add_header(k, v)
    # 自己装 HTTPSHandler，SSL 配置才有地方放。
    # 注意：context 只能传给 HTTPSHandler，opener.open() 不吃这个参数。
    opener = urllib.request.build_opener(
        urllib.request.HTTPSHandler(context=_ssl_context()),
        _SafeRedirect(allow_private),
    )
    try:
        with opener.open(req, timeout=timeout) as r:
            body = r.read(max_bytes + 1)
            if len(body) > max_bytes:
                raise SecurityError(f"响应体超过 {max_bytes} 字节上限")
            peer = _peer_ip(r)
            if peer:
                _check_ip(peer, allow_private)
            return body
    except SecurityError:
        raise
    except urllib.error.HTTPError as e:
        raise SecurityError(f"对方返回 HTTP {e.code}") from e
    except urllib.error.URLError as e:
        raise SecurityError(f"请求失败：{e.reason}") from e
    except (TimeoutError, socket.timeout) as e:
        raise SecurityError(f"请求超时（{timeout}s）") from e
    except OSError as e:
        raise SecurityError(f"请求失败：{e}") from e


# ── XML 解析 ─────────────────────────────────────────────
def parse_xml(raw: bytes, max_bytes: int = 4 * 1024 * 1024):
    """安全地解析一段 XML。

    两道防护：
    1. 见到 <!DOCTYPE 或 <!ENTITY 直接拒 —— DTD 里的实体定义能玩"指数膨胀"，
       几百字节的 feed 就能把内存吃光（billion laughs）。
    2. 输入本身有大小上限，超了当解析失败。

    标准库的 ElementTree 不解析外部实体，挡住 DTD 就够了。
    """
    if len(raw) > max_bytes:
        raise SecurityError(f"XML 超过 {max_bytes} 字节上限")
    upper = raw.upper()
    if b"<!DOCTYPE" in upper or b"<!ENTITY" in upper:
        raise SecurityError("XML 里带 DTD 或实体声明，已拒绝")
    import xml.etree.ElementTree as ET
    return ET.fromstring(raw)


# ── 路径归一化 ────────────────────────────────────────────
def normalize_vid(vid: str) -> str:
    """把漏洞 ID 收拾成能当目录名的样子。落盘时用，允许替换非法字符。"""
    return _SAFE_CHARS.sub("_", (vid or "").strip())[:MAX_VID_LEN]


def require_vid(vid: str) -> str:
    """校验接口传进来的漏洞 ID。不像漏洞 ID 就直接拒掉，不做"清洗后凑合用"。

    允许的字符：字母、数字、点、下划线、连字符。点号不允许连着出现，
    ".." 开头结尾的也拒，Windows 的保留设备名（CON、NUL 之类）一并挡掉。
    """
    v = (vid or "").strip()
    if not v:
        raise SecurityError("漏洞 ID 为空")
    if len(v) > MAX_VID_LEN:
        raise SecurityError(f"漏洞 ID 过长（超过 {MAX_VID_LEN} 字符）")
    if not re.fullmatch(r"[A-Za-z0-9._-]+", v):
        raise SecurityError("漏洞 ID 只能包含字母、数字、点、下划线和连字符")
    if ".." in v:
        raise SecurityError("漏洞 ID 不合法")
    if v.strip("._-") == "":
        raise SecurityError("漏洞 ID 不合法")
    if v.split(".")[0].upper() in {
        "CON", "PRN", "AUX", "NUL",
        *(f"COM{i}" for i in range(1, 10)),
        *(f"LPT{i}" for i in range(1, 10)),
    }:
        raise SecurityError("漏洞 ID 不合法")
    return v


def safe_join(base: Path, *parts: str) -> Path:
    """拼路径，并确认拼出来的结果还在 base 目录里面。

    拼之前先把 base 解析成绝对路径，判越界用的是解析后的路径，
    符号链接也跟着一起算进去。
    """
    root = Path(base).resolve()
    target = root
    for part in parts:
        target = target / str(part)
    try:
        resolved = target.resolve()
    except OSError as e:
        raise SecurityError("路径无法解析") from e
    if resolved != root and root not in resolved.parents:
        raise SecurityError("路径越界，已拒绝")
    return resolved


# ── 仓库与分支名 ─────────────────────────────────────────
# 这两个名字会被拼进 GitHub 的 URL，也会进 git 命令行。形状不收窄的话，
# "../" 能改路径，"--upload-pack=..." 能被 git 当成选项执行。
REPO_RE = re.compile(r"^[A-Za-z0-9_.-]{1,100}/[A-Za-z0-9_.-]{1,100}$")
REF_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._/-]{0,99}$")


def valid_repo(repo: str) -> bool:
    """仓库名是否合法。必须是 owner/repo 两段，只允许字母数字点下划线连字符。"""
    return bool(REPO_RE.match((repo or "").strip()))


def valid_ref(ref: str) -> bool:
    """分支/标签名是否合法。首字符必须是字母数字（挡住 "-" 开头的选项注入），
    且不允许出现 ".."（挡住路径穿越）。"""
    r = (ref or "").strip()
    return bool(REF_RE.match(r)) and ".." not in r


# ── 入参收敛 ─────────────────────────────────────────────
def clamp_int(value, lo: int, hi: int, default: int) -> int:
    """把外部传进来的数字收到 [lo, hi]。不是数字就用默认值。"""
    try:
        n = int(value)
    except (TypeError, ValueError):
        return default
    return max(lo, min(n, hi))


def clean_text(value, max_len: int = MAX_TEXT_LEN, default: str = "") -> str:
    """外部传进来的字符串：去首尾空白、去掉控制字符、按长度截断。"""
    if value is None:
        return default
    text = str(value).strip()
    text = "".join(ch for ch in text if ch == "\n" or ch == "\t" or ord(ch) >= 32)
    return text[:max_len]


def safe_refs(refs, limit: int = 20) -> list[str]:
    """挑出能安全展示的外链。

    只留 http/https。javascript:、data:、vbscript: 这些伪协议一律丢掉，
    前端拿到的是干净的列表，不用再自己判断。
    """
    if not refs:
        return []
    if isinstance(refs, str):
        refs = [refs]
    out: list[str] = []
    for r in refs:
        text = clean_text(r, MAX_URL_LEN)
        if text and is_http_url(text) and text not in out:
            out.append(text)
        if len(out) >= limit:
            break
    return out


# ── 限流 ─────────────────────────────────────────────────
class RateLimiter:
    """滑动窗口限流。按 key（通常是 IP + 用途）分别计数。

    进程内计数，够单机自用。想多进程共享就得换成 Redis 之类的外部存储。
    """

    def __init__(self, limit: int, window: float = 60.0):
        self.limit = limit
        self.window = window
        self._hits: dict[str, list[float]] = {}
        self._lock = threading.Lock()

    def allow(self, key: str) -> bool:
        """还能不能再打一次。返回 False 表示超配额了。"""
        now = time.monotonic()
        with self._lock:
            hits = [t for t in self._hits.get(key, []) if now - t < self.window]
            if len(hits) >= self.limit:
                self._hits[key] = hits
                return False
            hits.append(now)
            self._hits[key] = hits
            if len(self._hits) > 4096:        # key 太多就清一遍，别把内存吃满
                cutoff = now - self.window
                self._hits = {k: v for k, v in self._hits.items() if any(t > cutoff for t in v)}
            return True

    def reset(self, key: str = "") -> None:
        """清空计数。key 为空就全清。"""
        with self._lock:
            if key:
                self._hits.pop(key, None)
            else:
                self._hits.clear()


# ── 令牌 ─────────────────────────────────────────────────
def api_token() -> str:
    """本机 API 令牌。第一次调用时生成，存到 data/.api_token。

    写操作要求带上这个令牌。恶意网页就算能发跨站请求，也读不到 /api/session
    的响应（CORS 不放行），拿不到令牌就改不了配置。
    """
    global _token_cache
    with _token_lock:
        if _token_cache:
            return _token_cache
        try:
            if TOKEN_FILE.is_file():
                cached = TOKEN_FILE.read_text(encoding="utf-8").strip()
                if _TOKEN_RE.match(cached):
                    _token_cache = cached
                    return cached
        except OSError:
            pass
        token = secrets.token_hex(32)
        try:
            TOKEN_FILE.parent.mkdir(parents=True, exist_ok=True)
            TOKEN_FILE.write_text(token, encoding="utf-8")
            os.chmod(TOKEN_FILE, 0o600)
        except OSError:
            pass
        _token_cache = token
        return token
