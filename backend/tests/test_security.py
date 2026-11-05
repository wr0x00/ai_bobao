"""test_security.py —— 安全底座的回归测试

security.py 是整个项目的守门人：出站网关、路径归一化、入参收敛、限流、令牌。
这些逻辑一旦被改坏，后果是 SSRF、路径穿越、任意文件读，所以逐条钉住行为。
"""
import pytest

import security


# ── IP 判定 ──────────────────────────────────────────────
@pytest.mark.parametrize("ip", [
    "127.0.0.1", "10.0.0.5", "192.168.1.1", "172.16.0.1",       # 内网
    "169.254.169.254",                                        # 云元数据
    "100.100.100.200",                                        # 阿里云元数据
    "100.64.0.1",                                             # 运营商级 NAT
    "192.0.0.1", "198.18.0.1",                                # 保留段
    "0.0.0.0", "255.255.255.255",                             # 未指定/广播
    "::1", "::ffff:127.0.0.1",                                # IPv6 回环与映射
    "fc00::1", "fe80::1",                                     # IPv6 私有与链路本地
])
def test_private_ip_is_blocked(ip):
    """内网、回环、云元数据、保留段一律不能对外访问。"""
    import ipaddress

    assert security._ip_is_public(ipaddress.ip_address(ip)) is False


@pytest.mark.parametrize("ip", ["8.8.8.8", "1.1.1.1", "2001:4860:4860::8888"])
def test_public_ip_is_allowed(ip):
    """公网地址放行，不然程序什么都访问不了。"""
    import ipaddress

    assert security._ip_is_public(ipaddress.ip_address(ip)) is True


# ── URL 校验 ─────────────────────────────────────────────
@pytest.mark.parametrize("url", [
    "",                                  # 空
    "   ",                               # 纯空白
    "javascript:alert(1)",               # 伪协议
    "file:///etc/passwd",                # 本地文件
    "ftp://example.com/x",              # 不支持的协议
    "http://",                          # 没有主机名
    "http://user:pw@example.com/",      # 地址里带账号密码
    "http://" + "a" * 3000 + ".com/",    # 超长
])
def test_check_url_rejects_bad_input(url):
    """协议不对、没主机、带凭据、太长，全部直接拒。"""
    with pytest.raises(security.SecurityError):
        security.check_url(url)


def test_check_url_accepts_public_host(no_dns):
    """公网地址通过，返回去掉首尾空白的原串。"""
    assert security.check_url("  https://example.com/feed  ") == "https://example.com/feed"


def test_check_url_blocks_private_host(monkeypatch):
    """解析到内网地址的直接拒 —— 这是 SSRF 的主防线。"""
    import security as sec

    monkeypatch.setattr(sec, "resolve_host", lambda host, port=80: ["127.0.0.1"])
    with pytest.raises(sec.SecurityError):
        sec.check_url("http://evil.example.com/")


def test_check_url_allows_private_when_flag_set(monkeypatch):
    """allow_private=True 时内网放行（本机 Ollama 场景）。"""
    import security as sec

    monkeypatch.setattr(sec, "resolve_host", lambda host, port=80: ["127.0.0.1"])
    assert sec.check_url("http://127.0.0.1:11434/", allow_private=True)


def test_is_http_url():
    """只做表面检查，不解析 DNS。"""
    assert security.is_http_url("https://example.com/") is True
    assert security.is_http_url("http://example.com") is True
    assert security.is_http_url("javascript:alert(1)") is False
    assert security.is_http_url("data:text/html,x") is False
    assert security.is_http_url("") is False


# ── XML 解析 ─────────────────────────────────────────────
def test_parse_xml_blocks_dtd():
    """带 DOCTYPE 的直接拒 —— DTD 实体能做指数膨胀（billion laughs）。"""
    payload = b'<?xml version="1.0"?><!DOCTYPE r [<!ENTITY a "aa">]><r>&a;</r>'
    with pytest.raises(security.SecurityError):
        security.parse_xml(payload)


def test_parse_xml_blocks_entity():
    payload = b'<?xml version="1.0"?><!ENTITY xxe SYSTEM "file:///etc/passwd"><r>&xxe;</r>'
    with pytest.raises(security.SecurityError):
        security.parse_xml(payload)


def test_parse_xml_blocks_oversize():
    with pytest.raises(security.SecurityError):
        security.parse_xml(b"<r>x</r>", max_bytes=4)


def test_parse_xml_accepts_normal():
    root = security.parse_xml(b"<rss><channel><title>ok</title></channel></rss>")
    assert root.find("channel/title").text == "ok"


# ── 路径归一化 ────────────────────────────────────────────
@pytest.mark.parametrize("vid", [
    "",                 # 空
    "..",               # 上跳
    "a..b",             # 中间带 ..
    "a/b",              # 路径分隔符
    "a\\b",             # Windows 分隔符
    "a b",              # 空格
    "a;b",              # 命令分隔符
    "CON",              # Windows 保留设备名
    "nul.txt",          # 保留设备名带扩展名
    "COM1",             # 串口设备
    "LPT9",             # 并口设备
    "x" * 200,          # 超长
])
def test_require_vid_rejects_bad(vid):
    """不像漏洞 ID 的一律拒，不做"清洗后凑合用"。"""
    with pytest.raises(security.SecurityError):
        security.require_vid(vid)


@pytest.mark.parametrize("vid", ["CVE-2024-12345", "vuln_1", "a.b-c_d", "1"])
def test_require_vid_accepts_good(vid):
    assert security.require_vid(vid) == vid


def test_normalize_vid_sanitizes():
    """归一化是给落盘用的：非法字符换下划线，超长截断。"""
    assert security.normalize_vid("  CVE/2024  ") == "CVE_2024"
    assert security.normalize_vid("a" * 300) == "a" * security.MAX_VID_LEN
    assert security.normalize_vid("../etc/passwd") == ".._etc_passwd"


def test_safe_join_blocks_escape(tmp_path):
    """拼出来的路径必须还在基目录里。"""
    with pytest.raises(security.SecurityError):
        security.safe_join(tmp_path, "..", "..", "etc", "passwd")
    with pytest.raises(security.SecurityError):
        security.safe_join(tmp_path, "../outside.txt")


def test_safe_join_allows_inside(tmp_path):
    target = security.safe_join(tmp_path, "a", "b.txt")
    assert str(target).startswith(str(tmp_path.resolve()))


# ── 仓库与分支名 ──────────────────────────────────────────
@pytest.mark.parametrize("repo", [
    "", "no-slash", "a/b/c", "../evil", "a b/c", "a/" + "b" * 200,
])
def test_valid_repo_rejects(repo):
    assert security.valid_repo(repo) is False


def test_valid_repo_accepts():
    assert security.valid_repo("projectdiscovery/nuclei-templates") is True


@pytest.mark.parametrize("ref", ["", "-evil", "../x", "a..b", "a" * 200])
def test_valid_ref_rejects(ref):
    assert security.valid_ref(ref) is False


def test_valid_ref_accepts():
    assert security.valid_ref("main") is True
    assert security.valid_ref("v1.2.3") is True


# ── 入参收敛 ──────────────────────────────────────────────
def test_clamp_int():
    assert security.clamp_int("5", 1, 10, 0) == 5
    assert security.clamp_int("99", 1, 10, 0) == 10
    assert security.clamp_int("-3", 1, 10, 0) == 1
    assert security.clamp_int("abc", 1, 10, 7) == 7
    assert security.clamp_int(None, 1, 10, 7) == 7


def test_clean_text_strips_and_truncates():
    assert security.clean_text("  hi  ") == "hi"
    assert security.clean_text("a\x00b") == "ab"
    assert security.clean_text(None, default="-") == "-"
    assert len(security.clean_text("x" * 500, max_len=10)) == 10


def test_safe_refs_drops_pseudo_protocols():
    """只留 http/https，前端拿到就是干净的列表。"""
    refs = ["https://a.com/1", "javascript:alert(1)", "data:text/html,x",
            "http://b.com/2", "https://a.com/1"]
    assert security.safe_refs(refs) == ["https://a.com/1", "http://b.com/2"]


def test_safe_refs_handles_string_and_empty():
    assert security.safe_refs("https://a.com/") == ["https://a.com/"]
    assert security.safe_refs([]) == []
    assert security.safe_refs(None) == []


# ── 限流 ─────────────────────────────────────────────────
def test_rate_limiter_blocks_over_limit():
    limiter = security.RateLimiter(limit=3, window=60.0)
    assert limiter.allow("1.2.3.4") is True
    assert limiter.allow("1.2.3.4") is True
    assert limiter.allow("1.2.3.4") is True
    assert limiter.allow("1.2.3.4") is False


def test_rate_limiter_is_per_key():
    limiter = security.RateLimiter(limit=1, window=60.0)
    assert limiter.allow("a") is True
    assert limiter.allow("b") is True
    assert limiter.allow("a") is False


def test_rate_limiter_reset():
    limiter = security.RateLimiter(limit=1, window=60.0)
    limiter.allow("a")
    limiter.reset("a")
    assert limiter.allow("a") is True


# ── 令牌 ─────────────────────────────────────────────────
def test_api_token_shape(tmp_path, monkeypatch):
    """令牌是 32 字节随机数的十六进制，写盘后权限收紧到 600。"""
    import security as sec

    token_file = tmp_path / ".api_token"
    monkeypatch.setattr(sec, "TOKEN_FILE", token_file)
    monkeypatch.setattr(sec, "_token_cache", "")

    token = sec.api_token()
    assert len(token) == 64
    assert all(c in "0123456789abcdef" for c in token)
    assert token_file.read_text(encoding="utf-8").strip() == token
    # 再调一次应命中缓存，返回同一个值
    assert sec.api_token() == token


def test_allowed_hosts_default():
    """默认只认本机，挡 DNS 重绑定。"""
    hosts = security.allowed_hosts()
    assert "127.0.0.1" in hosts
    assert "localhost" in hosts
