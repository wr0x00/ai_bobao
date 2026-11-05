"""test_source_manager.py —— 播报源管理服务的回归测试

这里守的是"接入一个源"这条线：地址必须过 SSRF 网关，内网/云元数据地址
不能写进配置。HTTP 接口以前只查了 http:// 前缀，这条线是从 agent 那边
搬过来的，搬过来就不能再漏。
"""
import pytest

import config
import source_manager


@pytest.fixture(autouse=True)
def isolated_config(tmp_path, monkeypatch):
    """把配置文件指到临时目录，测试不碰真实的 backend/config.yaml。"""
    monkeypatch.setattr(config, "CONFIG_FILE", tmp_path / "config.yaml")
    config._cache = None
    yield
    config._cache = None


@pytest.fixture
def private_dns(monkeypatch):
    """假装域名解析到内网地址。"""
    import security

    monkeypatch.setattr(security, "resolve_host", lambda host, port=80: ["127.0.0.1"])


# ── 列表 ─────────────────────────────────────────────────
def test_list_sources_has_builtin_and_custom():
    r = source_manager.list_sources()
    assert "builtin" in r and "custom" in r
    assert r["builtin"], "内置源不应为空"
    assert all(s["builtin"] is True for s in r["builtin"])
    assert all(s["builtin"] is False for s in r["custom"])


def test_list_sources_custom_entries_come_from_config():
    config.update({"sources": {"custom": [
        {"name": "先知", "url": "https://xz.aliyun.com/feed", "enabled": True}]}})
    r = source_manager.list_sources()
    assert [s["name"] for s in r["custom"]] == ["先知"]
    assert r["custom"][0]["url"] == "https://xz.aliyun.com/feed"


# ── 接入 ─────────────────────────────────────────────────
def test_add_source_writes_config(no_dns):
    r = source_manager.add_source("先知", "https://xz.aliyun.com/feed")
    assert r["ok"] is True
    assert "先知" in r["message"]
    saved = config.get("sources", "custom")
    assert saved == [{"name": "先知", "url": "https://xz.aliyun.com/feed",
                      "enabled": True}]


def test_add_source_same_name_updates(no_dns):
    source_manager.add_source("先知", "https://xz.aliyun.com/feed")
    source_manager.add_source("先知", "https://xz.aliyun.com/rss")
    saved = config.get("sources", "custom")
    assert len(saved) == 1
    assert saved[0]["url"] == "https://xz.aliyun.com/rss"


def test_add_source_rejects_empty_name(no_dns):
    with pytest.raises(source_manager.SourceError) as ei:
        source_manager.add_source("   ", "https://xz.aliyun.com/feed")
    assert ei.value.status == 400


@pytest.mark.parametrize("url", [
    "ftp://xz.aliyun.com/feed",
    "javascript:alert(1)",
    "file:///etc/passwd",
    "not-a-url",
])
def test_add_source_rejects_bad_scheme(no_dns, url):
    with pytest.raises(source_manager.SourceError):
        source_manager.add_source("先知", url)
    assert config.get("sources", "custom") == []


def test_add_source_blocks_private_address(private_dns):
    """内网地址必须被 SSRF 网关拦下，不能写进配置。"""
    with pytest.raises(source_manager.SourceError) as ei:
        source_manager.add_source("内网", "http://192.168.1.10/feed")
    assert "安全网关" in ei.value.message
    assert config.get("sources", "custom") == []


def test_add_source_blocks_cloud_metadata(private_dns):
    with pytest.raises(source_manager.SourceError):
        source_manager.add_source("元数据", "http://169.254.169.254/latest/meta-data/")
    assert config.get("sources", "custom") == []


def test_add_source_rejects_overlong_url(no_dns):
    with pytest.raises(source_manager.SourceError):
        source_manager.add_source("先知", "https://xz.aliyun.com/" + "a" * 3000)


# ── 移除 ─────────────────────────────────────────────────
def test_remove_source_deletes_from_config(no_dns):
    source_manager.add_source("先知", "https://xz.aliyun.com/feed")
    r = source_manager.remove_source("先知")
    assert r["ok"] is True
    assert config.get("sources", "custom") == []


def test_remove_missing_source_is_404(no_dns):
    with pytest.raises(source_manager.SourceError) as ei:
        source_manager.remove_source("不存在的源")
    assert ei.value.status == 404
