"""test_static_site.py —— 前后端不分离版的静态托管回归测试

页面由后端自己发（backend/static），深链必须回落到 index.html，
路径拼接还不能被 ../ 带出静态目录。这几条一旦改坏，用户要么看到白屏，
要么能从 URL 里读到项目里的其他文件，所以逐条钉住。
"""
import pytest
from fastapi.testclient import TestClient

import main


@pytest.fixture
def site(tmp_path, monkeypatch):
    """造一份假的构建产物目录，把后端指过去。"""
    static = tmp_path / "static"
    (static / "assets").mkdir(parents=True)
    (static / "index.html").write_text(
        "<!DOCTYPE html><html><body><div id=\"app\"></div></body></html>",
        encoding="utf-8",
    )
    (static / "assets" / "index-abc123.js").write_text("console.log(1)", encoding="utf-8")
    (static / "icon-mini.svg").write_text("<svg/>", encoding="utf-8")
    monkeypatch.setattr(main, "_STATIC_DIR", static)
    monkeypatch.setattr(main, "_INDEX", static / "index.html")
    return static


@pytest.fixture
def client():
    # 不进 with，lifespan 里的定时任务不启动，测试不碰网络
    return TestClient(main.app)


# ── SPA 回落 ──────────────────────────────────────────────
@pytest.mark.parametrize("path", [
    "/", "/envs", "/vuln/abc123", "/settings", "/templates", "/a/b/c",
])
def test_deep_link_falls_back_to_index(client, site, path):
    """深链在磁盘上没有对应文件，但要回 index.html，不能 404。"""
    r = client.get(path)
    assert r.status_code == 200
    assert 'id="app"' in r.text


# ── 静态文件 ──────────────────────────────────────────────
def test_asset_is_served_with_long_cache(client, site):
    """带内容哈希的产物可以长缓存。"""
    r = client.get("/assets/index-abc123.js")
    assert r.status_code == 200
    assert "immutable" in r.headers.get("cache-control", "")


def test_icon_is_served_without_cache(client, site):
    """图标和 index.html 不能长缓存，否则重新构建后用户还拿到旧的。"""
    r = client.get("/icon-mini.svg")
    assert r.status_code == 200
    assert "no-cache" in r.headers.get("cache-control", "")


def test_unknown_static_path_falls_back(client, site):
    """静态目录里没有的路径也回 index.html，交给前端路由。"""
    r = client.get("/nope.png")
    assert r.status_code == 200
    assert 'id="app"' in r.text


# ── /api 不被 catch-all 抢走 ──────────────────────────────
def test_unknown_api_returns_json_404(client, site):
    """不存在的接口回 JSON 404，不能给前端吐一坨 HTML。"""
    r = client.get("/api/does-not-exist", headers={"X-AI-BaoBao": "1"})
    assert r.status_code == 404
    assert r.headers["content-type"].startswith("application/json")
    assert "detail" in r.json()


# ── 路径穿越 ──────────────────────────────────────────────
@pytest.mark.parametrize("path", [
    "/../config.yaml",
    "/assets/../../config.yaml",
    "/%2e%2e%2fconfig.yaml",
])
def test_path_traversal_is_contained(client, site, path):
    """../ 不能带出静态目录，读到的是 index.html 而不是项目里的文件。"""
    r = client.get(path)
    assert r.status_code == 200
    assert "llm:" not in r.text
    assert 'id="app"' in r.text


# ── 没构建过前端 ──────────────────────────────────────────
def test_not_built_returns_hint_page(tmp_path, monkeypatch):
    """没构建过时给一张提示页，而不是空白 404。"""
    empty = tmp_path / "static"
    empty.mkdir()
    monkeypatch.setattr(main, "_STATIC_DIR", empty)
    monkeypatch.setattr(main, "_INDEX", empty / "index.html")
    r = TestClient(main.app).get("/")
    assert r.status_code == 503
    assert "npm run build" in r.text
