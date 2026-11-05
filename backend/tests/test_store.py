"""test_store.py —— 漏洞库读写与缓存的回归测试

store 是唯一落盘的地方：漏洞 JSON、PoC、nuclei 模板、复核标记都走它。
这里盯三件事：写入落对位置、读回来内容一致、坏数据不把整个库拖垮。
"""
import json

import pytest

import store


def _meta(vid="CVE-2024-0001", **over):
    m = {
        "id": vid,
        "name": "测试漏洞",
        "source": "seebug",
        "cvss": 9.8,
        "level": "严重",
        "published": "2024-01-01",
        "component": "nginx",
        "summary": "摘要",
        "refs": ["https://example.com/1"],
        "principle": "原理分析",
        "impact": "影响",
        "keywords": "nginx,overflow",
        "ver": "v1",
        "iid": "iid-1",
        "is_cve": "1",
        "cve": "CVE-2024-0001",
        "cwe": "CWE-787",
    }
    m.update(over)
    return m


# ── 落盘 ─────────────────────────────────────────────────
def test_save_writes_meta_and_poc():
    vid = store.save(_meta(), "print('poc')", poc_lang="python")

    meta_file = store.VULN_DIR / vid / "meta.json"
    poc_file = store.VULN_DIR / vid / "poc.python"
    assert meta_file.exists()
    assert poc_file.exists()

    loaded = json.loads(meta_file.read_text(encoding="utf-8"))
    assert loaded["name"] == "测试漏洞"
    assert loaded["cvss"] == 9.8
    assert loaded["poc_file"] == "poc.python"
    assert poc_file.read_text(encoding="utf-8") == "print('poc')"


def test_save_poc_language_controls_suffix():
    store.save(_meta(vid="v1"), "# c", poc_lang="python")
    store.save(_meta(vid="v2"), "# c", poc_lang="http")
    assert (store.VULN_DIR / "v1" / "poc.python").exists()
    assert (store.VULN_DIR / "v2" / "poc.http").exists()


def test_save_unknown_poc_language_falls_back_to_python():
    """后缀白名单：认不出来的后缀一律按 python 存，不能拼进路径。"""
    vid = store.save(_meta(vid="v3"), "x", poc_lang="exe")
    assert vid == "v3"
    assert (store.VULN_DIR / "v3" / "poc.python").exists()
    assert not (store.VULN_DIR / "v3" / "poc.exe").exists()


def test_save_normalizes_path_traversal_vid():
    """VID 里的路径分隔符被归一化成下划线，落盘位置仍在漏洞目录内。"""
    vid = store.save(_meta(vid="../evil"), "x", poc_lang="python")
    assert "/" not in vid
    assert (store.VULN_DIR / vid).is_dir()
    assert (store.VULN_DIR / vid).resolve().parent == store.VULN_DIR.resolve()


def test_save_empty_vid_rejected():
    with pytest.raises(ValueError):
        store.save(_meta(vid="   "), "x", poc_lang="python")


def test_save_with_nuclei_yaml():
    store.save(_meta(vid="v4"), "x", poc_lang="python",
               nuclei_yaml="id: t\ninfo:\n  name: x\n")
    tpl = store.VULN_DIR / "v4" / "nuclei.yaml"
    assert tpl.exists()
    assert "id: t" in tpl.read_text(encoding="utf-8")
    # 汇总目录里也有一份，整体可以 nuclei -l 跑
    assert (store.NUCLEI_TPL_DIR / "v4.yaml").exists()


def test_save_overwrites_existing():
    store.save(_meta(vid="v5", name="第一次"), "x", poc_lang="python")
    store.save(_meta(vid="v5", name="第二次"), "y", poc_lang="python")
    loaded = json.loads((store.VULN_DIR / "v5" / "meta.json").read_text(encoding="utf-8"))
    assert loaded["name"] == "第二次"


# ── 读回 ─────────────────────────────────────────────────
def test_get_vuln_returns_meta_with_poc():
    store.save(_meta(), "print(1)", poc_lang="python")
    got = store.get_vuln("CVE-2024-0001")
    assert got["name"] == "测试漏洞"
    assert got["poc"].strip() == "print(1)"


def test_get_vuln_missing_returns_none():
    assert store.get_vuln("CVE-9999-9999") is None


def test_get_vuln_rejects_bad_vid():
    """非法 ID 直接返回 None，不抛异常到接口层。"""
    assert store.get_vuln("../../etc/passwd") is None


def test_get_vuln_drops_non_http_refs():
    store.save(_meta(refs=["https://ok.com/1", "javascript:alert(1)"]), "x", poc_lang="python")
    got = store.get_vuln("CVE-2024-0001")
    assert got["refs"] == ["https://ok.com/1"]


def test_get_vuln_ignores_tampered_poc_file():
    """meta 里的 poc_file 被手工改成越界路径时，不能读出漏洞目录外的文件。"""
    store.save(_meta(vid="v6"), "secret", poc_lang="python")
    meta_file = store.VULN_DIR / "v6" / "meta.json"
    m = json.loads(meta_file.read_text(encoding="utf-8"))
    m["poc_file"] = "../../../etc/passwd"
    meta_file.write_text(json.dumps(m, ensure_ascii=False), encoding="utf-8")

    got = store.get_vuln("v6")
    assert got["poc"] == ""


# ── 列表 ─────────────────────────────────────────────────
def test_list_vulns_pagination():
    for i in range(5):
        store.save(_meta(vid=f"CVE-2024-000{i}", name=f"标题{i}"), "x", poc_lang="python")

    page = store.list_vulns(page=1, page_size=2)
    assert len(page["items"]) == 2
    assert page["total"] == 5
    assert page["pages"] == 3


def test_list_vulns_source_filter():
    store.save(_meta(vid="a1", source="seebug"), "x", poc_lang="python")
    store.save(_meta(vid="a2", source="nuclei"), "x", poc_lang="python")
    got = store.list_vulns(page=1, page_size=10, source="nuclei")
    assert got["total"] == 1
    assert got["items"][0]["id"] == "a2"


def test_list_vulns_level_filter():
    store.save(_meta(vid="b1", level="严重"), "x", poc_lang="python")
    store.save(_meta(vid="b2", level="低危"), "x", poc_lang="python")
    got = store.list_vulns(page=1, page_size=10, level="严重")
    assert got["total"] == 1
    assert got["items"][0]["id"] == "b1"


def test_list_vulns_search_by_keyword():
    store.save(_meta(vid="CVE-2024-1000", name="缓冲区溢出", summary="栈溢出"), "x", poc_lang="python")
    store.save(_meta(vid="CVE-2024-1001", name="权限提升", summary="越权"), "x", poc_lang="python")
    got = store.list_vulns(page=1, page_size=10, q="溢出")
    assert got["total"] == 1
    assert got["items"][0]["id"] == "CVE-2024-1000"


def test_list_vulns_skips_broken_files():
    """坏 JSON 只跳这一条，不能让整个列表挂掉。"""
    store.save(_meta(vid="good"), "x", poc_lang="python")
    bad_dir = store.VULN_DIR / "bad"
    bad_dir.mkdir(parents=True, exist_ok=True)
    (bad_dir / "meta.json").write_text("{ 这不是 JSON", encoding="utf-8")

    got = store.list_vulns(page=1, page_size=10)
    assert got["total"] == 1
    assert got["items"][0]["id"] == "good"


def test_list_vulns_counts_are_global():
    """counts 是全库计数，不随筛选变。"""
    store.save(_meta(vid="c1", source="seebug"), "x", poc_lang="python")
    store.save(_meta(vid="c2", source="seebug"), "x", poc_lang="python")
    store.save(_meta(vid="c3", source="nuclei"), "x", poc_lang="python")
    got = store.list_vulns(page=1, page_size=10, source="nuclei")
    assert got["total"] == 1
    assert got["all_total"] == 3
    assert got["counts"]["seebug"] == 2


# ── 缓存 ─────────────────────────────────────────────────
def test_rows_cache_invalidated_on_save():
    store.save(_meta(vid="c1"), "x", poc_lang="python")
    assert store.list_vulns(page=1, page_size=10)["total"] == 1
    store.save(_meta(vid="c2"), "x", poc_lang="python")
    assert store.list_vulns(page=1, page_size=10)["total"] == 2


def test_invalidate_rows_forces_reload():
    store.save(_meta(vid="c3"), "x", poc_lang="python")
    store.list_vulns(page=1, page_size=10)
    store.invalidate_rows()
    assert store.list_vulns(page=1, page_size=10)["total"] == 1


# ── 文本读取上限 ──────────────────────────────────────────
def test_read_text_rejects_oversize(tmp_path):
    """超过上限的文件直接当没有，不整份读进内存。"""
    big = tmp_path / "big.txt"
    big.write_text("A" * 5000, encoding="utf-8")
    assert store._read_text(big, limit=100) == ""


def test_read_text_missing_file_returns_empty(tmp_path):
    assert store._read_text(tmp_path / "nope.txt") == ""


def test_read_text_handles_bad_encoding(tmp_path):
    f = tmp_path / "bad.txt"
    f.write_bytes(b"\xff\xfe\x00broken")
    assert isinstance(store._read_text(f), str)


# ── 派生字段 ─────────────────────────────────────────────
def test_entry_date_prefers_cve_year():
    """编号里只有年份时按该年最后一天算，并标记只有年份。"""
    date, year_only = store.entry_date({"id": "CVE-2024-12345", "name": "x"})
    assert date == "2024-12-31"
    assert year_only is True


def test_entry_date_falls_back_to_published():
    date, year_only = store.entry_date({"id": "vuln-1", "published": "2025-03-04"})
    assert date == "2025-03-04"
    assert year_only is False


def test_too_old():
    assert store.too_old({"id": "CVE-2020-1"}, keep_days=0) is False
    assert store.too_old({"id": "CVE-2020-1"}, keep_days=1) is True
    assert store.too_old({"id": "no-date-here"}, keep_days=1) is False


def test_level_of():
    assert store.level_of({"level": "严重"}) == "严重"
    assert store.level_of({"severity": "critical"}) == "严重"
    assert store.level_of({"cvss": 9.8}) == "严重"
    assert store.level_of({"cvss": 5.0}) == "中危"
    assert store.level_of({}) == "未评级"


def test_component_of_extracts_component():
    assert store.component_of("WordPress Plugin Elementor 3.5.0 - XSS") == "WordPress Plugin Elementor"
    assert store.component_of("") == ""
