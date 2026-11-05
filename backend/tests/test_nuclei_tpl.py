"""test_nuclei_tpl.py —— nuclei 模板生成与校验的回归测试

这里守的是"生成出来的模板会被别人拿去跑"这条线：
不能生成写操作模板、不能带 DSL 危险标签、YAML 必须合法。
"""
import pytest

import nuclei_tpl


# ── 校验 ─────────────────────────────────────────────────
def test_validate_yaml_accepts_normal():
    ok, msg = nuclei_tpl.validate_yaml(
        "id: test-vuln\n"
        "info:\n"
        "  name: Test\n"
        "  severity: high\n"
        "http:\n"
        "  - method: GET\n"
        "    path:\n"
        "      - \"{{BaseURL}}/x\"\n"
        "    matchers:\n"
        "      - type: status\n"
        "        status:\n"
        "          - 200\n")
    assert ok is True
    assert msg == ""


@pytest.mark.parametrize("text", [
    # id 不合法
    "id: bad id!\ninfo:\n  name: x\n  severity: high\n",
    # severity 不在白名单
    "id: test-vuln\ninfo:\n  name: x\n  severity: extreme\n",
    # 缺 http 段
    "id: test-vuln\ninfo:\n  name: x\n  severity: high\n",
    # http 段没有 path
    "id: test-vuln\ninfo:\n  name: x\n  severity: high\nhttp:\n  - method: GET\n",
    # http 段没有 matchers
    "id: test-vuln\ninfo:\n  name: x\n  severity: high\nhttp:\n"
    "  - method: GET\n    path:\n      - \"{{BaseURL}}/x\"\n",
])
def test_validate_yaml_rejects_bad(text):
    ok, msg = nuclei_tpl.validate_yaml(text)
    assert ok is False
    assert msg


# ── 写操作判定 ────────────────────────────────────────────
@pytest.mark.parametrize("spec", [
    {"http": [{"method": "POST", "path": ["{{BaseURL}}/api/x"]}]},
    {"http": [{"method": "DELETE", "path": ["{{BaseURL}}/api/x"]}]},
    {"http": [{"method": "PUT", "path": ["{{BaseURL}}/api/x"]}]},
    {"http": [{"method": "GET", "path": ["{{BaseURL}}/admin/reset"]}]},
    {"http": [{"method": "GET", "path": ["{{BaseURL}}/api/upload"]}]},
    {"http": [{"method": "GET", "path": ["{{BaseURL}}/user/create"]}]},
])
def test_is_write_risk_detects(spec):
    assert nuclei_tpl.is_write_risk(spec) is True


@pytest.mark.parametrize("spec", [
    {"http": [{"method": "GET", "path": ["{{BaseURL}}/news/1"]}]},
    {"http": [{"method": "HEAD", "path": ["{{BaseURL}}/static/x.js"]}]},
    {"http": [{"method": "GET", "path": ["{{BaseURL}}/api/query"]}]},
])
def test_is_write_risk_allows_readonly(spec):
    assert nuclei_tpl.is_write_risk(spec) is False


# ── 清洗 ─────────────────────────────────────────────────
def test_clean_spec_forces_attack_none():
    """attack 字段必须是 none，否则 nuclei 会按 batteringram 之类组合拳打。"""
    spec = {"http": [{"method": "GET", "path": ["{{BaseURL}}/x"],
                      "attack": "batteringram",
                      "matchers": [{"type": "status", "status": [200]}]}]}
    out = nuclei_tpl._clean_spec(spec, {})
    assert out["http"][0]["attack"] == "none"


def test_clean_spec_truncates_long_description():
    spec = {"description": "A" * 5000}
    out = nuclei_tpl._clean_spec(spec, {})
    assert len(out["description"]) <= 600


def test_clean_spec_keeps_shape():
    spec = {
        "id": "my-vuln",
        "name": "My Vuln",
        "severity": "high",
        "http": [{"method": "GET", "path": ["{{BaseURL}}/x"],
                  "matchers": [{"type": "status", "status": [200]}]}],
    }
    out = nuclei_tpl._clean_spec(spec, {})
    assert out["id"] == "my-vuln"
    assert out["http"][0]["method"] == "GET"
    assert out["http"][0]["matchers"][0]["status"] == [200]


def test_clean_spec_drops_dangerous_dsl_matcher():
    """DSL 里的 !code / !eval 之类标签不能带进模板 —— nuclei 会当代码执行。"""
    spec = {
        "id": "my-vuln",
        "severity": "high",
        "http": [{"method": "GET", "path": ["{{BaseURL}}/x"],
                  "matchers": [{"type": "dsl", "dsl": "!code exec('id')"}]}],
    }
    out = nuclei_tpl._clean_spec(spec, {})
    # 危险的 DSL matcher 整条被丢弃，这条请求没有可用 matcher 就该被丢掉
    assert out["http"] == []


def test_clean_spec_keeps_safe_dsl_matcher():
    """普通 DSL（不含自定义标签）保留。"""
    spec = {
        "id": "my-vuln",
        "severity": "high",
        "http": [{"method": "GET", "path": ["{{BaseURL}}/x"],
                  "matchers": [{"type": "dsl", "dsl": 'contains("admin")'}]}],
    }
    out = nuclei_tpl._clean_spec(spec, {})
    assert out["http"][0]["matchers"][0]["dsl"] == 'contains("admin")'


# ── 小工具 ───────────────────────────────────────────────
def test_severity_from_cvss():
    assert nuclei_tpl.severity_from_cvss(9.8) == "critical"
    assert nuclei_tpl.severity_from_cvss(7.0) == "high"
    assert nuclei_tpl.severity_from_cvss(4.0) == "medium"
    assert nuclei_tpl.severity_from_cvss(0.5) == "low"
    assert nuclei_tpl.severity_from_cvss(0.0) == "info"
    assert nuclei_tpl.severity_from_cvss(None) == "unknown"
    assert nuclei_tpl.severity_from_cvss("abc") == "unknown"


def test_slug():
    assert nuclei_tpl._slug("My Vuln Name!") == "my-vuln-name"
    assert nuclei_tpl._slug("") == "ai-bobao-vuln"
    assert nuclei_tpl._slug("!!!", fallback="fb") == "fb"


def test_parse_template_reads_metadata():
    doc = {
        "id": "cve-2024-1234",
        "info": {"name": "CVE-2024-1234", "severity": "high",
                 "reference": ["https://example.com/1"], "tags": "cve,rce"},
        "http": [{"method": "GET", "path": ["{{BaseURL}}/x"]}],
    }
    tpl = nuclei_tpl.parse_template(doc, "http/cve-2024-1234.yaml")
    assert tpl is not None
    assert tpl.id == "cve-2024-1234"
    assert tpl.severity == "high"
    assert "cve" in tpl.tags
    assert tpl.path == "http/cve-2024-1234.yaml"


def test_parse_template_rejects_non_dict():
    assert nuclei_tpl.parse_template(["not", "a", "dict"]) is None
    assert nuclei_tpl.parse_template({}) is None


def test_load_local_templates_skips_broken_files(tmp_path):
    """坏 YAML 只跳这一个文件。"""
    (tmp_path / "good.yaml").write_text(
        "id: good\ninfo:\n  name: Good\n  severity: info\n", encoding="utf-8")
    (tmp_path / "bad.yaml").write_text("id: [unclosed\n", encoding="utf-8")
    tpls = nuclei_tpl.load_local_templates(tmp_path)
    assert [t.id for t in tpls] == ["good"]


def test_load_local_templates_skips_tests_dir(tmp_path):
    (tmp_path / "tests").mkdir()
    (tmp_path / "tests" / "t.yaml").write_text(
        "id: t\ninfo:\n  name: T\n  severity: info\n", encoding="utf-8")
    assert nuclei_tpl.load_local_templates(tmp_path) == []
