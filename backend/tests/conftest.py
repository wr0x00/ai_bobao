"""conftest.py —— 测试公共夹具

两件事：
1. 把落盘目录（漏洞库、模板汇总）指到 pytest 的临时目录，测试不碰真实数据；
2. 把各类进程内缓存清干净，别让上一条测试的状态漏到下一条。
"""
import pytest

import store


@pytest.fixture(autouse=True)
def temp_data_dirs(tmp_path, monkeypatch):
    """每个测试都有一份干净的临时数据目录。"""
    monkeypatch.setattr(store, "VULN_DIR", tmp_path / "vulns")
    monkeypatch.setattr(store, "NUCLEI_TPL_DIR", tmp_path / "nuclei_tpl")
    store.invalidate_rows()
    store.invalidate_templates()
    yield tmp_path
    store.invalidate_rows()
    store.invalidate_templates()


@pytest.fixture(autouse=True)
def reset_config_cache():
    """配置是进程内缓存的，改完配置得强制重读，否则测试之间互相串味。"""
    import config

    config._cache = None
    yield
    config._cache = None


@pytest.fixture
def no_dns(monkeypatch):
    """禁止测试真的做 DNS 解析。

    默认把域名解析成公网地址（1.1.1.1），需要内网地址的测试自己覆盖。
    """
    import security

    monkeypatch.setattr(security, "resolve_host", lambda host, port=80: ["1.1.1.1"])
