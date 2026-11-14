"""test_lab_env.py —— 本地复现环境模块的测试

不碰真网络、不碰真 Docker：LLM 用假对象替，拉取用 monkeypatch 替，
所有落盘都在 pytest 的临时目录里。
"""
import pytest

import agent
import config
import lab_env
import security
import store


@pytest.fixture(autouse=True)
def temp_lab_root(tmp_path, monkeypatch):
    """把环境资产根目录指到临时目录。

    配置文件的落点也要一起挪走——config.update() 会往 CONFIG_FILE 里写，
    不挪的话测试会把 lab.root 写进真实的 backend/config.yaml。
    """
    monkeypatch.setattr(config, "CONFIG_FILE", tmp_path / "config.yaml")
    root = tmp_path / "lab_envs"
    monkeypatch.setitem(config.DEFAULTS["lab"], "root", str(root))
    config._cache = None
    yield root
    config._cache = None


class FakeLLM:
    """替掉真实 LLM。按预设返回方案，方便测各种分支。"""

    def __init__(self, reply):
        self.reply = reply
        self.calls = []

    def chat(self, system, user, timeout=None):
        self.calls.append((system, user))
        return self.reply


def _make_vuln(vid="CVE-2024-0001", **over):
    meta = {
        "id": vid,
        "name": "示例漏洞",
        "summary": "某设备存在远程代码执行",
        "principle": "未授权访问管理接口导致命令执行",
        "attack_scope": "型号 X100 的嵌入式设备，固件版本 1.2.3",
        "component": "ACME Router",
        "refs": ["https://example.com/a"],
    }
    meta.update(over)
    store.save(meta, poc="print(1)", poc_lang="python")
    return vid


# ── 方案规范化 ────────────────────────────────────────────
def test_norm_plan_keeps_docker_plan():
    p = lab_env._norm_plan({
        "component": "Tomcat", "version": "9.0.0", "source": "docker",
        "image": "tomcat:9.0.0", "available": True, "ports": [8080, 8443],
    })
    assert p["source"] == "docker"
    assert p["image"] == "tomcat:9.0.0"
    assert p["ports"] == [8080, 8443]
    assert p["available"] is True


def test_norm_plan_rejects_bad_image_name():
    """镜像名带空格或选项前缀的，一律作废，不能拿去拼 docker 命令。"""
    for bad in ["tom cat", "--rm -rf /", "../evil", "tomcat;rm -rf /"]:
        p = lab_env._norm_plan({"source": "docker", "image": bad, "available": True})
        assert p["source"] == "none"
        assert p["available"] is False
        assert p["reason"]


def test_norm_plan_rejects_non_http_url():
    p = lab_env._norm_plan({"source": "source", "repo": "file:///etc/passwd",
                             "available": True})
    assert p["source"] == "none"
    assert p["available"] is False


def test_norm_plan_none_source_is_always_unavailable():
    p = lab_env._norm_plan({"source": "none", "available": True})
    assert p["available"] is False


def test_norm_plan_drops_bad_ports():
    p = lab_env._norm_plan({"source": "docker", "image": "a:1", "available": True,
                             "ports": [0, 70000, "abc", 8080]})
    assert p["ports"] == [8080]


# ── 指纹与共享 ────────────────────────────────────────────
def test_fingerprint_same_plan_same_id():
    a = {"component": "Tomcat", "version": "9.0", "source": "docker", "image": "tomcat:9.0"}
    b = {"component": "tomcat", "version": "9.0", "source": "docker", "image": "tomcat:9.0"}
    assert lab_env._fingerprint(a) == lab_env._fingerprint(b)


def test_fingerprint_differs_by_version():
    a = {"component": "Tomcat", "version": "9.0", "source": "docker", "image": "tomcat:9.0"}
    b = {"component": "Tomcat", "version": "9.1", "source": "docker", "image": "tomcat:9.1"}
    assert lab_env._fingerprint(a) != lab_env._fingerprint(b)


def test_fingerprint_ignores_llm_wording():
    """组件名/版本号是模型自由描述的，同一份资源换个说法还是同一个环境。

    否则 "OpenSSH" 和 "OpenSSH sshd（musl libc）" 会各拉一份源码，白费带宽。
    """
    a = {"component": "OpenSSH", "version": "10.6p2 之前", "source": "source",
         "repo": "https://github.com/openssh/openssh-portable"}
    b = {"component": "OpenSSH sshd（musl libc）", "version": "低于 10.6p2", "source": "source",
         "repo": "https://github.com/openssh/openssh-portable"}
    assert lab_env._fingerprint(a) == lab_env._fingerprint(b)


def test_fingerprint_differs_by_resource():
    a = {"component": "X", "version": "1", "source": "source", "repo": "https://github.com/a/b"}
    b = {"component": "X", "version": "1", "source": "source", "repo": "https://github.com/c/d"}
    assert lab_env._fingerprint(a) != lab_env._fingerprint(b)


def test_fingerprint_differs_by_source_type():
    """同一个仓库，走 source 还是走 docker，是两套东西，不能合并。"""
    a = {"component": "X", "version": "1", "source": "source", "repo": "https://github.com/a/b"}
    b = {"component": "X", "version": "1", "source": "docker", "image": "x:1"}
    assert lab_env._fingerprint(a) != lab_env._fingerprint(b)


def test_merge_vulns_keeps_existing():
    meta = {"vulns": ["CVE-2024-0001"]}
    assert lab_env._merge_vulns(meta, "CVE-2024-0002") == ["CVE-2024-0001", "CVE-2024-0002"]
    assert lab_env._merge_vulns(meta, "CVE-2024-0001") == ["CVE-2024-0001"]
    assert lab_env._merge_vulns(None, "CVE-2024-0001") == ["CVE-2024-0001"]


# ── 目录 ──────────────────────────────────────────────────
def test_root_dir_follows_config(tmp_path):
    assert lab_env.root_dir() == tmp_path / "lab_envs"


def test_root_dir_falls_back_to_default(monkeypatch):
    monkeypatch.setitem(config.DEFAULTS["lab"], "root", "")
    config._cache = None
    assert lab_env.root_dir() == lab_env.default_root()


def test_env_dir_rejects_bad_id():
    with pytest.raises(lab_env.EnvError):
        lab_env._env_dir("../../etc")
    with pytest.raises(lab_env.EnvError):
        lab_env._env_dir("ABC")


# ── 放弃语义 ──────────────────────────────────────────────
def test_build_abandons_when_program_not_available(tmp_path):
    """网上找不到程序本体时放弃，并把理由记下来，不硬造环境。"""
    vid = _make_vuln()
    llm = FakeLLM({"component": "ACME Router", "version": "1.2.3",
                    "source": "none", "available": False,
                    "reason": "闭源固件，厂商不公开下载"})
    r = lab_env.build(vid, llm=llm)
    assert r["abandoned"] is True
    assert r["ok"] is False
    assert "闭源" in r["reason"]
    assert r["env"]["status"] == lab_env.STATUS_ABANDONED
    # 元数据落盘了，用户能在列表里看到"为什么放弃"
    assert list_envs_status() == [lab_env.STATUS_ABANDONED]


def list_envs_status():
    return [e["status"] for e in lab_env.list_envs()["items"]]


def test_build_abandons_when_llm_says_unavailable_but_source_docker():
    """LLM 填了 docker 但 available=false，也一样放弃。"""
    vid = _make_vuln()
    llm = FakeLLM({"source": "docker", "image": "acme/router:1.2.3", "available": False,
                    "reason": "该镜像不存在"})
    r = lab_env.build(vid, llm=llm)
    assert r["abandoned"] is True
    assert r["env"]["status"] == lab_env.STATUS_ABANDONED


# ── 真实拉取（用 monkeypatch 替掉外部命令）──────────────
def test_build_docker_pulls_and_records(monkeypatch):
    vid = _make_vuln()
    calls = []

    def fake_pull(image, timeout, cancel=None):
        calls.append(image)
        return True, "pulled"

    monkeypatch.setattr(lab_env, "_pull_docker", fake_pull)
    # build() 搭好会自动启动靶站 —— 这里是纯单测，把 docker 关掉，
    # 免得它真去 docker run 拉个几百 MB 的镜像把测试卡住
    monkeypatch.setattr(lab_env, "docker_available", lambda: False)
    llm = FakeLLM({"component": "Tomcat", "version": "9.0", "source": "docker",
                    "image": "tomcat:9.0", "available": True, "ports": [8080]})
    r = lab_env.build(vid, llm=llm)
    assert r["ok"] is True
    assert calls == ["tomcat:9.0"]
    env = r["env"]
    assert env["status"] == lab_env.STATUS_READY
    assert env["vulns"] == [vid]
    # 漏洞条目挂上了环境 ID
    assert store.get_vuln(vid)["env_id"] == env["id"]


def test_build_source_clones(monkeypatch, tmp_path):
    vid = _make_vuln()
    seen = {}

    def fake_clone(url, dest, timeout, ref="", cancel=None):
        seen["url"] = url
        seen["dest"] = dest
        dest.mkdir(parents=True, exist_ok=True)
        return True, "cloned"

    monkeypatch.setattr(lab_env, "_pull_source", fake_clone)
    llm = FakeLLM({"component": "Tomcat", "version": "9.0", "source": "source",
                    "repo": "https://github.com/apache/tomcat", "available": True})
    r = lab_env.build(vid, llm=llm)
    assert r["ok"] is True
    assert seen["url"] == "https://github.com/apache/tomcat"
    assert seen["dest"].parent == lab_env._env_dir(r["env"]["id"])


def test_build_shares_env_between_vulns(monkeypatch):
    """同一个组件+版本+来源，多条漏洞共享同一个环境，不重复拉。"""
    pulls = []

    def fake_pull(image, timeout, cancel=None):
        pulls.append(image)
        return True, "pulled"

    monkeypatch.setattr(lab_env, "_pull_docker", fake_pull)
    plan = {"component": "Tomcat", "version": "9.0", "source": "docker",
            "image": "tomcat:9.0", "available": True}
    v1 = _make_vuln("CVE-2024-0001")
    v2 = _make_vuln("CVE-2024-0002")

    r1 = lab_env.build(v1, llm=FakeLLM(plan))
    r2 = lab_env.build(v2, llm=FakeLLM(plan))
    assert pulls == ["tomcat:9.0"]              # 只拉了一次
    assert r2["shared"] is True
    assert r2["env"]["id"] == r1["env"]["id"]
    assert set(r2["env"]["vulns"]) == {v1, v2}
    # 两个漏洞条目都指向同一个环境
    assert store.get_vuln(v1)["env_id"] == store.get_vuln(v2)["env_id"]


def test_build_failure_records_reason(monkeypatch):
    vid = _make_vuln()
    monkeypatch.setattr(lab_env, "_pull_docker",
                        lambda image, timeout, cancel=None: (False, "镜像拉取失败：网络超时"))
    llm = FakeLLM({"component": "Tomcat", "version": "9.0", "source": "docker",
                    "image": "tomcat:9.0", "available": True})
    r = lab_env.build(vid, llm=llm)
    assert r["ok"] is False
    assert r["env"]["status"] == lab_env.STATUS_FAILED
    assert "网络超时" in r["reason"]


def test_build_abandons_when_resource_not_on_net(monkeypatch):
    """地址压根不存在（404/403）算"网上没有"，该记放弃而不是构建失败。"""
    vid = _make_vuln()
    monkeypatch.setattr(lab_env, "_pull_release",
                        lambda url, dest, timeout: (False, "下载失败：对方返回 HTTP 404"))
    llm = FakeLLM({"component": "Edimax", "version": "1.0", "source": "release",
                    "release": "https://www.edimax.com/download/x.zip", "available": True})
    r = lab_env.build(vid, llm=llm)
    assert r["ok"] is False
    assert r["abandoned"] is True
    assert r["env"]["status"] == lab_env.STATUS_ABANDONED


def test_is_unavailable_marks():
    assert lab_env._is_unavailable("下载失败：对方返回 HTTP 404") is True
    assert lab_env._is_unavailable("fatal: repository not found") is True
    assert lab_env._is_unavailable("下载失败：对方返回 HTTP 301（重定向死循环）") is True
    assert lab_env._is_unavailable("请求超时（600s）") is False


def test_build_keeps_vulns_when_rebuilding_failed_env(monkeypatch):
    """重建同一个失败环境，不能把之前关联的漏洞挤掉。"""
    v1 = _make_vuln("CVE-2024-0001")
    v2 = _make_vuln("CVE-2024-0002")
    plan = {"component": "Edimax", "version": "1.0", "source": "release",
            "release": "https://www.edimax.com/download/x.zip", "available": True}
    monkeypatch.setattr(lab_env, "_pull_release",
                        lambda url, dest, timeout: (False, "下载失败：对方返回 HTTP 404"))
    lab_env.build(v1, llm=FakeLLM(plan))
    r2 = lab_env.build(v2, llm=FakeLLM(plan))
    assert set(r2["env"]["vulns"]) == {v1, v2}


# ── 列表 / 详情 / 删除 ───────────────────────────────────
def test_list_envs_reports_root_and_docker(monkeypatch):
    monkeypatch.setattr(lab_env, "docker_available", lambda: True)
    r = lab_env.list_envs()
    assert r["root"] == str(lab_env.root_dir())
    assert r["docker"] is True
    assert r["items"] == []


def test_get_env_returns_asset_paths(monkeypatch):
    vid = _make_vuln()

    def fake_clone(url, dest, timeout, ref="", cancel=None):
        dest.mkdir(parents=True, exist_ok=True)
        return True, "cloned"

    monkeypatch.setattr(lab_env, "_pull_source", fake_clone)
    llm = FakeLLM({"component": "Tomcat", "version": "9.0", "source": "source",
                    "repo": "https://github.com/apache/tomcat", "available": True})
    r = lab_env.build(vid, llm=llm)
    detail = lab_env.get_env(r["env"]["id"])
    assert detail["assets"]["source"].endswith("source")
    assert detail["dir"]


def test_delete_env_clears_link(monkeypatch):
    vid = _make_vuln()
    monkeypatch.setattr(lab_env, "_pull_docker",
                        lambda image, timeout, cancel=None: (True, "pulled"))
    llm = FakeLLM({"component": "Tomcat", "version": "9.0", "source": "docker",
                    "image": "tomcat:9.0", "available": True})
    r = lab_env.build(vid, llm=llm)
    eid = r["env"]["id"]
    lab_env.delete_env(eid)
    assert not lab_env._env_dir(eid).exists()
    assert store.get_vuln(vid)["env_id"] == ""


def test_get_env_404():
    with pytest.raises(lab_env.EnvError) as e:
        lab_env.get_env("0123456789ab")
    assert e.value.status == 404


def test_agent_list_envs_tool_reads_items(monkeypatch):
    """agent 的 list_envs 工具：环境在 list_envs()["items"] 里，别把 dict 当 list 迭代。"""
    vid = _make_vuln()
    monkeypatch.setattr(lab_env, "_pull_docker",
                        lambda image, timeout, cancel=None: (True, "pulled"))
    llm = FakeLLM({"component": "Tomcat", "version": "9.0", "source": "docker",
                    "image": "tomcat:9.0", "available": True})
    lab_env.build(vid, llm=llm)

    r = agent._t_list_envs({})
    assert r["ok"] is True
    assert r["count"] == 1
    assert r["envs"][0]["component"] == "Tomcat"


# ── 启动 / 停止 ───────────────────────────────────────────
def test_cancel_build_highest_priority(monkeypatch):
    """「拒绝，停止」是最高优先级：拉取进行中点了停止，环境记失败（用户取消），
    后续步骤不再执行，最终写盘不许覆盖「用户取消」。"""
    vid = _make_vuln()

    def fake_pull(image, timeout, cancel=None):
        # 模拟用户在拉取进行中点了「拒绝，停止」
        lab_env.cancel_build(vid)
        assert cancel is not None and cancel.is_set()
        return False, "命令已被用户取消"

    monkeypatch.setattr(lab_env, "_pull_docker", fake_pull)
    llm = FakeLLM({"component": "Tomcat", "version": "9.0", "source": "docker",
                    "image": "tomcat:9.0", "available": True})
    r = lab_env.build(vid, llm=llm)
    assert r.get("canceled") is True
    assert r["env"]["status"] == lab_env.STATUS_FAILED
    assert r["env"]["reason"] == "用户取消"
    eid = r["env"]["id"]
    # build 结束后取消事件要被注销，别留着下次误触
    assert vid not in lab_env._CANCEL
    # 对没有活动任务的漏洞再点一次取消：半成品缓存（拉了一半的目录）一并清掉
    assert lab_env._env_dir(eid).exists()
    r2 = lab_env.cancel_build(vid)
    assert r2["ok"] is True and r2["canceled"] is False and r2["cleaned"] == [eid]
    assert not lab_env._env_dir(eid).exists()
    assert store.get_vuln(vid)["env_id"] == ""


def test_start_docker_env(monkeypatch):
    vid = _make_vuln()
    monkeypatch.setattr(lab_env, "_pull_docker",
                        lambda image, timeout, cancel=None: (True, "pulled"))
    monkeypatch.setattr(lab_env, "docker_available", lambda: True)
    monkeypatch.setattr(lab_env, "_run",
                        lambda args, timeout=300, cwd=None, cancel=None: (0, "container started"))
    llm = FakeLLM({"component": "Tomcat", "version": "9.0", "source": "docker",
                    "image": "tomcat:9.0", "available": True, "ports": [8080]})
    r = lab_env.build(vid, llm=llm)
    eid = r["env"]["id"]
    started = lab_env.start_env(eid)
    assert started["ok"] is True
    # docker run -d 返回只是容器被创建，服务还要起几秒：先「启动中」，
    # 后台健康检查通过了才转「运行中」，别刚起容器就号称能打
    assert started["env"]["status"] == lab_env.STATUS_STARTING
    assert started["env"]["container"] == f"ai_bb_lab_{eid}"


def test_start_refuses_failed_env(monkeypatch):
    vid = _make_vuln()
    monkeypatch.setattr(lab_env, "_pull_docker",
                        lambda image, timeout, cancel=None: (False, "pull failed"))
    llm = FakeLLM({"component": "Tomcat", "version": "9.0", "source": "docker",
                    "image": "tomcat:9.0", "available": True})
    r = lab_env.build(vid, llm=llm)
    with pytest.raises(lab_env.EnvError):
        lab_env.start_env(r["env"]["id"])


def test_stop_env(monkeypatch):
    vid = _make_vuln()
    monkeypatch.setattr(lab_env, "_pull_docker",
                        lambda image, timeout, cancel=None: (True, "pulled"))
    monkeypatch.setattr(lab_env, "docker_available", lambda: True)
    monkeypatch.setattr(lab_env, "_run",
                        lambda args, timeout=300, cwd=None, cancel=None: (0, "ok"))
    llm = FakeLLM({"component": "Tomcat", "version": "9.0", "source": "docker",
                    "image": "tomcat:9.0", "available": True})
    r = lab_env.build(vid, llm=llm)
    eid = r["env"]["id"]
    lab_env.start_env(eid)
    stopped = lab_env.stop_env(eid)
    assert stopped["env"]["status"] == lab_env.STATUS_READY
    assert stopped["env"]["container"] == ""


# ── LLM 出方案 ────────────────────────────────────────────
def test_plan_env_calls_llm_with_brief():
    vid = _make_vuln()
    llm = FakeLLM({"component": "Tomcat", "version": "9.0", "source": "docker",
                    "image": "tomcat:9.0", "available": True})
    plan = lab_env.plan_env(vid, llm=llm)
    assert plan["component"] == "Tomcat"
    # 提示词里带了攻击范围（影响设备与型号），LLM 才知道该找什么程序
    user = llm.calls[0][1]
    assert "X100" in user


def test_plan_env_rejects_unknown_vid():
    with pytest.raises(lab_env.EnvError) as e:
        lab_env.plan_env("CVE-1999-9999")
    assert e.value.status == 404


# ── 外部命令安全性 ───────────────────────────────────────
def test_run_uses_argv_not_shell(monkeypatch):
    """命令内容里的 shell 元字符必须原样传给程序，不能被 shell 解释。"""
    seen = {}

    class FakeProc:
        returncode = 0

        def communicate(self, timeout=None):
            return b"ok", b""

        def kill(self):
            pass

        def wait(self, timeout=None):
            return 0

    def fake_popen(args, **kw):
        seen["args"] = args
        seen["shell"] = kw.get("shell")
        return FakeProc()

    monkeypatch.setattr(lab_env.subprocess, "Popen", fake_popen)
    code, _out = lab_env._run(["git", "clone", "https://x/$(whoami).git"])
    assert code == 0
    assert seen["args"][-1] == "https://x/$(whoami).git"
    assert seen["shell"] is False


def test_pull_source_blocks_private_host(monkeypatch, no_dns):
    """内网地址要挡住，不能让人拿复现环境当内网探测器。"""
    monkeypatch.setattr(security, "resolve_host", lambda host, port=80: ["127.0.0.1"])
    ok, msg = lab_env._pull_source("http://127.0.0.1/x.git", security.DATA_DIR / "x", 5)
    assert ok is False
    assert "安全网关" in msg


def test_pull_release_blocks_private_host(monkeypatch):
    monkeypatch.setattr(security, "resolve_host", lambda host, port=80: ["169.254.169.254"])
    ok, msg = lab_env._pull_release("http://meta.example/fw.bin",
                                    security.DATA_DIR / "y", 5)
    assert ok is False
    assert "安全网关" in msg


# ── 配置 ──────────────────────────────────────────────────
def test_config_lab_section_exists():
    cfg = config.load(force=True)
    assert "lab" in cfg
    assert "root" in cfg["lab"]
    assert "docker_enabled" in cfg["lab"]


def test_config_rejects_bad_lab_timeout():
    with pytest.raises(ValueError):
        config.update({"lab": {"timeout": 99999}})


def test_config_lab_root_accepts_empty():
    cfg = config.update({"lab": {"root": ""}})
    assert cfg["lab"]["root"] == ""
