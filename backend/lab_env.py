"""lab_env.py —— 本地复现环境搭建

目的：把漏洞播报里"影响设备与型号"落成一台能跑的机器，用来验证 LLM 生成的 PoC
到底能不能用。

流程：
  1. 读漏洞条目（名称/原理/攻击范围/组件）→ 让 LLM 判断该复现哪个组件、哪个版本，
     以及能从哪里拿到程序本体；
  2. LLM 说"拿不到"（闭源设备固件、找不到公开下载）→ 直接放弃，记一条放弃理由，
     不硬造一个假环境；
  3. 拿得到 → 按 docker / 源码仓库 / 官方发布包三种方式之一真去拉，落盘到统一目录；
  4. 环境按「组件+版本+来源」算指纹，同一个指纹只建一份，多条漏洞共享同一环境。

资产都落在 lab.root（设置页可配）下：
  <root>/envs/<env_id>/meta.json   环境元数据
  <root>/envs/<env_id>/source/     源码 clone
  <root>/envs/<env_id>/binary/     官方二进制/固件包
  <root>/envs/<env_id>/docker/     docker 镜像与容器记录

安全口径：
  - 拉取地址一律过 security.check_url（挡内网与云元数据地址）
  - 镜像名走正则白名单，git/docker 命令用参数数组调用（不经过 shell）
  - 所有落盘路径经 security.safe_join 约束在 root 之内
"""
from __future__ import annotations

import hashlib
import json
import logging
import os
import re
import shlex
import shutil
import socket
import stat
import subprocess
import sys
import threading
import time
from datetime import UTC, datetime
from pathlib import Path
from urllib.parse import urlparse, urlunparse

import config
import net
import nuclei_sync
import security
import store
from llm import field_so_far, get_llm

logger = logging.getLogger("ai_bobao.lab_env")

MAX_NAME_LEN = 80
MAX_URL_LEN = security.MAX_URL_LEN
MAX_LOG_CHARS = 4000
MAX_PORTS = 8
MAX_DOWNLOAD = 64 * 1024 * 1024   # 固件包比模板大得多，单独放宽
MAX_OVERLAY = 4                   # 补充仓库最多几个
MAX_SETUP = 12                    # 容器内准备命令最多几条
MAX_CMD_LEN = 300                 # 单条命令最长多少字符

# 「先看方案」不再单独设短超时：走全局 llm.timeout（默认 300 秒），并且
# 新链路 plan_env_stream 是流式的——模型每生成一段就实时推给前端，
# 用户从第一秒起就能看到方案在逐字成形，不存在「点了没反应」的干等。

# 环境状态
STATUS_READY = "ready"        # 已就绪，未启动
STATUS_RUNNING = "running"    # 服务真的在监听（健康检查通过）
STATUS_STARTING = "starting"  # 容器已创建、服务还在起（健康检查进行中）
STATUS_BUILDING = "building"  # 正在拉取程序本体/构建镜像（中间态，轮询可见）
STATUS_FAILED = "failed"      # 拉取失败
STATUS_ABANDONED = "abandoned"  # 网上拿不到，已放弃

# 来源类型
SRC_DOCKER = "docker"
SRC_SOURCE = "source"
SRC_RELEASE = "release"
SRC_NONE = "none"

# 镜像名白名单：小写字母数字，斜杠分层，冒号打标签。不允许 "-"/"--" 开头
# （会被 docker 当成命令行选项），也不允许 ".."。
_IMAGE_RE = re.compile(r"^[a-z0-9][a-z0-9._/-]{0,255}(?::[A-Za-z0-9._-]{1,128})?$")
_EID_RE = re.compile(r"^[0-9a-f]{12}$")

# Windows 下别弹黑框
_NO_WINDOW = getattr(subprocess, "CREATE_NO_WINDOW", 0) if os.name == "nt" else 0

# 同一时刻只允许一个环境在构建，别把磁盘和 Docker 同时塞满
_build_lock = threading.Lock()

# 构建取消事件：vid → Event。build() 开头注册、finally 注销；cancel_build()
# 把事件一 set，正在跑的 docker pull / git clone / docker build 子进程立刻被杀，
# 各阶段间的检查点也会让 build() 不再往下走。用户点「拒绝，停止」是最高优先级。
_CANCEL: dict[str, threading.Event] = {}
# 取消后 build() 退出时 set，cancel_build() 等它确认 build 线程真的停了，
# 再去清理半成品缓存（拉了一半的源码/固件目录、自建镜像）。
_CANCEL_DONE: dict[str, threading.Event] = {}


def _canceled_result(d: Path, plan: dict, eid: str, meta: dict, vid: str) -> dict:
    """构建被用户取消：把环境记成失败（原因「用户取消」），返回取消结果。

    后续的正常写盘不会再发生——各检查点命中后直接 return，不会被覆盖。
    """
    rec = {
        "id": eid, "component": plan["component"], "version": plan["version"],
        "device": plan["device"], "source": plan["source"], "mode": plan["mode"],
        "image": _built_tag(eid) if plan["mode"] == "build" else plan["image"],
        "base_image": plan["base_image"],
        "repo": plan["repo"], "ref": plan["ref"], "overlay": plan["overlay"],
        "release": plan["release"], "cmd": plan["cmd"], "setup": plan["setup"],
        "ports": plan["ports"], "port_map": plan["port_map"],
        "size_estimate": plan.get("size_estimate", ""),
        "status": STATUS_FAILED, "reason": "用户取消",
        "vulns": _merge_vulns(meta, vid),
        "created_at": (meta or {}).get("created_at") or _now(), "log": "用户取消",
        "dir": str(d),
    }
    _write_meta(d, rec)
    store.patch_meta(vid, {"env_id": eid, "env_status": STATUS_FAILED})
    logger.info("环境 %s 构建被用户取消", eid)
    return {"ok": False, "canceled": True, "env": _view(rec), "reason": "用户取消"}


class EnvError(Exception):
    """环境模块失败。status 供 HTTP 层选状态码，message 是给用户看的说明。"""

    def __init__(self, message: str, status: int = 400):
        super().__init__(message)
        self.message = message
        self.status = status


# ── 目录 ──────────────────────────────────────────────────
def default_root() -> Path:
    """默认资产根目录：后端 data/lab_envs。"""
    return config.DATA_DIR / "lab_envs"


def root_dir() -> Path:
    """当前生效的资产根目录。设置页配了 lab.root 就用它，否则用默认目录。"""
    raw = str(config.get("lab", "root") or "").strip()
    if not raw:
        return default_root()
    p = Path(raw).expanduser()
    if not p.is_absolute():
        p = (config.BASE_DIR / p).resolve()
    return p


def _envs_dir() -> Path:
    return security.safe_join(root_dir(), "envs")


def _env_dir(eid: str) -> Path:
    if not _EID_RE.match(eid or ""):
        raise EnvError("环境 ID 不合法", 400)
    return security.safe_join(_envs_dir(), eid)


def _now() -> str:
    return datetime.now(UTC).isoformat(timespec="seconds")


# ── 元数据读写 ────────────────────────────────────────────
def _read_meta(d: Path) -> dict:
    f = d / "meta.json"
    if not f.is_file():
        return {}
    try:
        m = json.loads(f.read_text(encoding="utf-8", errors="replace"))
    except (OSError, ValueError):
        return {}
    return m if isinstance(m, dict) else {}


def _write_meta(d: Path, meta: dict) -> dict:
    d.mkdir(parents=True, exist_ok=True)
    meta = {**meta, "updated_at": _now()}
    tmp = d / "meta.json.tmp"
    tmp.write_text(json.dumps(meta, ensure_ascii=False, indent=2), encoding="utf-8")
    tmp.replace(d / "meta.json")
    return meta


def _display_url(m: dict) -> str:
    """页面上展示给用户的靶站地址。

    内部记的 target_url 永远是回环地址（PoC 验证、健康检查都走它，不受主机
    防火墙和网络状况影响），但那个地址别的机器点不开。对局域网开放时，
    展示地址要换成对外可达的 IP。
    """
    u = _target_url(m)
    if not u:
        return ""
    p = urlparse(u)
    host = p.hostname or "127.0.0.1"
    if security.lan_enabled():
        host = security.public_host()
    if not host:
        return u
    netloc = f"{host}:{p.port}" if p.port else host
    return urlunparse((p.scheme or "http", netloc, p.path or "", p.params, p.query, p.fragment))


def _view(m: dict) -> dict:
    """环境条目的对外形状。内部字段（比如落盘绝对路径）只在详情里给。"""
    return {
        "id": str(m.get("id") or ""),
        "component": str(m.get("component") or ""),
        "version": str(m.get("version") or ""),
        "device": str(m.get("device") or ""),
        "source": str(m.get("source") or SRC_NONE),
        "mode": str(m.get("mode") or ""),
        "image": str(m.get("image") or ""),
        "base_image": str(m.get("base_image") or ""),
        "repo": str(m.get("repo") or ""),
        "ref": str(m.get("ref") or ""),
        "overlay": list(m.get("overlay") or []),
        "release": str(m.get("release") or ""),
        "setup": list(m.get("setup") or []),
        "cmd": str(m.get("cmd") or ""),
        "ports": list(m.get("ports") or []),
        "port_map": list(m.get("port_map") or []),
        "size_estimate": str(m.get("size_estimate") or ""),
        "status": str(m.get("status") or STATUS_FAILED),
        "reason": str(m.get("reason") or ""),
        "vulns": list(m.get("vulns") or []),
        "container": str(m.get("container") or ""),
        "pid": int(m.get("pid") or 0),
        "target_url": _display_url(m),
        "verify": m.get("verify") if isinstance(m.get("verify"), dict) else None,
        "created_at": str(m.get("created_at") or ""),
        "updated_at": str(m.get("updated_at") or ""),
        "log": str(m.get("log") or "")[-MAX_LOG_CHARS:],
    }


# ── 外部命令 ──────────────────────────────────────────────
def _run(args: list[str], timeout: int = 300, cwd: Path | None = None,
         cancel: threading.Event | None = None) -> tuple[int, str]:
    """跑一条外部命令，返回 (退出码, 输出文本)。

    一律用参数数组、不开 shell，命令内容里带空格、引号、$ 都当普通字符传给程序，
    不会被 shell 再解释一遍。输出按 UTF-8 解码、坏字节替换，Windows 控制台
    编码是 GBK，不这么处理日志全是乱码。

    cancel 给了就在 0.5 秒粒度上盯着：事件一 set 立刻杀掉子进程返回 130，
    docker pull / git clone 这类长命令才能做到「点停止马上停」，而不是等它跑完。
    """
    try:
        proc = subprocess.Popen(
            args, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            cwd=str(cwd) if cwd else None, shell=False, creationflags=_NO_WINDOW)
    except FileNotFoundError:
        return 127, f"命令不存在：{args[0]}"
    except OSError as e:
        return 1, f"命令执行失败：{e}"
    deadline = time.monotonic() + max(timeout, 1)
    out: bytes = b""
    err: bytes = b""
    while True:
        if cancel is not None and cancel.is_set():
            proc.kill()
            try:
                proc.wait(timeout=10)
            except subprocess.TimeoutExpired:
                pass
            return 130, "命令已被用户取消"
        try:
            out, err = proc.communicate(timeout=0.5)
            break  # 进程正常退出
        except subprocess.TimeoutExpired:
            if time.monotonic() >= deadline:
                proc.kill()
                try:
                    proc.wait(timeout=10)
                except subprocess.TimeoutExpired:
                    pass
                return 124, f"命令超时（{timeout}s）：{' '.join(args[:2])}"
    out = out + b"\n" + err
    return proc.returncode, out.decode("utf-8", "replace").strip()


def docker_available() -> bool:
    """本机有没有能用的 Docker（客户端在、服务端也通）。"""
    code, _ = _run(["docker", "version", "--format", "{{.Server.Version}}"], timeout=15)
    return code == 0


def _docker_enabled() -> bool:
    return bool(config.get("lab", "docker_enabled"))


# ── LLM 出方案 ────────────────────────────────────────────
_PLAN_SYS = (
    "你是资深安全研究员，为漏洞播报系统规划「本地复现环境」，用于在本地沙箱里验证"
    "PoC 是否可用，已授权，不要反复询问授权/教育目的。\n"
    "根据漏洞信息判断要复现哪个组件、哪个版本，并找出能从公网拿到该组件程序本体的渠道。\n"
    "只返回 JSON："
    '{"component": "组件名", "version": "版本或版本范围", '
    '"device": "受影响的设备/型号/固件型号，没有就空字符串", '
    '"source": "docker|source|release|none", '
    '"image": "现成镜像名，仅 source=docker 时填（如 tomcat:9.0.0），否则空字符串", '
    '"base_image": "运行时基础镜像，仅 source=source/release 时填'
    '（如 php:7.4-cli-alpine），可空字符串", '
    '"repo": "官方源码仓库 https 地址（如 https://github.com/apache/tomcat），'
    '仅 source=source 时填，否则空字符串", '
    '"ref": "源码仓库的分支或 tag（如 5.0、v5.0.20），可空字符串", '
    '"overlay": [{"repo": "https://github.com/top-think/framework", "ref": "v5.0.20", '
    '"dest": "thinkphp"}], '
    '"release": "官方二进制/固件包的 https 直链，仅 source=release 时填，否则空字符串", '
    '"setup": ["容器内启动前要执行的准备命令，如 mkdir -p runtime"], '
    '"cmd": "容器启动命令（覆盖镜像默认 CMD），如 php -S 0.0.0.0:80 -t public public/router.php", '
    '"ports": [8080], "port_map": [{"host": 18081, "container": 80}], '
    '"size_estimate": "预估磁盘占用：镜像约 XX MB + 源码约 XX MB，合计约 XX MB（逐项列，别拍脑袋给总数）", '
    '"available": true, '
    '"reason": "拿不到时写清原因，如闭源无公开下载、组件名无法定位"}\n'
    "铁律：\n"
    "1. 只有确实能从公网拿到该组件程序本体时 available 才为 true。闭源设备固件、"
    "硬件厂商私有协议、找不到公开下载的组件一律 false，并在 reason 里说明，不要硬凑。\n"
    "2. 镜像名与下载地址必须是真实存在的官方或公认来源，不确定就给 false，不要编造。\n"
    "3. 只规划程序本体，不规划攻击步骤。\n"
    "4. version 照抄漏洞描述里的版本信息，别自己猜版本。\n"
    "5. 基础镜像要选官方的、尽量小的变体（alpine/slim），别选带完整桌面或大运行时的镜像。\n"
    "6. overlay 是补充仓库：主仓库里缺的运行时/框架本体单独再拉一个仓库放进指定子目录。"
    "dest 写相对路径，不要写 .. 或绝对路径。\n"
    "7. port_map 写宿主机端口到容器端口的映射，host 选 1024 以上、不常用的端口；"
    "容器端口填组件真正监听的端口。\n"
    "8. size_estimate 是用户决定批不批的关键：按公开资料逐项估（基础镜像多大、"
    "框架源码多大、依赖多大），给单项数字和合计；估不出来就写「约 XX，不确定」，"
    "不许隐瞒体积或写个模糊的『不大』。"
)


def _norm_overlay(items) -> list[dict]:
    """收敛 overlay 列表：补充仓库。地址只认 http/https，dest 只认安全的相对路径。

    dest 会被拼进容器内的 COPY 路径，形状不收窄的话 "../" 能把文件写到
    镜像工作目录外面去。
    """
    out: list[dict] = []
    for it in (items or [])[:MAX_OVERLAY]:
        if not isinstance(it, dict):
            continue
        repo = str(it.get("repo") or "").strip()[:MAX_URL_LEN]
        if not repo.startswith(("http://", "https://")):
            continue
        ref = str(it.get("ref") or "").strip()[:100]
        if ref and not security.valid_ref(ref):
            ref = ""
        dest = str(it.get("dest") or "").strip().strip("/\\")[:100]
        # dest 必须是相对路径且不含 ..，否则 COPY 能写到工作目录之外
        if not dest or ".." in dest or dest.startswith(("/", "\\")) or ":" in dest:
            continue
        out.append({"repo": repo, "ref": ref, "dest": dest})
    return out


def _norm_plan(r: dict) -> dict:
    """把 LLM 返回的方案收敛成可控形状。LLM 说什么都不能直接拿去拼命令。"""
    src = str(r.get("source") or "").strip().lower()
    if src not in (SRC_DOCKER, SRC_SOURCE, SRC_RELEASE):
        src = SRC_NONE

    image = str(r.get("image") or "").strip()[:300]
    base_image = str(r.get("base_image") or "").strip()[:300]
    repo = str(r.get("repo") or "").strip()[:MAX_URL_LEN]
    release = str(r.get("release") or "").strip()[:MAX_URL_LEN]
    ref = str(r.get("ref") or "").strip()[:100]
    if ref and not security.valid_ref(ref):
        ref = ""

    available = bool(r.get("available"))
    reason = str(r.get("reason") or "").strip()[:300]

    # 镜像名形状不对（带空格、带 --、带 ..）直接作废，别拿去拼 docker 命令
    for key, val in (("image", image), ("base_image", base_image)):
        if val and (not _IMAGE_RE.match(val) or ".." in val):
            if key == "image":
                src = SRC_NONE
                available = False
            reason = reason or f"{key} 镜像名不合法，已放弃"
            if key == "image":
                image = ""
            else:
                base_image = ""

    # 地址只认 http/https，其他协议（file://、ftp://）一律作废
    for key, val in (("repo", repo), ("release", release)):
        if val and not val.startswith(("http://", "https://")):
            src = SRC_NONE
            available = False
            reason = reason or f"{key} 地址不是 http/https，已放弃"

    if src == SRC_NONE:
        available = False

    overlay = _norm_overlay(r.get("overlay"))
    if src == SRC_SOURCE and overlay and not repo:
        src = SRC_NONE
        available = False
        reason = reason or "只有补充仓库、没有主仓库，已放弃"

    # 准备命令与启动命令：限制条数和长度，命令里不许出现换行（防止拼出多行脚本）
    setup = []
    for c in (r.get("setup") or [])[:MAX_SETUP]:
        text = str(c or "").strip()
        if text and len(text) <= MAX_CMD_LEN and "\n" not in text and "\r" not in text:
            setup.append(text)
    cmd = str(r.get("cmd") or "").strip()[:MAX_CMD_LEN]
    if "\n" in cmd or "\r" in cmd:
        cmd = ""

    ports = []
    for p in (r.get("ports") or [])[:MAX_PORTS]:
        try:
            n = int(p)
        except (TypeError, ValueError):
            continue
        if 1 <= n <= 65535:
            ports.append(n)

    port_map = []
    for pm in (r.get("port_map") or [])[:MAX_PORTS]:
        if not isinstance(pm, dict):
            continue
        try:
            host = int(pm.get("host"))
            ctr = int(pm.get("container"))
        except (TypeError, ValueError):
            continue
        if 1024 <= host <= 65535 and 1 <= ctr <= 65535:
            port_map.append({"host": host, "container": ctr})

    # 跑起来的方式：
    #   source=docker → 直接跑现成镜像
    #   source=source/release 且给了 base_image → 拿基础镜像自建（源码拷进去 + setup）
    #   其它 → 本机裸跑进程
    if src == SRC_DOCKER:
        mode = "docker"
    elif base_image:
        mode = "build"
    else:
        mode = "native"

    return {
        "component": str(r.get("component") or "").strip()[:MAX_NAME_LEN],
        "version": str(r.get("version") or "").strip()[:MAX_NAME_LEN],
        "device": str(r.get("device") or "").strip()[:MAX_NAME_LEN],
        "source": src,
        "mode": mode,
        "image": image if src == SRC_DOCKER else "",
        "base_image": base_image if src in (SRC_SOURCE, SRC_RELEASE) else "",
        "repo": repo if src == SRC_SOURCE else "",
        "ref": ref if src == SRC_SOURCE else "",
        "overlay": overlay if src == SRC_SOURCE else [],
        "release": release if src == SRC_RELEASE else "",
        "setup": setup,
        "cmd": cmd,
        "ports": ports,
        "port_map": port_map,
        "size_estimate": str(r.get("size_estimate") or "").strip()[:300],
        "available": available,
        "reason": reason,
    }


def _plan_brief(v: dict) -> str:
    """给模型的漏洞摘要，plan_env / plan_env_stream 共用。"""
    brief = {
        "name": v.get("name", ""),
        "summary": str(v.get("summary") or "")[:300],
        "principle": str(v.get("principle") or "")[:600],
        "attack_scope": str(v.get("attack_scope") or "")[:400],
        "component": v.get("component", ""),
        "refs": list(v.get("refs") or [])[:5],
    }
    return json.dumps(brief, ensure_ascii=False)


def _plan_messages(v: dict) -> list[dict]:
    return [{"role": "system", "content": _PLAN_SYS},
            {"role": "user", "content": _plan_brief(v)}]


def plan_env(vid: str, llm=None) -> dict:
    """让 LLM 给出这个漏洞的复现环境方案。不落盘，纯预判。"""
    v = store.get_vuln(vid)
    if not v:
        raise EnvError("漏洞不存在", 404)
    llm = llm or get_llm()
    try:
        r = llm.chat(_PLAN_SYS, _plan_brief(v))
    except Exception as e:  # LLM 挂了就是给不出方案，如实说
        raise EnvError(f"LLM 不可用：{e}", 502) from e
    return _norm_plan(r if isinstance(r, dict) else {})


# 流式方案里值得实时展示的字段：都是短文本，值一变就把完整值推给前端。
# available 是布尔、setup/ports/port_map/overlay 是结构，不适合逐字播报，不列。
_PLAN_STREAM_FIELDS = ("component", "version", "device", "source", "image",
                       "repo", "ref", "release", "size_estimate", "reason")


def plan_env_stream(vid: str, llm=None):
    """plan_env 的流式版：方案一边生成一边 yield 出去。

    yield 的事件（dict）：
      {"type": "field", "field": 字段名, "text": 该字段已生成的完整值}
      {"type": "done", "plan": 规范化后的完整方案}

    模型按 _PLAN_SYS 约定的顺序逐字段写 JSON，这里用 llm.field_so_far
    从半截 JSON 里实时抠字段值，前端能看到方案逐字成形，不用干等整段。
    失败抛 EnvError（与 plan_env 一致）。
    """
    v = store.get_vuln(vid)
    if not v:
        raise EnvError("漏洞不存在", 404)
    llm = llm or get_llm()

    shown: dict[str, str] = {}
    chunks: list[str] = []
    try:
        for piece in llm.chat_stream(_plan_messages(v), json_mode=True):
            chunks.append(piece)
            raw = "".join(chunks)
            for f in _PLAN_STREAM_FIELDS:
                val = field_so_far(raw, f)
                if val and val != shown.get(f):
                    shown[f] = val
                    yield {"type": "field", "field": f, "text": val}
    except EnvError:
        raise
    except Exception as e:  # LLM 挂了就是给不出方案，如实说
        raise EnvError(f"LLM 不可用：{e}", 502) from e

    raw = "".join(chunks)
    try:
        r = json.loads(raw)
    except ValueError:
        # 整段没闭合（连接中断之类）：拿流式过程中抠到的字段兜底拼方案，
        # _norm_plan 会把缺的字段补成空值并做可用性收窄，不会带出脏数据
        r = dict(shown)
    yield {"type": "done", "plan": _norm_plan(r if isinstance(r, dict) else {})}


# ── 指纹与共享 ────────────────────────────────────────────
def _merge_vulns(meta: dict | None, vid: str) -> list[str]:
    """合并漏洞关联列表：已有环境上的漏洞不能被后来的构建挤掉。"""
    vulns = list((meta or {}).get("vulns") or [])
    if vid not in vulns:
        vulns.append(vid)
    return vulns


def _fingerprint(plan: dict) -> str:
    """环境指纹：来源类型 + 实际拿到的资源。同指纹就是同一份资产，多条漏洞共享。

    只认"资源"不认"组件名/版本号"——这两个字段是模型用自然语言描述的，
    同一个东西在不同漏洞里可能被写成 "OpenSSH" 和 "OpenSSH sshd（musl libc）"、
    "10.6p2 之前" 和 "低于 10.6p2"，拿描述当身份会把同一份源码拆成好几个环境，
    白白重复 clone 一遍。资源才是真正决定下载内容的东西：
      · docker → 镜像名自带 tag，版本不同就是不同镜像
      · source → 仓库地址决定拉哪份代码（clone 拉的是 HEAD，本来就没锁版本）
      · release → 下载地址自带版本
    """
    resource = (plan.get("image") or plan.get("repo") or plan.get("release") or "").strip()
    if not resource:
        # 拿不到资源就没法判断共享，退回描述字段，至少保证不同描述不撞车
        resource = "|".join([plan.get("component", "").strip().lower(),
                             plan.get("version", "").strip().lower()])
    # 同一个仓库的不同 ref 是两份不同的程序本体，必须分开建环境
    ref = str(plan.get("ref") or "").strip()
    if ref:
        resource = f"{resource}@{ref}"
    # 补充仓库换了，程序本体也跟着变
    overlay = plan.get("overlay") or []
    if overlay:
        extra = "|".join(f"{o.get('repo','')}@{o.get('ref','')}#{o.get('dest','')}"
                         for o in overlay if isinstance(o, dict))
        resource = f"{resource}|{extra}"
    key = f"{plan.get('source', '')}|{resource.lower().rstrip('/')}"
    return hashlib.sha1(key.encode("utf-8")).hexdigest()[:12]


# ── 拉取执行 ──────────────────────────────────────────────
def _pull_docker(image: str, timeout: int,
                 cancel: threading.Event | None = None) -> tuple[bool, str]:
    if not _docker_enabled():
        return False, "设置里已关闭 docker 拉取"
    if not docker_available():
        return False, "本机没有可用的 Docker"
    code, out = _run(["docker", "pull", image], timeout=timeout, cancel=cancel)
    if code == 130:
        return False, out
    if code != 0:
        return False, f"镜像拉取失败：{out[-500:]}"
    return True, out[-500:]


def _private_hint(e: Exception) -> str:
    """被拦在"内网地址"上时补一句怎么放行。

    本机装了加速器（Steam++ 之类）时，github.com 会被 hosts 指到 127.0.0.1，
    源码仓库地址就归到内网去了，网关照规矩拦下——这是对的，但用户不知道
    怎么解决，只看到一句"不允许访问"就懵了。给出具体开关。
    """
    if "内网" in str(e) or "保留地址" in str(e):
        return ("（本机若装了加速器把域名指向 127.0.0.1，可设环境变量 "
                "AI_BAOBAO_ALLOW_PRIVATE=1 后重启后端放行）")
    return ""


# 地址"确实不存在"的标志。命中这些说明网上根本没有这个东西（或者站点
# 明确拒绝提供），按用户的要求该直接放弃，而不是记成一次构建失败。
# HTTP 301 只有在重定向成死循环时才会以错误形式冒出来（正常的 301 会被
# urllib 悄悄跟完），说明这个地址根本指不到文件，同样算"拿不到"。
_UNAVAILABLE_MARKS = (
    "HTTP 301", "HTTP 404", "HTTP 403", "HTTP 410", "HTTP 451",
    "repository not found", "could not read from remote repository",
    "does not exist", "no such file or directory",
)


def _is_unavailable(log: str) -> bool:
    """这次拉取失败是不是因为"网上就没有这个东西"。"""
    low = (log or "").lower()
    return any(m.lower() in low for m in _UNAVAILABLE_MARKS)


def _pull_source(url: str, dest: Path, timeout: int, ref: str = "",
                 cancel: threading.Event | None = None) -> tuple[bool, str]:
    """clone 官方源码仓库。地址先过 SSRF 网关，挡内网与云元数据地址。

    ref 给了就拉那个分支/tag（--branch 对 tag 同样管用），不拉默认分支。
    同一仓库的不同版本是两份不同的程序本体，ref 必须进 clone 命令。
    """
    try:
        security.check_url(url)
    except security.SecurityError as e:
        return False, f"源码地址被安全网关拦下：{e}{_private_hint(e)}"
    git = nuclei_sync.find_git()
    if not git:
        return False, "未找到 git，可执行文件未加入 PATH，无法拉取源码"
    if dest.exists():
        _rmtree(dest)
    dest.parent.mkdir(parents=True, exist_ok=True)
    args = [git, "clone", "--depth", "1", "--quiet"]
    if ref:
        args += ["--branch", ref]
    args += [url, str(dest)]
    code, out = _run(args, timeout=timeout, cancel=cancel)
    if code == 130:
        return False, out
    if code != 0:
        return False, f"源码拉取失败：{out[-500:]}"
    return True, out[-500:]


def _pull_overlay(items: list[dict], base: Path, timeout: int,
                  cancel: threading.Event | None = None) -> tuple[bool, str]:
    """把补充仓库拉到指定子目录。

    典型场景：应用骨架仓库里没有框架本体（ThinkPHP 的 top-think/think 只算
    应用骨架，运行时在 top-think/framework），两边拼起来才是一份能跑的程序。
    """
    logs: list[str] = []
    for it in items:
        repo = str(it.get("repo") or "")
        ref = str(it.get("ref") or "")
        dest = str(it.get("dest") or "")
        try:
            target = security.safe_join(base, dest)
        except security.SecurityError as e:
            return False, f"补充仓库落盘路径不合法：{e}"
        ok, out = _pull_source(repo, target, timeout, ref, cancel)
        if not ok:
            return False, f"补充仓库拉取失败（{repo}）：{out[-300:]}"
        logs.append(f"{repo}@{ref or 'HEAD'} → {dest}")
    return True, "\n".join(logs)


def _pull_release(url: str, dest: Path, timeout: int) -> tuple[bool, str]:
    """下载官方发布包/固件。走 net.http_get，也就是 security.open_url 那道网关。"""
    try:
        security.check_url(url)
    except security.SecurityError as e:
        return False, f"下载地址被安全网关拦下：{e}{_private_hint(e)}"
    try:
        raw = net.http_get(url, timeout=timeout, max_bytes=MAX_DOWNLOAD)
    except Exception as e:  # noqa: BLE001 —— 网关的各类失败统一报出来
        return False, f"下载失败：{e}"
    dest.parent.mkdir(parents=True, exist_ok=True)
    name = url.rsplit("/", 1)[-1].split("?")[0] or "package.bin"
    name = re.sub(r"[^A-Za-z0-9._-]", "_", name)[:80]
    dest.mkdir(parents=True, exist_ok=True)
    (dest / name).write_bytes(raw)
    return True, f"{name}（{len(raw)} 字节）"


def _dockerfile_text(plan: dict) -> str:
    """按方案生成 Dockerfile。

    运行时基础镜像 + 落盘的程序本体 = 一份能跑起来的镜像。
    setup 是容器内的准备命令（建目录、改权限），cmd 是启动命令。
    """
    src = str(plan.get("source") or "")
    root = "/var/www/html" if src == SRC_SOURCE else "/opt/app"
    copy_from = "source/" if src == SRC_SOURCE else "binary/"
    lines = [f"FROM {plan.get('base_image') or ''}", f"WORKDIR {root}",
             f"COPY {copy_from}/ {root}/"]
    setup = list(plan.get("setup") or [])
    if setup:
        lines.append("RUN " + " && ".join(setup))
    ports = [int(p) for p in (plan.get("ports") or []) if isinstance(p, int)]
    if ports:
        lines.append("EXPOSE " + " ".join(str(p) for p in ports))
    cmd = str(plan.get("cmd") or "").strip()
    if cmd:
        try:
            parts = shlex.split(cmd)
        except ValueError:
            parts = []
        # exec 形式（JSON 数组）不经过 shell，命令里带空格引号也不会被二次解释
        lines.append("CMD " + (json.dumps(parts) if parts else cmd))
    return "\n".join(lines) + "\n"


def _build_image(plan: dict, d: Path, timeout: int, eid: str,
                 cancel: threading.Event | None = None) -> tuple[bool, str]:
    """用基础镜像 + 落盘的程序本体自建一个镜像。"""
    base = str(plan.get("base_image") or "")
    if not base or not _IMAGE_RE.match(base) or ".." in base:
        return False, "基础镜像名不合法，无法自建镜像"
    if not _docker_enabled():
        return False, "设置里已关闭 docker 拉取"
    if not docker_available():
        return False, "本机没有可用的 Docker"
    ok, log = _pull_docker(base, timeout, cancel)
    if not ok:
        return False, f"基础镜像拉取失败：{log[-300:]}"
    tag = f"ai_bb_lab_{eid}:1" if eid else "ai_bb_lab_build:1"
    df = d / "Dockerfile"
    df.write_text(_dockerfile_text(plan), encoding="utf-8")
    # .git 有几百 MB，拉进构建上下文纯粹浪费时间和磁盘
    (d / ".dockerignore").write_text(".git\n**/.git\n", encoding="utf-8")
    code, out = _run(["docker", "build", "-t", tag, "-f", str(df), str(d)],
                     timeout=timeout, cancel=cancel)
    if code == 130:
        return False, out
    if code != 0:
        return False, f"镜像构建失败：{out[-800:]}"
    code, out = _run(["docker", "image", "inspect", tag, "--format", "{{.Size}}"], timeout=60)
    if code == 0:
        try:
            size = int(out.strip())
            return True, f"自建镜像 {tag}（{size // 1048576}MB）"
        except ValueError:
            pass
    return True, f"自建镜像 {tag}"


def _build_assets(plan: dict, d: Path, timeout: int, eid: str = "",
                  cancel: threading.Event | None = None) -> tuple[bool, str]:
    """按方案真去拉程序本体。返回 (成功与否, 说明)。"""
    src = plan["source"]
    mode = str(plan.get("mode") or "")
    if src == SRC_DOCKER:
        return _pull_docker(plan["image"], timeout, cancel)
    if src == SRC_SOURCE:
        ok, log = _pull_source(plan["repo"], d / "source", timeout,
                               plan.get("ref", ""), cancel)
        if not ok:
            return False, log
        overlay = plan.get("overlay") or []
        if overlay:
            ok2, log2 = _pull_overlay(overlay, d / "source", timeout, cancel)
            if not ok2:
                return False, log2
            log = f"{log}\n{log2}".strip()
        if mode == "build":
            return _build_image(plan, d, timeout, eid, cancel)
        return True, log
    if src == SRC_RELEASE:
        ok, log = _pull_release(plan["release"], d / "binary", timeout)
        if not ok:
            return False, log
        if cancel is not None and cancel.is_set():
            return False, "命令已被用户取消"
        if mode == "build":
            return _build_image(plan, d, timeout, eid, cancel)
        return True, log
    return False, plan.get("reason") or "网上找不到可获取的程序本体"


# ── 生命周期 ──────────────────────────────────────────────
def build(vid: str, llm=None, plan: dict | None = None) -> dict:
    """为一条漏洞搭复现环境。已有同指纹环境就直接共享，不再拉一遍。

    拿不到程序本体时返回 abandoned，并把理由记进环境条目 —— 用户能在列表里
    看到"这条放弃了、为什么"，而不是静悄悄地什么都不发生。

    plan：用户审批过的方案（前端 resolve 后点「按此方案搭建」带回来的）。
    传了就不再问 LLM，方案即最终决定 —— 规划归规划、审批归审批，
    用户没点头的东西一分钱带宽都不该花。
    """
    v = store.get_vuln(vid)
    if not v:
        raise EnvError("漏洞不存在", 404)

    ev = _CANCEL.setdefault(vid, threading.Event())
    _CANCEL_DONE.setdefault(vid, threading.Event())
    if not _build_lock.acquire(blocking=False):
        raise EnvError("已有环境在构建中，稍后再试", 429)
    try:
        if isinstance(plan, dict) and plan:
            plan = _norm_plan(plan)
        else:
            plan = plan_env(vid, llm)
        eid = _fingerprint(plan)
        d = _env_dir(eid)
        meta = _read_meta(d)

        # 检查点 1：方案刚拿到。用户已经点了「拒绝/停止」就不往下走——
        # 已经在跑的现成环境不受影响，新环境记成失败（用户取消）
        if ev.is_set():
            if meta and meta.get("status") in (STATUS_READY, STATUS_RUNNING):
                return {"ok": False, "canceled": True, "env": _view(meta),
                        "reason": "用户取消"}
            return _canceled_result(d, plan, eid, meta, vid)

        # 已有能用的环境 → 共享，把这条漏洞挂上去
        if meta and meta.get("status") in (STATUS_READY, STATUS_RUNNING):
            vulns = list(meta.get("vulns") or [])
            if vid not in vulns:
                vulns.append(vid)
                meta = _write_meta(d, {**meta, "vulns": vulns})
            store.patch_meta(vid, {"env_id": eid})
            # 复用的环境要是停着的，同样直接拉起来给个能打开的地址
            if meta.get("status") == STATUS_READY:
                try:
                    start_env(eid)
                    meta = _read_meta(d)
                except EnvError:
                    pass
            return {"ok": True, "shared": True, "env": _view(meta)}

        # 放弃：网上确实没有程序本体
        if not plan["available"] or plan["source"] == SRC_NONE:
            reason = plan.get("reason") or "网上找不到可获取的程序本体（闭源或未公开下载）"
            rec = {
                "id": eid, "component": plan["component"], "version": plan["version"],
                "device": plan["device"], "source": SRC_NONE, "mode": plan["mode"],
                "image": "", "base_image": "", "repo": "", "ref": "",
                "overlay": [], "release": "", "cmd": "", "setup": [],
                "ports": plan["ports"], "port_map": plan["port_map"],
                "size_estimate": plan.get("size_estimate", ""),
                "status": STATUS_ABANDONED, "reason": reason,
                # 之前失败/放弃过同一个资源就沿用那份关联，别把别的漏洞踢掉
                "vulns": _merge_vulns(meta, vid),
                "created_at": (meta or {}).get("created_at") or _now(),
            }
            meta = _write_meta(d, rec)
            store.patch_meta(vid, {"env_id": eid, "env_status": STATUS_ABANDONED})
            logger.info("放弃环境 %s（%s %s）：%s", eid, plan["component"], plan["version"], reason)
            return {"ok": False, "abandoned": True, "reason": reason, "env": _view(meta)}

        # 真去拉
        timeout = int(config.get("lab", "timeout") or 600)
        # 先落一份 building 状态：拉源码/构建镜像要几分钟，前端轮询这份状态
        # 就能实时播报进度，而不是干等一个不知道多久才回来的 HTTP 请求
        building = {
            "id": eid, "component": plan["component"], "version": plan["version"],
            "device": plan["device"], "source": plan["source"], "mode": plan["mode"],
            "image": _built_tag(eid) if plan["mode"] == "build" else plan["image"],
            "base_image": plan["base_image"],
            "repo": plan["repo"], "ref": plan["ref"], "overlay": plan["overlay"],
            "release": plan["release"], "cmd": plan["cmd"], "setup": plan["setup"],
            "ports": plan["ports"], "port_map": plan["port_map"],
            "size_estimate": plan.get("size_estimate", ""),
            "status": STATUS_BUILDING, "reason": "正在拉取程序本体/构建镜像…",
            "vulns": _merge_vulns(meta, vid),
            "created_at": (meta or {}).get("created_at") or _now(), "log": "",
            "dir": str(d),
        }
        meta = _write_meta(d, building)
        store.patch_meta(vid, {"env_id": eid, "env_status": STATUS_BUILDING})
        # 检查点 2：马上要真去拉了（docker pull / git clone / 下载固件，都是长活）
        if ev.is_set():
            return _canceled_result(d, plan, eid, meta, vid)
        ok, log = _build_assets(plan, d, timeout, eid, ev)
        # 检查点 3：拉取/构建刚结束。被取消时正常的结果写盘不许覆盖「用户取消」
        if ev.is_set():
            return _canceled_result(d, plan, eid, meta, vid)
        # 拉不下来有两种：一种是这个东西网上压根没有（该放弃），一种是网络/环境
        # 临时抽风（该记失败，下次还能重试）。分清楚，别把"确实没有"记成故障。
        unavailable = (not ok) and _is_unavailable(log)
        status = STATUS_READY if ok else (STATUS_ABANDONED if unavailable else STATUS_FAILED)
        reason = "" if ok else log
        rec = {
            "id": eid, "component": plan["component"], "version": plan["version"],
            "device": plan["device"], "source": plan["source"], "mode": plan["mode"],
            # 自建镜像模式下 image 存的是自己构建出来的 tag（基础镜像在 base_image）
            "image": _built_tag(eid) if plan["mode"] == "build" else plan["image"],
            "base_image": plan["base_image"],
            "repo": plan["repo"], "ref": plan["ref"], "overlay": plan["overlay"],
            "release": plan["release"], "cmd": plan["cmd"], "setup": plan["setup"],
            "ports": plan["ports"], "port_map": plan["port_map"],
            "size_estimate": plan.get("size_estimate", ""),
            "status": status,
            "reason": reason,
            "vulns": _merge_vulns(meta, vid),
            "created_at": (meta or {}).get("created_at") or _now(), "log": log,
            "dir": str(d),
        }
        meta = _write_meta(d, rec)
        store.patch_meta(vid, {"env_id": eid, "env_status": status})
        if not ok:
            logger.warning("环境 %s %s：%s", eid,
                           "放弃" if unavailable else "构建失败", log)
        # 搭好了就直接把靶站跑起来：用户要的是"一条龙到能打开的网址"，
        # 不是再让他研究怎么点启动。起容器很快（健康检查在后台跑），
        # 失败也不影响"环境已搭好"这个事实，只是要手动点一下启动。
        started_msg = ""
        if ok and (plan["ports"] or plan["port_map"]):
            # 检查点 4：环境搭好了、还没起容器。取消了就不再启动
            if ev.is_set():
                return _canceled_result(d, plan, eid, meta, vid)
            try:
                sr = start_env(eid)
                meta = _read_meta(d)
                started_msg = sr.get("message") or ""
            except EnvError as e:
                started_msg = f"自动启动没成功（{e.message}），可在列表里手动启动"
        return {"ok": ok, "env": _view(meta), "reason": reason,
                "abandoned": unavailable, "auto_start": started_msg}
    finally:
        _CANCEL.pop(vid, None)
        done = _CANCEL_DONE.pop(vid, None)
        if done:
            done.set()
        _build_lock.release()


def cancel_build(vid: str) -> dict:
    """最高优先级取消：立即终止该漏洞本次环境搭建的一切进行中任务，并清缓存。

    1. set 取消事件 → build() 里的 docker pull / git clone / docker build
       子进程在 0.5 秒内被杀，各检查点让后续步骤不再执行；
    2. 等 build 线程退出（杀子进程通常不到 1 秒，LLM 规划阶段最多等 10 秒，
       超时就不等了，build 的检查点自己会把构建标成用户取消）；
    3. 「构建中」或已被检查点标成「用户取消」的环境 → 半成品缓存一并清掉
       （拉了一半的源码/固件目录、自建镜像）；
    4. 环境已在运行/启动中 → 立即停掉容器。
    """
    ev = _CANCEL.get(vid)
    if ev:
        ev.set()
        done = _CANCEL_DONE.get(vid)
        if done:
            done.wait(timeout=10)
    stopped: list[str] = []
    cleaned: list[str] = []
    v = store.get_vuln(vid)
    eid = str((v or {}).get("env_id") or "")
    if eid and _EID_RE.match(eid):
        d = _env_dir(eid)
        m = _read_meta(d)
        st = str(m.get("status") or "")
        if st == STATUS_BUILDING:
            _cleanup_partial(d, eid, m, vid)
            cleaned.append(eid)
        elif st == STATUS_FAILED and str(m.get("reason") or "") == "用户取消":
            # build 的检查点已经把取消写进 meta：半成品资产也一并清掉
            _cleanup_partial(d, eid, m, vid)
            cleaned.append(eid)
        elif st in (STATUS_RUNNING, STATUS_STARTING):
            try:
                stop_env(eid)
                stopped.append(eid)
            except EnvError:
                pass
    return {"ok": True, "canceled": bool(ev), "stopped": stopped, "cleaned": cleaned}


def _cleanup_partial(d: Path, eid: str, meta: dict, vid: str) -> None:
    """清掉搭建一半的环境缓存：目录连同拉了一半的源码/固件一起删，自建镜像也删。

    环境是多漏洞共享的就不删目录（别的漏洞还指着它），只把状态记成失败；
    本漏洞的 env_id 关联一律解除，别留着指向一个没了的环境。
    """
    store.patch_meta(vid, {"env_id": "", "env_status": ""})
    others = [x for x in (meta.get("vulns") or []) if x != vid]
    if others:
        _write_meta(d, {**meta, "status": STATUS_FAILED, "reason": "用户取消",
                        "log": "用户取消"})
        for other in others:
            store.patch_meta(str(other), {"env_status": STATUS_FAILED})
        logger.info("环境 %s 为多漏洞共享，保留目录，仅标记取消", eid)
        return
    if str(meta.get("mode") or "") == "build":
        _run(["docker", "rmi", "-f", _built_tag(eid)], timeout=120)
    _rmtree(d)
    logger.info("已清理未完成的环境缓存 %s", eid)


def list_envs() -> dict:
    """环境列表。附带资产根目录和 Docker 可用性，前端顶部要显示这两个。"""
    base = _envs_dir()
    items = []
    if base.exists():
        for d in sorted(base.iterdir()):
            if not d.is_dir():
                continue
            m = _read_meta(d)
            if not m.get("id"):
                continue
            items.append(_view(m))
    items.sort(key=lambda x: (x["status"] == STATUS_ABANDONED, -len(x["vulns"]),
                               x["updated_at"]), reverse=False)
    return {"items": items, "root": str(root_dir()),
            "docker": docker_available(), "docker_enabled": _docker_enabled()}


def get_env(eid: str) -> dict:
    """环境详情。多返回落盘绝对路径与资产清单，方便用户自己去目录里看。"""
    d = _env_dir(eid)
    m = _read_meta(d)
    if not m.get("id"):
        raise EnvError("环境不存在", 404)
    out = _view(m)
    out["dir"] = str(d)
    out["assets"] = {
        "source": str(d / "source") if (d / "source").is_dir() else "",
        "binary": str(d / "binary") if (d / "binary").is_dir() else "",
        "docker": str(d / "docker") if (d / "docker").is_dir() else "",
    }
    return out


def _container_name(eid: str) -> str:
    return f"ai_bb_lab_{eid}"


def _built_tag(eid: str) -> str:
    """自建镜像的 tag。跟 _build_image 里保持一致。"""
    return f"ai_bb_lab_{eid}:1"


def _image_exposed_ports(image: str) -> list[int]:
    """问镜像自己：里面进程真正监听哪些端口（EXPOSE 指令）。

    计划里的 ports 是 LLM 按"组件对外习惯端口"填的，现成镜像里实际监听的
    端口以镜像为准 —— vulhub/thinkphp 就是典型：宿主习惯用 8080，
    容器里 Apache 只听 80。同端口硬连会把流量打进一个没人监听的端口。
    """
    code, out = _run(["docker", "image", "inspect", image,
                      "--format", "{{json .Config.ExposedPorts}}"], timeout=60)
    if code != 0 or not out.strip():
        return []
    try:
        raw = json.loads(out.strip())
    except ValueError:
        return []
    ports: list[int] = []
    for k in (raw or {}):
        try:
            ports.append(int(str(k).rsplit("/", 1)[0]))
        except ValueError:
            continue
    return ports


def _port_args(m: dict) -> tuple[list[str], int]:
    """docker run 的端口映射参数，以及对外暴露的宿主机端口。

    port_map 优先（host:container 能把 80 映射到宿主机 18081）；没有 port_map
    就退回 ports：容器侧端口以镜像 EXPOSE 为准，对不上就映射到 EXPOSE 的第一个。
    """
    args: list[str] = []
    host_port = 0
    for pm in (m.get("port_map") or [])[:MAX_PORTS]:
        try:
            h = int(pm.get("host"))
            c = int(pm.get("container"))
        except (TypeError, ValueError):
            continue
        if not (1024 <= h <= 65535 and 1 <= c <= 65535):
            continue
        args += ["-p", f"{h}:{c}"]
        if not host_port:
            host_port = h
    if not args:
        exposed = _image_exposed_ports(str(m.get("image") or ""))
        for p in (m.get("ports") or [])[:MAX_PORTS]:
            if not isinstance(p, int) or not (1 <= p <= 65535):
                continue
            # 计划端口不在镜像 EXPOSE 里，说明 LLM 报的是宿主习惯端口；
            # 容器侧改听镜像实际暴露的端口，别把流量打进没人监听的洞里
            ctr = p if (not exposed or p in exposed) else exposed[0]
            args += ["-p", f"{p}:{ctr}"]
            if not host_port:
                host_port = p
    return args, host_port


def _start_docker(eid: str, d: Path, m: dict, timeout: int) -> dict:
    """起容器。自建镜像（mode=build）额外把源码目录挂进去，改代码不用重新构建。"""
    image = str(m.get("built_image") or m.get("image") or "")
    if not _IMAGE_RE.match(image) or ".." in image:
        raise EnvError("镜像名不合法，拒绝启动", 400)
    name = _container_name(eid)
    _run(["docker", "rm", "-f", name], timeout=60)
    args = ["docker", "run", "-d", "--name", name]
    port_args, host_port = _port_args(m)
    args += port_args
    if str(m.get("mode") or "") == "build":
        src = (d / "source").resolve()
        if src.is_dir():
            args += ["-v", f"{src.as_posix()}:/var/www/html", "-w", "/var/www/html"]
    args.append(image)
    cmd = str(m.get("cmd") or "").strip()
    if cmd:
        try:
            args += shlex.split(cmd)
        except ValueError as e:
            raise EnvError(f"启动命令解析不了：{e}", 400) from e
    code, out = _run(args, timeout=timeout)
    if code != 0:
        meta = _write_meta(d, {**m, "status": STATUS_FAILED, "reason": out[-500:]})
        raise EnvError(f"容器启动失败：{out[-300:]}", 500)
    # docker run -d 返回只代表容器被创建了，里面的 Apache/服务还要再起几秒。
    # 这时候就号称"运行中"纯属误导 —— 用户马上去打只会拿到连接失败。
    # 先挂「启动中」，后台健康检查能连上了再转正。
    patch = {"status": STATUS_STARTING, "container": name, "reason": "", "log": out[-500:]}
    if host_port:
        patch["target_url"] = f"http://127.0.0.1:{host_port}"
    meta = _write_meta(d, {**m, **patch})
    threading.Thread(target=_wait_service, args=(eid, d, patch.get("target_url", "")),
                     daemon=True).start()
    return {"ok": True, "env": _view(meta), "message": f"容器 {name} 已创建，等服务就绪…"}


def _port_open(host: str, port: int) -> bool:
    """端口能不能连上（TCP 层）。连上就说明服务在监听，能打了。"""
    try:
        with socket.create_connection((host, port), timeout=2):
            return True
    except OSError:
        return False


def _wait_service(eid: str, d: Path, url: str) -> None:
    """后台健康检查：容器里的服务端口能连上才算「运行中」，90 秒连不上算失败。"""
    host, port = "127.0.0.1", 80
    if url:
        p = urlparse(url)
        host = p.hostname or host
        port = p.port or 80
    deadline = time.time() + 90
    while time.time() < deadline:
        m = _read_meta(d)
        if str(m.get("status") or "") != STATUS_STARTING:
            return  # 被别处改了状态（比如手动停了/删了），别覆盖
        if _port_open(host, port):
            _write_meta(d, {**m, "status": STATUS_RUNNING})
            return
        time.sleep(2)
    m = _read_meta(d)
    if str(m.get("status") or "") == STATUS_STARTING:
        _write_meta(d, {**m, "status": STATUS_FAILED,
                        "reason": "容器起了但 90 秒内服务端口没监听，健康检查未通过"})


def start_env(eid: str) -> dict:
    """启动环境。docker 环境起容器，源码/二进制环境起进程。"""
    d = _env_dir(eid)
    m = _read_meta(d)
    if not m.get("id"):
        raise EnvError("环境不存在", 404)
    status = str(m.get("status") or "")
    if status == STATUS_RUNNING:
        return {"ok": True, "env": _view(m), "message": "已经在运行"}
    if status == STATUS_STARTING:
        return {"ok": True, "env": _view(m), "message": "正在启动中，等服务就绪"}
    if status in (STATUS_ABANDONED, STATUS_FAILED, STATUS_BUILDING):
        raise EnvError("这个环境没构建成功，不能启动" if status != STATUS_BUILDING
                       else "正在搭建中，等它就绪再启动", 400)

    timeout = int(config.get("lab", "timeout") or 600)
    src = str(m.get("source") or "")
    mode = str(m.get("mode") or "")
    if src == SRC_DOCKER or mode == "build":
        if not _docker_enabled():
            raise EnvError("设置里已关闭 docker 拉取", 400)
        if not docker_available():
            raise EnvError("本机没有可用的 Docker", 400)
        return _start_docker(eid, d, m, timeout)
    else:
        cmd = str(m.get("cmd") or m.get("run") or "").strip()
        if not cmd:
            raise EnvError("这个环境没配启动命令", 400)
        work = d / "source" if src == SRC_SOURCE else d / "binary"
        if not work.is_dir():
            raise EnvError("程序文件不在了", 400)
        try:
            args = shlex.split(cmd)
        except ValueError as e:
            raise EnvError(f"启动命令解析不了：{e}", 400) from e
        if not args:
            raise EnvError("启动命令是空的", 400)
        try:
            p = subprocess.Popen(args, cwd=str(work), stdout=subprocess.PIPE,
                                 stderr=subprocess.STDOUT, shell=False,
                                 creationflags=_NO_WINDOW)
        except OSError as e:
            raise EnvError(f"启动失败：{e}", 500) from e
        meta = _write_meta(d, {**m, "status": STATUS_RUNNING, "pid": p.pid,
                               "reason": "", "log": f"启动命令：{cmd}（pid {p.pid}）"})
        return {"ok": True, "env": _view(meta), "message": f"已启动（pid {p.pid}）"}


def _is_container_env(m: dict) -> bool:
    """这个环境是不是用容器跑的。docker 现成镜像和自建镜像都是容器。"""
    return (str(m.get("source") or "") == SRC_DOCKER
            or str(m.get("mode") or "") in ("docker", "build"))


def container_logs(eid: str, tail: int = 50) -> str:
    """读容器最近日志。修环境/查失败原因用——服务没起来时答案多半在这里。"""
    d = _env_dir(eid)
    m = _read_meta(d)
    if not m.get("id"):
        raise EnvError("环境不存在", 404)
    name = str(m.get("container") or "") or _container_name(eid)
    if not name:
        raise EnvError("这个环境不是容器环境，没有容器日志", 400)
    tail = max(1, min(int(tail), 200))
    code, out = _run(["docker", "logs", "--tail", str(tail), name], timeout=30)
    return out[-MAX_LOG_CHARS:] if code == 0 else f"(docker logs 退出码 {code}) {out[-500:]}"


def stop_env(eid: str) -> dict:
    """停掉环境。docker 停容器，源码/二进制进程按 pid 结束。"""
    d = _env_dir(eid)
    m = _read_meta(d)
    if not m.get("id"):
        raise EnvError("环境不存在", 404)
    if _is_container_env(m):
        name = str(m.get("container") or "") or _container_name(eid)
        if not _EID_RE.match(eid):
            raise EnvError("环境 ID 不合法", 400)
        _run(["docker", "rm", "-f", name], timeout=120)
        meta = _write_meta(d, {**m, "status": STATUS_READY, "container": "", "pid": 0})
        return {"ok": True, "env": _view(meta), "message": f"容器 {name} 已停止"}
    pid = int(m.get("pid") or 0)
    if pid > 0:
        try:
            os.kill(pid, 15)
        except (OSError, ProcessLookupError):
            pass
    meta = _write_meta(d, {**m, "status": STATUS_READY, "pid": 0})
    return {"ok": True, "env": _view(meta), "message": "已停止"}


def _rmtree(path: Path) -> None:
    """删目录树，Windows 上要先把只读属性摘掉。

    git clone 出来的 .git/objects/pack/*.pack 是只读文件，shutil.rmtree 直接
    删会抛 PermissionError——用户点"删除环境"就删不掉了。
    """
    def fix(func, p, _exc):
        try:
            os.chmod(p, stat.S_IWRITE)
            func(p)
        except OSError:
            pass

    if sys.version_info >= (3, 12):
        shutil.rmtree(path, onexc=fix)
    else:
        shutil.rmtree(path, onerror=fix)


def delete_env(eid: str) -> dict:
    """删掉环境。目录连同里面的源码/二进制一起清，容器也一并删掉。

    多个漏洞共享的环境删掉后，那些漏洞的 env_id 一并清掉，别留着指向空环境。
    """
    d = _env_dir(eid)
    m = _read_meta(d)
    if not m.get("id"):
        raise EnvError("环境不存在", 404)
    if _is_container_env(m):
        _run(["docker", "rm", "-f", str(m.get("container") or _container_name(eid))], timeout=120)
        # 自建镜像也一并删掉，别在磁盘上留一堆几百 MB 的镜像
        if str(m.get("mode") or "") == "build":
            _run(["docker", "rmi", "-f", _built_tag(eid)], timeout=120)
    try:
        _rmtree(d)
    except OSError as e:
        raise EnvError(f"删不掉：{e}", 500) from e
    for vid in (m.get("vulns") or []):
        store.patch_meta(str(vid), {"env_id": "", "env_status": ""})
    logger.info("删除环境 %s（%s）", eid, m.get("component"))
    return {"ok": True, "message": "环境已删除", "vulns": list(m.get("vulns") or [])}


# ── 打：拿 PoC 真打这个环境 ────────────────────────────────
# PoC 里的地址占位符有好几种写法：LLM 生成的 PoC 习惯写 TARGET = "http://TARGET"，
# 我们自己写的 PoC 走 argv[1] 或环境变量。两种都支持。
_VERIFY_OK_MARKS = ("命中", "复现成功", "vulnerable", "vuln confirmed", "exploit succeeded")
_VERIFY_FAIL_MARKS = ("未命中", "未复现", "not vulnerable", "not reproduced", "无法复现")


def _inject_target(poc: str, target: str) -> str:
    """把 PoC 里的 TARGET 占位符换成真实地址。

    只替换字面量，不动代码结构：带引号的 "TARGET"、"http://TARGET" 这几种。
    """
    out = poc.replace("http://TARGET", target).replace("https://TARGET", target)
    out = out.replace('"TARGET"', f'"{target}"').replace("'TARGET'", f"'{target}'")
    return out


def _target_url(m: dict) -> str:
    """这个环境对外的地址。容器看端口映射，本机进程从启动命令里抠端口。"""
    u = str(m.get("target_url") or "").strip()
    if u:
        return u
    for pm in (m.get("port_map") or []):
        try:
            host = int(pm.get("host"))
        except (TypeError, ValueError):
            continue
        if 1024 <= host <= 65535:
            return f"http://127.0.0.1:{host}"
    for p in (m.get("ports") or []):
        if isinstance(p, int) and 1 <= p <= 65535:
            return f"http://127.0.0.1:{p}"
    cmd = str(m.get("cmd") or m.get("run") or "")
    hit = re.search(r":(\d{2,5})\b", cmd)
    if hit:
        return f"http://127.0.0.1:{hit.group(1)}"
    return ""


def _judge(code: int, out: str) -> tuple[bool | None, str]:
    """按输出和退出码判复现结论。

    顺序很重要：先看输出里的明确信号，最后才拿退出码兜底。
    我们自己的 PoC 约定 0=复现 / 2=未复现 / 3=跑挂了；但 LLM 写的通用 PoC
    退出码不可靠，输出里写了"未复现"就得以输出为准。
    """
    low = out.lower()
    for mark in _VERIFY_FAIL_MARKS:
        if mark in low:
            return False, f"输出里出现「{mark}」，判定为未复现"
    for mark in _VERIFY_OK_MARKS:
        if mark in low:
            return True, f"输出里出现「{mark}」，判定为已复现"
    if code == 0:
        return True, "PoC 执行成功（退出码 0）"
    if code == 2:
        return False, "PoC 跑完了，判定为未复现（退出码 2）"
    return None, f"退出码 {code}，输出里没有明确的复现信号，需要人工看一眼"


def verify_env(eid: str, vid: str = "", timeout: int = 120) -> dict:
    """拿库里那条漏洞的 PoC 真打这个环境，看能不能复现。

    流程：确认环境在跑 → 定出对外地址 → 取出 PoC → 把地址填进去执行 →
    按退出码和输出下结论 → 回填环境条目和漏洞条目。
    """
    d = _env_dir(eid)
    m = _read_meta(d)
    if not m.get("id"):
        raise EnvError("环境不存在", 404)
    status = str(m.get("status") or "")
    if status in (STATUS_ABANDONED, STATUS_FAILED, STATUS_BUILDING):
        raise EnvError("正在搭建中，就绪后才能验证" if status == STATUS_BUILDING
                       else "这个环境没构建成功，先重新搭一个再验证", 400)

    auto_started = False
    if status == STATUS_READY:
        # 顺手拉起来：用户点一下就想看到结果
        m = start_env(eid)["env"]
        auto_started = True
    # 容器起了不等于服务能连了。启动中就等健康检查转正再打，
    # 否则 PoC 只会拿到连接失败，结论变成"未复现"纯属冤枉。
    waited = 0
    while str(m.get("status") or "") == STATUS_STARTING and waited < 120:
        time.sleep(2)
        waited += 2
        m = _read_meta(d)
    if str(m.get("status") or "") != STATUS_RUNNING:
        raise EnvError("服务还没就绪（启动失败或超时），没法验证", 400)

    vids = list(m.get("vulns") or [])
    target_vid = vid or (vids[0] if vids else "")
    if not target_vid:
        raise EnvError("这个环境没关联漏洞，先在漏洞详情里关联一条", 400)
    v = store.get_vuln(target_vid)
    if not v:
        raise EnvError("漏洞不存在", 404)
    poc = str(v.get("poc") or "")
    if not poc.strip():
        raise EnvError("这条漏洞还没有 PoC，先生成一条再验证", 400)
    lang = str(v.get("poc_file") or "poc.python").rsplit(".", 1)[-1].lower()
    if lang not in ("python", "py"):
        raise EnvError(f"只有 Python PoC 能自动跑，这条是 {lang}，请手动执行", 400)

    target = _target_url(m)
    if not target:
        raise EnvError("这个环境没有对外端口，不知道往哪打", 400)

    work = d / "verify"
    work.mkdir(parents=True, exist_ok=True)
    script = work / "poc.py"
    script.write_text(_inject_target(poc, target), encoding="utf-8")
    env = {**os.environ, "TARGET": target}
    try:
        proc = subprocess.run(
            [sys.executable, str(script), target], cwd=str(work), capture_output=True,
            timeout=timeout, env=env, shell=False, creationflags=_NO_WINDOW)
    except subprocess.TimeoutExpired:
        rec = {"at": _now(), "vid": target_vid, "target": target, "exit_code": 124,
               "reproduced": None, "verdict": f"PoC 执行超时（{timeout}s）",
               "output": ""}
        meta = _write_meta(d, {**m, "verify": rec})
        store.patch_meta(target_vid, {"poc_verified": "timeout",
                                      "poc_verify_note": rec["verdict"]})
        return {"ok": False, "verify": rec, "env": _view(meta)}
    except OSError as e:
        raise EnvError(f"PoC 跑不起来：{e}", 500) from e

    out = ((proc.stdout or b"") + b"\n" + (proc.stderr or b"")).decode("utf-8", "replace")
    reproduced, verdict = _judge(proc.returncode, out)
    rec = {"at": _now(), "vid": target_vid, "target": target,
           "exit_code": proc.returncode, "reproduced": reproduced,
           "verdict": verdict, "output": out[-MAX_LOG_CHARS:], "auto_started": auto_started}
    meta = _write_meta(d, {**m, "verify": rec})
    # 失败时把输出末尾也写进漏洞 meta：gen_poc 重写 PoC 时要拿它当"换路子"的依据
    note = verdict
    if reproduced is False and rec["output"]:
        note += "；PoC 输出末尾：" + rec["output"][-300:]
    store.patch_meta(target_vid, {
        "poc_verified": "reproduced" if reproduced else ("not_reproduced" if reproduced is False else "unknown"),
        "poc_verify_note": note, "poc_verified_at": rec["at"]})
    logger.info("验证环境 %s（%s）：%s", eid, target_vid, verdict)
    return {"ok": True, "verify": rec, "env": _view(meta)}
