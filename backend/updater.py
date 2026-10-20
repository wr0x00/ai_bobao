"""updater.py —— 自更新：看看 GitHub 上有没有新版本，一键快进到最新

用户装的是一份 clone 下来的代码，"更新"就是 git pull。既然 nuclei_sync 已经有
一套跑 git 的地方（Windows PATH 兜底、超时、报错整理），这里就不再自己造一遍。

两条路：
- check()：本地 HEAD 和 GitHub API 的分支头比一比，只读，不动工作区
- apply()：git fetch + git merge --ff-only，快进到远端

只允许快进（--ff-only）：本地有未提交的改动或者自己的提交时，宁可报错让用户
自己处理，也不能一把 reset 掉人家写的东西。
"""
import json
import logging
from pathlib import Path

import config
import nuclei_sync
import security

logger = logging.getLogger("ai_bobao.updater")

REPO = "wr0x00/ai_bobao"
BRANCH = "main"
PROJECT_DIR = config.BASE_DIR.parent        # backend/ 的上一层，也就是项目根

# GitHub API 每次只读一丁点，返回给前端的也只有 sha 和首行信息，
# 所以响应体上限压到 256KB，比下载模板时紧得多。
_MAX_REPLY = 256 * 1024
_UA = "ai-bobao-updater"


def _api_url() -> str:
    return f"https://api.github.com/repos/{REPO}/commits/{BRANCH}"


def _web_url() -> str:
    return f"https://github.com/{REPO}"


def _is_repo(path: Path) -> bool:
    """这个目录是不是本项目的 git 工作区。不是的话就别乱 pull。"""
    return (path / ".git").exists()


def local_commit() -> str:
    """本地 HEAD 的完整 sha。取不到就返回空串（可能是压缩包部署的，没有 .git）。"""
    if not _is_repo(PROJECT_DIR):
        return ""
    try:
        return nuclei_sync.run_git(["rev-parse", "HEAD"], PROJECT_DIR, timeout=30).strip()
    except (RuntimeError, OSError) as e:
        logger.warning("读本地 commit 失败：%s", e)
        return ""


def remote_commit() -> str:
    """远端分支头的 sha。走 security.open_url 出站（SSRF 网关 + 大小上限）。

    出站失败统一吞成空串：连不上 GitHub 是常态（断网、被墙、限流），
    不该让"检测更新"整个报错。
    """
    try:
        raw = security.open_url(_api_url(), timeout=15.0, max_bytes=_MAX_REPLY,
                                headers={"User-Agent": _UA,
                                         "Accept": "application/vnd.github+json"})
    except security.SecurityError as e:
        logger.info("读远端 commit 失败：%s", e)
        return ""
    try:
        doc = json.loads(raw.decode("utf-8", errors="replace"))
    except ValueError:
        return ""
    return str(doc.get("sha") or "") if isinstance(doc, dict) else ""


def check() -> dict:
    """看看有没有新版本。纯只读，失败也返回结构化结果，不抛异常。

    返回 {repo, branch, url, local, remote, has_update, message}。
    """
    base = {"repo": REPO, "branch": BRANCH, "url": _web_url(),
            "local": "", "remote": "", "has_update": False, "message": ""}
    if not _is_repo(PROJECT_DIR):
        base["message"] = "当前不是 git 仓库部署，无法自动更新"
        return base
    base["local"] = local_commit()
    base["remote"] = remote_commit()
    if not base["local"]:
        base["message"] = "读不到本地 commit，可能没装 git 或目录损坏"
    elif not base["remote"]:
        base["message"] = "连不上 GitHub，稍后再试"
    elif base["local"] == base["remote"]:
        base["message"] = "已经是最新版本"
    else:
        base["has_update"] = True
        base["message"] = "发现新版本"
    return base


def apply() -> dict:
    """拉最新版本。只快进，不动本地改动。

    返回 {ok, local, remote, message}。ok 为 False 时 message 说明原因。
    """
    if not _is_repo(PROJECT_DIR):
        return {"ok": False, "local": "", "remote": "", "message": "当前不是 git 仓库部署，无法自动更新"}
    try:
        dirty = nuclei_sync.run_git(["status", "--porcelain"], PROJECT_DIR, timeout=60).strip()
    except (RuntimeError, OSError) as e:
        return {"ok": False, "local": "", "remote": "", "message": f"读工作区状态失败：{e}"}
    if dirty:
        return {"ok": False, "local": local_commit(), "remote": "",
                "message": "本地有未提交的改动，先提交或暂存再更新"}
    try:
        nuclei_sync.run_git(["fetch", "origin", BRANCH], PROJECT_DIR, timeout=180)
        nuclei_sync.run_git(["merge", "--ff-only", f"origin/{BRANCH}"], PROJECT_DIR, timeout=180)
    except (RuntimeError, OSError) as e:
        logger.warning("更新失败：%s", e)
        return {"ok": False, "local": local_commit(), "remote": "",
                "message": f"更新失败：{e}"}
    head = local_commit()
    logger.info("已更新到 %s", head[:12])
    return {"ok": True, "local": head, "remote": head, "message": "已更新到最新版本，重启后端后生效"}
