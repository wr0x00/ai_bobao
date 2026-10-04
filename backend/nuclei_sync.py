"""nuclei_sync.py —— nuclei-templates 每日增量同步

为什么不用 GitHub API：nuclei-templates 有 1.5w+ 文件，走 API 要么超限流、要么按目录
抽样（抽到的还是旧的那批）。git 增量才是"今天更新了什么"的准确答案。

流程：clone（首次）→ pull → diff 上次同步的 commit 与当前 commit → 只处理变更的
yaml 模板。原样入库，不过 LLM —— 模板本身就是最规范的探测逻辑，让模型改写只会变差。

状态记在 data/nuclei_sync.json：{last_commit, last_sync, history}，
所以进程重启、断网失败都不会重复入库。
"""
from __future__ import annotations

import json
import re
import subprocess
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

import yaml

import nuclei_tpl
from config import NUCLEI_REPO_DIR, NUCLEI_SYNC_STATE, TPL_REPO_URL

# 仓库里这些目录不是可独立运行的模板，跳过
_SKIP_DIRS = ("helpers/", "workflows/", ".github/", "tests/", "testdata/",
              "internal/", "cmd/", "lib/", "pkg/", "static/", "helm/")

_CLONE_TIMEOUT = 600       # 首次克隆 1.5w 文件，给足
_PULL_TIMEOUT = 300

# 同步点 tag 名：浅克隆的历史会被 gc，用 tag 把上次同步到的 commit 钉住
SYNC_TAG = "ai-bobao-sync"


@dataclass
class SyncResult:
    changed: int = 0          # git 报告的变更文件数
    imported: int = 0         # 实际入库数
    skipped: int = 0          # 已存在，跳过
    failed: int = 0           # 解析失败
    from_commit: str = ""     # 上次同步到的 commit（空 = 首次全量）
    to_commit: str = ""
    files: list[str] = None   # 入库条目的漏洞 id
    message: str = ""

    def as_dict(self) -> dict:
        return {"changed": self.changed, "imported": self.imported,
                "skipped": self.skipped, "failed": self.failed,
                "from_commit": self.from_commit[:12], "to_commit": self.to_commit[:12],
                "files": self.files or [], "message": self.message}


def _git(args: list[str], cwd: Path, timeout: int = _PULL_TIMEOUT) -> str:
    """跑 git。Windows 下 Git 不在系统 PATH 常见，先试 git 再试常见安装位置。"""
    exe = _find_git()
    if not exe:
        raise RuntimeError("未找到 git，可执行文件未加入 PATH")
    r = subprocess.run([exe, "-C", str(cwd), *args], capture_output=True,
                       timeout=timeout, encoding="utf-8", errors="replace")
    if r.returncode != 0:
        raise RuntimeError(f"git {' '.join(args[:2])} 失败: {(r.stderr or r.stdout).strip()[:300]}")
    return r.stdout


def _find_git() -> str | None:
    import shutil
    exe = shutil.which("git")
    if exe:
        return exe
    for p in (r"C:\Program Files\Git\cmd\git.exe",
              r"C:\Program Files\Git\bin\git.exe",
              r"C:\Program Files (x86)\Git\cmd\git.exe"):
        if Path(p).is_file():
            return p
    return None


def _state() -> dict:
    if NUCLEI_SYNC_STATE.is_file():
        try:
            return json.loads(NUCLEI_SYNC_STATE.read_text(encoding="utf-8"))
        except Exception:  # noqa: BLE001 —— 状态文件坏了就当没同步过，重新全量
            pass
    return {}


def _save_state(st: dict) -> None:
    NUCLEI_SYNC_STATE.parent.mkdir(parents=True, exist_ok=True)
    NUCLEI_SYNC_STATE.write_text(json.dumps(st, ensure_ascii=False, indent=2), encoding="utf-8")


def _head_commit(repo: Path) -> str:
    return _git(["rev-parse", "HEAD"], repo, timeout=60).strip()


def ensure_repo(ref: str) -> Path:
    """确保模板仓库在本地且 ref 正确。首次克隆，浅克隆（--depth 1）省 90% 体积和时间。"""
    repo = NUCLEI_REPO_DIR
    if not (repo / ".git").is_dir():
        repo.parent.mkdir(parents=True, exist_ok=True)
        exe = _find_git()
        if not exe:
            raise RuntimeError("未找到 git，无法克隆 nuclei-templates")
        print(f"[sync] 首次克隆 {TPL_REPO_URL} → {repo}（约 1.5w 文件，请稍候）")
        r = subprocess.run(
            [exe, "clone", "--depth", "1", "--branch", ref, TPL_REPO_URL, str(repo)],
            capture_output=True, timeout=_CLONE_TIMEOUT, encoding="utf-8", errors="replace")
        if r.returncode != 0:
            # 目录可能是上次失败留下的半成品，删掉重来
            import shutil as _sh
            if repo.exists():
                _sh.rmtree(repo, ignore_errors=True)
            raise RuntimeError(f"克隆失败: {(r.stderr or r.stdout).strip()[:300]}")
        return repo
    # 本地有仓库，把 ref 切到配置的分支（用户改了 config.ref 时才动）
    cur = _git(["rev-parse", "--abbrev-ref", "HEAD"], repo, timeout=60).strip()
    if cur != ref:
        print(f"[sync] 本地分支 {cur} → 切换到 {ref}")
        _git(["fetch", "--depth", "1", "origin", ref], repo, timeout=_PULL_TIMEOUT)
        _git(["checkout", "FETCH_HEAD"], repo, timeout=120)
    return repo


def _tag(repo: Path, commit: str, name: str) -> None:
    """给同步点打永久 tag。浅克隆的 history 会被 GC 掉，tag 能把那个 commit 钉住，
    下次 diff 就不必去补全历史。"""
    try:
        _git(["tag", "-f", name, commit], repo, timeout=60)
    except RuntimeError:
        pass       # tag 失败不影响主流程，后面还有全量兜底


def _tag_commit(repo: Path, name: str) -> str:
    """上次同步点（优先读 tag，它比 shallow history 可靠）。"""
    try:
        return _git(["rev-parse", f"{name}^{{commit}}"], repo, timeout=60).strip()
    except RuntimeError:
        return _state().get("last_commit") or ""


def pull(repo: Path, ref: str, old: str = "") -> str:
    """拉到最新，返回同步后的 commit。

    不指定 --depth：浅克隆仓库的 depth 会在后续 fetch 时自然加深，
    上次同步点通常就还在本地，diff 直接可做。只有它真丢了（首次/远端 rebase）
    才由 changed_files() 回退全量。
    """
    if old:
        _tag(repo, old, SYNC_TAG)     # 钉住同步点，别被 shallow GC 掉
    _git(["fetch", "origin", ref], repo, timeout=_PULL_TIMEOUT)
    _git(["reset", "--hard", f"origin/{ref}"], repo, timeout=120)
    return _head_commit(repo)


def changed_files(repo: Path, old: str, new: str) -> list[str] | None:
    """两次提交之间新增/修改的模板文件。

    返回 None 表示"算不出来"（首次同步 / 上次同步点已被浅克隆截掉），调用方决定是否全量扫。
    """
    if not old:
        return None
    try:
        r = _git(["diff", "--name-only", "--diff-filter=AM", old, new], repo)
    except RuntimeError:
        return None      # old 不在本地历史里（浅克隆深度不够），退回全量
    return [ln.strip() for ln in r.splitlines() if ln.strip() and _is_tpl(ln.strip())]


def changed_dates(repo: Path, old: str, new: str) -> dict[str, str]:
    """变更文件 → 该文件最后一次提交日期（YYYY-MM-DD）。

    模板有多老，看的是它最后被改的时间，不是它入库的时间。git log --name-only
    一次就能拿到全部文件的日期，比逐文件 log 快几百倍；log 是新→旧，
    同一文件第一次出现的日期就是最新提交日。
    """
    if not old:
        return {}
    try:
        r = _git(["log", "--format=%cI", "--name-only", f"{old}..{new}"], repo)
    except RuntimeError:
        return {}
    out: dict[str, str] = {}
    cur = ""
    for ln in r.splitlines():
        s = ln.strip()
        if not s:
            continue
        if s[0].isdigit() and "T" in s:      # 提交头里的 ISO 时间
            cur = s[:10]
        elif cur and _is_tpl(s):
            out.setdefault(s, cur)
    return out


def last_commit_date(repo: Path, rel: str) -> str:
    """单个模板的最后提交日期，取不到返回空串（调用方自己兜）。"""
    try:
        r = _git(["log", "-1", "--format=%cI", "--", rel], repo, timeout=60).strip()
    except RuntimeError:
        return ""
    return r[:10] if r else ""


def all_files(repo: Path) -> list[str]:
    """工作区全量模板清单。"""
    out = []
    for f in repo.rglob("*.yaml"):
        rel = f.relative_to(repo).as_posix()
        if _is_tpl(rel):
            out.append(rel)
    return out


def _is_tpl(rel: str) -> bool:
    """是不是可独立运行的模板文件。"""
    low = rel.lower()
    if not low.endswith((".yaml", ".yml")):
        return False
    if any(low.startswith(d) or f"/{d}" in low for d in _SKIP_DIRS):
        return False
    return True


# 模板里常带的自定义 YAML 标签，safe_load 不认，直接崩
_TAG_RE = re.compile(r"!(?:code|dsl|helper|eval)")


def parse_tpl_file(repo: Path, rel: str):
    """读单个模板文件并抽元信息。返回 None 表示不是有效模板。"""
    f = repo / rel
    if not f.is_file():
        return None
    try:
        text = f.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return None
    # 自定义标签（!code/!dsl）只在 workflow 里出现，已在 _is_tpl 排除；
    # 残留的未知标签在下面 load 时兜住
    try:
        doc = yaml.safe_load(text)
    except Exception:  # noqa: BLE001
        return None
    if not isinstance(doc, dict) or not doc.get("id"):
        return None
    tpl = nuclei_tpl.parse_template(doc, rel)
    if tpl:
        # 原样保留文件全文（含注释/字段顺序），别让 yaml.safe_dump 重排
        tpl.extra["raw"] = text
        tpl.source = f"nuclei-git:{rel.split('/')[0]}"
    return tpl


def sync(ref: str = "main", full: bool = False, limit: int = 0) -> SyncResult:
    """同步模板库 → 返回待入库的模板文件清单。入库存盘由调用方做（要写文件库）。

    full=True 忽略上次状态，强制全量重扫（修模板/改筛选条件时用）。
    limit>0 只取这么多条（调试用）。

    首次同步只建立基线、记下当前 commit，不把 1.5w 个历史模板一股脑灌进库 ——
    播报系统要的是"今天更新了什么"，不是 nuclei 全部存量。
    """
    r = SyncResult(files=[])
    repo = ensure_repo(ref)
    old = _tag_commit(repo, SYNC_TAG)
    new = pull(repo, ref, old)
    r.from_commit, r.to_commit = old, new

    if not full and not old:
        _touch_state(new, 0)
        total = len(all_files(repo))
        r.message = (f"首次同步完成，已建立基线（{total} 个模板）。"
                     f"本轮不导入存量，之后只同步每日增量。")
        return r

    if old == new and not full:
        r.message = f"模板库无更新（{new[:12]}）"
        return r

    files = all_files(repo) if full else changed_files(repo, old, new)
    if files is None:
        # 上次同步点已不可比（浅克隆截断/远端 rebase），只能全量重来
        files = all_files(repo)
        r.message = "上次同步点不可比，已回退全量扫描"
    r.changed = len(files)
    if limit and len(files) > limit:
        files = files[:limit]
        r.message = (r.message + f"；" if r.message else "") + \
            f"本次仅处理前 {limit} 个（共 {r.changed} 个）"
    if not files:
        r.message = r.message or f"无模板变更（{new[:12]}）"
        _touch_state(new, 0)
        return r
    r.files = files
    return r


def _touch_state(commit: str, imported: int) -> None:
    st = _state()
    st["last_commit"] = commit
    st["last_sync"] = datetime.now(timezone.utc).isoformat(timespec="seconds")
    st["last_imported"] = imported
    _save_state(st)
    # 同步点也写进 tag：state 文件可能被删/损坏，tag 才是 diff 的可靠来源
    if commit and NUCLEI_REPO_DIR.is_dir():
        _tag(NUCLEI_REPO_DIR, commit, SYNC_TAG)


def commit_state(commit: str, imported: int) -> None:
    """同步成功入库后调用，把 commit 记为已处理。"""
    _touch_state(commit, imported)


def status() -> dict:
    """同步状态，给前端展示用。"""
    st = _state()
    repo = NUCLEI_REPO_DIR
    return {"repo": str(repo), "cloned": (repo / ".git").is_dir(),
            "last_commit": st.get("last_commit", ""),
            "last_commit_short": (st.get("last_commit") or "")[:12],
            "last_sync": st.get("last_sync", ""),
            "last_imported": st.get("last_imported", 0),
            "local_templates": sum(1 for _ in repo.rglob("*.yaml")) if (repo / ".git").is_dir() else 0}
