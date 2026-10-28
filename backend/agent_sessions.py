"""agent_sessions.py —— AI 对话的多会话历史（session）存储

一个会话一个文件：data/sessions/<sid>.json。选文件而不是数据库，是因为这个项目
本来就是文件库（漏洞、模板、导出全是文件），会话量级也就几十上百个，一个目录
就够，还不用多引一个依赖。

会话 id 是 16 位十六进制随机串，正则卡死之后再 safe_join 兜底，路径穿越走不通。
写入用「临时文件 + os.replace」原子替换，进程中途被杀只会留下一个 .tmp，
不会把正式文件写成半截 JSON。

存的是用户真正说过的话和助手真正给过的答复。工具轨迹（steps）也存，因为前端
气泡下面要展开显示「执行了 N 步操作」，重进会话时得能还原。
"""
import json
import logging
import os
import re
import secrets
import threading
from datetime import datetime
from pathlib import Path

import security
from config import DATA_DIR

logger = logging.getLogger("ai_bobao.sessions")

SESSIONS_DIR = DATA_DIR / "sessions"
SID_RE = re.compile(r"^[0-9a-f]{16}$")   # 会话 id 形状：16 位小写十六进制

MAX_SESSIONS = 100     # 最多留几个会话，超出的按最旧的删
MAX_MESSAGES = 200     # 单个会话最多留几条消息，超出丢最旧的
MAX_STEPS = 20         # 单条消息最多存几步工具轨迹
TITLE_MAX = 60         # 会话标题长度上限
MSG_MAX = 6000         # 单条消息长度上限（与 agent.MSG_MAX 对齐）
STEP_OUT_MAX = 500     # 一步操作的结果摘要上限
STEP_ARGS_MAX = 80     # 一步操作的参数值上限

DEFAULT_TITLE = "新会话"

_lock = threading.RLock()   # 读改写同一个会话时别互相覆盖


# ── 底层读写 ──────────────────────────────────────────────

def _now() -> str:
    return datetime.now().isoformat(timespec="seconds")


def _new_id() -> str:
    return secrets.token_hex(8)


def _check_sid(sid: str) -> str:
    sid = (sid or "").strip().lower()
    if not SID_RE.match(sid):
        raise ValueError("会话 ID 不合法")
    return sid


def _path(sid: str) -> Path:
    """会话 id → 磁盘路径。正则先卡一道，safe_join 再兜一层。"""
    return security.safe_join(SESSIONS_DIR, f"{_check_sid(sid)}.json")


def _write(data: dict) -> None:
    SESSIONS_DIR.mkdir(parents=True, exist_ok=True)
    path = _path(data["id"])
    tmp = path.with_name(path.name + ".tmp")
    tmp.write_text(json.dumps(data, ensure_ascii=False, indent=1), encoding="utf-8")
    os.replace(tmp, path)          # 原子替换，避免半截文件


def _read(sid: str) -> dict | None:
    try:
        path = _path(sid)
    except ValueError:
        return None
    try:
        raw = path.read_text(encoding="utf-8")
    except OSError:
        return None
    try:
        data = json.loads(raw)
    except ValueError:
        return None
    return data if isinstance(data, dict) else None


def _norm_steps(steps) -> list[dict]:
    """工具轨迹只留前端要用的几个字段，参数值截短，别把会话文件撑大。"""
    out = []
    for s in (steps or [])[:MAX_STEPS]:
        if not isinstance(s, dict):
            continue
        args = s.get("args")
        args = ({str(k): str(v)[:STEP_ARGS_MAX] for k, v in args.items()}
                if isinstance(args, dict) else {})
        out.append({"tool": str(s.get("tool") or "")[:40],
                    "args": args,
                    "ok": bool(s.get("ok")),
                    "out": str(s.get("out") or "")[:STEP_OUT_MAX],
                    "file": str(s.get("file") or "")[:120]})
    return out


def _blank(sid: str, title: str = "") -> dict:
    now = _now()
    return {"id": sid, "title": title or DEFAULT_TITLE,
            "created_at": now, "updated_at": now, "messages": []}


def _prune() -> None:
    """会话文件超上限就按修改时间从最旧开始删。"""
    try:
        files = list(SESSIONS_DIR.glob("*.json"))
    except OSError:
        return
    if len(files) <= MAX_SESSIONS:
        return

    def _mtime(f: Path) -> float:
        try:
            return f.stat().st_mtime
        except OSError:
            return 0.0

    files.sort(key=_mtime)
    for f in files[:len(files) - MAX_SESSIONS]:
        try:
            f.unlink()
        except OSError:
            pass


# ── 对外接口 ──────────────────────────────────────────────

def list_sessions() -> list[dict]:
    """会话列表，不含消息体。按最近更新排在前面。"""
    out = []
    try:
        files = list(SESSIONS_DIR.glob("*.json"))
    except OSError:
        return out
    for f in files:
        d = _read(f.stem)
        if not d:
            continue
        out.append({"id": d.get("id") or f.stem,
                    "title": str(d.get("title") or DEFAULT_TITLE)[:TITLE_MAX],
                    "created_at": d.get("created_at") or "",
                    "updated_at": d.get("updated_at") or "",
                    "count": len(d.get("messages") or [])})
    out.sort(key=lambda s: s["updated_at"], reverse=True)
    return out


def get_session(sid: str) -> dict | None:
    """取一个会话的完整内容（含消息）。不存在返回 None。"""
    return _read(sid)


def create_session(title: str = "", messages=None) -> dict:
    """新建会话。标题留空时，后面按第一句话自动起名。

    messages 是可选的初始历史（老版本把对话存在浏览器里，第一次用新版本时搬过来）。
    """
    with _lock:
        t = security.clean_text(title, TITLE_MAX)
        data = _blank(_new_id(), t)
        for m in (messages or []):
            if not isinstance(m, dict):
                continue
            role = m.get("role")
            content = str(m.get("content") or "")
            if role not in ("user", "assistant") or not content.strip():
                continue
            msg = {"role": role, "content": content[:MSG_MAX], "at": _now()}
            if role == "assistant":
                msg["steps"] = _norm_steps(m.get("steps"))
            data["messages"].append(msg)
        del data["messages"][:-MAX_MESSAGES]
        if not t and data["messages"]:
            first = next((m for m in data["messages"] if m["role"] == "user"), None)
            if first:
                data["title"] = (security.clean_text(first["content"].replace("\n", " "), 24)
                                 or DEFAULT_TITLE)
        _write(data)
        _prune()
        logger.info("新建会话 %s", data["id"])
        return data


def rename_session(sid: str, title: str) -> dict | None:
    """给会话改名。"""
    with _lock:
        d = _read(sid)
        if not d:
            return None
        t = security.clean_text(title, TITLE_MAX)
        if not t:
            raise ValueError("标题不能为空")
        d["title"] = t
        d["updated_at"] = _now()
        _write(d)
        return d


def delete_session(sid: str) -> bool:
    """删掉一个会话（连消息一起）。"""
    with _lock:
        try:
            path = _path(sid)
        except ValueError:
            return False
        try:
            path.unlink()
        except OSError:
            return False
        return True


def clear_messages(sid: str) -> dict | None:
    """清空会话里的消息，保留会话本身。"""
    with _lock:
        d = _read(sid)
        if not d:
            return None
        d["messages"] = []
        d["updated_at"] = _now()
        _write(d)
        return d


def append_message(sid: str, role: str, content: str, steps=None) -> dict | None:
    """往会话尾部追加一条消息。会话不存在返回 None。

    第一条用户消息会拿来当会话标题（还没手动改过标题的话），
    免得会话栏里全是「新会话」分不清谁是谁。
    """
    with _lock:
        d = _read(sid)
        if not d:
            return None
        msg = {"role": role, "content": (content or "")[:MSG_MAX], "at": _now()}
        if role == "assistant":
            msg["steps"] = _norm_steps(steps)
        msgs = d.setdefault("messages", [])
        if role == "user" and d.get("title") in ("", DEFAULT_TITLE):
            d["title"] = security.clean_text(content.replace("\n", " "), 24) or DEFAULT_TITLE
        msgs.append(msg)
        del msgs[:-MAX_MESSAGES]        # 保留最后 MAX_MESSAGES 条
        d["updated_at"] = _now()
        _write(d)
        return d


def resolve(sid: str = "") -> str:
    """校验会话 id；没给就新建一个。

    给了 id 但磁盘上没这个会话（比如刚被删了），就地按这个 id 重建一个空的，
    别让前端拿着一个死 id 一直报错。
    """
    sid = (sid or "").strip()
    if not sid:
        return create_session()["id"]
    sid = _check_sid(sid)
    with _lock:
        if _read(sid) is None:
            _write(_blank(sid))
            logger.info("会话 %s 不存在，已重建", sid)
    return sid
