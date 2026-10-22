"""translate.py —— 漏洞情报中文化

nuclei 模板库里的 name/summary 是英文，直接进播报列表不好读。这里用 LLM 把它们
译成中文；英文原文仍在 nuclei.yaml 里（模板全文原样落盘没动过），随时可对照。

translated 标记写在 meta 上，回填时靠它跳过已译条目，避免重复烧 token。

路径安全：漏洞 ID 来自接口参数，一律先过 security.require_vid，再经
security.safe_join 拼出 meta.json 的完整路径，免得 "../../../etc/passwd"
这种 ID 把文件读写引到漏洞库外面去。
"""
import json
import logging
from pathlib import Path

import config
import security
import store
from llm import get_llm

logger = logging.getLogger("ai_bobao.translate")

_TRANSLATE_SYS = (
    "你是漏洞情报翻译，负责把英文漏洞信息译成简体中文，用于内部漏洞播报。只返回 JSON："
    '{"name": "中文漏洞名称", "summary": "中文简介", "principle": "中文漏洞原理"}。'
    "规则：CVE 编号、组件名、函数名、协议名、文件路径保留英文原文，其余译为简体中文；"
    "不要添加原文没有的判断、影响面或利用结论。"
)

_FIELDS = ("name", "summary", "principle")


def need_translate(meta: dict) -> bool:
    """name 里没有中文才需要译 —— 文章流水线产出的本来就是中文，别浪费调用。

    中文判定走 store.is_zh_name，和列表页共用一份；它会剥掉 llm_generate 兜底时
    拼的「（兜底）」，否则 LLM 挂掉那阵子抓回来的英文条目会被误判成已译。
    """
    if meta.get("translated"):
        return False
    return not store.is_zh_name(str(meta.get("name") or ""))


def translate_meta(meta: dict, llm=None) -> dict:
    """译一个漏洞的三个文本字段。返回空 dict 表示译文不完整，别写回。"""
    llm = llm or get_llm()
    src = {k: str(meta.get(k) or "")[:900] for k in _FIELDS}
    r = llm.chat(_TRANSLATE_SYS, json.dumps(src, ensure_ascii=False))
    out = {}
    for k in _FIELDS:
        t = str(r.get(k) or "").strip()
        if not t:
            return {}                 # 模型漏了字段，半截译文比原文更糟
        out[k] = t
    return out


def _write(f: Path, meta: dict) -> None:
    """写回 meta.json。先写临时文件再原子替换，避免写到一半断电留下半个 JSON。"""
    tmp = f.with_suffix(".json.tmp")
    tmp.write_text(json.dumps(meta, ensure_ascii=False, indent=2), encoding="utf-8")
    tmp.replace(f)


def _meta_path(vid: str) -> Path:
    """由漏洞 ID 算出 meta.json 的路径。ID 不合法就抛 SecurityError。"""
    return security.safe_join(config.VULN_DIR, security.require_vid(vid), "meta.json")


def translate_one(vid: str) -> dict:
    """译单条并落盘。LLM 不可用直接返回原因，不写回。

    vid 是接口参数，属于外部输入，先过 require_vid 白名单再拼路径。
    """
    try:
        f = _meta_path(vid)
    except security.SecurityError as e:
        logger.warning("拒绝翻译：%s", e)
        return {"ok": False, "reason": f"漏洞 ID 不合法：{e}"}
    if not f.is_file():
        return {"ok": False, "reason": "漏洞不存在"}
    try:
        meta = json.loads(f.read_text(encoding="utf-8"))
    except (OSError, ValueError) as e:
        logger.warning("漏洞 %s 的 meta.json 读不出来：%s", vid, e)
        return {"ok": False, "reason": "漏洞信息读取失败"}
    if not isinstance(meta, dict):
        return {"ok": False, "reason": "漏洞信息格式不对"}
    if not need_translate(meta):
        return {"ok": True, "skipped": True, "message": "已是中文"}
    try:
        zh = translate_meta(meta)
    except Exception as e:  # noqa: BLE001 —— 断网/超时/模型抽风都归到一条可读原因
        return {"ok": False, "reason": f"翻译失败：{e}"}
    if not zh:
        return {"ok": False, "reason": "AI 未返回完整译文"}
    meta.update(zh)
    meta["translated"] = True
    meta["updated_at"] = store._now()     # 翻译也算一次更新，排序列要看
    _write(f, meta)
    store.invalidate_rows()
    return {"ok": True, **zh}


def translate_and_fill(meta: dict, llm=None) -> dict:
    """入库前就地中文化。LLM 不可用/译文不完整就原样返回，绝不写半截译文。

    入库流水线（nuclei 同步、文章抓取）都走这里，省得先落盘再读回来改一遍。
    """
    if not need_translate(meta):
        return meta
    try:
        zh = translate_meta(meta, llm)
    except Exception as e:  # noqa: BLE001
        logger.warning("LLM 不可用（%r）→ 保留英文原名", e)
        return meta
    if not zh:
        logger.warning("%s 译文不完整 → 保留英文原名", meta.get("id"))
        return meta
    meta.update(zh)
    meta["translated"] = True
    return meta


def backfill(limit: int = 20, llm=None, ids: list[str] | None = None) -> dict:
    """批量翻译。传 ids 就只翻这几条（列表页"翻译本页"用），否则扫全库补存量。

    串行 + 逐条失败跳过：LLM 单条 3-5s，一次 10 条不到一分钟。
    """
    llm = llm or get_llm()
    if ids is not None:
        files = []
        for vid in ids:
            try:
                files.append(_meta_path(vid))
            except security.SecurityError as e:
                logger.warning("批量翻译跳过非法 ID %r：%s", vid, e)
                files.append(None)
    else:
        files = []
        for f in sorted(config.VULN_DIR.glob("*/meta.json")):
            if len(files) >= limit:
                break
            files.append(f)
    ok, failed, skipped, done = [], [], 0, []
    for f in files:
        if f is None:
            failed.append({"id": "", "reason": "漏洞 ID 不合法"})
            continue
        if not f.is_file():
            failed.append({"id": f.parent.name, "reason": "漏洞不存在"})
            continue
        try:
            meta = json.loads(f.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            failed.append({"id": f.parent.name, "reason": "漏洞信息读取失败"})
            continue
        if not isinstance(meta, dict):
            failed.append({"id": f.parent.name, "reason": "漏洞信息格式不对"})
            continue
        vid = str(meta.get("id") or f.parent.name)
        if not need_translate(meta):
            skipped += 1
            continue
        try:
            zh = translate_meta(meta, llm)
        except Exception as e:  # noqa: BLE001
            failed.append({"id": vid, "reason": str(e)[:120]})
            continue
        if not zh:
            failed.append({"id": vid, "reason": "译文不完整"})
            continue
        meta.update(zh)
        meta["translated"] = True
        meta["updated_at"] = store._now()     # 批量翻译也刷新更新时间
        _write(f, meta)
        ok.append(vid)
        done.append(zh["name"])
    if ok:
        store.invalidate_rows()
    return {"ok": len(ok), "skipped": skipped, "failed": failed,
            "ids": ok, "names": done}
