"""translate.py —— 漏洞情报中文化

nuclei 模板库里的 name/summary 是英文，直接进播报列表不好读。这里用 LLM 把它们
译成中文；英文原文仍在 nuclei.yaml 里（模板全文原样落盘没动过），随时可对照。

translated 标记写在 meta 上，回填时靠它跳过已译条目，避免重复烧 token。
"""
import json

import config
import store
from llm import get_llm

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


def _write(f, meta: dict) -> None:
    f.write_text(json.dumps(meta, ensure_ascii=False, indent=2), encoding="utf-8")


def translate_one(vid: str) -> dict:
    """译单条并落盘。LLM 不可用直接返回原因，不写回。"""
    f = config.VULN_DIR / vid / "meta.json"
    if not f.is_file():
        return {"ok": False, "reason": "漏洞不存在"}
    meta = json.loads(f.read_text(encoding="utf-8"))
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
    _write(f, meta)
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
        print(f"[translate] LLM 不可用({e!r}) → 保留英文原名")
        return meta
    if not zh:
        print(f"[translate] {meta.get('id')} 译文不完整 → 保留英文原名")
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
        files = [config.VULN_DIR / vid / "meta.json" for vid in ids]
    else:
        files = []
        for f in config.VULN_DIR.glob("*/meta.json"):
            if len(files) >= limit:
                break
            files.append(f)
    ok, failed, skipped, done = [], [], 0, []
    for f in files:
        if not f.is_file():
            failed.append({"id": f.parent.name, "reason": "漏洞不存在"})
            continue
        meta = json.loads(f.read_text(encoding="utf-8"))
        vid = meta.get("id", f.parent.name)
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
        _write(f, meta)
        ok.append(vid)
        done.append(zh["name"])
    return {"ok": len(ok), "skipped": skipped, "failed": failed,
            "ids": ok, "names": done}
