"""content_judge.py —— 用 LLM 判断抓到的内容到底是不是漏洞情报

漏洞源是"站点级别"筛出来的：先知、FreeBuf、WatchTowr 这些站确实是安全社区，
但站里同时有赛事 WriteUp、工具教程、行业新闻、漏洞复现。站点合格不代表每篇
文章都合格——以前只按日期筛，《数信杯 WriteUp》这种技术文章就被当成漏洞播了出去。

为什么不用关键词表：标题的花样太多（"复现"、"合集"、"某系统漏洞分析"……），
写死关键词要么漏要么误杀。内容是什么性质，读一遍才知道，这活儿交给模型正合适。

模型不可用时的口径：宁可漏收也不误收。判不准就不收，等下一轮再抓——
漏洞播报少一条只是少一条，把技术文章当漏洞播出去是 misinformation。

对外三个函数：
- judge()      判一条，返回 is_vuln / kind / component / reason
- judge_many() 批量判，返回 {id: 判定}
- KIND_*       分类常量，前端按这个分色
"""
import json
import logging

logger = logging.getLogger("ai_bobao.content_judge")

# 判定结果的分类。前端按 kind 分色，统计也按它分组。
KIND_VULN = "vuln"          # 漏洞情报：收
KIND_WRITEUP = "writeup"    # 比赛 / CTF 解题报告：不收
KIND_TOOL = "tool"          # 工具、框架、扫描器介绍：不收
KIND_TUTORIAL = "tutorial"  # 通用技术教程：不收
KIND_NEWS = "news"          # 行业新闻、观点评论、活动通知：不收
KIND_OTHER = "other"        # 说不清：不收
KIND_UNKNOWN = "unknown"    # 模型没给结论：不收

_KINDS = (KIND_VULN, KIND_WRITEUP, KIND_TOOL, KIND_TUTORIAL, KIND_NEWS, KIND_OTHER)

_JUDGE_SYS = (
    "你是漏洞播报系统的内容审核员。用户会把安全社区里抓到的一篇文章（标题、摘要、"
    "正文片段）发给你，你要判断它是不是一条「漏洞情报」——描述了某个具体产品、"
    "系统或组件的安全缺陷，包含成因、影响版本、漏洞类型或利用方式之一。"
    "只返回 JSON，不要解释，不要输出 JSON 以外的内容。"
)

_JUDGE_KEYS = """按这个格式返回 JSON：
{"is_vuln": true 或 false,
 "kind": "vuln"(漏洞情报) / "writeup"(比赛、CTF 的解题报告) / "tool"(工具、框架、扫描器介绍) /
          "tutorial"(通用技术教程) / "news"(行业新闻、观点评论、活动通知) / "other",
 "component": "受影响的产品或组件名，如 WordPress、Django、某OA系统；不是漏洞就填空字符串",
 "reason": "一句话说明判断依据"}"""

_JUDGE_BATCH_KEYS = """按这个格式返回 JSON：
{"results": [{"id": "把用户给的 id 原样带回", "is_vuln": true 或 false, "kind": "...",
              "component": "...", "reason": "..."}]}
输入几条就要返回几条，顺序一致。"""


def _brief(item: dict, content: str = "") -> str:
    """把一条内容压成模型能读的简报。正文只取前面一段，够判断性质就行。"""
    return json.dumps({
        "id": item.get("id", ""),
        "title": item.get("title") or item.get("name") or "",
        "summary": str(item.get("summary") or "")[:500],
        "content": str(content or "")[:2500],
        "refs": (item.get("refs") or [])[:5],
    }, ensure_ascii=False)


def _verdict(raw: dict) -> dict:
    """把模型返回的原始字典收拾成统一的判定结果。

    模型自相矛盾时（is_vuln 为 true 但 kind 写成 writeup）取严的一边：
    宁可漏收也不误收。
    """
    raw_kind = str(raw.get("kind") or "").strip().lower()
    is_vuln = bool(raw.get("is_vuln"))
    if raw_kind and raw_kind != KIND_VULN:
        is_vuln = False
    kind = raw_kind if raw_kind in _KINDS else (KIND_OTHER if raw_kind else "")
    return {
        "is_vuln": is_vuln,
        "kind": kind or KIND_UNKNOWN,
        "component": str(raw.get("component") or "").strip()[:60],
        "reason": str(raw.get("reason") or "").strip()[:200],
    }


def judge(llm, item: dict, content: str = "") -> dict:
    """判断一条内容是不是漏洞情报。

    返回 {is_vuln, kind, component, reason, by_llm}。LLM 不可用时 by_llm 为
    False 且 is_vuln 为 False——判不了就不收，等下一轮再试。
    """
    try:
        r = llm.chat(_JUDGE_SYS, _brief(item, content) + "\n\n" + _JUDGE_KEYS)
    except Exception as e:  # noqa: BLE001 —— 模型挂了不该让整轮抓取崩掉
        logger.warning("内容判定失败（%s）：%r", item.get("id"), e)
        return {"is_vuln": False, "kind": KIND_UNKNOWN, "component": "",
                "reason": f"模型不可用，本轮不收录：{e}", "by_llm": False}
    if not isinstance(r, dict):
        return {"is_vuln": False, "kind": KIND_UNKNOWN, "component": "",
                "reason": "模型返回的不是 JSON 对象", "by_llm": True}
    v = _verdict(r)
    v["by_llm"] = True
    return v


def judge_many(llm, items: list[dict], batch: int = 8) -> dict[str, dict]:
    """批量判定，返回 {id: 判定}。

    一次问多条，省得一条一次往返。模型没回的条目不会出现在结果里，调用方
    要当"判不了"处理（留着别删）。
    """
    out: dict[str, dict] = {}
    size = max(1, min(int(batch or 8), 20))
    for i in range(0, len(items), size):
        group = items[i:i + size]
        payload = json.dumps([_brief(it, it.get("content", "")) for it in group],
                             ensure_ascii=False)
        try:
            r = llm.chat(_JUDGE_SYS, payload + "\n\n" + _JUDGE_BATCH_KEYS)
        except Exception as e:  # noqa: BLE001
            logger.warning("批量内容判定失败：%r", e)
            continue
        results = r.get("results") if isinstance(r, dict) else None
        if not isinstance(results, list):
            logger.warning("批量判定返回里没有 results 数组")
            continue
        for raw in results:
            if not isinstance(raw, dict):
                continue
            vid = str(raw.get("id") or "")
            if not vid:
                continue
            v = _verdict(raw)
            v["by_llm"] = True
            out[vid] = v
    return out
