"""analyzer.py —— AI 生成层（流水线：爬文章 → 提 PoC → AI 按公开思路生成 → 落文件库）

AI 只干两件事：抓全网漏洞、按公开思路生成 PoC。**不做"漏洞是否可用"的判断** ——
那是人（或授权测试）看到播报之后的事，模型自己拍板只会把新漏洞误杀在门外。

PoC 来源两条路（字段 poc_source）：
- article：文章里已含 PoC 代码块，爬虫提取原样入库
- ai：文章只有思路没有 PoC → 调 LLM 按公开思路编写
两层 LLM 调用均带 mock 兜底（LLM 不可用时框架照常跑）。

nuclei 通道：
- 条目自带 _nuclei（TplRef）→ 说明来自模板库，直接把原模板落盘，不走生成
- 文章来源的条目 → 落盘前调 nuclei_tpl.convert() 生成模板（默认只生成只读探测型）
- 模板库增量同步（sync_templates）独立成入口，模板原样入库不过 LLM
"""
import json
from datetime import datetime

import config
import crawler
import nuclei_sync
import nuclei_tpl
import store
import translate
from llm import LLM, get_llm
from sources import fetch_all, fetch_nuclei_remote

_GENERATE_SYS = (
    "你是资深安全研究员，为漏洞播报系统生成结构化情报，内容仅用于防御研究与"
    "授权测试教育目的。根据文章信息只返回 JSON："
    '{"name": "中文漏洞名称", "summary": "一句话简介", '
    '"principle": "漏洞原理，2-4句", "attack_scope": "攻击范围/影响面", '
    '"poc": "python 概念验证代码，带注释", "poc_lang": "python"}。'
    "若用户消息里给了 article_poc，则 poc 字段必须原样使用它，不要改写。"
)


def _brief(item: dict, content: str) -> str:
    return json.dumps(
        {"title": item.get("title"), "summary": item.get("summary"),
         "content": content[:2500], "refs": item.get("refs")},
        ensure_ascii=False)


def llm_generate(llm: LLM, item: dict, content: str = "", poc: str | None = None) -> dict:
    try:
        user = _brief(item, content)
        if poc:
            user = json.dumps({"article_poc": poc, "context": json.loads(user)},
                              ensure_ascii=False)
        r = llm.chat(_GENERATE_SYS, user)
        if r.get("name") and r.get("poc"):
            return r
    except Exception as e:  # noqa: BLE001
        print(f"[generate] LLM 不可用({e!r}) → 模板兜底")
    fallback_poc = poc or (
        f"# {item['id']} 概念验证模板（兜底生成，仅用于授权测试）\n"
        "import requests\n\nTARGET = \"http://TARGET\"\n\n"
        "def probe():\n"
        "    \"\"\"思路：按文章分析构造触发请求，观察响应差异确认漏洞存在。\"\"\"\n"
        "    r = requests.get(TARGET, timeout=10, verify=False)\n"
        "    print(r.status_code, r.text[:200])\n\n"
        "if __name__ == \"__main__\":\n"
        "    probe()\n")
    return {"name": f"{item.get('title', item['id'])}（兜底）",
            "summary": item.get("summary", "")[:120],
            "principle": "成因与利用思路见原文，建议阅读参考链接确认影响版本。",
            "attack_scope": "以原文描述的影响范围为准（模板兜底生成）。",
            "poc_lang": "python", "poc": fallback_poc}


_POC_SYS = (
    "你是资深安全研究员，为漏洞播报系统写 Python 概念验证代码，仅用于防御研究与"
    "授权测试教育目的。根据漏洞信息与 nuclei 模板只返回 JSON："
    '{"poc": "python 代码，带注释"}。'
    "要求：TARGET 留成占位符；请求构造要与模板的 payload 逻辑一致；"
    "不得写入破坏性 payload，只做无害探测；代码要能直接运行。"
)


def gen_poc(vid: str, llm=None) -> dict:
    """给已收录漏洞补一份 Python PoC，已有则按公开思路重写。

    nuclei 模板库进来的条目本来只有 yaml（poc 为空），这里让模型把模板的 payload
    翻成可读可运行的 Python；模板原文仍在 nuclei.yaml 里没动。

    别因为"已经有 PoC"就拒掉：前端按钮在有 PoC 时显示的就是「重新生成」，
    后端再拦一次的话点下去只会报一句看不懂的失败。
    """
    v = store.get_vuln(vid)
    if not v:
        return {"ok": False, "reason": "漏洞不存在"}
    llm = llm or get_llm()
    brief = {"name": v.get("name", ""), "summary": v.get("summary", ""),
             "principle": v.get("principle", ""), "cvss": v.get("cvss"),
             "refs": v.get("refs", [])[:5], "nuclei_template": v.get("nuclei_yaml", "")[:4000]}
    try:
        r = llm.chat(_POC_SYS, json.dumps(brief, ensure_ascii=False))
    except Exception as e:  # noqa: BLE001
        return {"ok": False, "reason": f"LLM 不可用：{e}"}
    poc = str(r.get("poc") or "").strip()
    if not poc:
        return {"ok": False, "reason": "AI 未返回 PoC 代码"}
    meta = {k: val for k, val in v.items()
            if k not in ("poc", "nuclei_yaml", "poc_file")}   # 这三个由 store 重算
    meta["poc_source"] = "ai"
    store.save(meta, poc, "python", v.get("nuclei_yaml", ""))
    return {"ok": True, "poc": poc, "chars": len(poc)}


def from_template(tpl, vid: str = "", published: str = "") -> tuple[dict, str, str]:
    """模板库条目 → (meta, poc, nuclei_yaml)。原模板已经是最规范的探测逻辑，直接用。"""
    meta = {"name": tpl.name, "summary": tpl.description or tpl.name,
            "principle": "见模板 description 与官方 reference。",
            "attack_scope": f"协议：{', '.join(tpl.extra.get('protocols') or ['-'])}；"
                            f"严重性：{tpl.severity}",
            "refs": tpl.refs[:8], "poc_source": "nuclei",
            "note": "来自 nuclei 模板库，原样收录"}
    if vid:
        meta["id"] = vid
    if published:
        meta["published"] = published
    return meta, "", tpl.extra.get("raw", "")


def sync_templates(full: bool = False, limit: int = 0) -> dict:
    """nuclei-templates 增量同步入库（独立入口，不过 LLM 做筛选）。

    git diff 出上次同步后新增/修改的模板 → 逐个解析 → 按最后提交日期筛掉太旧的
    → 顺手中文化 → 原样落盘。模板本身是最规范的探测逻辑，过一遍 LLM 只会把它
    改差，所以这里只让 LLM 翻译标题/简介/原理，不碰模板内容。
    """
    ref = config.get("nuclei", "ref")
    limit = limit or config.get("nuclei", "sync_limit") or 0
    keep_days = config.get("collect", "keep_days") or 0
    do_zh = bool(config.get("collect", "auto_translate"))
    r = nuclei_sync.sync(ref=ref, full=full, limit=limit)
    if r.message and not r.files:
        return r.as_dict()

    repo = nuclei_sync.NUCLEI_REPO_DIR
    dates = nuclei_sync.changed_dates(repo, r.from_commit, r.to_commit)
    today = datetime.now().strftime("%Y-%m-%d")
    llm = get_llm() if do_zh else None
    saved, skipped, failed, expired, zh_ok, zh_fail = [], 0, 0, 0, 0, 0
    for rel in r.files:
        tpl = nuclei_sync.parse_tpl_file(repo, rel)
        if tpl is None:
            failed += 1
            continue
        vid = f"nuclei-{nuclei_tpl._slug(tpl.id)}"
        if store.get_vuln(vid):
            skipped += 1
            continue
        # 模板的"新鲜度"看它最后一次被改的提交日；增量 diff 出来的必然是近期，
        # 全量重扫时靠它把 2000 年的老模板筛掉
        published = dates.get(rel) or today
        meta, poc, yaml_text = from_template(tpl, vid, published)
        meta.update({"id": vid, "source": tpl.source, "cvss": tpl.cvss,
                     "tpl_path": rel, "sync_commit": r.to_commit[:12]})
        if store.too_old(meta, keep_days):
            expired += 1
            continue
        if do_zh:
            translate.translate_and_fill(meta, llm)
            if meta.get("translated"):
                zh_ok += 1
            else:
                zh_fail += 1
        saved.append(store.save(meta, poc, "python", yaml_text))
    nuclei_sync.commit_state(r.to_commit, len(saved))
    print(f"[sync] 入库 {len(saved)} 条（译文 {zh_ok} / 保留英文 {zh_fail}），"
          f"已存在 {skipped}，过期丢弃 {expired}，解析失败 {failed}")
    return {**r.as_dict(), "imported": len(saved), "skipped": skipped,
            "failed": failed, "expired": expired, "translated": zh_ok,
            "files": saved}


def pull_templates(limit: int = 0, severity: str = "", tag: str = "") -> dict:
    """手动从远程模板库拉一批模板入库（原样落盘，不过 LLM 做筛选）。"""
    items = fetch_nuclei_remote(limit or config.get("nuclei", "remote_limit"),
                                severity=severity, tag=tag)
    keep_days = config.get("collect", "keep_days") or 0
    do_zh = bool(config.get("collect", "auto_translate"))
    llm = get_llm() if do_zh else None
    saved, skipped, expired = [], [], 0
    for it in items:
        vid = it["id"]
        if store.get_vuln(vid):
            skipped.append(vid)
            continue
        meta, poc, yaml_text = from_template(it.pop("_nuclei"))
        meta.update({"id": vid, "source": it["source"], "cvss": it.get("cvss"),
                     "published": it.get("published", "")})
        if store.too_old(meta, keep_days):
            expired += 1
            continue
        if do_zh:
            translate.translate_and_fill(meta, llm)
        saved.append(store.save(meta, poc, "python", yaml_text))
    return {"fetched": len(items), "saved": saved, "skipped": skipped, "expired": expired}


def run_collect() -> dict:
    """完整流水线：爬文章 → 抓正文/提 PoC → AI 按公开思路生成 → nuclei 模板 → 落文件库。

    不做"漏洞是否可用"的筛选：抓到就播，可不可用由看到播报的人判断。
    """
    items = fetch_all()
    llm = get_llm()
    keep_days = config.get("collect", "keep_days") or 0
    kept = skipped = tpl_ok = tpl_skip = expired = 0
    for it in items:
        if store.get_vuln(it["id"]):        # 已收录 → 去重跳过
            skipped += 1
            continue

        tpl = it.pop("_nuclei", None)       # 来自 nuclei 模板库的条目
        if tpl is not None:
            meta, poc, yaml_text = from_template(tpl)
            meta.update({"id": it["id"], "source": it["source"], "cvss": it.get("cvss"),
                         "published": it.get("published", "")})
        else:
            # 文章条目的日期在 fetch 时就定了，先判保留期：过期的不该先花钱爬正文、
            # 调 LLM 生成，再被丢掉。标题里的 CVE 年份和 published 都在 it 上，
            # 够 entry_date 判了。
            if store.too_old(it, keep_days):
                expired += 1
                print(f"[skip] {it['id']} 超出保留期（{store.entry_date(it)[0]}）")
                continue
            pre_poc = it.pop("_poc", None)  # mock 样本预置的现成 PoC
            content, poc = crawler.fetch_article_content(it.get("link", "")) \
                if it.get("link") else ("", None)
            poc = poc or pre_poc

            gen = llm_generate(llm, it, content, poc)
            # 不硬写 translated：LLM 挂掉时 name 是原文标题（exploit-db 全是英文），
            # 谎报已译会让回填永远跳过它。need_translate 自己按有没有汉字判断。
            meta = {"id": it["id"], "name": gen["name"], "source": it["source"],
                    "summary": gen["summary"], "principle": gen["principle"],
                    "attack_scope": gen["attack_scope"], "cvss": it.get("cvss"),
                    "published": it.get("published", ""), "refs": it.get("refs", []),
                    "poc_source": "article" if poc else "ai"}
            poc = gen["poc"]
            yaml_text = ""
            if config.get("nuclei", "gen_templates"):
                r = nuclei_tpl.convert(meta, poc, llm=llm)
                if r["ok"]:
                    yaml_text = r["yaml"]
                    tpl_ok += 1
                else:
                    tpl_skip += 1
                    print(f"[nuclei] {it['id']} 未生成模板: {r['reason']}")

        if store.too_old(meta, keep_days):   # 模板条目的日期要等 from_template 出来才有
            expired += 1
            print(f"[skip] {it['id']} 超出保留期（{store.entry_date(meta)[0]}）")
            continue
        if tpl is not None:
            translate.translate_and_fill(meta, llm)   # 模板条目是英文，入库前先中文化
        vid = store.save(meta, poc, "python", yaml_text)
        print(f"[saved] {vid} :: {meta['name']}  poc_source={meta['poc_source']}"
              f"  nuclei={'有' if yaml_text else '无'}")
        kept += 1
    return {"fetched": len(items), "kept": kept, "skipped": skipped,
            "expired": expired, "nuclei_ok": tpl_ok, "nuclei_skipped": tpl_skip}
