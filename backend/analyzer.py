"""analyzer.py —— AI 生成层（流水线：爬文章 → 提 PoC → AI 按公开思路生成 → 落文件库）

AI 干三件事：抓全网漏洞、给漏洞写 PoC、**分清抓到的东西是不是漏洞情报**。
最后这项以前没有，于是《XX 大赛 WriteUp》这种技术文章也被当成漏洞播了出去；
现在交给 content_judge 用模型判，判不出就不收。

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
import logging
from datetime import datetime

import config
import content_judge
import crawler
import nuclei_sync
import nuclei_tpl
import store
import translate
from llm import LLM, get_llm
from sources import fetch_all, fetch_nuclei_remote

logger = logging.getLogger("ai_bobao.analyzer")

# 评级标准（四档边界写死，防止模型把所有东西都评成高危）。AI 生成情报、
# 存量条目回填评级两处共用这一份，改标准只动这里。
_RATE_RULES = (
    "严重=能直接拿下重要服务器/客户端的远程代码执行（任意命令执行、上传 webshell、"
    "可利用的远程缓冲区溢出/内核代码执行/浏览器 UAF），或直接造成严重信息泄漏"
    "（重要系统可拖走大量数据的 SQL 注入）、直接拿到目标单位核心机密；"
    "高危=能直接拿到普通系统权限（远程命令/代码执行、上传 webshell、溢出），"
    "或严重逻辑/流程缺陷（任意账号密码修改、重要业务配置修改或泄露）、"
    "可批量盗取用户身份（普通系统 SQL 注入、用户订单遍历）、严重权限绕过"
    "（绕过认证直接进管理后台、cookie 欺骗）、运维相关未授权访问（后台弱口令、服务未授权）；"
    "中危=有条件限制下才能拿服务器/网站权限或核心数据库数据（交互性代码执行、"
    "一定条件下的注入、特定版本 getshell），或任意文件操作（任意写/删除/下载、"
    "敏感文件读取），或水平权限绕过（绕过限制改用户资料、执行用户操作）；"
    "低危=只能拿到少量非核心数据、苛刻条件下才影响核心数据/业务、"
    "或需要用户交互才触发（典型如 XSS）。"
)

_LEVELS_OK = ("严重", "高危", "中危", "低危")

_GENERATE_SYS = (
    "你是资深安全研究员，为漏洞播报系统生成结构化情报，内容仅用于防御研究与"
    "授权测试教育目的。根据文章信息只返回 JSON："
    '{"name": "中文漏洞名称", "summary": "一句话简介", '
    '"principle": "漏洞原理，2-4句", "attack_scope": "攻击范围/影响面", '
    '"poc": "python 概念验证代码，带注释", "poc_lang": "python", '
    '"level": "评级，严重|高危|中危|低危 四选一"}。'
    "若用户消息里给了 article_poc，则 poc 字段必须原样使用它，不要改写。"
    "评级按这条标准：" + _RATE_RULES
)

# 存量回填专用的轻提示：只要评级，不要成稿
_RATE_SYS = ("你是漏洞评级员。看漏洞信息只返回 JSON："
             '{"level": "严重|高危|中危|低危"}。评级标准：' + _RATE_RULES)


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
        logger.warning("LLM 不可用（%r），改用兜底模板", e)
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
            "poc_lang": "python", "poc": fallback_poc,
            # 标记出来：模型没给出成稿的条目不该入库，否则列表里会挂着一堆
            # 「XXX（兜底）」，既不是可信情报，也不是像样的情报
            "fallback": True}


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
            # 模板自带 EN 级别（critical/high/...），store.level_of 映射成中文评级
            "severity": tpl.severity,
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
    logger.info("模板同步入库 %s 条（译文 %s / 保留英文 %s），已存在 %s，过期丢弃 %s，解析失败 %s",
                len(saved), zh_ok, zh_fail, skipped, expired, failed)
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
    """完整流水线：爬文章 → 抓正文 → 内容性质判定 → AI 生成 → nuclei 模板 → 落文件库。

    收录与否分两层：
    - nuclei 模板库来的条目直接收，模板本身就是最规范的探测逻辑
    - 文章来的条目先让 LLM 判性质（content_judge.judge）：赛事 WriteUp、工具
      教程、行业新闻一律不收。判定在抓正文之后、生成之前，省掉一次 LLM 调用
    - 模型给不出成稿（llm_generate 走了兜底）同样不收，兜底名进库只会污染列表

    判断"漏洞好不好用"仍然交给看到播报的人，模型只负责分清这是不是漏洞情报。
    """
    items = fetch_all()
    llm = get_llm()
    keep_days = config.get("collect", "keep_days") or 0
    kept = skipped = tpl_ok = tpl_skip = expired = rejected = 0
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
                logger.info("跳过 %s：已超出保留期（%s）", it["id"], store.entry_date(it)[0])
                continue
            pre_poc = it.pop("_poc", None)  # mock 样本预置的现成 PoC
            content, poc = crawler.fetch_article_content(it.get("link", "")) \
                if it.get("link") else ("", None)
            poc = poc or pre_poc

            # 内容性质判定。站点是安全社区不代表每篇文章都是漏洞：先知上既有
            # 漏洞分析也有比赛 WriteUp，只按日期筛会把《XX 大赛 WriteUp》播出去。
            # 判不准就不收，下一轮再抓；这里没有关键词兜底，因为关键词表写死就
            # 一定有漏网和误杀。
            verdict = content_judge.judge(llm, it, content)
            if not verdict["is_vuln"]:
                rejected += 1
                logger.info("不收 %s：%s（%s）", it["id"],
                            verdict["reason"] or "非漏洞情报", verdict["kind"])
                continue

            gen = llm_generate(llm, it, content, poc)
            if gen.get("fallback"):
                rejected += 1
                logger.warning("不收 %s：内容判定通过，但模型没给出成稿，"
                               "留着兜底条目只会污染列表", it["id"])
                continue

            # 不硬写 translated：LLM 挂掉时 name 是原文标题（exploit-db 全是英文），
            # 谎报已译会让回填永远跳过它。need_translate 自己按有没有汉字判断。
            # level 只收认可的四个值；模型给了奇怪的值就留空，落库后按 CVSS 划线兜底
            lv = str(gen.get("level") or "").strip()
            meta = {"id": it["id"], "name": gen["name"], "source": it["source"],
                    "summary": gen["summary"], "principle": gen["principle"],
                    "attack_scope": gen["attack_scope"], "cvss": it.get("cvss"),
                    "level": lv if lv in _LEVELS_OK else "",
                    "published": it.get("published", ""), "refs": it.get("refs", []),
                    "component": verdict["component"],
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
                    logger.info("%s 未生成模板：%s", it["id"], r["reason"])

        if store.too_old(meta, keep_days):   # 模板条目的日期要等 from_template 出来才有
            expired += 1
            logger.info("跳过 %s：已超出保留期（%s）", it["id"], store.entry_date(meta)[0])
            continue
        if tpl is not None:
            translate.translate_and_fill(meta, llm)   # 模板条目是英文，入库前先中文化
        vid = store.save(meta, poc, "python", yaml_text)
        logger.info("已收录 %s :: %s（poc 来源 %s，nuclei 模板 %s）",
                    vid, meta["name"], meta["poc_source"], "有" if yaml_text else "无")
        kept += 1
    try:
        rate_backfill(llm, limit=20)     # 抓取轮顺手给存量补评级；独立试错不影响主流程
    except Exception as e:  # noqa: BLE001 —— 评级是锦上添花，绝不让整轮报错
        logger.warning("存量评级补全中断：%r", e)
    return {"fetched": len(items), "kept": kept, "skipped": skipped,
            "expired": expired, "rejected": rejected,
            "nuclei_ok": tpl_ok, "nuclei_skipped": tpl_skip}


# 评过失败/无效回答的条目记在内存里，本轮进程内不再重试，免得每次抓取
# 都在同一批最难的条目上空烧额度。重启进程（每天一关一开）会重新给机会。
_RATE_TRIED: set[str] = set()


def rate_backfill(llm: LLM | None = None, limit: int = 20) -> int:
    """给存量没有可靠评级的条目按标准补 level，返回本轮评上的条数。

    每条只要一个词的答案，prompt 很短；失败/模型跑偏就跳过并标记已试，
    下一轮抓取继续补下一批。limit 控制单轮的调用数（默认 20），
    全靠多轮积少成多补完整个库，不指望一口气评完 800+ 条。
    """
    todo = store.ids_missing_level(limit + len(_RATE_TRIED))
    todo = [vid for vid in todo if vid not in _RATE_TRIED][:limit]
    if not todo:
        return 0
    llm = llm or get_llm()
    rated = 0
    for vid in todo:
        v = store.get_vuln(vid)
        if not v:
            _RATE_TRIED.add(vid)
            continue
        brief = json.dumps({"name": v.get("name"),
                            "summary": str(v.get("summary") or "")[:200],
                            "principle": str(v.get("principle") or "")[:400]},
                           ensure_ascii=False)
        try:
            r = llm.chat(_RATE_SYS, brief)
            lv = str(r.get("level") or "").strip()
            if lv in _LEVELS_OK and store.patch_meta(vid, {"level": lv}):
                rated += 1
        except Exception as e:  # noqa: BLE001 —— 单条评级失败只跳过，不抬走整轮
            logger.debug("评级失败 %s：%r", vid, e)
        finally:
            _RATE_TRIED.add(vid)
    logger.info("存量评级补全 %s/%s 条（已试 %s）", rated, len(todo), len(_RATE_TRIED))
    return rated


def recheck_library(limit: int = 0, llm=None) -> dict:
    """拿已经收进库的条目重新过一遍内容判定，清掉历史脏数据。

    干两件事：
    - 判定为非漏洞（赛事 WriteUp、教程、新闻）→ 直接删掉漏洞目录和汇总模板
    - 标题带「（兜底）」→ 当时模型没给出成稿，直接删掉

    兜底条目不再重写：模型重写一遍还是可能失败，白花配额还留个半成品在库里。
    现在抓取阶段就已经拒收兜底条目（见 run_collect），存量这批直接清掉。

    limit=0 表示全库复检；处理量按 limit 截断，够先看效果了。nuclei 模板库
    来的条目（id 以 nuclei- 开头、poc_source 为 nuclei）跳过复检——模板的
    名字本来就是漏洞 ID，判了也只会浪费模型配额。
    """
    llm = llm or get_llm()
    metas = store.all_metas()
    scanned = removed = kept = 0
    removed_ids, failed = [], []
    for m in metas:
        if limit and scanned >= limit:
            break
        if m.get("poc_source") == "nuclei" or str(m.get("id", "")).startswith("nuclei-"):
            continue                        # 模板库条目不参与判定
        scanned += 1
        name = str(m.get("name") or "")
        if "（兜底）" in name:
            # 当时模型挂了才留下的半成品，没成稿也没可信度，直接清掉。
            # 放在判定之前：这类条目不用问模型也知道要删，省下模型配额。
            if store.delete_vuln(m["id"]):
                removed += 1
                removed_ids.append(m["id"])
                logger.info("复检删除兜底条目 %s：%s", m["id"], name)
            else:
                failed.append(m["id"])
            continue

        # 复检时手上只有 meta，没有正文；name + summary + 原理已经够模型判断性质
        verdict = content_judge.judge(llm, m, m.get("summary", ""))
        if not verdict["is_vuln"]:
            if store.delete_vuln(m["id"]):
                removed += 1
                removed_ids.append(m["id"])
                logger.info("复检删除 %s：%s（%s）", m["id"],
                            verdict["reason"] or "非漏洞情报", verdict["kind"])
            else:
                failed.append(m["id"])
            continue

        if verdict["component"]:
            store.update_meta(m["id"], {"component": verdict["component"]})

        kept += 1
    return {"scanned": scanned, "removed": removed, "removed_ids": removed_ids,
            "kept": kept, "failed": failed}
