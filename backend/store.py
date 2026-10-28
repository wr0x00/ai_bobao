"""store.py —— 文件库（暂不落数据库）：

data/vulns/{漏洞ID}/
  ├── meta.json     元数据：名称/来源/简介/原理/攻击范围/参考链接...
  ├── poc.py        PoC 文本（前端在线查看）
  └── nuclei.yaml   对应的 nuclei 模板（有才写；生成或从模板库拉来的）

data/nuclei_tpl/   所有模板的汇总目录，可直接 `nuclei -l data/nuclei_tpl` 跑
列表 = 扫目录读 meta.json；详情 = 目录名 → meta + poc 全文 + 模板。
以后换数据库只需重写本文件的几个函数，其他层不动。

路径安全：漏洞 ID 一律经 security.require_vid 校验，meta.json 里回读的
poc_file 一律当不可信输入处理（限定 poc.<白名单后缀> 且必须在漏洞目录内）。
"""
import json
import logging
import re
import shutil
import threading
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path

import security
from config import NUCLEI_TPL_DIR, VULN_DIR

logger = logging.getLogger("ai_bobao.store")

_CVE_YEAR = re.compile(r"CVE-(\d{4})", re.I)
_DATE_RE = re.compile(r"(\d{4})-(\d{2})-(\d{2})")
_HAS_ZH = re.compile(r"[\u4e00-\u9fff]")
_FALLBACK_MARK = "（兜底）"   # llm_generate 兜底时拼在标题末尾的标记

# PoC 文件允许的后缀。poc_lang 会直接拼进文件名并落到磁盘上，不设白名单的话
# 一个 "../.." 就能把文件写到漏洞目录外面去。
_POC_LANGS = frozenset({"python", "py", "txt", "http", "md"})
_POC_FILE_RE = re.compile(r"^poc\.(python|py|txt|http|md)$")

# 组件名提取用的规则。nuclei 模板的 id 长这样：
#   "WordPress Plugin Elementor 3.5.0 - XSS"
#   "CVE-2024-12345 - Apache HTTP Server 路径遍历"
# 先按分隔符砍掉后半段的"漏洞类型"，再砍掉版本号和编号，剩下的就是组件名。
# 这只是统计口径（总览页按组件分组），不参与"这条要不要收录"的判断——
# 收录与否一律由 content_judge 交给模型判。
_VER_RE = re.compile(r"\s+v?\d+(?:\.\d+){1,4}(?:[-.]\w+)*\s*$")   # 末尾版本号 3.5.0 / v2.1
_CMP_RE = re.compile(r"[\s<>=~^]+$")                    # 砍完版本号剩下的 "<=" ">" "~" 之类
_CVE_RE = re.compile(r"\bCVE-\d{4}-\d+\b", re.I)
_CNAF_RE = re.compile(r"\b(CNAF|CNVD|CNNVD|CNNVD)-[\d\-]+\b", re.I)
_LEAD_TYPE_RE = re.compile(
    r"^(HTTP|SSL|TLS|DNS|TCP|FTP|SMB|SSH|WebSocket|RPC|SOAP|PAN|GPON|CVE|GHSA|DNN)\b[:\s]*", re.I)

# 列表缓存。_load_rows 每次要读完 200 多个 meta.json，列表页翻页和状态页轮询
# 都靠它，短缓存能省掉大量重复 IO。写操作（save / purge）会主动失效。
_ROW_CACHE_TTL = 10.0
_rows_cache: dict = {"at": 0.0, "rows": [], "gen": 0}
_rows_lock = threading.Lock()
# 读盘的单飞锁：缓存过期那一瞬间，前端首屏会同时打 stats / vulns / llm 三个接口，
# 三个都在等同一批 meta.json。以前每个线程各自去扫盘，等于同一个盘扫 N 遍。
_rows_load_lock = threading.Lock()

# 模板库缓存。841 个 yaml 要全量解析一遍，缓存住省得每次翻模板页都重来。
# 模板目录只在 save（写入）和 _remove_summary_tpl（删除）时变，这两处会主动失效。
_TPL_CACHE_TTL = 30.0
_tpl_cache: dict = {"at": 0.0, "items": []}
_tpl_lock = threading.Lock()

# YAML 解析器。PyYAML 自带 libyaml 的 C 扩展时用它，比纯 Python 的 safe_load 快 5 倍，
# 结果完全一致；没编译 C 扩展就退回 safe_load。
_YAML_LOADER = None


def _yaml_loader():
    """拿最好的那个 YAML loader：优先 CSafeLoader（libyaml），否则 safe_load。"""
    global _YAML_LOADER
    if _YAML_LOADER is None:
        import yaml
        _YAML_LOADER = getattr(yaml, "CSafeLoader", yaml.SafeLoader)
    return _YAML_LOADER


def _parse_yaml(text: str):
    """解析一段 YAML。libyaml 解析不了的（极少数自定义标签）退回纯 Python 再试一次。"""
    import yaml
    try:
        return yaml.load(text, Loader=_yaml_loader())
    except Exception:  # noqa: BLE001 —— 换回 safe_load 再试，还是不行就当这条模板坏了
        try:
            return yaml.safe_load(text)
        except Exception:  # noqa: BLE001
            return None


def is_zh_name(name: str) -> bool:
    """标题是不是真的中文。translate.need_translate 也用这个判断，别再各写一份。

    必须先剥掉「（兜底）」：兜底名是 LLM 挂掉时拿原文标题拼出来的，而"兜""底"
    两个字本身就在汉字区间里，不剥掉的话 exploit-db 那种全英文标题会被当成
    已中文化，回填永远跳过它。
    """
    return bool(_HAS_ZH.search((name or "").replace(_FALLBACK_MARK, "")))


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def entry_date(meta: dict) -> tuple[str, bool]:
    """条目的真实披露日期，返回 (YYYY-MM-DD, 是否只有年份)。

    CVE 编号的年份优先于 published：nuclei 模板的 published 是"入库当天"，
    不是漏洞本身的年龄，不拿它判新鲜度的话列表里会一直混着 2000 年的漏洞。
    文章源给的 published 反而可能是旧文的转载，所以年份说话时以年份为准。

    编号里通常只有年份没有月日，这种按"该年最后一天"算：取 1 月 1 日会被
    keep_days 误杀当年的新漏洞，宁可多留一条。返回的 bool 用来让前端只显示年份，
    免得列表里出现 2026-12-31 这种未来日期。
    """
    blob = f"{meta.get('id', '')} {meta.get('name', '')} {' '.join(meta.get('refs') or [])}"
    years = _CVE_YEAR.findall(blob)
    if years:
        return f"{max(int(y) for y in years)}-12-31", True
    m = _DATE_RE.search(str(meta.get("published") or ""))
    if m:
        return m.group(0), False
    m = _DATE_RE.search(str(meta.get("created_at") or ""))
    return (m.group(0), False) if m else ("", False)


def too_old(meta: dict, keep_days: int) -> bool:
    """是否超出保留期。keep_days=0 表示不按日期筛。"""
    if keep_days <= 0:
        return False
    d = entry_date(meta)[0]
    if not d:
        return False                      # 日期不明的先留着，别误杀
    try:
        return datetime.strptime(d, "%Y-%m-%d").date() < \
            (datetime.now().date() - timedelta(days=keep_days))
    except ValueError:
        return False


def component_of(name: str, vid: str = "") -> str:
    """从标题里量出"这是哪个组件的漏洞"，量不出就返回空串。

    只用于统计分组：老条目入库时还没有 component 字段（那时还没让模型判），
    总览页要把它们和 nuclei 模板条目放在同一张图上，就在这儿按标题切一刀。
    切完还剩不出东西的返回空串，由调用方落到"未分类"。
    """
    raw = (name or "").strip()
    if not raw:
        return ""
    # nuclei 模板的 id 形如 "WordPress Plugin Elementor 3.5.0 - XSS"，
    # " - " 后面基本是漏洞类型（XSS / RCE / 路径遍历），前面才是组件
    head = re.split(r"\s+[-–—]\s+", raw)[0]
    head = _CVE_RE.sub(" ", head)
    head = _CNAF_RE.sub(" ", head)
    head = _LEAD_TYPE_RE.sub("", head)
    head = _VER_RE.sub("", head)
    head = _CMP_RE.sub("", head)              # "SiYuan <=0.58" 砍完版本号还剩个 "<="
    head = re.sub(r"[（(].*?[)）]", " ", head)      # 括注一般是说明，不是组件名
    head = re.sub(r"\s{2,}", " ", head).strip(" -–—:：,，、")
    # 砍完太短说明切错了（多半整段都是编号），这种宁可归"未分类"
    return head[:60] if len(head) >= 3 else ""





































# ── 评级 ──────────────────────────────────────────────────
# 评级三条来源，按可靠性排：AI 生成/回填时给的 level、nuclei 模板自带的
# severity（EN→中文映射）、CVSS 分数划线。都凑不齐就"未评级"，前端给灰块。
# CVSS 划线按业界惯例：≥9 严重、≥7 高危、≥4 中危、>0 低危。
_SEV_ZH = {"critical": "严重", "high": "高危", "medium": "中危",
           "low": "低危", "info": "低危"}
_LEVELS = ("严重", "高危", "中危", "低危")
_LEVEL_FILTERS = frozenset((*_LEVELS, "未评级"))   # list_vulns 的 level 参数白名单
_LEVEL_RANK = {"严重": 0, "高危": 1, "中危": 2, "低危": 3}


def level_of(m: dict) -> str:
    """条目的中文评级。AI 评过的直接用，其次模板 severity，再不行按 CVSS 划。"""
    lv = str(m.get("level") or "").strip()
    if lv in _LEVELS:
        return lv
    sev = str(m.get("severity") or "").strip().lower()
    if sev in _SEV_ZH:
        return _SEV_ZH[sev]
    try:
        c = float(m.get("cvss") or 0)
    except (TypeError, ValueError):
        c = 0.0
    if c >= 9:
        return "严重"
    if c >= 7:
        return "高危"
    if c >= 4:
        return "中危"
    if c > 0:
        return "低危"
    return "未评级"


def _dump(d: Path, meta: dict) -> None:
    (d / "meta.json").write_text(
        json.dumps(meta, ensure_ascii=False, indent=2), encoding="utf-8")


def save(meta: dict, poc: str, poc_lang: str = "python", nuclei_yaml: str = "") -> str:
    """把一条漏洞写进文件库，返回最终用的漏洞 ID。

    目录名由 security.normalize_vid 从原始 ID 归一化而来（非法字符换下划线、
    截断到 120 字符），文件名后缀走 _POC_LANGS 白名单。两道都过了才落盘，
    免得 meta["id"] 或 poc_lang 里带一个 ".." 就把文件写到数据目录外面。
    """
    vid = security.normalize_vid(meta["id"])
    if not vid:
        raise ValueError("漏洞 ID 归一化之后是空的")
    lang = (poc_lang or "python").lower().strip().lstrip(".")
    if lang not in _POC_LANGS:
        lang = "python"                      # 认不出来的后缀一律按 python 存，别拼进路径

    d = security.safe_join(VULN_DIR, vid)
    d.mkdir(parents=True, exist_ok=True)
    meta = {**meta, "id": vid, "poc_file": f"poc.{lang}",
            "created_at": meta.get("created_at") or _now(),
            # 每次写盘都刷新更新时间：入库、重新生成 PoC、补模板都会走到这
            "updated_at": _now()}
    (d / f"poc.{lang}").write_text(poc, encoding="utf-8")
    if nuclei_yaml:
        meta["nuclei_file"] = "nuclei.yaml"
        (d / "nuclei.yaml").write_text(nuclei_yaml, encoding="utf-8")
        NUCLEI_TPL_DIR.mkdir(parents=True, exist_ok=True)   # 汇总一份，整体可 nuclei -l 跑
        shutil.copyfile(d / "nuclei.yaml", security.safe_join(NUCLEI_TPL_DIR, f"{vid}.yaml"))
        invalidate_templates()          # 汇总目录变了，模板库缓存要跟着失效
    _dump(d, meta)
    invalidate_rows()
    return vid


def _read_text(path: Path, limit: int = 4 * 1024 * 1024) -> str:
    """读文本，坏编码按替换处理。单文件超过 limit 就当没有，省得一条坏数据吃光内存。"""
    try:
        if path.stat().st_size > limit:
            return ""
        return path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return ""


def _load_rows_uncached() -> list[dict]:
    """全量读 meta.json，附带排序用的日期。列表页和筛选都基于它。"""
    rows = []
    if not VULN_DIR.exists():
        return rows
    for d in VULN_DIR.iterdir():
        f = d / "meta.json"
        if not f.is_file():
            continue
        try:
            m = json.loads(f.read_text(encoding="utf-8"))
        except Exception:  # noqa: BLE001 —— 单条坏文件不该让整个列表打不开
            continue
        if not isinstance(m, dict) or not m.get("id"):
            continue
        date, year_only = entry_date(m)
        name = m.get("name") or m["id"]
        # 组件名三条来源：判定时模型给的 component、老条目从标题里量的，
        # 都没有就显示"未分类"——总览页的条形图按它分组。
        component = str(m.get("component") or "").strip()[:80] \
            or component_of(name, m.get("id", "")) or "未分类"
        # 关键词检索用的合并文本，只在列表页内部用，不返回给前端
        _text = " ".join(str(m.get(k) or "") for k in
                         ("id", "name", "summary", "principle")).lower()
        rows.append({"id": m["id"], "name": name,
                     "source": str(m.get("source") or "-")[:100],
                     "component": component,
                     "poc_source": str(m.get("poc_source") or "")[:20],
                     "summary": str(m.get("summary") or ""),
                     "published": str(m.get("published") or ""),
                     "cvss": m.get("cvss"),
                     # translated 只说明"是 LLM 翻的"；老条目没这个标记但本来就是中文，
                     # 所以额外看一眼标题有没有汉字，不然列表页会给中文标题挂 EN 角标
                     "translated": bool(m.get("translated")) or is_zh_name(name),
                     "has_nuclei": (d / "nuclei.yaml").is_file(),
                     # 编号里只有年份时只显示年份，别拿 12-31 糊弄用户
                     "entry_date": date[:4] if year_only else date,
                     "entry_iso": date or (m.get("created_at") or "")[:10],
                     # 评级 + 更新时间：列表色块、排序、详情页「更新于」都用它。
                     # updated 切到分钟，"2026-10-22T09:15" 转成空格分隔好读
                     "level": level_of(m),
                     "updated": str(m.get("updated_at")
                                    or m.get("created_at") or date or "")[:16].replace("T", " "),
                     "_text": _text})
    # 排序两层：主要键更新日期（只看天，新的在前）；次要键评级（高的在前）。
    # Python 排序稳定，先按评级排一遍，再按更新日排一遍，第二遍不拆第一遍的同分键。
    for r in rows:
        r["_upd"] = r["updated"][:10]
        r["_rank"] = _LEVEL_RANK.get(r["level"], 9)
    rows.sort(key=lambda x: x["_rank"])
    rows.sort(key=lambda x: x["_upd"], reverse=True)
    return rows


def invalidate_rows() -> None:
    """写完盘就把列表缓存丢掉。抓取任务和列表页并发是常态，不失效会看到旧数据。

    对外公开是因为 translate.py 也会改 meta.json，改完一样得让列表刷新。
    gen 加一是为了告诉正在读盘的那个线程："你手上这批数据已经过期了"，
    别再往缓存里写。
    """
    with _rows_lock:
        _rows_cache["at"] = 0.0
        _rows_cache["rows"] = []
        _rows_cache["gen"] += 1


def _load_rows() -> list[dict]:
    """带 10 秒缓存的全量行。返回的是同一份 list，调用方只读不改。

    缓存过期那一瞬间，前端首屏会同时打 stats / vulns / llm 三个接口，
    三个都要全量行。以前各扫各的盘，等于同一个盘被扫三遍，并发反而比串行慢。
    所以这里用 single-flight：慢的那次读盘放进 _rows_load_lock，
    别的线程在锁上排队，拿到锁再检查一次缓存，命中就直接用。
    """
    with _rows_lock:
        if time.monotonic() - _rows_cache["at"] <= _ROW_CACHE_TTL:
            return _rows_cache["rows"]
        gen = _rows_cache["gen"]

    with _rows_load_lock:                       # 只有一个线程进去读盘，其余在这排队
        with _rows_lock:
            if time.monotonic() - _rows_cache["at"] <= _ROW_CACHE_TTL:
                return _rows_cache["rows"]      # 等锁这段时间别人已经填好了
        rows = _load_rows_uncached()
        with _rows_lock:
            if _rows_cache["gen"] == gen:        # 读盘期间有人写盘了，这批数据作废
                _rows_cache["rows"] = rows
                _rows_cache["at"] = time.monotonic()
        return rows



def list_vulns(page: int = 1, page_size: int = 10, source: str = "", q: str = "",
               level: str = "", days: int = 0) -> dict:
    """分页列表。返回 {items, total, page, pages, page_size, all_total, counts}。

    前端只渲染当前页，一次传 4000 条没必要。counts 是全库按来源的计数，
    切页签时徽标数字不受分页影响。q 是关键词，在标题/编号/简介/原理里匹配，
    空格分隔的多个词要全部命中（AND）；counts 始终是全库计数，不随关键词变。
    level 按评级精确筛（只认四档 + 未评级，别的值当没传）；days 取"最近 N 天"
    （含今天，按更新时间算，和卡片上显示的更新日期同源）。
    """
    rows = _load_rows()
    counts: dict[str, int] = {}
    for r in rows:
        counts[r["source"]] = counts.get(r["source"], 0) + 1
    grand_total = len(rows)
    words = [w for w in q.lower().split() if w]
    if words:
        rows = [r for r in rows if all(w in r["_text"] for w in words)]
    if source and source != "全部":
        rows = [r for r in rows if r["source"] == source]
    if level and level != "全部" and level in _LEVEL_FILTERS:
        rows = [r for r in rows if r["level"] == level]
    if days and int(days) > 0:
        # updated 的日期部分是 UTC 日，与列表显示的更新日期同源，直接按字典序比较
        cutoff = (datetime.now(timezone.utc).date()
                  - timedelta(days=int(days) - 1)).isoformat()
        rows = [r for r in rows if r["_upd"] >= cutoff]
    total = len(rows)
    page_size = max(1, min(int(page_size or 10), 100))
    pages = max(1, -(-total // page_size))       # 向上取整
    page = max(1, min(int(page or 1), pages))
    items = [{k: v for k, v in r.items() if not k.startswith("_")}
             for r in rows[(page - 1) * page_size: page * page_size]]
    return {"items": items, "total": total, "page": page, "pages": pages,
            "page_size": page_size, "all_total": grand_total, "counts": counts}


def ids_missing_level(limit: int = 50) -> list[str]:
    """还没有可靠评级的条目 ID（level/severity/cvss 都凑不齐），给 AI 回填评级用。

    列表本身按「更新时间新的在前」排好，缺评级的老条目自然沉底排前面——先补它们。
    """
    out = []
    for r in _load_rows():
        if r["level"] != "未评级":
            continue
        out.append(r["id"])
        if len(out) >= limit:
            break
    return out


def patch_meta(vid: str, updates: dict) -> bool:
    """就地改一条 meta.json 的部分字段（评级回填用），改完刷新列表缓存。

    不碰 PoC/模板文件，只改 meta；临时文件 + replace 保证半截写不进去。
    找不到条目返回 False，调用方按跳过处理。
    """
    d = security.safe_join(VULN_DIR, security.normalize_vid(vid or ""))
    f = d / "meta.json" if d else None
    if not f or not f.is_file():
        return False
    try:
        m = json.loads(f.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return False
    m.update(updates)
    m["updated_at"] = _now()
    tmp = f.with_suffix(".json.tmp")
    tmp.write_text(json.dumps(m, ensure_ascii=False, indent=2), encoding="utf-8")
    tmp.replace(f)
    invalidate_rows()
    return True


def purge_expired(keep_days: int) -> dict:
    """删掉超出保留期的条目（漏洞目录 + 汇总模板目录一起清）。

    判定直接复用 too_old，别自己再写一遍日期逻辑，两边一旦不一致就会出现
    "列表里还留着过期条目"的漏网之鱼。

    删完必须让列表缓存失效，不然前端十秒内还能看到已经删掉的条目。
    """
    if keep_days <= 0 or not VULN_DIR.exists():
        return {"removed": 0, "ids": [], "failed": []}
    cutoff = datetime.now().date() - timedelta(days=keep_days)
    ids, failed = [], []
    for d in list(VULN_DIR.iterdir()):
        f = d / "meta.json"
        if not f.is_file():
            continue
        try:
            m = json.loads(f.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            continue
        if not isinstance(m, dict) or not too_old(m, keep_days):
            continue
        vid = str(m.get("id") or d.name)
        # 不能用 ignore_errors：文件被占用时它会静默跳过，删不掉却照样报成功，
        # 结果是过期条目留在库里，下一轮又被抓回来，抖个没完。
        try:
            shutil.rmtree(d)
        except OSError as e:
            failed.append(vid)
            logger.warning("漏洞 %s 删不掉（%s），可能正被占用", vid, e.strerror or e)
            continue
        _remove_summary_tpl(vid)
        ids.append(vid)
    if ids:
        logger.info("清理过期漏洞 %s 条（早于 %s）", len(ids), cutoff)
        invalidate_rows()
    return {"removed": len(ids), "ids": ids, "failed": failed}


def _remove_summary_tpl(vid: str) -> None:
    """删掉汇总模板目录里对应的 yaml。vid 来自 meta.json，不可信，重新归一化后再拼路径。"""
    name = security.normalize_vid(vid)
    if not name:
        return
    try:
        path = security.safe_join(NUCLEI_TPL_DIR, f"{name}.yaml")
    except security.SecurityError:
        return
    try:
        path.unlink(missing_ok=True)
    except OSError as e:
        logger.warning("汇总模板 %s 删不掉：%s", name, e)
    invalidate_templates()              # 汇总目录变了，模板库缓存要跟着失效


def pending_translate_count() -> int:
    """全库还有多少条没中文化。列表页只关心本页，这个数只给设置/状态页做提示。"""
    return sum(1 for r in _load_rows() if not r["translated"])


def list_templates() -> list[dict]:
    """模板库列表：data/nuclei_tpl 下每个 yaml 一条（可直接 nuclei -l 跑这个目录）。

    841 个模板全量解析一次要 3.4 秒，其中九成是 YAML 解析本身。这里做两件事：
    换 libyaml（PyYAML 的 C 扩展）解析，快 5 倍；再缓存 30 秒，翻页翻页不用重算。
    """
    with _tpl_lock:
        if time.monotonic() - _tpl_cache["at"] <= _TPL_CACHE_TTL:
            return _tpl_cache["items"]

    out = []
    if NUCLEI_TPL_DIR.exists():
        for f in sorted(NUCLEI_TPL_DIR.glob("*.yaml")):
            doc = _parse_yaml(f.read_text(encoding="utf-8", errors="replace"))
            if not isinstance(doc, dict) or not doc.get("id"):
                continue
            info = doc.get("info") or {}
            out.append({"id": doc["id"], "vid": f.stem, "name": info.get("name", doc["id"]),
                        "severity": info.get("severity", "unknown"),
                        "tags": info.get("tags", ""), "file": f.name,
                        "requests": len(doc.get("http") or [])})
    out.sort(key=lambda x: (x["severity"] != "critical", x["severity"] != "high", x["id"]))

    with _tpl_lock:
        _tpl_cache["items"] = out
        _tpl_cache["at"] = time.monotonic()
    return out


def invalidate_templates() -> None:
    """模板目录变了就把模板库缓存丢掉。save 写入和 _remove_summary_tpl 删除后都要调。"""
    with _tpl_lock:
        _tpl_cache["at"] = 0.0
        _tpl_cache["items"] = []


def get_vuln(vid: str) -> dict | None:
    """读一条漏洞详情。不存在或 ID 不合法都返回 None。

    meta.json 里的 poc_file 是回读字段——它写进去的时候是干净的，但文件库可能
    被手工改过、也可能被别的程序写脏，所以这里不直接信任：只接受
    poc.<白名单后缀> 这一个形状，再用 safe_join 确认拼出来的路径还在漏洞目录里。
    两道都过才读，否则当成没有 PoC。
    """
    try:
        vid = security.require_vid(vid)
        d = security.safe_join(VULN_DIR, vid)
    except security.SecurityError as e:
        logger.warning("拒绝读取漏洞详情：%s", e)
        return None

    f = d / "meta.json"
    if not f.is_file():
        return None
    try:
        m = json.loads(f.read_text(encoding="utf-8"))
    except (OSError, ValueError) as e:
        logger.warning("漏洞 %s 的 meta.json 读不出来：%s", vid, e)
        return None
    if not isinstance(m, dict):
        return None

    m["id"] = str(m.get("id") or vid)
    m["poc"] = _read_poc(d, m)
    tpl_path = security.safe_join(d, "nuclei.yaml")
    m["nuclei_yaml"] = _read_text(tpl_path) if tpl_path.is_file() else ""
    m["refs"] = security.safe_refs(m.get("refs"))     # 只留 http/https，前端不用再判
    return m


def _read_poc(d: Path, meta: dict) -> str:
    """按 meta 里记的 poc_file 读 PoC 全文。文件名不合规就读默认的 poc.txt。"""
    name = str(meta.get("poc_file") or "")
    if not _POC_FILE_RE.match(name):
        name = "poc.txt"
    try:
        path = security.safe_join(d, name)
    except security.SecurityError:
        return ""
    return _read_text(path) if path.is_file() else ""


# ---------------------------------------------------------------- 复检与统计

def all_metas() -> list[dict]:
    """全库 meta.json 的列表，按条目日期从新到旧排。

    复检存量要用，不能走 _load_rows：那个是给列表页的精简行（没有正文、
    原理这些判定要用的字段），而且带 10 秒缓存，复检要的是当下的全量。
    """
    metas = []
    if not VULN_DIR.exists():
        return metas
    for d in VULN_DIR.iterdir():
        f = d / "meta.json"
        if not f.is_file():
            continue
        try:
            m = json.loads(f.read_text(encoding="utf-8"))
        except Exception:  # noqa: BLE001 —— 单条坏文件不该让整个复检中断
            continue
        if isinstance(m, dict) and m.get("id"):
            m["_poc_text"] = _read_poc(d, m)
            metas.append(m)
    metas.sort(key=lambda x: str(x.get("created_at") or ""), reverse=True)
    return metas


def update_meta(vid: str, patch: dict) -> bool:
    """只改 meta.json 里的几个字段，PoC 和 nuclei 模板一个字都不动。

    复检补 component 走这里。别拿它做批量改写：patch 里的
    键会原样覆盖，所以调用方自己负责别把 id / poc_file 塞进去。
    """
    try:
        vid = security.require_vid(vid)
        d = security.safe_join(VULN_DIR, vid)
    except security.SecurityError as e:
        logger.warning("拒绝改写 meta：%s", e)
        return False
    f = d / "meta.json"
    if not f.is_file():
        return False
    try:
        m = json.loads(f.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return False
    if not isinstance(m, dict):
        return False
    m.update({k: v for k, v in patch.items() if k not in ("id", "poc_file")})
    _dump(d, m)
    invalidate_rows()
    return True


def save_poc(vid: str, poc: str, poc_lang: str = "python") -> bool:
    """重写某条的 PoC 文件。文件名后缀跟 save 一样走白名单。"""
    try:
        vid = security.require_vid(vid)
        d = security.safe_join(VULN_DIR, vid)
    except security.SecurityError:
        return False
    if not (d / "meta.json").is_file():
        return False
    lang = (poc_lang or "python").lower().strip().lstrip(".")
    if lang not in _POC_LANGS:
        lang = "python"
    try:
        (d / f"poc.{lang}").write_text(poc, encoding="utf-8")
    except OSError as e:
        logger.warning("PoC 写不进 %s：%s", vid, e)
        return False
    update_meta(vid, {"poc_file": f"poc.{lang}"})
    return True


def delete_vuln(vid: str) -> bool:
    """删掉一条漏洞：漏洞目录 + 汇总模板目录里的 yaml 一起清。

    和 purge_expired 一样不用 ignore_errors：文件被占用时它会静默跳过，
    表面删成功、实际条目还在库里，下一轮又被抓回来。
    """
    try:
        vid = security.require_vid(vid)
        d = security.safe_join(VULN_DIR, vid)
    except security.SecurityError as e:
        logger.warning("拒绝删除漏洞：%s", e)
        return False
    if not d.is_dir():
        return False
    try:
        shutil.rmtree(d)
    except OSError as e:
        logger.warning("漏洞 %s 删不掉（%s），可能正被占用", vid, e.strerror or e)
        return False
    _remove_summary_tpl(vid)
    invalidate_rows()
    return True


def stats() -> dict:
    """总览页要的全库统计。

    返回 {total, last7, with_tpl, translated, by_source, by_component}。
    by_source 给环状图（平台分布），by_component 给横向条形图（组件 Top N）。
    条形图只给前 20 名：组件名粒度不一，不截断的话一屏拉出去几百个长条，
    看不出重点。剩下的并进"其他"。
    """
    rows = _load_rows()
    by_source: dict[str, int] = {}
    by_component: dict[str, int] = {}
    for r in rows:
        by_source[r["source"]] = by_source.get(r["source"], 0) + 1
        by_component[r["component"]] = by_component.get(r["component"], 0) + 1

    week = (datetime.now() - timedelta(days=7)).strftime("%Y-%m-%d")
    comp_sorted = sorted(by_component.items(), key=lambda kv: -kv[1])
    top = comp_sorted[:20]
    rest = comp_sorted[20:]
    if rest:
        top.append(("其他（" + str(len(rest)) + " 项）", sum(n for _, n in rest)))
    return {
        "total": len(rows),
        "last7": sum(1 for r in rows if (r["entry_iso"] or "") >= week),
        "with_tpl": sum(1 for r in rows if r["has_nuclei"]),
        "translated": sum(1 for r in rows if r["translated"]),
        "by_source": by_source,
        "by_component": top,
    }

