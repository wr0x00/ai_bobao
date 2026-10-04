"""store.py —— 文件库（暂不落数据库）：

data/vulns/{漏洞ID}/
  ├── meta.json     元数据：名称/来源/简介/原理/攻击范围/参考链接...
  ├── poc.py        PoC 文本（前端在线查看）
  └── nuclei.yaml   对应的 nuclei 模板（有才写；生成或从模板库拉来的）

data/nuclei_tpl/   所有模板的汇总目录，可直接 `nuclei -l data/nuclei_tpl` 跑
列表 = 扫目录读 meta.json；详情 = 目录名 → meta + poc 全文 + 模板。
以后换数据库只需重写本文件的几个函数，其他层不动。
"""
import json
import re
import shutil
from datetime import datetime, timedelta, timezone
from pathlib import Path

from config import NUCLEI_TPL_DIR, VULN_DIR

_SAFE = re.compile(r"[^A-Za-z0-9._-]+")  # 目录名白名单，防路径穿越
_CVE_YEAR = re.compile(r"CVE-(\d{4})", re.I)
_DATE_RE = re.compile(r"(\d{4})-(\d{2})-(\d{2})")
_HAS_ZH = re.compile(r"[\u4e00-\u9fff]")
_FALLBACK_MARK = "（兜底）"   # llm_generate 兜底时拼在标题末尾的标记


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


def _dump(d: Path, meta: dict) -> None:
    (d / "meta.json").write_text(
        json.dumps(meta, ensure_ascii=False, indent=2), encoding="utf-8")


def save(meta: dict, poc: str, poc_lang: str = "python", nuclei_yaml: str = "") -> str:
    vid = _SAFE.sub("_", meta["id"])
    d = VULN_DIR / vid
    d.mkdir(parents=True, exist_ok=True)
    meta = {**meta, "id": vid, "poc_file": f"poc.{poc_lang}",
            "created_at": meta.get("created_at") or _now()}
    (d / f"poc.{poc_lang}").write_text(poc, encoding="utf-8")
    if nuclei_yaml:
        meta["nuclei_file"] = "nuclei.yaml"
        (d / "nuclei.yaml").write_text(nuclei_yaml, encoding="utf-8")
        NUCLEI_TPL_DIR.mkdir(parents=True, exist_ok=True)   # 汇总一份，整体可 nuclei -l 跑
        shutil.copyfile(d / "nuclei.yaml", NUCLEI_TPL_DIR / f"{vid}.yaml")
    _dump(d, meta)
    return vid


def _load_rows() -> list[dict]:
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
        date, year_only = entry_date(m)
        name = m.get("name") or m["id"]
        rows.append({"id": m["id"], "name": name,
                     "source": m.get("source", "-"),
                     "summary": m.get("summary", ""),
                     "published": m.get("published", ""),
                     "cvss": m.get("cvss"),
                     # translated 只说明"是 LLM 翻的"；老条目没这个标记但本来就是中文，
                     # 所以额外看一眼标题有没有汉字，不然列表页会给中文标题挂 EN 角标
                     "translated": bool(m.get("translated")) or is_zh_name(name),
                     "has_nuclei": (d / "nuclei.yaml").is_file(),
                     # 编号里只有年份时只显示年份，别拿 12-31 糊弄用户
                     "entry_date": date[:4] if year_only else date,
                     "entry_iso": date or (m.get("created_at") or "")[:10]})
    rows.sort(key=lambda x: x["entry_iso"], reverse=True)   # 新的在前
    return rows


def list_vulns(page: int = 1, page_size: int = 10, source: str = "") -> dict:
    """分页列表。返回 {items, total, page, pages, page_size, all_total, counts}。

    前端只渲染当前页，一次传 4000 条没必要。counts 是全库按来源的计数，
    切页签时徽标数字不受分页影响。
    """
    rows = _load_rows()
    counts: dict[str, int] = {}
    for r in rows:
        counts[r["source"]] = counts.get(r["source"], 0) + 1
    grand_total = len(rows)
    if source and source != "全部":
        rows = [r for r in rows if r["source"] == source]
    total = len(rows)
    page_size = max(1, min(int(page_size or 10), 100))
    pages = max(1, -(-total // page_size))       # 向上取整
    page = max(1, min(int(page or 1), pages))
    items = rows[(page - 1) * page_size: page * page_size]
    return {"items": items, "total": total, "page": page, "pages": pages,
            "page_size": page_size, "all_total": grand_total, "counts": counts}


def purge_expired(keep_days: int) -> dict:
    """删掉超出保留期的条目（漏洞目录 + 汇总模板目录一起清）。

    判定直接复用 too_old，别自己再写一遍日期逻辑，两边一旦不一致就会出现
    "列表里还留着过期条目"的漏网之鱼。
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
        except Exception:  # noqa: BLE001
            continue
        if not too_old(m, keep_days):
            continue
        vid = m.get("id", d.name)
        # 不能用 ignore_errors：文件被占用时它会静默跳过，删不掉却照样报成功，
        # 结果是过期条目留在库里，下一轮又被抓回来，抖个没完。
        try:
            shutil.rmtree(d)
        except OSError as e:
            failed.append(vid)
            print(f"[purge] {vid} 删不掉（{e.strerror or e}），可能正被占用")
            continue
        (NUCLEI_TPL_DIR / f"{_SAFE.sub('_', vid)}.yaml").unlink(missing_ok=True)
        ids.append(vid)
    if ids:
        print(f"[purge] 清理过期漏洞 {len(ids)} 条（早于 {cutoff}）")
    return {"removed": len(ids), "ids": ids, "failed": failed}


def pending_translate_count() -> int:
    """全库还有多少条没中文化。列表页只关心本页，这个数只给设置/状态页做提示。"""
    return sum(1 for r in _load_rows() if not r["translated"])


def list_templates() -> list[dict]:
    """模板库列表：data/nuclei_tpl 下每个 yaml 一条（可直接 nuclei -l 跑这个目录）。"""
    import yaml

    out = []
    if NUCLEI_TPL_DIR.exists():
        for f in sorted(NUCLEI_TPL_DIR.glob("*.yaml")):
            try:
                doc = yaml.safe_load(f.read_text(encoding="utf-8", errors="replace"))
            except Exception:  # noqa: BLE001
                continue
            if not isinstance(doc, dict) or not doc.get("id"):
                continue
            info = doc.get("info") or {}
            out.append({"id": doc["id"], "vid": f.stem, "name": info.get("name", doc["id"]),
                        "severity": info.get("severity", "unknown"),
                        "tags": info.get("tags", ""), "file": f.name,
                        "requests": len(doc.get("http") or [])})
    out.sort(key=lambda x: (x["severity"] != "critical", x["severity"] != "high", x["id"]))
    return out


def get_vuln(vid: str) -> dict | None:
    d = VULN_DIR / _SAFE.sub("_", vid)
    f = d / "meta.json"
    if not f.is_file():
        return None
    m = json.loads(f.read_text(encoding="utf-8"))
    poc_path = d / m.get("poc_file", "poc.txt")
    m["poc"] = poc_path.read_text(encoding="utf-8") if poc_path.is_file() else ""
    tpl_path = d / "nuclei.yaml"
    m["nuclei_yaml"] = tpl_path.read_text(encoding="utf-8") if tpl_path.is_file() else ""
    return m
