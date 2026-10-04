"""sources.py —— 漏洞源聚合：文章爬虫（crawler.py）+ nuclei 模板（本地/远程）

所有可调项都走 config.get() 现读 config.yaml，设置页改完下一轮就生效。

nuclei 模板库的主路径是 nuclei_sync.py 的 git 增量同步（独立入口，不过 LLM）；
这里的本地/远程两条是手动按需取样用的旁路。
"""
import config
import nuclei_tpl
from config import NUCLEI_CACHE_DIR, NUCLEI_REPO_DIR
from crawler import fetch_articles


def fetch_nuclei(limit: int = 0) -> list[dict]:
    """已 clone 的本地模板库（data/nuclei_templates，由同步模块维护）。"""
    tpls = nuclei_tpl.load_local_templates(
        NUCLEI_REPO_DIR, limit=limit or config.get("collect", "fetch_limit"))
    print(f"[source] nuclei 本地 → {len(tpls)} 条")
    return [nuclei_tpl.tpl_to_item(t) for t in tpls]


def fetch_nuclei_remote(limit: int = 0, severity: str = "", tag: str = "") -> list[dict]:
    """远程模板库（默认 projectdiscovery/nuclei-templates）。首次拉会慢，索引缓存 6 小时。"""
    if not config.get("nuclei", "fetch_remote"):
        return []
    repo = config.get("nuclei", "repo")
    tpls = nuclei_tpl.fetch_remote_templates(
        repo, ref=config.get("nuclei", "ref"),
        limit=limit or config.get("nuclei", "remote_limit"),
        severity=severity, tag=tag, cache_dir=NUCLEI_CACHE_DIR)
    print(f"[source] nuclei 远程({repo}) → {len(tpls)} 条")
    return [nuclei_tpl.tpl_to_item(t) for t in tpls]


def fetch_all() -> list[dict]:
    """聚合所有源 + 按 id 去重。各源内部已容错，这里逐个兜底不让单源拖垮整轮。"""
    items = list(fetch_articles())
    for name, fn in (("nuclei 本地", fetch_nuclei),
                     ("nuclei 远程", fetch_nuclei_remote)):
        try:
            items.extend(fn())
        except Exception as e:  # noqa: BLE001
            print(f"[source] {name} 失败: {e!r}")
    seen, uniq = set(), []
    for it in items:
        if it["id"] and it["id"] not in seen:
            seen.add(it["id"])
            uniq.append(it)
    return uniq
