"""main.py —— FastAPI 入口

启动：cd backend && python main.py   （或 uvicorn main:app --port 8100）
接口：
 GET  /api/vulns             漏洞列表（分页，默认一页 10 条）
 GET  /api/vulns/{vid}       漏洞详情（含 PoC 与 nuclei 模板全文）
 POST /api/vulns/purge       按 collect.keep_days 清理过期漏洞
 POST /api/collect           手动触发一轮抓取（与定时任务互斥）
 GET  /api/collect/status    抓取状态（上次/下次时间）
 GET  /api/nuclei/sync       模板库同步状态（上次 commit / 本地模板数）
 POST /api/nuclei/sync       同步 nuclei-templates 增量（git diff，不过 LLM）
 GET  /api/nuclei/templates      本地模板库列表（data/nuclei_tpl，可整体 nuclei -l）
 GET  /api/nuclei/remote         预览远程模板库（不落盘）
 POST /api/nuclei/pull           从远程模板库拉取入库
 POST /api/vulns/{vid}/nuclei    为指定漏洞重新生成 nuclei 模板
 POST /api/vulns/{vid}/poc       按公开思路生成 Python PoC
 POST /api/vulns/{vid}/translate 单条情报译成中文
 POST /api/translate/backfill    批量翻译（传 ids = 只翻这几条）
 GET  /api/settings           读配置（API Key 脱敏）
 POST /api/settings           存配置（写 backend/config.yaml，立即生效）
 POST /api/settings/test      用当前配置试连 LLM
定时：启动 10s 后先跑一轮，之后每 collect.interval_minutes 分钟自动更新
      每轮抓完按 collect.keep_days 清一次过期漏洞
"""
import asyncio
import threading
from contextlib import asynccontextmanager
from datetime import datetime, timedelta

import uvicorn
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

import config
import crawler
import nuclei_sync
import nuclei_tpl
import source_discovery
import store
from analyzer import gen_poc, pull_templates, run_collect, sync_templates
from config import NUCLEI_CACHE_DIR, NUCLEI_TPL_DIR
from llm import LLM, get_llm
from store import get_vuln, list_templates, list_vulns
import translate

_collect_lock = threading.Lock()
_sync_lock = threading.Lock()
_status = {"running": False, "last_run": None, "last_result": None}
_sync_status = {"running": False, "last_run": None, "last_result": None}


class PullReq(BaseModel):
    limit: int = 10
    severity: str = ""
    tag: str = ""


class SyncReq(BaseModel):
    full: bool = False        # 忽略上次状态，全量重扫
    limit: int = 0            # 本次最多入库几条，0 = 不限


class GenReq(BaseModel):
    allow_write: bool = False


class SourceReq(BaseModel):
    model_config = {"extra": "forbid"}

    name: str = ""
    url: str = ""
    enabled: bool = True


class DiscoverReq(BaseModel):
    url: str
    llm_judge: bool = True    # 关掉就只做 XML 探测，不问 AI


class SettingsReq(BaseModel):
    # extra=forbid：前端传错节名要报出来，不然 pydantic 会默默丢掉，看着像保存成功了
    model_config = {"extra": "forbid"}

    llm: dict = {}
    collect: dict = {}
    nuclei: dict = {}


def _do_sync(full: bool = False, limit: int = 0) -> dict:
    """模板同步唯一入口：定时任务和手动接口共用，互斥防撞车。"""
    if not _sync_lock.acquire(blocking=False):
        return {"skipped": True, "reason": "已有同步任务在运行"}
    _sync_status["running"] = True
    try:
        result = sync_templates(full=full, limit=limit)
        _sync_status["last_run"] = datetime.now().isoformat(timespec="seconds")
        _sync_status["last_result"] = result
        return result
    finally:
        _sync_lock.release()
        _sync_status["running"] = False


def _do_collect() -> dict:
    """抓取唯一入口：定时任务和手动接口共用，互斥防撞车。"""
    if not _collect_lock.acquire(blocking=False):
        return {"skipped": True, "reason": "已有抓取任务在运行"}
    _status["running"] = True
    try:
        result = run_collect()
        _status["last_run"] = datetime.now().isoformat(timespec="seconds")
        _status["last_result"] = result
        return result
    finally:
        _collect_lock.release()
        _status["running"] = False


async def _scheduler():
    await asyncio.sleep(10)          # 启动 10s 后先跑一轮
    while True:
        # 先同步模板库增量（LLM 只用于翻译，不改模板），再跑文章流水线。
        # 两条互不阻断。抓完统一按 keep_days 清理过期条目，列表不会被老漏洞撑爆。
        if config.get("nuclei", "sync_enabled"):
            try:
                r = await asyncio.to_thread(_do_sync)   # git 是阻塞活儿，扔线程池
                print(f"[scheduler] 模板同步 → {r.get('imported', 0)} 条"
                      f"（{r.get('message') or r.get('to_commit', '')}）")
            except Exception as e:  # noqa: BLE001
                print(f"[scheduler] 模板同步失败: {e!r}")
        try:
            print("[scheduler] 定时抓取开始")
            r = await asyncio.to_thread(_do_collect)
            print(f"[scheduler] 定时抓取完成 → {r}")
        except Exception as e:       # noqa: BLE001
            print(f"[scheduler] 定时抓取失败: {e!r}")
        try:
            keep = config.get("collect", "keep_days") or 0
            if keep > 0:
                p = await asyncio.to_thread(store.purge_expired, keep)
                print(f"[scheduler] 过期清理 → {p['removed']} 条（保留 {keep} 天）")
        except Exception as e:       # noqa: BLE001
            print(f"[scheduler] 清理失败: {e!r}")
        await asyncio.sleep(config.get("collect", "interval_minutes") * 60)


@asynccontextmanager
async def lifespan(_app: FastAPI):
    task = asyncio.create_task(_scheduler())
    yield
    task.cancel()


app = FastAPI(title="AI 漏洞播报系统", lifespan=lifespan)
app.add_middleware(
    CORSMiddleware, allow_origins=["*"], allow_methods=["*"], allow_headers=["*"])


@app.get("/api/vulns")
def api_list(page: int = 1, page_size: int = 10, source: str = ""):
    """漏洞列表（分页）。page_size 默认 10，前端一页只渲染这些。"""
    return list_vulns(page=page, page_size=page_size, source=source)


@app.get("/api/vulns/{vid}")
def api_detail(vid: str):
    v = get_vuln(vid)
    if not v:
        raise HTTPException(404, "漏洞不存在")
    return v


@app.post("/api/collect")
async def api_collect():
    return await asyncio.to_thread(_do_collect)


@app.get("/api/collect/status")
def api_status():
    interval = config.get("collect", "interval_minutes")
    nxt = ""
    if _status["last_run"]:
        nxt = (datetime.fromisoformat(_status["last_run"])
               + timedelta(minutes=interval)).isoformat(timespec="seconds")
    return {**_status, "interval_minutes": interval, "next_run": nxt}


# ── nuclei 双向通道 ──────────────────────────────────────
@app.get("/api/nuclei/sync")
def nuclei_sync_status():
    """模板库同步状态：上次同步到的 commit、本地模板数、仓库是否已 clone。"""
    return {**nuclei_sync.status(), **_sync_status}


@app.post("/api/nuclei/sync")
def nuclei_sync_run(req: SyncReq):
    """同步 nuclei-templates 增量：git diff 出新增/修改的模板，原样入库（不过 LLM）。"""
    try:
        r = _do_sync(full=req.full, limit=req.limit)
    except Exception as e:  # noqa: BLE001 —— git 没装/网络断了，给前端一条可读原因
        return {"error": str(e), "imported": 0, "files": []}
    return r


@app.get("/api/nuclei/templates")
def api_templates():
    """本地模板库：生成的和拉来的都在这，整个目录可直接 nuclei -l 跑。"""
    return {"dir": str(NUCLEI_TPL_DIR), "items": list_templates()}


@app.get("/api/nuclei/remote")
def api_remote(limit: int = 10, severity: str = "", tag: str = ""):
    """预览远程模板库条目，不落库。首次拉索引可能要 1-2 分钟。"""
    repo, ref = config.get("nuclei", "repo"), config.get("nuclei", "ref")
    try:
        tpls = nuclei_tpl.fetch_remote_templates(
            repo, ref=ref, limit=limit, severity=severity,
            tag=tag, cache_dir=NUCLEI_CACHE_DIR)
    except Exception as e:  # noqa: BLE001
        raise HTTPException(502, f"远程模板库拉取失败: {e}") from e
    return {"repo": repo, "ref": ref,
            "items": [{"id": t.id, "name": t.name, "severity": t.severity,
                       "description": t.description, "tags": t.tags,
                       "path": t.path, "refs": t.refs} for t in tpls]}


@app.post("/api/nuclei/pull")
async def api_pull(req: PullReq):
    """远程模板入库（原样落盘，不过 LLM 筛选/生成）。"""
    try:
        return await asyncio.to_thread(
            pull_templates, req.limit, req.severity, req.tag)
    except Exception as e:  # noqa: BLE001
        raise HTTPException(502, f"拉取失败: {e}") from e


@app.post("/api/vulns/{vid}/nuclei")
async def api_gen_nuclei(vid: str, req: GenReq):
    """给已收录漏洞补/重生成 nuclei 模板。"""
    v = get_vuln(vid)
    if not v:
        raise HTTPException(404, "漏洞不存在")
    if v.get("poc_source") == "nuclei":
        raise HTTPException(400, "该条目本身来自 nuclei 模板库，无需再生成")
    r = await asyncio.to_thread(
        nuclei_tpl.convert, v, v.get("poc", ""), get_llm(), req.allow_write)
    if not r["ok"]:
        return {"ok": False, "reason": r["reason"], "origin": r["origin"]}
    store.save(v, v.get("poc", ""), "python", r["yaml"])
    return {"ok": True, "origin": r["origin"], "yaml": r["yaml"]}


# ── AI 加工：中文翻译 / PoC 生成 ─────────────────────────
@app.post("/api/vulns/{vid}/poc")
async def api_gen_poc(vid: str):
    """按公开思路生成 Python PoC。nuclei 进来的条目默认只有 yaml，点这里补一份。"""
    r = await asyncio.to_thread(gen_poc, vid)
    if not r.get("ok"):
        raise HTTPException(502, r.get("reason", "生成失败"))
    return {"ok": True, "chars": r["chars"]}


@app.post("/api/vulns/{vid}/translate")
async def api_translate_one(vid: str):
    """把单条漏洞情报译成中文。LLM 不可用时返回原因，不改原数据。"""
    r = await asyncio.to_thread(translate.translate_one, vid)
    if not r.get("ok"):
        raise HTTPException(502, r.get("reason", "翻译失败"))
    return r


class BackfillReq(BaseModel):
    limit: int = 20
    ids: list[str] = []            # 传了就只翻这几条（列表页"翻译本页"）


@app.post("/api/translate/backfill")
async def api_translate_backfill(req: BackfillReq):
    """批量翻译。传 ids = 翻译当前页的 10 条；不传 = 按 limit 补存量。"""
    ids = [v for v in req.ids if v][:20]
    return await asyncio.to_thread(
        translate.backfill, max(1, min(req.limit, 200)), None, ids or None)


@app.post("/api/vulns/purge")
def api_purge():
    """按 collect.keep_days 清理过期漏洞，手动触发一次。"""
    keep_days = config.get("collect", "keep_days") or 0
    if keep_days <= 0:
        raise HTTPException(400, "保留天数为 0，未启用按日期清理")
    return store.purge_expired(keep_days)


@app.get("/api/llm/status")
def api_llm_status():
    """LLM 是否可用 + 全库待译数。前端据此决定「AI 生成」按钮是否点亮。"""
    llm = get_llm()
    return {"available": bool(llm.base and llm.key and llm.model),
            "model": llm.model, "base": llm.base,
            "key_set": bool(llm.key),
            "pending_translate": store.pending_translate_count()}


# ── 设置页 ──────────────────────────────────────────────
def _mask(key: str) -> str:
    """密钥脱敏：只露头尾，中间打码。空 key 原样返回。"""
    if not key:
        return ""
    return f"{key[:4]}{'*' * 8}{key[-4:]}" if len(key) > 12 else "****"


@app.get("/api/settings")
def api_get_settings():
    cfg = config.load(force=True)          # 外部手改过 yaml 也能读到
    return {**cfg, "llm": {**cfg["llm"], "key": _mask(cfg["llm"].get("key", ""))},
            "config_file": str(config.CONFIG_FILE),
            "key_set": bool(cfg["llm"].get("key"))}


@app.post("/api/settings")
def api_save_settings(req: SettingsReq):
    """前端表单 → 校验 → 写 config.yaml。key 传空串表示保持原值。"""
    patch = {s: v for s, v in (("llm", req.llm), ("collect", req.collect),
                               ("nuclei", req.nuclei)) if v}
    try:
        cfg = config.update(patch)
    except (ValueError, TypeError) as e:
        raise HTTPException(400, str(e)) from e
    return {"ok": True, "config_file": str(config.CONFIG_FILE),
            "llm": {**cfg["llm"], "key": _mask(cfg["llm"].get("key", ""))}}


@app.post("/api/settings/test")
async def api_test_llm(req: SettingsReq = SettingsReq()):
    """用表单里的值（不落盘）试连一次，验证地址/密钥/模型三项。"""
    if req.llm:
        saved = dict(config.load()["llm"])      # 拷贝，别污染进程内缓存
        for k, v in req.llm.items():
            if v or k not in ("key", "base"):   # key/base 空串 = 用已存的
                saved[k] = v
        llm = LLM(saved.get("base", ""), saved.get("key", ""), saved.get("model", ""))
    else:
        llm = get_llm()
    try:
        reply = await asyncio.to_thread(llm.ping)
    except Exception as e:  # noqa: BLE001
        raise HTTPException(502, f"连接失败：{e}") from e
    return {"ok": True, "reply": reply, "model": llm.model, "base": llm.base}


# ── 漏洞源接入 ──────────────────────────────────────────
@app.get("/api/sources")
def api_list_sources():
    """内置源 + 用户接入的源。内置源标 builtin，只能看不能删。"""
    custom = config.get("sources", "custom") or []
    return {"builtin": [{"name": n, "url": u, "builtin": True}
                        for n, u in crawler.FEEDS],
            "custom": [{**s, "builtin": False} for s in custom]}


@app.post("/api/sources/discover")
async def api_discover_source(req: DiscoverReq):
    """给定社区首页，探测 feed 地址并让 AI 判断是否漏洞社区。不落配置。"""
    if not req.url.strip():
        raise HTTPException(400, "请填写社区地址")
    try:
        return await asyncio.to_thread(source_discovery.discover,
                                       req.url.strip(), req.llm_judge)
    except Exception as e:  # noqa: BLE001
        raise HTTPException(502, f"探测失败：{e}") from e


@app.post("/api/sources")
def api_add_source(req: SourceReq):
    """把探测出来的 feed 地址接入。已存在的同名源视为更新地址。"""
    if not req.url.startswith(("http://", "https://")):
        raise HTTPException(400, "源地址必须以 http:// 或 https:// 开头")
    name = req.name.strip()
    if not name:
        raise HTTPException(400, "请填写源名称")
    custom = list(config.get("sources", "custom") or [])
    entry = {"name": name, "url": req.url.strip(), "enabled": req.enabled}
    for i, s in enumerate(custom):
        if s.get("name") == name:
            custom[i] = entry
            break
    else:
        custom.append(entry)
    try:
        config.update({"sources": {"custom": custom}})
    except (ValueError, TypeError) as e:
        raise HTTPException(400, str(e)) from e
    return {"ok": True, "sources": custom,
            "message": f"已接入 {name}，下一轮抓取生效"}


@app.delete("/api/sources/{name}")
def api_del_source(name: str):
    """移除用户接入的源。内置源不在这里，删不掉。"""
    custom = list(config.get("sources", "custom") or [])
    rest = [s for s in custom if s.get("name") != name]
    if len(rest) == len(custom):
        raise HTTPException(404, f"未找到源：{name}")
    try:
        config.update({"sources": {"custom": rest}})
    except (ValueError, TypeError) as e:
        raise HTTPException(400, str(e)) from e
    return {"ok": True, "sources": rest, "message": f"已移除 {name}"}


if __name__ == "__main__":
    uvicorn.run(app, host="127.0.0.1", port=8100)  # 8000 在 Windows 保留端口段内，避开
