"""main.py —— FastAPI 入口

启动：cd backend && python main.py   （或 uvicorn main:app --port 8100）
     前端构建产物要放在 backend/static（cd frontend && npm run build），
     前后端不分离：一个进程既发页面又发接口，都是 8100 端口。

此模块功能：对外暴露 HTTP 接口、给接口套上安全护栏、跑定时任务。
真正的业务逻辑都在 analyzer / store / nuclei_tpl 这些模块里，这里不重复写。

安全护栏（顺序不能乱，见 app 下面的中间件注册处）：
  同源标记   每个 /api 请求都要带 X-AI-BaoBao: 1，浏览器跨站发不出来这个自定义头
  令牌       写操作还要带 X-AI-BaoBao-Token，令牌从 GET /api/session 拿
  限流       读接口宽松、写接口收紧、跑 LLM 的重活儿接口单独最严
  请求体     超过 64KB 直接 413，够写配置，不够塞攻击载荷
  Host 白名单 陌生 Host 头直接 400，挡 DNS 重绑定
  安全响应头  nosniff / DENY / no-referrer / CSP

接口清单（AI_BAOBAO_DOCS=1 才会生成 /docs）：
 GET  /api/vulns             漏洞列表（分页，默认一页 10 条）
 GET  /api/vulns/{vid}       漏洞详情（含 PoC 与 nuclei 模板全文）
 POST /api/vulns/purge       按 collect.keep_days 清理过期漏洞
 POST /api/vulns/recheck     复检存量：LLM 重判内容性质，删掉非漏洞和兜底条目
 GET  /api/stats             总览统计（组件分布 / 平台分布 / 几个总数）
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
 GET  /api/llm/status        LLM 连通性与用量
 GET  /api/settings           读配置（API Key 脱敏，只回白名单字段）
 POST /api/settings           存配置（写 backend/config.yaml，立即生效）
 POST /api/settings/test      用当前配置试连 LLM
 GET  /api/sources            内置源 + 用户接入的源
 POST /api/sources/discover   探测社区的 feed 地址
 POST /api/sources            接入一个源
 DELETE /api/sources/{name}   移除一个源
 GET  /api/envs               本地复现环境列表（含资产根目录）
 GET  /api/envs/{eid}         环境详情（资产落盘位置）
 POST /api/envs/resolve       只让 LLM 出复现方案，不拉东西
 POST /api/envs/resolve/stream  方案的流式版（SSE，字段边生成边推）
 POST /api/envs/build         为一条漏洞搭环境（拉程序/源码/镜像，找不到就放弃）
 POST /api/envs/{eid}/start   启动环境
 POST /api/envs/{eid}/stop    停止环境
 DELETE /api/envs/{eid}       删除环境
 GET  /api/update/check     比对本仓库 HEAD 与 GitHub 远端，只读
 POST /api/update/apply     快进到远端最新（只 --ff-only，不动本地改动）
 GET  /api/session            下发本次会话的写操作令牌
 POST /api/agent/chat         跟内嵌 agent 对话（带 session_id 就把这一轮存进会话）
 POST /api/agent/chat/stream  agent 对话的流式版（SSE，思考/答复/工具步实时推）
 GET  /api/agent/sessions     会话列表（对话面板左侧栏用）
 POST /api/agent/sessions     新建会话
 GET  /api/agent/sessions/{sid}       读一个会话（含全部消息）
 PUT  /api/agent/sessions/{sid}       重命名会话
 DELETE /api/agent/sessions/{sid}     删掉会话
 DELETE /api/agent/sessions/{sid}/messages  清空会话里的消息

定时：启动 10s 后先跑一轮，之后每 collect.interval_minutes 分钟自动更新；
      每轮抓完按 collect.keep_days 清一次过期漏洞。
"""
import asyncio
import json
import logging
import re
import secrets
import threading
import time
from contextlib import asynccontextmanager
from datetime import datetime, timedelta

import uvicorn
from fastapi import FastAPI, HTTPException, Path, Query, Request
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, JSONResponse, Response, StreamingResponse
from pydantic import BaseModel, Field
from starlette.concurrency import iterate_in_threadpool
from starlette.middleware.trustedhost import TrustedHostMiddleware

import agent
import agent_sessions
import config
import lab_env
import nuclei_sync
import nuclei_tpl
import security
import source_discovery
import source_manager
import store
import translate
import updater
from analyzer import (
    gen_poc,
    pull_templates,
    rate_backfill,
    recheck_library,
    run_collect,
    sync_templates,
)
from config import NUCLEI_CACHE_DIR
from llm import LLM, get_llm
from store import get_vuln, list_templates, list_vulns

logger = logging.getLogger("ai_bobao")

# ── 入参边界 ──────────────────────────────────────────────
# 这些数字是"再大就不像人干的事"的分界线，统一收在这里，别散落到各个接口里。
MAX_PAGE = 10_000            # 页码上限，够翻完所有数据
MAX_PAGE_SIZE = 100          # 一页最多 100 条
MAX_Q_LEN = 200              # 搜索关键词长度
MAX_SOURCE_LEN = 100         # 来源筛选值长度
MAX_REMOTE_PREVIEW = 50      # /nuclei/remote 一次最多预览几条
MAX_PULL = 500               # /nuclei/pull 一次最多入库几条
MAX_SYNC_IMPORT = 5000       # /nuclei/sync 一次最多入库几条
MAX_BACKFILL = 200           # 批量翻译一次最多翻几条
MAX_BACKFILL_IDS = 20        # 批量翻译一次最多指定几条 ID
MAX_RECHECK = 2000           # 存量复检一次最多处理几条
MAX_LLM_TIMEOUT = 600        # LLM 超时上限（秒）
MAX_INTERVAL_MINUTES = 1440  # 定时间隔上限（一天）

# 限流配额：每分钟多少次。单窗口、进程内计数，只为本机自用场景兜底。
RATE_READ = 300
RATE_WRITE = 60
RATE_HEAVY = 10

# 跑 LLM / git / 联网的重活儿接口，单独最严。它们一次能烧掉真金白银，不能被刷。
_HEAVY_EXACT = frozenset({
    "/api/agent/chat",
    "/api/agent/chat/stream",
    "/api/agent/export",
    "/api/collect",
    "/api/nuclei/sync",
    "/api/nuclei/pull",
    "/api/nuclei/remote",
    "/api/sources/discover",
    "/api/settings/test",
    "/api/translate/backfill",
    "/api/update/apply",
    "/api/vulns/purge",
    "/api/vulns/rate",
    "/api/vulns/recheck",
    "/api/envs/resolve",
    "/api/envs/resolve/stream",
    "/api/envs/build",
})
_HEAVY_PREFIX = ("/api/vulns/", "/api/envs/")     # 配合 _HEAVY_SUFFIX 用
_HEAVY_SUFFIX = ("/nuclei", "/poc", "/translate", "/verify")

_limiter_read = security.RateLimiter(RATE_READ)
_limiter_write = security.RateLimiter(RATE_WRITE)
_limiter_heavy = security.RateLimiter(RATE_HEAVY)

_collect_lock = threading.Lock()
_sync_lock = threading.Lock()
_status = {"running": False, "last_run": None, "last_result": None}
_sync_status = {"running": False, "last_run": None, "last_result": None}


def _is_heavy(path: str, method: str) -> bool:
    """这个请求算不算重活儿。GET 的 remote 只预览不落库，但一样要联网，照样限。"""
    if path in _HEAVY_EXACT:
        return True
    return (method == "POST" and path.startswith(_HEAVY_PREFIX)
            and path.endswith(_HEAVY_SUFFIX))


# ── 请求体校验 ────────────────────────────────────────────
class _BodyTooLargeError(Exception):
    """请求体超了 MAX_BODY。"""


async def _read_body(receive, max_bytes: int) -> list[dict]:
    """把请求体一口气读完，顺手盯着总大小。

    必须读完再交给下游，不能边收边透传：uvicorn 会把请求体拆成好几条 http.request 发，
    最后一条是 body 为空、more_body 为 False 的收尾消息。只透传最后一条的话，
    下游拿到的就是空 body，FastAPI 会报"请求体解析失败"，真正的载荷反而丢了。
    """
    messages: list[dict] = []
    total = 0
    while True:
        message = await receive()
        if message["type"] != "http.request":
            break                       # 客户端断了，或者不是请求体消息，收工
        total += len(message.get("body", b""))
        if total > max_bytes:
            raise _BodyTooLargeError
        messages.append(message)
        if not message.get("more_body", False):
            break
    if not messages:                    # 没 body 的请求（GET / DELETE），补一条空的
        messages = [{"type": "http.request", "body": b"", "more_body": False}]
    return messages


def _replay(messages: list[dict], receive):
    """造一个 receive，把收好的分片原样重放。下游读几次都是同一份数据。

    重放完不能直接回 http.disconnect：SSE 这类流式响应在发送期间会一直轮询
    receive 探测客户端断开，这里若立刻回 disconnect，Starlette 会当场取消
    整个响应（"ASGI callable returned without completing response"）。
    所以分片放完之后转交给真实的 receive——既让断开探测正常工作，
    也保证没有第二个消费者会把同一份数据读两遍。
    """
    it = iter(messages)

    async def recv():
        msg = next(it, None)
        if msg is not None:
            return msg
        return await receive()

    return recv


class ApiGuard:
    """同源 + 令牌 + 请求体上限，三个检查合成一个纯 ASGI 中间件。

    为什么要求 X-AI-BaoBao 这个头：跨站发起的"简单请求"（GET、POST 表单）浏览器只
    会自动带 Origin 这类禁止头，Content-Type 限定死的 JSON 请求又会先发 OPTIONS 预检。
    只要强制要求一个自定义头，恶意网页就既发不出去、也读不到响应——CSRF 天然被挡掉，
    不需要再单独维护 token 表单。

    纯 ASGI 而非 BaseHTTPMiddleware，是因为后者在中间件里读完 body 之后，
    下游拿不到数据，chunked 请求会挂住。这里改成"先收齐、再重放"就解决了。
    """

    def __init__(self, app):
        self.app = app

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http" or not scope["path"].startswith("/api"):
            await self.app(scope, receive, send)
            return

        headers = {k.decode("latin-1").lower(): v.decode("latin-1")
                   for k, v in scope["headers"]}
        method = scope["method"]

        # 预检请求交给外层的 CORSMiddleware 处理，这里直接放行。
        if method == "OPTIONS":
            await self.app(scope, receive, send)
            return

        if headers.get(security.HEADER_FLAG.lower()) != security.HEADER_VALUE:
            await _reject(send, 403, f"缺少 {security.HEADER_FLAG} 头，只接受同源前端请求")
            return

        if method in ("POST", "PUT", "PATCH", "DELETE"):
            sent = headers.get(security.HEADER_TOKEN.lower(), "")
            if not security.api_token() or not sent:
                await _reject(send, 403, "写操作需要有效令牌，请先调用 /api/session")
                return
            if not _constant_eq(sent, security.api_token()):
                await _reject(send, 403, "令牌不正确")
                return

        # 请求体先在这里收下：超限直接 413。不能让异常冒到 FastAPI 里，
        # 它会把任何读取失败都当成"body 解析不了"回 400，超限提示就丢了。
        try:
            body = await _read_body(receive, security.MAX_BODY)
        except _BodyTooLargeError:
            await _reject(send, 413, f"请求体过大，上限 {security.MAX_BODY // 1024}KB")
            return

        await self.app(scope, _replay(body, receive), send)


def _constant_eq(a: str, b: str) -> bool:
    """定长比较。逐字符比较会在第一个不同字节就返回，时间差能侧信道出令牌。"""
    return secrets.compare_digest(a, b)


async def _reject(send, code: int, message: str) -> None:
    """中间件里直接回一条 JSON 错误。响应体格式和 FastAPI 抛的错保持一致。"""
    response = JSONResponse({"detail": message}, status_code=code)
    await response({"type": "http"}, _empty_receive, send)


async def _empty_receive():  # pragma: no cover —— 只为满足 Response 的调用签名
    return {"type": "http.disconnect"}


class RateLimit:
    """按 IP + 接口分档限流。超了回 429，顺带带上 Retry-After。"""

    def __init__(self, app):
        self.app = app

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http" or not scope["path"].startswith("/api"):
            await self.app(scope, receive, send)
            return
        method, path = scope["method"], scope["path"]
        client = scope.get("client") or ("unknown", 0)
        ip = client[0]

        if _is_heavy(path, method):
            limiter = _limiter_heavy
        elif method in ("POST", "PUT", "PATCH", "DELETE"):
            limiter = _limiter_write
        else:
            limiter = _limiter_read

        if not limiter.allow(ip):
            response = JSONResponse(
                {"detail": f"请求太频繁，请 {limiter.window:.0f} 秒后再试"},
                status_code=429,
                headers={"Retry-After": str(int(limiter.window))},
            )
            await response(scope, receive, send)
            return
        await self.app(scope, receive, send)


class SecurityHeaders:
    """给响应补安全头。/api 的数据不许被缓存，也不许被页面嵌进来。"""

    # /docs 要单独一份 CSP，否则 Swagger UI 自己的脚本会被这份严格策略挡掉。
    _API_CSP = ("default-src 'none'; frame-ancestors 'none'; "
                "base-uri 'none'; form-action 'none'")

    def __init__(self, app):
        self.app = app

    async def __call__(self, scope, receive, send):
        path = scope.get("path", "")
        api = path.startswith("/api")

        async def send_wrapper(message):
            if message["type"] == "http.response.start":
                headers = message.setdefault("headers", [])
                for key, value in (
                    (b"x-content-type-options", b"nosniff"),
                    (b"x-frame-options", b"DENY"),
                    (b"referrer-policy", b"no-referrer"),
                    (b"cross-origin-opener-policy", b"same-origin"),
                    (b"cross-origin-resource-policy", b"same-origin"),
                    (b"permissions-policy",
                     b"geolocation=(), microphone=(), camera=(), interest-cohort=()"),
                ):
                    headers.append((key, value))
                if api:
                    headers.append((b"cache-control", b"no-store"))
                    headers.append((b"content-security-policy",
                                    self._API_CSP.encode("latin-1")))
            await send(message)

        await self.app(scope, receive, send_wrapper)


# ── 请求模型 ──────────────────────────────────────────────
# 约定：字段全部 Optional，默认 None 表示"这次不改"。
# 前端表单总是把三个节都发全，None 用来区分"没传"和"传了空串"。

class LlmSettings(BaseModel):
    """LLM 连接参数。base / key 允许空串——空串在 config.update 里意思是"保持原值"。"""

    model_config = {"extra": "forbid"}   # 传错键名要报错，不然会被默默丢掉，像保存成功了

    base: str | None = Field(default=None, max_length=500)
    key: str | None = Field(default=None, max_length=300)
    model: str | None = Field(default=None, max_length=200)
    timeout: int | None = Field(default=None, ge=5, le=MAX_LLM_TIMEOUT)


class CollectSettings(BaseModel):
    """抓取行为参数。"""

    model_config = {"extra": "forbid"}

    interval_minutes: int | None = Field(default=None, ge=1, le=MAX_INTERVAL_MINUTES)
    fetch_limit: int | None = Field(default=None, ge=1, le=MAX_PAGE_SIZE)
    keep_days: int | None = Field(default=None, ge=0, le=3650)
    auto_translate: bool | None = None


class NucleiSettings(BaseModel):
    """模板库参数。repo / ref 会直接拼进 git 命令，加正则白名单挡住选项注入。"""

    model_config = {"extra": "forbid"}

    repo: str | None = Field(default=None, max_length=200)
    ref: str | None = Field(default=None, max_length=100)
    remote_limit: int | None = Field(default=None, ge=1, le=MAX_REMOTE_PREVIEW)
    fetch_remote: bool | None = None
    gen_templates: bool | None = None
    sync_enabled: bool | None = None
    sync_limit: int | None = Field(default=None, ge=0, le=MAX_SYNC_IMPORT)


class LabSettings(BaseModel):
    """本地复现环境参数。root 是环境资产落盘目录，空串 = 用默认目录。"""

    model_config = {"extra": "forbid"}

    root: str | None = Field(default=None, max_length=500)
    docker_enabled: bool | None = None
    timeout: int | None = Field(default=None, ge=5, le=3600)


class SettingsReq(BaseModel):
    """设置页整体表单。各节都可省，省掉的那节不动。"""

    model_config = {"extra": "forbid"}

    llm: LlmSettings = Field(default_factory=LlmSettings)
    collect: CollectSettings = Field(default_factory=CollectSettings)
    nuclei: NucleiSettings = Field(default_factory=NucleiSettings)
    lab: LabSettings = Field(default_factory=LabSettings)

    def to_patch(self) -> dict:
        """摊成 config.update 认识的 {节: {键: 值}}，只带走真正传了的字段。"""
        patch: dict = {}
        for section in (self.llm, self.collect, self.nuclei, self.lab):
            given = {k: v for k, v in section.model_dump().items() if v is not None}
            if given:
                patch[section.__class__.__name__.removesuffix("Settings").lower()] = given
        return patch


# /api/settings/test 允许不传 body。默认值放模块级，避免在函数签名里直接调构造函数。
_DEFAULT_SETTINGS_REQ = SettingsReq()


class PullReq(BaseModel):
    model_config = {"extra": "forbid"}

    limit: int = Field(default=10, ge=1, le=MAX_PULL)
    severity: str = Field(default="", max_length=MAX_SOURCE_LEN)
    tag: str = Field(default="", max_length=MAX_SOURCE_LEN)


class SyncReq(BaseModel):
    model_config = {"extra": "forbid"}

    full: bool = False        # 忽略上次状态，全量重扫
    limit: int = Field(default=0, ge=0, le=MAX_SYNC_IMPORT)   # 0 = 不限


class GenReq(BaseModel):
    model_config = {"extra": "forbid"}

    allow_write: bool = False


class SourceReq(BaseModel):
    model_config = {"extra": "forbid"}

    name: str = Field(default="", max_length=MAX_SOURCE_LEN)
    url: str = Field(default="", max_length=security.MAX_URL_LEN)
    enabled: bool = True


class DiscoverReq(BaseModel):
    model_config = {"extra": "forbid"}

    url: str = Field(max_length=security.MAX_URL_LEN)
    llm_judge: bool = True    # 关掉就只做 XML 探测，不问 AI


class BackfillReq(BaseModel):
    model_config = {"extra": "forbid"}

    limit: int = Field(default=20, ge=1, le=MAX_BACKFILL)
    ids: list[str] = Field(default_factory=list, max_length=MAX_BACKFILL_IDS)


class RecheckReq(BaseModel):
    model_config = {"extra": "forbid"}

    limit: int = Field(default=0, ge=0, le=MAX_RECHECK)     # 0 = 全库


class EnvReq(BaseModel):
    """搭环境用的请求：漏洞 ID + 用户审批过的方案（可选）。

    plan 是前端 resolve 出方案、用户点「按此方案搭建」后原样带回来的。
    不带 plan 就由后端 LLM 现场规划（AI 助手对话链路走这条）。
    """

    model_config = {"extra": "forbid"}

    vid: str = Field(max_length=security.MAX_VID_LEN)
    plan: dict | None = None


class EnvVerifyReq(BaseModel):
    """打 PoC 验证的请求：环境 ID 在路径里，vid 可选（默认用环境关联的第一条漏洞）。"""

    model_config = {"extra": "forbid"}

    vid: str = Field(default="", max_length=security.MAX_VID_LEN)


class AgentMsg(BaseModel):
    """对话消息。role 只收 user/assistant，content 长度在 agent 里二次截断。"""

    model_config = {"extra": "forbid"}

    role: str = Field(pattern="^(user|assistant)$")
    content: str = Field(min_length=1, max_length=agent.MSG_MAX)


class AgentChatReq(BaseModel):
    model_config = {"extra": "forbid"}

    # 会话 id。给了就这一轮存进会话文件（历史也从服务端会话里取）；
    # 不给就是一次性问答，历史全靠前端带过来。
    session_id: str = Field(default="", max_length=32)
    messages: list[AgentMsg] = Field(default_factory=list, max_length=agent.HISTORY_MAX * 2)
    # 前端随消息带来的界面快照：用户停留在哪个页面/页签。只进 prompt 不落库
    ui: str = Field(default="", max_length=300)
    # 自定义系统提示词：留空就用内置那套
    system_prompt: str = Field(default="", max_length=4000)
    # 上下文优化策略：drop / compress / keep
    context_mode: str = Field(default="compress", max_length=16)
    # 压缩时保留最近多少轮（×2 条消息）
    context_rounds: int = Field(default=6)
    # 摘要里每条早期消息截断到多少字
    history_chars: int = Field(default=300)
    # 采样参数：None 表示不传这个字段，由模型端用默认值
    temperature: float | None = None
    max_tokens: int | None = None


class AgentSessionMsg(BaseModel):
    """往会话里塞的一条历史消息。允许带 steps（老版本浏览器里的对话轨迹）。"""

    model_config = {"extra": "ignore"}

    role: str = Field(pattern="^(user|assistant)$")
    content: str = Field(default="", max_length=6000)
    steps: list[dict] = Field(default_factory=list, max_length=20)


class AgentSessionReq(BaseModel):
    """新建/重命名会话。标题留空就等第一句话自动起名。"""

    model_config = {"extra": "forbid"}

    title: str = Field(default="", max_length=60)
    # 只在新建时用：把老版本存在浏览器里的对话一次性搬进来
    messages: list[AgentSessionMsg] = Field(default_factory=list, max_length=200)


# ── 唯一入口：抓取与同步 ──────────────────────────────────
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
    except Exception:
        logger.exception("模板同步失败")
        raise
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
    except Exception:
        logger.exception("定时抓取失败")
        raise
    finally:
        _collect_lock.release()
        _status["running"] = False


async def _scheduler():
    """定时任务。启动 10s 后先跑一轮，之后按配置间隔循环。

    阻塞的活儿（git、HTTP、磁盘）一律扔线程池，别把事件循环占住。
    每一步单独 try：一环失败不影响后面几环。
    """
    await asyncio.sleep(10)
    while True:
        # 先同步模板库增量（LLM 只用于翻译，不改模板），再跑文章流水线。
        # 两条互不阻断。抓完统一按 keep_days 清理过期条目，列表不会被老漏洞撑爆。
        if config.get("nuclei", "sync_enabled"):
            try:
                r = await asyncio.to_thread(_do_sync)   # git 是阻塞活儿，扔线程池
                logger.info("模板同步 → %s 条（%s）",
                            r.get("imported", 0), r.get("message") or r.get("to_commit", ""))
            except Exception:  # noqa: BLE001 —— _do_collect 已经记过日志了
                pass
        try:
            logger.info("定时抓取开始")
            r = await asyncio.to_thread(_do_collect)
            logger.info("定时抓取完成 → %s", r)
        except Exception:  # noqa: BLE001
            pass
        try:
            keep = config.get("collect", "keep_days") or 0
            if keep > 0:
                p = await asyncio.to_thread(store.purge_expired, keep)
                logger.info("过期清理 → %s 条（保留 %s 天）", p["removed"], keep)
        except Exception:  # noqa: BLE001
            pass
        await asyncio.sleep(config.get("collect", "interval_minutes") * 60)


@asynccontextmanager
async def lifespan(_app: FastAPI):
    task = asyncio.create_task(_scheduler())
    yield
    task.cancel()


# ── 应用与中间件 ──────────────────────────────────────────
_docs = security.docs_enabled()
app = FastAPI(
    title="AI 漏洞播报系统",
    lifespan=lifespan,
    docs_url="/docs" if _docs else None,
    redoc_url="/redoc" if _docs else None,
    openapi_url="/openapi.json" if _docs else None,
)

# Starlette 里 add_middleware 是"后加的在外层"，所以这段要按执行顺序的倒序写。
# 实际执行：安全头 → Host 白名单 → CORS → 同源/令牌/请求体 → 限流 → 路由
app.add_middleware(RateLimit)
app.add_middleware(ApiGuard)
app.add_middleware(
    CORSMiddleware,
    allow_origins=security.cors_origins(),   # 只放行本机前端，不再是通配符
    allow_methods=["GET", "POST", "DELETE", "OPTIONS"],
    allow_headers=["Content-Type", security.HEADER_FLAG, security.HEADER_TOKEN],
    allow_credentials=False,                 # 令牌走自定义头，不靠 Cookie，不需要凭证
    max_age=600,
)
app.add_middleware(TrustedHostMiddleware, allowed_hosts=security.allowed_hosts())
app.add_middleware(SecurityHeaders)


# ── 统一异常出口 ──────────────────────────────────────────
@app.exception_handler(security.SecurityError)
async def _on_security_error(_request: Request, exc: security.SecurityError) -> JSONResponse:
    """security 层拒绝的，统一回 400。原因写得直白点，方便自己排查。"""
    return JSONResponse({"detail": str(exc)}, status_code=400)


@app.exception_handler(RequestValidationError)
async def _on_validation_error(_request: Request, exc: RequestValidationError) -> JSONResponse:
    """参数校验不过。回 400 而不是 422，并把出错字段和原因一起给前端。"""
    return JSONResponse({"detail": exc.errors()}, status_code=400)


@app.exception_handler(Exception)
async def _on_unexpected(request: Request, exc: Exception) -> JSONResponse:
    """兜底。细节只进服务端日志，返回给前端只说"出错了"，别把栈和路径漏出去。"""
    logger.exception("接口 %s %s 处理失败", request.method, request.url.path)
    return JSONResponse({"detail": "服务器内部错误，请查看后端日志"}, status_code=500)


# ── 会话 ──────────────────────────────────────────────────
@app.get("/api/session")
def api_session():
    """下发写操作令牌。

    前端启动时调一次，把令牌缓存下来，之后每个 POST / DELETE 都带上。
    恶意网页拿不到这个响应（CORS 不放行、也过不了同源检查），所以改不了配置。
    """
    return {"token": security.api_token(), "flag": security.HEADER_FLAG,
            "max_body": security.MAX_BODY}


# ── 漏洞列表与详情 ────────────────────────────────────────
@app.get("/api/vulns")
def api_list(
    page: int = Query(default=1, ge=1, le=MAX_PAGE),
    page_size: int = Query(default=10, ge=1, le=MAX_PAGE_SIZE),
    source: str = Query(default="", max_length=MAX_SOURCE_LEN),
    q: str = Query(default="", max_length=MAX_Q_LEN),
    level: str = Query(default="", max_length=8),
    days: int = Query(default=0, ge=0, le=3650),
):
    """漏洞列表（分页）。q 同时搜标题和正文；level/days 按评级、最近 N 天过滤。"""
    return list_vulns(page=page, page_size=page_size, source=source, q=q,
                      level=level, days=days)


@app.get("/api/vulns/{vid}")
def api_detail(vid: str = Path(max_length=security.MAX_VID_LEN)):
    """漏洞详情，含 PoC 和 nuclei 模板全文。ID 不合法直接 400。"""
    v = get_vuln(security.require_vid(vid))
    if not v:
        raise HTTPException(404, "漏洞不存在")
    # 详情是裸 meta，不保证有 level 字段（老条目没评过）；列表同源的兜底链在这补一份
    v["level"] = store.level_of(v)
    return v


@app.post("/api/vulns/purge")
def api_purge():
    """按 collect.keep_days 清理过期漏洞，手动触发一次。"""
    keep_days = config.get("collect", "keep_days") or 0
    if keep_days <= 0:
        raise HTTPException(400, "保留天数为 0，未启用按日期清理")
    return store.purge_expired(keep_days)


@app.post("/api/vulns/recheck")
async def api_recheck(req: RecheckReq):
    """复检存量：让模型重判每条的内容性质，删掉赛事 WriteUp 这类技术文章，
    把当时没生成出成稿的「（兜底）」条目直接删掉。

    逐条调模型，跑起来慢，放线程池别把事件循环占住。跟抓取共用一把锁，
    正在抓的时候直接返回 skipped——两边都在写同一个文件库。
    """
    if not _collect_lock.acquire(blocking=False):
        return {"skipped": True, "reason": "已有抓取任务在运行"}
    try:
        return await asyncio.to_thread(recheck_library, req.limit)
    except Exception:
        logger.exception("存量复检失败")
        return {"error": "复检失败，请查看后端日志", "scanned": 0, "removed": 0,
                "kept": 0, "removed_ids": [], "failed": []}
    finally:
        _collect_lock.release()


@app.get("/api/stats")
def api_stats():
    """总览页的统计：总数、近 7 天、带 nuclei 模板、已中文化，
    以及按组件（条形图）和按平台（环状图）的分布。"""
    return store.stats()


@app.post("/api/vulns/rate")
async def api_vulns_rate():
    """手动给存量条目补一轮 AI 评级（每轮抓取结束也会自动评 20 条）。

    逐条调模型，慢，放线程池；跟抓取共用一把锁——两边都在写 meta.json。
    """
    if not _collect_lock.acquire(blocking=False):
        return {"skipped": True, "reason": "已有抓取任务在运行"}
    try:
        return {"rated": await asyncio.to_thread(rate_backfill, None, 50)}
    except Exception:
        logger.exception("存量评级失败")
        return {"rated": 0, "error": "评级失败，请查看后端日志"}
    finally:
        _collect_lock.release()


# ── 抓取 ──────────────────────────────────────────────────
@app.post("/api/collect")
async def api_collect():
    """手动触发一轮抓取。跟定时任务共用一把锁，正在跑就直接返回 skipped。"""
    return await asyncio.to_thread(_do_collect)


@app.get("/api/collect/status")
def api_status():
    """抓取状态：上次跑完的时间、结果，以及按间隔算出来的下次时间。"""
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
    """同步 nuclei-templates 增量：git diff 出新增/修改的模板，原样入库（不过 LLM）。

    git 没装、网断了这类问题前端需要看到，所以错误照样返回，但只给一句话，
    完整异常进服务端日志。
    """
    try:
        return _do_sync(full=req.full, limit=req.limit)
    except Exception:
        logger.exception("手动同步模板库失败")
        return {"error": "同步失败，请查看后端日志", "imported": 0, "files": []}


@app.get("/api/nuclei/templates")
def api_templates():
    """本地模板库：生成的和拉来的都在这，整个目录可直接 nuclei -l 跑。"""
    return {"dir": config.NUCLEI_TPL_DIR.name, "items": list_templates()}


@app.get("/api/nuclei/remote")
def api_remote(
    limit: int = Query(default=10, ge=1, le=MAX_REMOTE_PREVIEW),
    severity: str = Query(default="", max_length=MAX_SOURCE_LEN),
    tag: str = Query(default="", max_length=MAX_SOURCE_LEN),
):
    """预览远程模板库条目，不落库。首次拉索引可能要 1-2 分钟。"""
    repo, ref = config.get("nuclei", "repo"), config.get("nuclei", "ref")
    try:
        tpls = nuclei_tpl.fetch_remote_templates(
            repo, ref=ref, limit=limit, severity=severity,
            tag=tag, cache_dir=NUCLEI_CACHE_DIR)
    except Exception:
        logger.exception("拉远程模板库失败 repo=%s ref=%s", repo, ref)
        raise HTTPException(502, "远程模板库拉取失败，请查看后端日志") from None
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
    except Exception:
        logger.exception("远程模板入库失败")
        raise HTTPException(502, "拉取失败，请查看后端日志") from None


@app.post("/api/vulns/{vid}/nuclei")
async def api_gen_nuclei(vid: str = Path(max_length=security.MAX_VID_LEN), req: GenReq = None):
    """给已收录漏洞补/重生成 nuclei 模板。"""
    req = req or GenReq()
    v = get_vuln(security.require_vid(vid))
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
async def api_gen_poc(vid: str = Path(max_length=security.MAX_VID_LEN)):
    """按公开思路生成 Python PoC。nuclei 进来的条目默认只有 yaml，点这里补一份。"""
    r = await asyncio.to_thread(gen_poc, security.require_vid(vid))
    if not r.get("ok"):
        raise HTTPException(502, r.get("reason", "生成失败"))
    return {"ok": True, "chars": r["chars"]}


@app.post("/api/vulns/{vid}/translate")
async def api_translate_one(vid: str = Path(max_length=security.MAX_VID_LEN)):
    """把单条漏洞情报译成中文。LLM 不可用时返回原因，不改原数据。"""
    r = await asyncio.to_thread(translate.translate_one, security.require_vid(vid))
    if not r.get("ok"):
        raise HTTPException(502, r.get("reason", "翻译失败"))
    return r


@app.post("/api/translate/backfill")
async def api_translate_backfill(req: BackfillReq):
    """批量翻译。传 ids = 翻译当前页的 10 条；不传 = 按 limit 补存量。"""
    ids = [security.require_vid(v) for v in req.ids if v]
    return await asyncio.to_thread(translate.backfill, req.limit, None, ids or None)


# ── LLM 状态 ──────────────────────────────────────────────
_pending_cache: dict = {"at": 0.0, "value": 0}
_PENDING_TTL = 30.0     # 全盘扫 200 多个目录要几十毫秒，缓存 30 秒足够了


@app.get("/api/llm/status")
def api_llm_status():
    """LLM 是否可用 + 全库待译数。前端据此决定「AI 生成」按钮是否点亮。

    待译数要遍历整个漏洞库，加个短缓存，别让每次刷新列表都扫一遍盘。
    """
    now = time.monotonic()
    if now - _pending_cache["at"] > _PENDING_TTL:
        try:
            _pending_cache["value"] = store.pending_translate_count()
        except Exception:
            logger.exception("统计待译数失败")
        _pending_cache["at"] = now
    llm = get_llm()
    return {"available": bool(llm.base and llm.key and llm.model),
            "model": llm.model, "base": llm.base,
            "key_set": bool(llm.key),
            "pending_translate": _pending_cache["value"]}


# ── 设置页 ──────────────────────────────────────────────
def _mask(key: str) -> str:
    """密钥脱敏：只露头尾，中间打码。空 key 原样返回。"""
    if not key:
        return ""
    return f"{key[:4]}{'*' * 8}{key[-4:]}" if len(key) > 12 else "****"


def _public_settings() -> dict:
    """给前端看的配置快照。

    只回白名单里的几节，sources 不回（那是另一个接口的事），config_file 只给文件名。
    少回一个字段就少一条信息泄露路径，接口清单本身没必要对外。
    """
    cfg = config.load(force=True)          # 外部手改过 yaml 也能读到
    return {"llm": {**cfg["llm"], "key": _mask(cfg["llm"].get("key", ""))},
            "collect": cfg["collect"],
            "nuclei": cfg["nuclei"],
            "lab": cfg["lab"],
            "config_file": config.CONFIG_FILE.name,
            "key_set": bool(cfg["llm"].get("key"))}


@app.get("/api/settings")
def api_get_settings():
    """读配置。API Key 只回脱敏后的样子，真实值永不出口。"""
    return _public_settings()


@app.post("/api/settings")
def api_save_settings(req: SettingsReq):
    """前端表单 → 逐字段校验 → 写 config.yaml。key 传空串表示保持原值。"""
    try:
        config.update(req.to_patch())
    except (ValueError, TypeError) as e:
        raise HTTPException(400, str(e)) from e
    return {"ok": True, **_public_settings()}


@app.post("/api/settings/test")
async def api_test_llm(req: SettingsReq = _DEFAULT_SETTINGS_REQ):
    """用表单里的值（不落盘）试连一次，验证地址/密钥/模型三项。"""
    if req.llm.base or req.llm.key or req.llm.model:
        saved = dict(config.load()["llm"])      # 拷贝，别污染进程内缓存
        given = req.llm.model_dump()
        for k, v in given.items():
            if v is not None and (v or k not in ("key", "base")):
                saved[k] = v                   # key/base 空串 = 用已存的
        llm = LLM(saved.get("base", ""), saved.get("key", ""), saved.get("model", ""))
    else:
        llm = get_llm()
    try:
        reply = await asyncio.to_thread(llm.ping)
    except Exception:
        logger.exception("LLM 连通性测试失败 base=%s", llm.base)
        raise HTTPException(502, "连接失败，请查看后端日志") from None
    return {"ok": True, "reply": reply, "model": llm.model, "base": llm.base}


# ── 漏洞源接入 ──────────────────────────────────────────
@app.get("/api/sources")
def api_list_sources():
    """内置源 + 用户接入的源。内置源标 builtin，只能看不能删。"""
    return source_manager.list_sources()


@app.post("/api/sources/discover")
async def api_discover_source(req: DiscoverReq):
    """给定社区首页，探测 feed 地址并让 AI 判断是否漏洞社区。不落配置。

    地址本身先过一遍安全网关：只放 http/https，解析出来的 IP 不能是内网或云元数据地址。
    """
    try:
        target = security.check_url(req.url)
    except security.SecurityError as e:
        raise HTTPException(400, str(e)) from e
    try:
        return await asyncio.to_thread(source_discovery.discover, target, req.llm_judge)
    except security.SecurityError as e:
        raise HTTPException(400, str(e)) from e
    except Exception:
        logger.exception("源探测失败 url=%s", target)
        raise HTTPException(502, "探测失败，请查看后端日志") from None


@app.post("/api/sources")
def api_add_source(req: SourceReq):
    """把探测出来的 feed 地址接入。已存在的同名源视为更新地址。

    增删逻辑都在 source_manager 里，这里只负责把领域错误翻成 HTTP 状态码。
    """
    try:
        return source_manager.add_source(req.name, req.url, req.enabled)
    except source_manager.SourceError as e:
        raise HTTPException(e.status, e.message) from e


@app.delete("/api/sources/{name}")
def api_del_source(name: str = Path(max_length=MAX_SOURCE_LEN)):
    """移除用户接入的源。内置源不在这里，删不掉。"""
    try:
        return source_manager.remove_source(name)
    except source_manager.SourceError as e:
        raise HTTPException(e.status, e.message) from e


# ── SSE 流式响应 ─────────────────────────────────────────
def _sse_response(sync_gen, errors: tuple = (Exception,)):
    """把同步事件生成器包成 SSE 响应：每帧 data: {json}\\n\\n。

    同步生成器的每次 next() 都扔线程池跑——里面是阻塞的 socket 读，
    直接在事件循环里迭代会把整个后端卡住（轮询、静态页全都跟着僵住）。
    errors 里列的异常转成 {"type": "error"} 帧推给前端（str(e) 已是人话）；
    其余异常记日志后推通用错误帧。前端断开时 Starlette 会收掉生成器。
    """
    async def gen():
        try:
            async for ev in iterate_in_threadpool(sync_gen):
                yield f"data: {json.dumps(ev, ensure_ascii=False)}\n\n"
        except errors as e:
            yield f"data: {json.dumps({'type': 'error', 'message': str(e)}, ensure_ascii=False)}\n\n"
        except Exception:
            logger.exception("SSE 流异常")
            yield f"data: {json.dumps({'type': 'error', 'message': '服务异常，请查看后端日志'}, ensure_ascii=False)}\n\n"

    return StreamingResponse(gen(), media_type="text/event-stream",
                             headers={"Cache-Control": "no-store",
                                      "X-Accel-Buffering": "no"})


# ── 本地复现环境 ──────────────────────────────────────────
@app.get("/api/envs")
def api_list_envs():
    """环境列表。附带资产根目录和 Docker 可用性，前端顶部要显示。"""
    return lab_env.list_envs()


@app.get("/api/envs/{eid}")
def api_get_env(eid: str = Path(max_length=32)):
    """环境详情：落盘目录、程序/源码/docker 资产位置。"""
    try:
        return lab_env.get_env(eid)
    except lab_env.EnvError as e:
        raise HTTPException(e.status, e.message) from e


@app.post("/api/envs/resolve")
async def api_resolve_env(req: EnvReq):
    """只让 LLM 出方案，不拉任何东西。用来先看看打算搭什么。

    网上确实没有程序本体时，方案里 source=none、available=false，并带上原因。
    """
    try:
        vid = security.require_vid(req.vid)
        plan = await asyncio.to_thread(lab_env.plan_env, vid)
    except security.SecurityError as e:
        raise HTTPException(400, str(e)) from e
    except lab_env.EnvError as e:
        raise HTTPException(e.status, e.message) from e
    return {"ok": True, "plan": plan}


@app.post("/api/envs/resolve/stream")
async def api_resolve_env_stream(req: EnvReq):
    """「先看方案」流式版：方案字段一边生成一边推给前端。

    事件：{"type": "field", "field", "text"} 逐字段播报 →
          {"type": "done", "plan"} 完整方案 →
          {"type": "error", "message"} 失败原因。
    模型一直在后台干活，前端从第一秒起就能看到方案逐字成形，没有「干等 60 秒」。
    """
    try:
        vid = security.require_vid(req.vid)
    except security.SecurityError as e:
        raise HTTPException(400, str(e)) from e

    def gen():
        yield from lab_env.plan_env_stream(vid)

    return _sse_response(gen(), (lab_env.EnvError,))


@app.post("/api/envs/build")
async def api_build_env(req: EnvReq):
    """为一条漏洞搭建复现环境：方案 → 真去拉 → 落盘到统一目录。

    方案来源两种：req.plan 带了审批过的方案就按方案搭（不问 LLM）；
    没带就 LLM 现场规划（AI 助手对话链路）。已有同指纹环境直接共享，
    网上找不到程序本体就放弃，返回放弃理由。
    """
    try:
        vid = security.require_vid(req.vid)
        r = await asyncio.to_thread(lab_env.build, vid, None, req.plan)
    except security.SecurityError as e:
        raise HTTPException(400, str(e)) from e
    except lab_env.EnvError as e:
        raise HTTPException(e.status, e.message) from e
    return r


@app.post("/api/envs/cancel")
async def api_cancel_env(req: EnvReq):
    """最高优先级取消：立即终止该漏洞本次环境搭建的一切进行中任务。

    正在跑的 docker pull / git clone / docker build 子进程马上被杀；
    环境还在「构建中」就记失败，已在运行/启动中就立刻停容器。
    """
    try:
        vid = security.require_vid(req.vid)
    except security.SecurityError as e:
        raise HTTPException(400, str(e)) from e
    return await asyncio.to_thread(lab_env.cancel_build, vid)


@app.post("/api/envs/{eid}/start")
async def api_start_env(eid: str = Path(max_length=32)):
    """启动环境：docker 环境起容器，源码/二进制环境起进程。"""
    try:
        return await asyncio.to_thread(lab_env.start_env, eid)
    except lab_env.EnvError as e:
        raise HTTPException(e.status, e.message) from e


@app.post("/api/envs/{eid}/stop")
async def api_stop_env(eid: str = Path(max_length=32)):
    """停止环境。"""
    try:
        return await asyncio.to_thread(lab_env.stop_env, eid)
    except lab_env.EnvError as e:
        raise HTTPException(e.status, e.message) from e


@app.post("/api/envs/{eid}/verify")
async def api_verify_env(eid: str = Path(max_length=32), req: EnvVerifyReq | None = None):
    """拿 PoC 真打这个环境，验证漏洞能不能复现。

    req.vid 可选：不传就用环境关联的第一条漏洞。
    环境没起来会顺手拉起来再打。
    """
    vid = ""
    if req is not None and req.vid:
        try:
            vid = security.require_vid(req.vid)
        except security.SecurityError as e:
            raise HTTPException(400, str(e)) from e
    try:
        return await asyncio.to_thread(lab_env.verify_env, eid, vid)
    except lab_env.EnvError as e:
        raise HTTPException(e.status, e.message) from e


@app.delete("/api/envs/{eid}")
def api_delete_env(eid: str = Path(max_length=32)):
    """删掉环境：容器、源码、程序一并清掉，引用它的漏洞也解除关联。"""
    try:
        return lab_env.delete_env(eid)
    except lab_env.EnvError as e:
        raise HTTPException(e.status, e.message) from e


# ── AI Agent 对话 ────────────────────────────────────────
def _agent_chat_prepare(req: AgentChatReq) -> tuple[str, str, list[dict], dict]:
    """api_agent_chat / api_agent_chat_stream 共用的入参准备。

    返回 (last_user, sid, history, opts)。会话模式历史以服务端文件为准，
    前端带来的旧消息不用；参数越界的就地收到安全范围。
    """
    last_user = ""
    for m in reversed(req.messages):
        if m.role == "user":
            last_user = m.content.strip()
            break
    if not last_user:
        raise HTTPException(400, "最后一条必须是用户消息")

    sid = ""
    if req.session_id:
        try:
            sid = agent_sessions.resolve(req.session_id)
        except ValueError as e:
            raise HTTPException(400, str(e)) from e

    if sid:
        sess = agent_sessions.get_session(sid) or {}
        history = [{"role": m["role"], "content": m["content"]}
                   for m in sess.get("messages", [])
                   if m.get("role") in ("user", "assistant") and m.get("content")]
        history.append({"role": "user", "content": last_user})
    else:
        history = [m.model_dump() for m in req.messages]

    # 用户在面板右侧配的参数：越界的就地收到安全范围，认不出来的退回默认值
    mode = req.context_mode if req.context_mode in ("drop", "compress", "keep") else "compress"
    opts = {
        "system_prompt": security.clean_text(req.system_prompt, 4000),
        "context_mode": mode,
        "context_rounds": security.clamp_int(req.context_rounds, 1, 50, 6),
        "history_chars": security.clamp_int(req.history_chars, 50, 8000, 300),
        "temperature": (None if req.temperature is None
                        else max(0.0, min(2.0, req.temperature))),
        "max_tokens": (None if not req.max_tokens or req.max_tokens <= 0
                       else min(req.max_tokens, 32000)),
    }
    return last_user, sid, history, opts


@app.post("/api/agent/chat")
async def api_agent_chat(req: AgentChatReq):
    """跟内嵌 agent 说一句话。阻塞的 LLM 往返扔线程池。
    工具会在 agent 模块里就地执行（改配置/查库/导出），返回答复与操作轨迹。

    带 session_id 时走会话模式：历史从服务端会话文件里取，本轮问答回写进文件，
    刷新页面、换标签页都还在。不带 session_id 是一次性问答（老行为）。
    """
    if not req.messages:
        raise HTTPException(400, "对话内容为空")
    last_user, sid, history, opts = _agent_chat_prepare(req)

    try:
        result = await asyncio.to_thread(agent.run_chat, history, req.ui, opts)
    except (ValueError, RuntimeError) as e:
        # 参数级错误 / LLM 侧失败（端点 500、超时……），原样转给人看
        raise HTTPException(400, str(e)) from e
    except Exception:
        logger.exception("Agent 对话失败")
        raise HTTPException(502, "Agent 服务异常，请查看后端日志") from None

    if sid:
        agent_sessions.append_message(sid, "user", last_user)
        agent_sessions.append_message(sid, "assistant",
                                      result.get("reply", ""), result.get("steps"))
        result["session_id"] = sid
    return result


@app.post("/api/agent/chat/stream")
async def api_agent_chat_stream(req: AgentChatReq):
    """agent 对话流式版：思考、答复、工具步逐个事件推给前端，不等整轮结束。

    事件：{"type": "text", "field": "thought"|"final", "text"} 增量文字 →
          {"type": "step", "step"} 工具执行完一步 →
          {"type": "done", "reply", "steps", "sent"}（带 session_id）→
          {"type": "error", "message"} 失败原因。
    模型吐一个字就推一个字，不再「转圈几十秒后整段蹦出来」。
    """
    if not req.messages:
        raise HTTPException(400, "对话内容为空")
    last_user, sid, history, opts = _agent_chat_prepare(req)

    def gen():
        final: dict | None = None
        for ev in agent.run_chat_stream(history, req.ui, opts):
            if ev.get("type") == "done":
                final = ev
                if sid:
                    ev = {**ev, "session_id": sid}
            yield ev
        if sid and final:
            agent_sessions.append_message(sid, "user", last_user)
            agent_sessions.append_message(sid, "assistant",
                                          final.get("reply", ""), final.get("steps"))

    return _sse_response(gen(), (ValueError, RuntimeError))


# ── AI Agent 会话历史 ────────────────────────────────────
@app.get("/api/agent/sessions")
def api_agent_sessions():
    """会话列表。左侧栏用：id、标题、时间、消息条数，不带正文。"""
    return {"sessions": agent_sessions.list_sessions()}


@app.post("/api/agent/sessions")
def api_agent_session_new(req: AgentSessionReq):
    """新建一个会话。带 messages 就是「把老对话搬进来」。"""
    return agent_sessions.create_session(
        req.title, [m.model_dump() for m in req.messages])


@app.get("/api/agent/sessions/{sid}")
def api_agent_session_get(sid: str = Path(max_length=32)):
    """读一个会话，含全部消息。"""
    try:
        data = agent_sessions.get_session(sid)
    except ValueError as e:
        raise HTTPException(400, str(e)) from e
    if not data:
        raise HTTPException(404, "会话不存在")
    return data


@app.put("/api/agent/sessions/{sid}")
def api_agent_session_rename(req: AgentSessionReq, sid: str = Path(max_length=32)):
    """给会话改名。"""
    try:
        data = agent_sessions.rename_session(sid, req.title)
    except ValueError as e:
        raise HTTPException(400, str(e)) from e
    if not data:
        raise HTTPException(404, "会话不存在")
    return data


@app.delete("/api/agent/sessions/{sid}")
def api_agent_session_del(sid: str = Path(max_length=32)):
    """删掉整个会话。"""
    if not agent_sessions.delete_session(sid):
        raise HTTPException(404, "会话不存在")
    return {"ok": True}


@app.delete("/api/agent/sessions/{sid}/messages")
def api_agent_session_clear(sid: str = Path(max_length=32)):
    """清空当前会话的消息，会话本身留着。"""
    try:
        data = agent_sessions.clear_messages(sid)
    except ValueError as e:
        raise HTTPException(400, str(e)) from e
    if not data:
        raise HTTPException(404, "会话不存在")
    return data


@app.get("/api/agent/export/{name}")
def api_agent_export(name: str = Path(max_length=80)):
    """下载 agent 导出的 JSON 文件。文件名先过正则再 safe_join，越界拒之门外。

    不用 FileResponse：它按块流式发 body，在这套中间件栈下发不完整；
    导出文件撑死几 MB，整读进内存换一个单 body 消息的 Response，稳。
    """
    try:
        path = agent.export_path(name)
    except (ValueError, security.SecurityError) as e:
        raise HTTPException(400, str(e)) from e
    if not path.is_file():
        raise HTTPException(404, "导出文件不存在或已被清理")
    try:
        data = path.read_bytes()
    except OSError:
        raise HTTPException(502, "导出文件读不出来") from None
    return Response(
        content=data,
        media_type="application/json",
        headers={"Content-Disposition": f'attachment; filename="{name}"',
                 "Cache-Control": "no-store"},
    )


# ── 自更新 ────────────────────────────────────────────────
@app.get("/api/update/check")
async def api_update_check():
    """看看 GitHub 上有没有新版本。只读：跑本地 git 和一次 GitHub API 请求，
    不碰工作区，联网失败也照常返回结构化结果。"""
    return await asyncio.to_thread(updater.check)


@app.post("/api/update/apply")
async def api_update_apply():
    """拉取最新版本。只做 --ff-only 快进；本地有未提交改动直接拒绝，
    不替用户 reset 掉自己写的东西。git 和网络都是阻塞活儿，扔线程池。"""
    return await asyncio.to_thread(updater.apply)


# ── 前端静态资源（前后端不分离）──────────────────────────────
# vite build 的产物落在 backend/static，由后端自己发出去：页面和接口同源同端口，
# 不用再单独起 vite dev server。前端 api.js 里全是相对路径 /api/...，天然同源，
# 也不会有跨域和"两个服务端口不一致"这类问题。
#
# vue-router 用的是 history 模式（createWebHistory），/envs、/vuln/xxx 这些深链
# 在磁盘上并没有对应文件，直接刷新就是 404。所以非 /api 的未知路径一律回落 index.html，
# 让前端路由自己接管。
_STATIC_DIR = config.STATIC_DIR
_INDEX = _STATIC_DIR / "index.html"

# 页面 CSP 里的 frame-src 要按运行时实际 IP 生成，所以不能只靠构建产物里写死的那份。
# CSP 的 host-source 不支持 CIDR 网段（http://192.168.0.0/16 是无效写法，浏览器会当成
# 一个陌生主机名直接拒掉），只能写精确主机 + 端口通配。
_CSP_META_RE = re.compile(
    r'(<meta\s+http-equiv="Content-Security-Policy"\s+content=")([^"]*)(")',
    re.IGNORECASE,
)


def _frame_src_sources() -> str:
    """iframe 允许嵌入的来源列表。

    复现环境页要把本地靶站（容器映射出来的端口）嵌进 iframe 预览。靶站端口是
    随机高位端口，所以端口要带 *；对局域网开放时，本机所有 IPv4 都要放行。
    """
    hosts = ["'self'", "http://127.0.0.1:*", "http://localhost:*"]
    if security.lan_enabled():
        # 对局域网开放时靶站地址会换成对外 IP（见 lab_env._display_url），
        # iframe 要能嵌它。本机所有 IPv4 都列上，端口用 *（容器端口是随机高位端口）。
        for ip in security.local_ipv4s():
            hosts.append(f"http://{ip}:*")
    return " ".join(hosts)


def _patch_csp(html: str) -> str:
    """按运行时实际 IP 改写页面 CSP 的 frame-src。

    meta 里的 CSP 与响应头 CSP 是叠加生效的，放开来源只能改 meta 这侧。
    """
    sources = _frame_src_sources()

    def _repl(m: re.Match) -> str:
        csp = re.sub(r"frame-src\s+[^;]*", f"frame-src {sources}", m.group(2))
        return m.group(1) + csp + m.group(3)

    return _CSP_META_RE.sub(_repl, html, count=1)


def _index_response() -> Response:
    """首页 / SPA 回落。返回前按运行时 IP 改写 CSP 的 frame-src。"""
    try:
        html = _INDEX.read_text(encoding="utf-8")
    except OSError:
        return Response(_NOT_BUILT_PAGE,
                        media_type="text/html; charset=utf-8", status_code=503)
    return Response(_patch_csp(html), media_type="text/html; charset=utf-8",
                    headers={"Cache-Control": "no-cache"})

_NOT_BUILT_PAGE = """<!doctype html>
<html lang="zh-CN"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>前端未构建</title>
<style>
 body{background:#0f1115;color:#e6e8eb;font:15px/1.7 "Microsoft YaHei",system-ui,sans-serif;
      display:flex;align-items:center;justify-content:center;min-height:100vh;margin:0}
 .box{max-width:560px;padding:32px 36px;border:1px solid #262a33;border-radius:14px;background:#151820}
 h1{margin:0 0 12px;font-size:20px}
 code{background:#0b0d12;border:1px solid #262a33;border-radius:6px;padding:2px 8px;
      display:inline-block;font-family:Consolas,monospace;color:#7fd1a0}
 pre{background:#0b0d12;border:1px solid #262a33;border-radius:8px;padding:14px 16px;
     font-family:Consolas,monospace;color:#cfd6e4;overflow:auto}
 p{color:#9aa3b2}
</style></head>
<body><div class="box">
<h1>前端构建产物缺失</h1>
<p>后端已经在跑了，但 <code>backend/static</code> 里没有构建产物，所以页面出不来。
   正常情况下这些产物<b>已随仓库附带</b>，克隆下来就能直接用——
   多半是下载不完整，或者被人删掉了。可以重新拉一份，或自己构建一次：</p>
<pre>cd frontend
npm install      # 首次才需要
npm run build    # 产物落到 backend/static
cd ../backend
python main.py</pre>
<p>然后打开 <code>http://127.0.0.1:8100</code>。</p>
</div></body></html>
"""


@app.get("/{full_path:path}", include_in_schema=False)
async def spa(full_path: str):
    """前端静态资源 + SPA 回落。

    路由必须注册在所有 /api 接口之后，否则接口会被这条 catch-all 抢走。
    """
    # /api 下面不存在的接口老老实实回 404 JSON，别给前端吐一坨 HTML。
    if full_path == "api" or full_path.startswith("api/"):
        raise HTTPException(404, "接口不存在")

    if not _INDEX.is_file():
        return Response(_NOT_BUILT_PAGE,
                        media_type="text/html; charset=utf-8", status_code=503)

    # 拼路径可能带 ../，解析后必须确认还在静态目录里，否则能读到项目任意文件。
    target = (_STATIC_DIR / full_path).resolve()
    try:
        target.relative_to(_STATIC_DIR.resolve())
    except ValueError:
        target = None
    if target is not None and target.is_file():
        # vite 的 assets 文件名带内容哈希，可以放心长缓存；
        # index.html 和图标不能长缓存，不然重新构建后用户还拿到旧的。
        if full_path.startswith("assets/"):
            headers = {"Cache-Control": "public, max-age=31536000, immutable"}
        else:
            headers = {"Cache-Control": "no-cache"}
        if target == _INDEX.resolve():
            return _index_response()
        return FileResponse(target, headers=headers)

    # 深链（/envs、/vuln/xxx…）落回首页，交给 vue-router。
    return _index_response()


if __name__ == "__main__":
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s | %(message)s",
    )
    # 默认只绑 127.0.0.1。这个服务没有鉴权体系，暴露到局域网等于把配置和密钥敞开。
    # 真要给别人访问，显式设 AI_BAOBAO_HOST=0.0.0.0（这时 Host 白名单会自动
    # 放行本机的局域网 IP，否则浏览器会被 TrustedHostMiddleware 挡成 400）。
    # 8000 在 Windows 保留端口段内，避开。
    host = security.bind_host()
    port = security.bind_port()
    if security.lan_enabled():
        logger.warning(
            "已对局域网开放：%s:%s，其他机器用 http://%s:%s 访问。"
            "本服务没有登录鉴权，等于把 LLM 密钥和复现环境资产敞开，请确认网络环境可信。",
            host, port, security.public_host(), port,
        )
    uvicorn.run(app, host=host, port=port)
