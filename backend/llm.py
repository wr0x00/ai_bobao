"""llm.py —— OpenAI 兼容 LLM 客户端（stdlib 实现）

配置每次调用现读 config.yaml，所以设置页改完立即生效，不用重启。

出站安全：base 地址是用户在设置页填的，而请求头里带着 API Key。
一旦这个地址能随便填，密钥就会被送到对方手里，服务器还能被当跳板。
所以发请求前先过 security.check_url（只允许 http/https，域名不能解析到内网），
请求本身再走 security.open_url。

本机 Ollama 这类内网服务确实要用，把 AI_BAOBAO_ALLOW_PRIVATE=1 打开即可。
"""
import json
import logging
import time
import urllib.error
from collections.abc import Iterator

import config
import security

logger = logging.getLogger("ai_bobao.llm")

# 有些中转站前面挂了 Cloudflare，按 UA 拦非浏览器客户端（Python-urllib 直接 403
# "error code: 1010"）。带上一个常规 UA 就通了，跟 openai 官方 SDK 的做法一样。
_UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 " \
      "(KHTML, like Gecko) Chrome/122.0 Safari/537.36"

MAX_REPLY = 4 * 1024 * 1024      # 模型回复上限 4MB

# 瞬时错误：服务商限流/过载/网关抖动，等一两秒重试通常就过了。
# 401/404 这类确定性错误不在列，第一次就抛，别白等。
_RETRY_CODES = frozenset({429, 500, 502, 503, 504})

# 最多试几次（含首次）。抖动重试用这个数，流式和非流式保持一致。
_RETRIES = 3


class LLM:
    available = True

    def __init__(self, base: str = "", key: str = "", model: str = ""):
        self.base = (base or config.get("llm", "base")).rstrip("/")
        # 有些服务商的页面直接给的是带 /v1 的完整地址（如
        # https://api-inference.modelscope.cn/v1），而本类统一在末尾拼
        # /v1/chat/completions。不归一化的话会拼出 /v1/v1/... 直接 404，
        # 用户看起来就是"模型连接不上"。
        if self.base.endswith("/v1"):
            self.base = self.base[:-3]
        self.key = key or config.get("llm", "key")
        self.model = model or config.get("llm", "model")

    def _post_chat(self, endpoint: str, body: bytes, timeout: int | None = None) -> bytes:
        """发对话请求，瞬时错误（限流/5xx/网络抖动）自动重试两次。

        服务商偶发 500/429 是家常便饭（本家刚见过：ModelScope 限流 429、
        nccsec 网关 500），直接把异常甩给上层，用户看到的就是「LLM 不可用」。
        这种抖动值得在底层消掉：2s、4s 退避重试，确定性错误照样立刻抛。

        timeout 为空时用配置里的全局超时；交互式的小请求可以传更小的值，
        免得网关挂住时让人在界面上干等十分钟。
        """
        err: Exception | None = None
        for attempt in range(_RETRIES):
            if attempt:
                time.sleep(2 * attempt)
            try:
                return security.open_url(
                    endpoint,
                    timeout=timeout or config.get("llm", "timeout"),
                    max_bytes=MAX_REPLY,
                    method="POST",
                    data=body,
                    headers={"Content-Type": "application/json",
                             "User-Agent": _UA,
                             "Authorization": f"Bearer {self.key}"},
                )
            except urllib.error.HTTPError as e:
                if e.code not in _RETRY_CODES:
                    raise
                err = e
                logger.warning("LLM 瞬时错误 HTTP %s（第 %s 次重试）", e.code, attempt + 1)
            except (ConnectionError, TimeoutError) as e:
                err = e
                logger.warning("LLM 网络抖动（%s），第 %s 次重试", e, attempt + 1)
        raise err  # type: ignore[misc]

    def chat(self, system: str, user: str, timeout: int | None = None) -> dict:
        """问模型一句话，期望回一段 JSON。

        地址先校验后发送，校验不过就直接拒绝，绝不带着密钥往外跑。
        """
        endpoint = f"{self.base}/v1/chat/completions"
        security.check_url(endpoint)

        body = json.dumps({
            "model": self.model,
            "messages": [{"role": "system", "content": system},
                         {"role": "user", "content": user}],
            "response_format": {"type": "json_object"},
        }).encode()
        raw = self._post_chat(endpoint, body, timeout)
        content = json.loads(raw)["choices"][0]["message"]["content"]
        return json.loads(content)

    def chat_messages(self, messages: list[dict]) -> str:
        """多轮对话版：agent 用。整份 messages 原样发出，回原文不解析——
        agent 里的回复要么是协议 JSON、要么要当裸文本兜底，解析交给调用方。"""
        text, _ = self.chat_messages_full(messages)
        return text

    def chat_messages_full(self, messages: list[dict],
                           temperature: float | None = None,
                           max_tokens: int | None = None,
                           json_mode: bool = True) -> tuple[str, dict]:
        """多轮对话版，同时回传「实际发出去的请求体」，方便前端展示。

        temperature 为 None 就不带这个字段，max_tokens 不是正整数也不带，
        跟不传时用的是模型端的同一套默认值。

        json_mode=False 时不带 response_format，用于纯文本对话。
        """
        endpoint = f"{self.base}/v1/chat/completions"
        security.check_url(endpoint)

        payload = {
            "model": self.model,
            # 复制一份列表：调用方后面还会往原 messages 里追加内容，
            # 这里要留住"发出那一刻"的原样
            "messages": list(messages),
        }
        if json_mode:
            payload["response_format"] = {"type": "json_object"}
        if temperature is not None:
            payload["temperature"] = temperature
        if isinstance(max_tokens, int) and max_tokens > 0:
            payload["max_tokens"] = max_tokens

        body = json.dumps(payload).encode()
        raw = self._post_chat(endpoint, body)
        return str(json.loads(raw)["choices"][0]["message"]["content"] or ""), payload

    def chat_stream(self, messages: list[dict],
                    temperature: float | None = None,
                    max_tokens: int | None = None,
                    json_mode: bool = True,
                    timeout: float | None = None,
                    payload_out: dict | None = None) -> Iterator[str]:
        """流式对话：模型吐一段就 yield 一段，不用等它把整段写完。

        走 OpenAI 兼容的 SSE（text/event-stream）：响应里每行 "data: {...}"，
        其中 choices[0].delta.content 就是这一小段增量文字，"data: [DONE]" 收尾。

        json_mode=True 时照样要 response_format=json_object（agent 协议靠它
        稳定输出 JSON）；关掉就是纯文本流。

        payload_out 传个 dict 进来，请求发完后会填上「实际发出去的请求体」，
        用法跟 chat_messages_full 的返回值一样，前端照着展示。

        服务端不支持 stream 参数时会回 4xx，这种情况退回非流式一次拿整段，
        再当成"一口气吐完的流"yield 出去——上层代码不用关心走的哪条路。

        出错处理跟非流式不一样：已经吐过字的流不重试（重试会把内容重复一遍），
        只有一个字都还没吐出来时才重试。
        """
        endpoint = f"{self.base}/v1/chat/completions"
        security.check_url(endpoint)

        payload: dict = {
            "model": self.model,
            "messages": list(messages),
            "stream": True,
        }
        if json_mode:
            payload["response_format"] = {"type": "json_object"}
        if temperature is not None:
            payload["temperature"] = temperature
        if isinstance(max_tokens, int) and max_tokens > 0:
            payload["max_tokens"] = max_tokens

        if payload_out is not None:
            payload_out.clear()
            payload_out.update({k: v for k, v in payload.items() if k != "stream"})

        body = json.dumps(payload).encode()

        wait = timeout or config.get("llm", "timeout")
        headers = {"Content-Type": "application/json",
                   "User-Agent": _UA,
                   "Authorization": f"Bearer {self.key}",
                   "Accept": "text/event-stream"}

        last_err: Exception | None = None
        for attempt in range(_RETRIES):
            if attempt:
                time.sleep(2 * attempt)
            got = False
            try:
                with security.open_stream(endpoint, timeout=wait, method="POST",
                                          data=body, headers=headers) as r:
                    ctype = (r.headers.get("Content-Type") or "").lower()
                    if "text/event-stream" in ctype:
                        # 正经 SSE：逐行拆 data: 帧，delta.content 是增量文字
                        for raw_line in r:
                            line = raw_line.decode("utf-8", "replace").strip()
                            if not line or not line.startswith("data:"):
                                continue
                            chunk = line[5:].strip()
                            if chunk == "[DONE]":
                                return
                            try:
                                obj = json.loads(chunk)
                            except ValueError:
                                continue
                            err = obj.get("error")
                            if isinstance(err, dict):
                                # 有的网关把业务错误（如积分不足）包成 SSE 帧下发，
                                # HTTP 状态还是 200——不识别的话就是"静默吐空"
                                raise RuntimeError(
                                    f"模型返回错误：{err.get('message') or err}")
                            for ch in obj.get("choices") or []:
                                piece = (ch.get("delta") or {}).get("content")
                                if piece:
                                    got = True
                                    yield str(piece)
                    else:
                        # 有的中转对 stream:true 不做处理，直接回一份完整 JSON。
                        # 内容在 choices[0].message.content，当"一口气吐完的流"下发。
                        raw_body = r.read(MAX_REPLY)
                        try:
                            obj = json.loads(raw_body)
                        except ValueError:
                            obj = {}
                        err = obj.get("error")
                        if isinstance(err, dict):
                            raise RuntimeError(
                                f"模型返回错误：{err.get('message') or err}")
                        text = str(obj.get("choices", [{}])[0]
                                   .get("message", {}).get("content") or "")
                        if text:
                            got = True
                            yield text
                return
            except security.SecurityError as e:
                msg = str(e)
                if "HTTP 4" in msg:
                    # 服务端多半不支持 stream 参数（有的中转会 400/404）。
                    # 退回非流式把整段拿回来，效果上等于"一口气吐完的流"。
                    logger.warning("LLM 流式被拒（%s），退回非流式", msg)
                    text, _ = self.chat_messages_full(messages, temperature,
                                                      max_tokens, json_mode)
                    if text:
                        yield text
                    return
                last_err = e
            except (OSError, urllib.error.URLError) as e:
                last_err = e
            if got:
                # 已经吐过内容了，再重试会把同一段话发两遍
                raise RuntimeError(f"流式输出中断：{last_err}")
            logger.warning("LLM 流式第 %s 次失败：%s", attempt + 1, last_err)
        raise RuntimeError(f"LLM 流式请求失败：{last_err}")

    def ping(self) -> str:
        """连通性自检：让模型回一个 JSON 探针，验证地址/密钥/模型三项都对。"""
        r = self.chat("只返回 JSON，不要任何解释。",
                      '{"task": "connectivity check", "reply": "pong"}')
        return str(r.get("reply", "")) or "ok"


def field_so_far(raw: str, field: str) -> str:
    """半截 JSON 里把 field 字段的字符串值「到目前为止」的部分抠出来。

    流式时模型一个字一个字往外吐，整段 JSON 还没闭合，json.loads 解不了。
    这里不做完整解析，只做状态机扫描：找到 "field" 这个键，越过冒号，
    从值的开头引号一路读到当前文本末尾（或值结束的引号），把已经吐出来的
    部分还原出来。转义序列按 JSON 规则解开，没写完的尾部转义先不吐。
    解析不动就返回空串，调用方只是少显示几个字，不影响最终结果。

    agent（thought/final）和环境方案（component/reason 等）的实时展示都靠它。
    """
    i = raw.find(f'"{field}"')
    if i < 0:
        return ""
    i += len(field) + 2
    while i < len(raw) and (raw[i].isspace() or raw[i] == ":"):
        i += 1
    if i >= len(raw) or raw[i] != '"':
        return ""
    i += 1
    out: list[str] = []
    mapping = {'"': '"', "\\": "\\", "/": "/", "n": "\n", "t": "\t",
               "r": "\r", "b": "\b", "f": "\f"}
    while i < len(raw):
        ch = raw[i]
        if ch == "\\":
            if i + 1 >= len(raw):       # 尾部转义没写完，等下一片
                break
            nxt = raw[i + 1]
            if nxt in mapping:
                out.append(mapping[nxt])
                i += 2
                continue
            if nxt == "u":
                if i + 6 > len(raw):    # \uXXXX 不完整，等下一片
                    break
                try:
                    out.append(chr(int(raw[i + 2:i + 6], 16)))
                except ValueError:
                    pass
                i += 6
                continue
            break                       # 不认识的转义，到此为止
        if ch == '"':
            break                       # 值结束
        out.append(ch)
        i += 1
    return "".join(out)


def get_llm() -> LLM:
    return LLM()
