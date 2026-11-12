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

    def _post_chat(self, endpoint: str, body: bytes) -> bytes:
        """发对话请求，瞬时错误（限流/5xx/网络抖动）自动重试两次。

        服务商偶发 500/429 是家常便饭（本家刚见过：ModelScope 限流 429、
        nccsec 网关 500），直接把异常甩给上层，用户看到的就是「LLM 不可用」。
        这种抖动值得在底层消掉：2s、4s 退避重试，确定性错误照样立刻抛。
        """
        err: Exception | None = None
        for attempt in range(3):
            if attempt:
                time.sleep(2 * attempt)
            try:
                return security.open_url(
                    endpoint,
                    timeout=config.get("llm", "timeout"),
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

    def chat(self, system: str, user: str) -> dict:
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
        raw = self._post_chat(endpoint, body)
        content = json.loads(raw)["choices"][0]["message"]["content"]
        return json.loads(content)

    def chat_messages(self, messages: list[dict]) -> str:
        """多轮对话版：agent 用。整份 messages 原样发出，回原文不解析——
        agent 里的回复要么是协议 JSON、要么要当裸文本兜底，解析交给调用方。"""
        text, _ = self.chat_messages_full(messages)
        return text

    def chat_messages_full(self, messages: list[dict],
                           temperature: float | None = None,
                           max_tokens: int | None = None) -> tuple[str, dict]:
        """多轮对话版，同时回传「实际发出去的请求体」，方便前端展示。

        temperature 为 None 就不带这个字段，max_tokens 不是正整数也不带，
        跟不传时用的是模型端的同一套默认值。
        """
        endpoint = f"{self.base}/v1/chat/completions"
        security.check_url(endpoint)

        payload = {
            "model": self.model,
            # 复制一份列表：调用方后面还会往原 messages 里追加内容，
            # 这里要留住"发出那一刻"的原样
            "messages": list(messages),
            "response_format": {"type": "json_object"},
        }
        if temperature is not None:
            payload["temperature"] = temperature
        if isinstance(max_tokens, int) and max_tokens > 0:
            payload["max_tokens"] = max_tokens

        body = json.dumps(payload).encode()
        raw = self._post_chat(endpoint, body)
        return str(json.loads(raw)["choices"][0]["message"]["content"] or ""), payload

    def ping(self) -> str:
        """连通性自检：让模型回一个 JSON 探针，验证地址/密钥/模型三项都对。"""
        r = self.chat("只返回 JSON，不要任何解释。",
                      '{"task": "connectivity check", "reply": "pong"}')
        return str(r.get("reply", "")) or "ok"


def get_llm() -> LLM:
    return LLM()
