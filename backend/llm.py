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

import config
import security

logger = logging.getLogger("ai_bobao.llm")

# 有些中转站前面挂了 Cloudflare，按 UA 拦非浏览器客户端（Python-urllib 直接 403
# "error code: 1010"）。带上一个常规 UA 就通了，跟 openai 官方 SDK 的做法一样。
_UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 " \
      "(KHTML, like Gecko) Chrome/122.0 Safari/537.36"

MAX_REPLY = 4 * 1024 * 1024      # 模型回复上限 4MB


class LLM:
    available = True

    def __init__(self, base: str = "", key: str = "", model: str = ""):
        self.base = (base or config.get("llm", "base")).rstrip("/")
        self.key = key or config.get("llm", "key")
        self.model = model or config.get("llm", "model")

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
        raw = security.open_url(
            endpoint,
            timeout=config.get("llm", "timeout"),
            max_bytes=MAX_REPLY,
            method="POST",
            data=body,
            headers={"Content-Type": "application/json",
                     "User-Agent": _UA,
                     "Authorization": f"Bearer {self.key}"},
        )
        content = json.loads(raw)["choices"][0]["message"]["content"]
        return json.loads(content)

    def chat_messages(self, messages: list[dict]) -> str:
        """多轮对话版：agent 用。整份 messages 原样发出，回原文不解析——
        agent 里的回复要么是协议 JSON、要么要当裸文本兜底，解析交给调用方。"""
        endpoint = f"{self.base}/v1/chat/completions"
        security.check_url(endpoint)

        body = json.dumps({
            "model": self.model,
            "messages": messages,
            "response_format": {"type": "json_object"},
        }).encode()
        raw = security.open_url(
            endpoint,
            timeout=config.get("llm", "timeout"),
            max_bytes=MAX_REPLY,
            method="POST",
            data=body,
            headers={"Content-Type": "application/json",
                     "User-Agent": _UA,
                     "Authorization": f"Bearer {self.key}"},
        )
        return str(json.loads(raw)["choices"][0]["message"]["content"] or "")

    def ping(self) -> str:
        """连通性自检：让模型回一个 JSON 探针，验证地址/密钥/模型三项都对。"""
        r = self.chat("只返回 JSON，不要任何解释。",
                      '{"task": "connectivity check", "reply": "pong"}')
        return str(r.get("reply", "")) or "ok"


def get_llm() -> LLM:
    return LLM()
