"""llm.py —— OpenAI 兼容 LLM 客户端（stdlib 实现）

配置每次调用现读 config.yaml，所以设置页改完立即生效，不用重启。
"""
import json
import urllib.request

import config

# 有些中转站前面挂了 Cloudflare，按 UA 拦非浏览器客户端（Python-urllib 直接 403
# "error code: 1010"）。带上一个常规 UA 就通了，跟 openai 官方 SDK 的做法一样。
_UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 " \
      "(KHTML, like Gecko) Chrome/122.0 Safari/537.36"


class LLM:
    available = True

    def __init__(self, base: str = "", key: str = "", model: str = ""):
        self.base = (base or config.get("llm", "base")).rstrip("/")
        self.key = key or config.get("llm", "key")
        self.model = model or config.get("llm", "model")

    def chat(self, system: str, user: str) -> dict:
        body = json.dumps({
            "model": self.model,
            "messages": [{"role": "system", "content": system},
                         {"role": "user", "content": user}],
            "response_format": {"type": "json_object"},
        }).encode()
        req = urllib.request.Request(
            f"{self.base}/v1/chat/completions", data=body,
            headers={"Content-Type": "application/json",
                     "User-Agent": _UA,
                     "Authorization": f"Bearer {self.key}"})
        with urllib.request.urlopen(req, timeout=config.get("llm", "timeout")) as r:
            content = json.loads(r.read())["choices"][0]["message"]["content"]
        return json.loads(content)

    def ping(self) -> str:
        """连通性自检：让模型回一个 JSON 探针，验证地址/密钥/模型三项都对。"""
        r = self.chat("只返回 JSON，不要任何解释。",
                      '{"task": "connectivity check", "reply": "pong"}')
        return str(r.get("reply", "")) or "ok"


def get_llm() -> LLM:
    return LLM()
