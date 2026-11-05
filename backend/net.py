"""net.py —— 出站 HTTP 的统一出口

之前 crawler.py 与 nuclei_tpl.py 各写了一份 _with_deadline / _http_get，
两边的超时、重试、错误语义都不一样，改一处忘另一处是迟早的事。
这里收敛成一处，三个模块都走它：

  with_deadline(fn, timeout, retry)   硬死线（线程 + join），可选重试
  http_get(url, ...)                  取字节，统一走 security.open_url
  http_get_text(url, ...)             取文本（UTF-8，坏字节替换）
  http_json(url, ...)                 取 JSON，可带 Bearer Token

出站请求一律经 security.open_url —— 它负责拦内网地址与云元数据地址、
逐跳复检重定向、限制响应体大小、核对实际对端 IP。本模块只管超时与重试。
"""
from __future__ import annotations

import json
import logging
import os
import threading

import security

logger = logging.getLogger("ai_bobao.net")

UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/130.0.0.0"

# GitHub 的匿名 API 配额很低，带了 Token 能省不少限流。
_GITHUB_TOKEN_ENV = "GITHUB_TOKEN"


def with_deadline(fn, timeout: float = 30.0, retry: int = 0):
    """硬死线包装：网络调用卡死不能拖垮流水线。

    超时是真超时 —— 线程还活着就直接放弃它，调用方拿到 TimeoutError，
    不会等到那个卡死的调用自己结束。retry>0 时每次尝试各给一份 timeout。
    """
    for attempt in range(retry + 1):
        box: dict = {}

        def run(box=box):     # box 用默认参数绑死，免得闭包捕获到下一轮的 box
            try:
                box["data"] = fn()
            except Exception as e:  # noqa: BLE001
                box["err"] = e

        t = threading.Thread(target=run, daemon=True)
        t.start()
        t.join(timeout)
        if t.is_alive():
            err: Exception = TimeoutError(f"超过 {timeout}s 未完成")
        elif "err" in box:
            err = box["err"]
        else:
            return box["data"]
        if attempt >= retry:
            raise err
        logger.warning("%r，%d/%d 次重试", err, attempt + 1, retry)
    raise RuntimeError("unreachable")


def http_get(
    url: str,
    timeout: float = 20.0,
    max_bytes: int = security.MAX_DOWNLOAD,
    headers: dict | None = None,
) -> bytes:
    """取一个 URL 的字节内容。内网地址和超大响应都拿不到。"""
    hdrs = {"User-Agent": UA, "Accept": "*/*"}
    hdrs.update(headers or {})
    return security.open_url(url, timeout=timeout, max_bytes=max_bytes, headers=hdrs)


def http_get_text(
    url: str,
    timeout: float = 20.0,
    max_bytes: int = security.MAX_DOWNLOAD,
    headers: dict | None = None,
) -> str:
    """取一个 URL 的文本内容。坏字节按替换处理，不抛异常。"""
    return http_get(url, timeout=timeout, max_bytes=max_bytes,
                    headers=headers).decode("utf-8", "replace")


def http_json(
    url: str,
    timeout: float = 20.0,
    max_bytes: int = security.MAX_DOWNLOAD,
    headers: dict | None = None,
    token: str = "",
) -> dict:
    """取一个 JSON 接口。token 非空时按 Bearer 带上。"""
    hdrs = {"User-Agent": UA, "Accept": "application/json"}
    if token:
        hdrs["Authorization"] = f"Bearer {token}"
    hdrs.update(headers or {})
    raw = security.open_url(url, timeout=timeout, max_bytes=max_bytes, headers=hdrs)
    return json.loads(raw)


def github_json(url: str, timeout: float = 20.0, max_bytes: int = security.MAX_DOWNLOAD) -> dict:
    """取 GitHub API 的 JSON。环境变量里设了 GITHUB_TOKEN 就自动带上。"""
    token = os.getenv(_GITHUB_TOKEN_ENV, "")
    hdrs = {"Accept": "application/vnd.github+json"}
    return http_json(url, timeout=timeout, max_bytes=max_bytes, headers=hdrs, token=token)
