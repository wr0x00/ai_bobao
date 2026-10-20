"""nuclei_tpl.py —— nuclei 模板的双向通道

两条方向：

1. 拉（import）：把 nuclei 模板（本地模板库 / 远程 GitHub）解析成统一 dict，
   字段结构对齐 analyzer 流水线，source="nuclei" 直接入库。
   - 本地：递归扫目录，yaml.safe_load 真解析（workflow 只取元信息）
   - 远程：GitHub API 拉目录树 + 按需拉 raw，磁盘缓存

2. 转（export）：把漏洞的原理/影响/PoC 转成 nuclei 模板 YAML。
   - 结构化字段（id/severity/tags/path/matcher）优先用 LLM 抽
   - 抽不到的用启发式兜底（从 PoC 里正则捞 path、匹配关键词）
   - 最后过一遍 schema 校验，不合法就不落盘（宁可没有也别给错模板）

导出只产出"只读探测"型模板：GET/HEAD 或明确无害的 POST。带 body 的写操作
模板默认拒绝，除非显式 allow_write=True —— 生成的模板会被人拿去跑，
写操作模板的破坏性必须由使用者显式承担。
"""
from __future__ import annotations

import base64
import hashlib
import json
import logging
import os
import re
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path

import yaml

import security

logger = logging.getLogger("ai_bobao.nuclei_tpl")

_UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/130.0.0.0"

SEVERITIES = ["info", "low", "medium", "high", "critical"]
_CVSS_BANDS = [(9.0, "critical"), (7.0, "high"), (4.0, "medium"), (0.1, "low"), (0.0, "info")]
_INDEX_TTL = 6 * 3600          # 远程索引缓存时长（秒）
MAX_TREE = 32 * 1024 * 1024    # GitHub 文件树响应上限 32MB
MAX_TPL = 2 * 1024 * 1024      # 单个模板响应上限 2MB

# 仓库名与分支名的白名单放在 security.py（config.py、nuclei_sync.py 也要用），
# 这里直接转出去，省得三处各写一份、日后改形状时漏掉一处。
REPO_RE = security.REPO_RE
REF_RE = security.REF_RE
valid_repo = security.valid_repo
valid_ref = security.valid_ref

# 写操作路径特征 —— 命中就要求显式 allow_write
_WRITE_HINT = re.compile(
    r"(?i)(?:\bpost\b|\bput\b|\bpatch\b|\bdelete\b|\baction\b|/upload|/create|/add|"
    r"/new\b|/insert|/register|/signup|/login\b|/logout\b|/invite|/reset|"
    r"/admin|/import|/exec|/eval|/run\b|/generate|/send|/publish|/update|/drop)"
)

# PoC 里捞探测路径：url 变量、path 拼接、requests 调用行
_PATH_PATTERNS = [
    re.compile(r"""["'](https?://[^"'/\s]+)((?:/[^"'\s]*)+)["']"""),
    re.compile(r"""["'](\{\{?BaseURL\}?(?:/[^"'\s]*)+)["']"""),
    re.compile(r"""url\s*=\s*[^"'\n]*["'](/[^"'\s]{2,})["']"""),
    re.compile(r"""(?:GET|POST|PUT|DELETE|PATCH|HEAD)\s+(\/\S{2,})"""),
    re.compile(r"""/api/[A-Za-z0-9_./{}-]{2,}"""),
    re.compile(r"""/(?:admin|actuator|console|manager|phpmyadmin|wp-admin|debug|metrics|config)(?:/\S*)?"""),
]
# 抓取正文里的 HTML 实体残留（&lt; &gt; &amp; &#39; …），路径里出现就是没剥干净
_ENT_RE = re.compile(r"&(?:#x[0-9a-fA-F]{2}|#\d{2,3}|[a-zA-Z]{2,6});")
_ENT_MAP = {"lt": "<", "gt": ">", "amp": "&", "quot": '"', "apos": "'", "nbsp": " ",
            "sol": "/", "period": ".", "comma": ",", "semi": ";", "#39": "'", "#47": "/"}


def _ent_unmatch(m: re.Match) -> str:
    body = m.group(0)[1:-1]
    if body in _ENT_MAP:
        return _ENT_MAP[body]
    if body.startswith("#x") or body.startswith("#"):
        try:
            return chr(int(body[2:] if body.startswith("#x") else body[1:], 16 if body.startswith("#x") else 10))
        except ValueError:
            return m.group(0)
    return m.group(0)


_METHOD_RE = re.compile(r"""(?i)\b(method\s*=\s*["'](get|post|put|patch|delete|head)["'])""")
# 从 PoC 提取"判定依据"关键词：出现在判断/断言里的字符串
_EVIDENCE_RE = re.compile(
    r"""(?i)(?:assert|if)\s*[^\n]*?["']([A-Za-z0-9_./{}\-: ]{4,60})["']|"""
    r"""["']([0-9]{3})["']\s*==|"""
    r"""(?:status_code|status)\s*==\s*(\d{3})"""
)


def _with_deadline(fn, timeout: float = 30.0, retry: int = 0):
    """硬死线包装：网络调用卡死不能拖垮流水线。retry>0 时每次尝试各给一份 timeout。"""
    for attempt in range(retry + 1):
        box: dict = {}

        def run():
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


def _http_get(url: str, timeout: float = 20.0, raw: bool = True, max_bytes: int = MAX_TPL):
    """取一个 URL 的内容。走安全网关，内网地址和超大响应都拿不到。"""
    body = security.open_url(
        url,
        timeout=timeout,
        max_bytes=max_bytes,
        headers={"User-Agent": _UA, "Accept": "*/*"},
    )
    return body if raw else body.decode("utf-8", "replace")


def _http_json(url: str, timeout: float = 20.0, max_bytes: int = MAX_TREE) -> dict:
    """取一个 JSON 接口。GitHub Token 存在环境变量里，设了就带上，能省不少限流配额。"""
    token = os.getenv("GITHUB_TOKEN", "")
    headers = {"User-Agent": _UA, "Accept": "application/vnd.github+json"}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    raw = security.open_url(url, timeout=timeout, max_bytes=max_bytes, headers=headers)
    return json.loads(raw)


def _slug(text: str, fallback: str = "ai-bobao-vuln") -> str:
    """nuclei id 规范：小写字母数字与连字符。"""
    s = re.sub(r"[^A-Za-z0-9]+", "-", text or "").strip("-").lower()
    s = re.sub(r"-{2,}", "-", s)
    return s[:80] or fallback


def severity_from_cvss(cvss) -> str:
    try:
        v = float(cvss)
    except (TypeError, ValueError):
        return "unknown"
    for lo, name in _CVSS_BANDS:
        if v >= lo:
            return name
    return "info"


# ══════════════════════════════════════════════════════════ 拉：模板 → dict
# 模板元信息
@dataclass
class TplRef:
    id: str
    name: str
    severity: str
    description: str = ""
    tags: list[str] = field(default_factory=list)
    refs: list[str] = field(default_factory=list)
    cvss: float | None = None
    path: str = ""              # 本地文件相对路径 / 远程仓库内路径
    source: str = "nuclei"
    extra: dict = field(default_factory=dict)   # 协议/作者/raw 模板文本


def _as_list(v) -> list[str]:
    if v is None:
        return []
    if isinstance(v, str):
        return [s.strip() for s in v.split(",") if s.strip()]
    if isinstance(v, (list, tuple)):
        return [str(s).strip() for s in v if str(s).strip()]
    return [str(v)]


def _extract_cvss(info: dict):
    """CVSS 分数。模板里两个位置都放过：classification 下是官方的，
    少数老模板塞在 metadata 下，都找一下。"""
    for block in (info.get("classification"), info.get("metadata")):
        if isinstance(block, dict) and block.get("cvss-score") is not None:
            return block["cvss-score"]
    return None


def parse_template(doc: dict, path: str = "") -> TplRef | None:
    """从已 load 的 YAML 抽元信息。workflow/非 http 模板只取能用的部分。"""
    if not isinstance(doc, dict) or not doc.get("id"):
        return None
    info = doc.get("info") or {}
    if not isinstance(info, dict):
        info = {}
    tags = _as_list(info.get("tags")) or _as_list(doc.get("tags"))
    severity = str(info.get("severity") or doc.get("severity") or "unknown").lower()
    if severity not in SEVERITIES:
        severity = "unknown"
    authors = _as_list(info.get("author"))
    protos = [k for k in ("http", "dns", "tcp", "network", "file", "headless",
                          "ssl", "websocket", "whois", "javascript", "code")
              if k in doc]
    return TplRef(
        id=str(doc["id"]),
        name=str(info.get("name") or doc["id"]),
        severity=severity,
        description=(str(info.get("description") or "")[:600]),
        tags=tags,
        refs=_as_list(info.get("reference")),
        cvss=_extract_cvss(info),
        path=path,
        extra={"authors": authors, "protocols": protos,
               "author": ", ".join(authors), "raw": yaml.safe_dump(doc, allow_unicode=True)},
    )


def load_local_templates(root: Path, limit: int = 0, include_tests: bool = False) -> list[TplRef]:
    """递归扫本地模板目录。默认跳过 Go 仓库自带的测试模板（无 id 的 workflow 等）。"""
    if not root.exists():
        return []
    out: list[TplRef] = []
    for f in sorted(root.rglob("*.yaml")):
        rel = f.relative_to(root).as_posix()      # 统一成 /，Windows 下才是 /tests/ 而不是 \tests\
        low = rel.lower()
        if not include_tests and (
            "/tests/" in low or "/testdata/" in low or "/testcases/" in low
            or low.startswith("tests/") or "/helm/" in low or low.startswith("helm/")
            or low.startswith(".github/") or "/.github/" in low
        ):
            continue
        try:
            doc = yaml.safe_load(f.read_text(encoding="utf-8", errors="replace"))
        except Exception:      # 模板语法错误/自定义标签，跳过
            continue
        tpl = parse_template(doc, rel)
        if tpl:
            out.append(tpl)
        if limit and len(out) >= limit:
            break
    return out


def fetch_remote_index(repo: str, ref: str = "main", timeout: float = 120.0) -> list[str]:
    """GitHub API 拉模板仓库文件树（只拿路径，不下内容）。

    nuclei-templates 有 1.5 万个节点，未认证时这接口要 80s+，所以默认超时给足；
    设 GITHUB_TOKEN 环境变量可显著提速。结果会被 fetch_remote_templates 缓存 6 小时。
    响应有 2MB+，网关偶发中途截断，重死线放在每次尝试内部（整体再包一层就误杀重试了）。

    repo 和 ref 会被拼进 GitHub 的 URL，形状不合法直接拒 —— config.yaml
    可能被人手改过，光靠设置页的校验不够。
    """
    if not valid_repo(repo):
        raise ValueError(f"仓库名不合法：{repo}")
    if not valid_ref(ref):
        raise ValueError(f"分支名不合法：{ref}")
    url = f"https://api.github.com/repos/{repo}/git/trees/{ref}?recursive=1"
    data = _with_deadline(lambda: _http_json(url, timeout), timeout + 30, retry=2)
    if data.get("truncated"):
        logger.warning("文件树被 GitHub 截断，结果不完整")
    paths = []
    for node in data.get("tree", []):
        p = node.get("path", "")
        if node.get("type") == "blob" and p.endswith((".yaml", ".yml")) and not p.startswith("."):
            paths.append(p)
    return paths


_RAW_OK = True          # raw 域名探测结果：首次 502 后置 False，后续直接走 contents


def _fetch_text(repo: str, path: str, ref: str, timeout: float) -> str:
    """取模板原文。raw.githubusercontent.com 在部分网络下被网关拦（502），
    这时回落到 api.github.com 的 contents 接口（base64），所以做双通道。"""
    global _RAW_OK
    if _RAW_OK:
        try:
            url = f"https://raw.githubusercontent.com/{repo}/{ref}/{path}"
            return _with_deadline(lambda: _http_get(url, timeout).decode("utf-8", "replace"), timeout + 5)
        except Exception:  # noqa: BLE001
            _RAW_OK = False
    api = f"https://api.github.com/repos/{repo}/contents/{path}?ref={ref}"
    data = _with_deadline(lambda: _http_json(api, timeout), timeout + 5)
    return base64.b64decode(data["content"]).decode("utf-8", "replace")


def fetch_remote_template(repo: str, path: str, ref: str = "main",
                          cache_dir: Path | None = None, timeout: float = 30.0) -> dict | None:
    """拉单个模板原文并 parse。命中磁盘缓存则不重复走网络。"""
    cache_key = hashlib.sha1(f"{repo}/{ref}/{path}".encode()).hexdigest()[:16]
    cache_f = (cache_dir / f"{cache_key}.json") if cache_dir else None
    if cache_f and cache_f.is_file():
        try:
            return json.loads(cache_f.read_text(encoding="utf-8"))
        except Exception:
            pass
    doc = yaml.safe_load(_fetch_text(repo, path, ref, timeout))
    if not isinstance(doc, dict):
        return None
    if cache_f:
        cache_f.parent.mkdir(parents=True, exist_ok=True)
        cache_f.write_text(json.dumps(doc, ensure_ascii=False), encoding="utf-8")
    return doc


def _spread(paths: list[str], limit: int) -> list[str]:
    """按二级目录轮转取样，避免 limit 条全落在同一个分类里（否则拉回来的都是 cloud/）。"""
    buckets: dict[str, list[str]] = {}
    for p in paths:
        key = "/".join(p.lower().split("/")[:2])
        buckets.setdefault(key, []).append(p)
    out = []
    while len(out) < limit and any(buckets.values()):
        for key in sorted(buckets):
            if buckets[key] and len(out) < limit:
                out.append(buckets[key].pop(0))
    return out


def fetch_remote_templates(repo: str, ref: str = "main", limit: int = 30,
                          severity: str = "", tag: str = "",
                          cache_dir: Path | None = None) -> list[TplRef]:
    """按需拉远程模板：先索引过滤，再逐个下 raw。索引本身也缓存 6 小时。

    severity 只能下完模板按 info.severity 精确筛（仓库目录不按严重性分），
    所以按 severity 拉时候选池放大到 limit*5。

    repo 和 ref 会被拼进 GitHub 的 URL，形状不合法直接拒 —— config.yaml
    可能被人手改过，光靠设置页的校验不够。
    """
    if not valid_repo(repo):
        raise ValueError(f"仓库名不合法：{repo}")
    if not valid_ref(ref):
        raise ValueError(f"分支名不合法：{ref}")
    idx_f = (cache_dir / "_index.json") if cache_dir else None
    paths: list[str] = []
    if idx_f and idx_f.is_file():
        try:
            blob = json.loads(idx_f.read_text(encoding="utf-8"))
            fresh = (time.time() - idx_f.stat().st_mtime) < _INDEX_TTL
            if fresh and blob.get("repo") == repo and blob.get("ref") == ref and blob.get("paths"):
                paths = blob["paths"]
        except Exception:
            paths = []
    if not paths:
        paths = fetch_remote_index(repo, ref)
        if idx_f:
            idx_f.parent.mkdir(parents=True, exist_ok=True)
            idx_f.write_text(json.dumps({"repo": repo, "ref": ref, "paths": paths},
                                        ensure_ascii=False), encoding="utf-8")
    paths = [p for p in paths if not p.lower().startswith(("helpers/", "workflows/"))]
    if tag:
        paths = [p for p in paths if tag.lower() in p.lower()]
        pick = paths[:limit]
    else:
        pick = _spread(paths, limit * 5 if severity else limit)
    out: list[TplRef] = []
    for p in pick:
        if len(out) >= limit:
            break
        try:
            doc = fetch_remote_template(repo, p, ref, cache_dir)
        except Exception as e:  # noqa: BLE001
            logger.warning("拉取失败 %s：%r", p, e)
            continue
        tpl = parse_template(doc, p) if doc else None
        if tpl and (not severity or tpl.severity == severity.lower()):
            tpl.source = f"nuclei-remote:{repo}"
            out.append(tpl)
    return out


def tpl_to_item(tpl: TplRef) -> dict:
    """TplRef → analyzer 流水线用的统一条目。"""
    return {"id": f"nuclei-{_slug(tpl.id)}",
            "title": tpl.name,
            "source": tpl.source,
            "summary": tpl.description or tpl.name,
            "refs": (tpl.refs or []) + ([f"https://github.com/projectdiscovery/nuclei-templates/blob/main/{tpl.path}"]
                                        if tpl.path else []),
            "cvss": tpl.cvss,
            "published": "",
            "link": "",
            "_nuclei": tpl}          # 内部字段：analyzer 识别后直接用现成模板，不走生成


# ══════════════════════════════════════════════════════════ 转：漏洞 → 模板
_SYS_SPEC = (
    "你是 nuclei 模板编写助手。把给定漏洞情报转成 nuclei v3 模板的**结构化字段**，"
    "只返回 JSON，不要输出 YAML，不要写解释。字段：\n"
    '{"id":"英文小写连字符id","name":"中文漏洞名","severity":"info|low|medium|high|critical",'
    '"tags":["tag1"],"description":"中文描述","references":["https://..."],'
    '"http":[{"method":"GET","path":["{{BaseURL}}/xxx"],"headers":{},"body":"",'
    '"matchers":[{"type":"word|status|regex|dsl","part":"body|header|all","words":["..."],'
    '"condition":"and|or"}],"attack":"none"}]}\n'
    "规则：1) path 必须以 {{BaseURL}} 开头，用真实接口路径；"
    "2) 优先只读方法（GET/HEAD），POST 仅当漏洞本身无副作用时用；"
    "3) matchers 必须可判定漏洞是否命中，不要写恒真条件；"
    "4) 没有把握的字段就给空，不要编造。内容仅用于防御研究与授权测试。"
)


def _norm_path(raw: str) -> str:
    """把捞出来的原始路径收拾成 nuclei 能用的 path：剥 host、剥尾随引号/标点。"""
    p = (raw or "").strip()
    p = _ENT_RE.sub(_ent_unmatch, p)      # 先还原实体：&lt; 的尾巴是 ;，被 strip 掉就认不出了
    p = p.strip("\"'`,;)]}")
    p = p.split("#", 1)[0].split("?", 1)[0]
    p = re.sub(r"^https?://[^/]+", "", p)          # 去掉 scheme://host，只留路径
    p = re.sub(r"^\{\{?BaseURL\}?\}?", "", p, flags=re.I)
    p = p.rstrip("\"'`)]},; ")
    if not p:
        return ""
    if not p.startswith("/"):
        p = "/" + p
    # 截断到只剩零散标点的残段（"/." "/," "/-"）没有探测价值
    seg = p.rsplit("/", 1)[-1]
    if not re.search(r"[A-Za-z0-9]", seg):
        return ""
    if seg.count(".") == 1:          # 句号残留（"/api/jwt_login."），有扩展名的文件名不动
        p = p[: p.rfind(".")]
        if not p.rsplit("/", 1)[-1]:
            return ""
    return p if len(p) > 1 else ""


def _heuristic_spec(meta: dict, poc: str) -> dict:
    """LLM 不可用/抽不出时的启发式兜底：从 PoC 文本里捞证据。"""
    sev = severity_from_cvss(meta.get("cvss"))
    if sev == "unknown":
        sev = "medium"
    paths, seen = [], set()
    for pat in _PATH_PATTERNS:
        for m in pat.finditer(poc or ""):
            p = _norm_path(m.group(1) if m.lastindex else m.group(0))
            if p and p not in seen:
                seen.add(p)
                paths.append(p)
            if len(paths) >= 8:
                break
        if len(paths) >= 8:
            break
    words: list[str] = []
    for m in _EVIDENCE_RE.finditer(poc or ""):
        w = next((g for g in m.groups() if g), "")
        if w and w not in words:
            words.append(w)
        if len(words) >= 6:
            break
    method = "GET"
    mm = _METHOD_RE.search(poc or "")
    if mm and mm.group(1).lower() != "head":
        method = mm.group(1).upper()
    http = []
    # 长路径优先：PoC 里完整 URL 最可能有信息量，裸的 /config 之类太泛
    ranked = sorted(dict.fromkeys(paths), key=len, reverse=True)[:3] or ["{{BaseURL}}"]
    for p in ranked:
        full = p if p.startswith("{{") else "{{BaseURL}}" + p
        http.append({"method": method, "path": [full],
                     "matchers": [{"type": "word", "part": "body", "words": words, "condition": "or"}]
                                 if words else [{"type": "status", "status": [200]}]})
    return {"id": _slug(meta.get("id", "")), "name": meta.get("name") or meta.get("id", ""),
            "severity": sev, "tags": [], "description": meta.get("summary", "")[:300],
            "references": meta.get("refs", [])[:5], "http": http}


def _clean_spec(spec: dict, meta: dict) -> dict:
    """规整 LLM 产出：补缺字段、压类型、砍非法项。"""
    sev = str(spec.get("severity", "")).lower()
    if sev not in SEVERITIES:
        sev = severity_from_cvss(meta.get("cvss"))
    http = []
    for req in (spec.get("http") or [])[:5]:
        if not isinstance(req, dict):
            continue
        paths = req.get("path") or req.get("paths") or []
        if isinstance(paths, str):
            paths = [paths]
        paths = [p for p in paths if isinstance(p, str) and p.strip()][:5]
        for p in paths:
            if not p.startswith("{{BaseURL}}"):
                p = p if p.startswith("/") else "/" + p
                p = "{{BaseURL}}" + p
        if not paths:
            continue
        method = str(req.get("method", "GET")).upper()
        if method not in ("GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"):
            method = "GET"
        ms = []
        for mt in (req.get("matchers") or [])[:4]:
            if not isinstance(mt, dict) or not mt.get("type"):
                continue
            m = {"type": str(mt["type"]),
                 "condition": "and" if str(mt.get("condition", "and")) == "and" else "or"}
            if m["type"] in ("word", "regex"):
                w = mt.get("words") or []
                if isinstance(w, str):
                    w = [w]
                w = [str(x) for x in w if str(x).strip()][:10]
                if not w:
                    continue
                m["words"] = w
                m["part"] = str(mt.get("part", "body"))   # part 只对 word/regex 有意义
                m["negative"] = bool(mt.get("negative", False))
            elif m["type"] == "status":
                s = mt.get("status") or []
                if isinstance(s, (str, int)):
                    s = [s]
                s = [int(x) for x in s if str(x).isdigit()][:5]
                if not s:
                    continue
                m["status"] = s
            elif m["type"] == "dsl":
                d = mt.get("dsl")
                if isinstance(d, list):
                    d = " && ".join(str(x) for x in d if str(x).strip())
                if not isinstance(d, str) or not d.strip():
                    continue
                m["dsl"] = d[:500]
            else:
                continue
            ms.append(m)
        if not ms:
            continue
        item = {"method": method, "path": paths, "matchers": ms}
        if req.get("headers") and isinstance(req["headers"], dict):
            h = {str(k): str(v) for k, v in list(req["headers"].items())[:10] if v is not None}
            if h:
                item["headers"] = h
        if req.get("body") and isinstance(req["body"], (str, dict)):
            body = req["body"]
            item["body"] = json.dumps(body, ensure_ascii=False) if isinstance(body, dict) else str(body)[:2000]
        # 标上 attack: none，告诉 nuclei 这是只读探测模板，不会真的去改目标。
        # 不标的话 nuclei 会按普通攻击模板跑，GET 探测也会被当成要执行的漏洞利用。
        item["attack"] = "none"
        http.append(item)
    return {"id": _slug(spec.get("id") or meta.get("id", "")),
            "name": str(spec.get("name") or meta.get("name") or meta.get("id", ""))[:120],
            "severity": sev,
            "tags": _as_list(spec.get("tags"))[:8],
            "description": str(spec.get("description") or meta.get("summary", ""))[:600],
            "references": _as_list(spec.get("references"))[:8] or _as_list(meta.get("refs"))[:8],
            "http": http}


def spec_to_yaml(spec: dict, author: str = "ai-bobao") -> str:
    """结构化 spec → nuclei 模板 YAML 文本。"""
    info: dict = {"name": spec["name"], "author": author, "severity": spec["severity"]}
    if spec.get("description"):
        info["description"] = spec["description"]
    if spec.get("tags"):
        info["tags"] = ",".join(spec["tags"])
    if spec.get("references"):
        info["reference"] = spec["references"]
    doc = {"id": spec["id"], "info": info, "http": spec["http"]}
    return yaml.safe_dump(doc, allow_unicode=True, sort_keys=False, width=400)


def validate_yaml(text: str) -> tuple[bool, str]:
    """落盘前自检：能 load、有 id、至少一条带 matcher 的请求。"""
    try:
        doc = yaml.safe_load(text)
    except Exception as e:  # noqa: BLE001
        return False, f"YAML 解析失败: {e}"
    if not isinstance(doc, dict) or not doc.get("id"):
        return False, "缺少 id"
    if not re.fullmatch(r"[a-z0-9\-]+", str(doc["id"])):
        return False, f"id 非法（只允许小写字母数字和连字符）: {doc['id']}"
    info = doc.get("info") or {}
    if str(info.get("severity", "")).lower() not in SEVERITIES:
        return False, "severity 非法"
    http = doc.get("http")
    if not isinstance(http, list) or not http:
        return False, "缺少 http 请求"
    for req in http:
        if not req.get("path") or not req.get("matchers"):
            return False, "存在缺少 path 或 matchers 的请求"
    return True, ""


def is_write_risk(spec: dict) -> bool:
    """模板是否含写操作（生成出来给人跑，必须标风险）。"""
    for req in spec.get("http", []):
        if req.get("method", "GET") not in ("GET", "HEAD", "OPTIONS"):
            return True
        for p in req.get("path", []):
            if _WRITE_HINT.search(str(p)):
                return True
    return False


def vuln_to_spec(meta: dict, poc: str, llm=None) -> tuple[dict, str]:
    """漏洞 meta + PoC → spec。返回 (spec, 产出方式 llm|heuristic)。

    llm 抽出的 http 段若全部被 _clean_spec 判死（路径没对上、matcher 不合法），
    自动回退启发式，避免"LLM 给了但没法用"的空模板。
    """
    heuristic = _heuristic_spec(meta, poc)
    if llm is None:
        return heuristic, "heuristic"
    user = json.dumps({"name": meta.get("name"), "summary": meta.get("summary"),
                       "principle": meta.get("principle"), "attack_scope": meta.get("attack_scope"),
                       "cvss": meta.get("cvss"), "refs": meta.get("refs"), "poc": (poc or "")[:3000]},
                      ensure_ascii=False)
    try:
        r = llm.chat(_SYS_SPEC, user)
        spec = _clean_spec(r if isinstance(r, dict) else {}, meta)
        if spec["http"]:
            return spec, "llm"
        logger.info("LLM spec 无有效 http 段 → 启发式兜底")
    except Exception as e:  # noqa: BLE001
        logger.warning("LLM 不可用（%r）→ 启发式兜底", e)
    return heuristic, "heuristic"


def convert(meta: dict, poc: str, llm=None, allow_write: bool = False) -> dict:
    """对外主入口：漏洞 → nuclei 模板。

    返回 {ok, yaml, spec, origin, reason}。失败不抛异常，调用方按 ok 处理。
    """
    spec, origin = vuln_to_spec(meta, poc, llm)
    if not spec["http"]:
        return {"ok": False, "yaml": "", "spec": spec, "origin": origin,
                "reason": "未能提取任何可用的 http 请求（PoC 里没有可识别的路径）"}
    if is_write_risk(spec) and not allow_write:
        return {"ok": False, "yaml": "", "spec": spec, "origin": origin,
                "reason": "模板含写操作（POST/PUT/DELETE 或 admin/import 等路径），"
                          "为避免生成的模板被误用于破坏性测试已拦下；确认无害可加 allow_write=true 强制生成"}
    text = spec_to_yaml(spec)
    ok, why = validate_yaml(text)
    if not ok:
        return {"ok": False, "yaml": text, "spec": spec, "origin": origin, "reason": f"自检未通过: {why}"}
    return {"ok": True, "yaml": text, "spec": spec, "origin": origin, "reason": ""}
