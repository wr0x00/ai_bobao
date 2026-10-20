"""config.py —— 全局配置。优先读 config.yaml（前端可改），环境变量可覆盖单条。

新增配置项只改 DEFAULTS + config.yaml，不用改这里。

配置里有两个值会直接进入网络请求（llm.base）和 git 命令（nuclei.repo / ref），
所以在 _validate 里就卡死形状：地址只允许 http/https，仓库名必须是 owner/repo，
分支名不能以 "-" 开头（会被 git 当成命令行选项）。
"""
import os
import threading
from pathlib import Path

import yaml

import security

BASE_DIR = Path(__file__).resolve().parent
DATA_DIR = BASE_DIR / "data"
VULN_DIR = DATA_DIR / "vulns"                  # 文件库：每个漏洞一个目录
CONFIG_FILE = BASE_DIR / "config.yaml"        # 前端设置页写这个文件

DEFAULTS: dict = {
    "llm": {
        "base": "https://api.openai.com",       # OpenAI 兼容端点，不带 /v1
        "key": "",
        "model": "gpt-4o-mini",
        "timeout": 60,
    },
    "collect": {
        "interval_minutes": 10,                # 定时抓取间隔
        "fetch_limit": 10,                     # 单个文章源最多取多少条
        "keep_days": 60,                       # 漏洞保留天数，超期的自动舍弃，0 = 不按日期筛
        "auto_translate": True,                # 入库时顺带把英文情报译成中文
    },
    "nuclei": {
        "repo": "projectdiscovery/nuclei-templates",
        "ref": "main",
        "remote_limit": 20,                    # 每轮从远程拉几个模板
        "fetch_remote": False,                 # 是否走 GitHub API 抽样（增量同步才是主路径）
        "gen_templates": True,                 # 是否为收录漏洞生成模板
        "sync_enabled": True,                  # 定时任务是否自动同步模板库增量
        "sync_limit": 0,                       # 单次同步最多入库几条，0 = 不限
    },
    # 用户在设置页接入的漏洞社区。与 crawler.FEEDS（内置源）叠加，两者都抓。
    # 列表而非标量，所以 update() 的标量校验路径不适用，单独在下面处理。
    "sources": {
        "custom": [],                         # [{name, url, enabled}]
    },
}

# 环境变量 → 配置路径。部署环境临时覆盖用，日常在设置页改就行。
_ENV = {
    "AI_BAOBAO_LLM_BASE": ("llm", "base"),
    "AI_BAOBAO_LLM_KEY": ("llm", "key"),
    "AI_BAOBAO_LLM_MODEL": ("llm", "model"),
    "AI_BAOBAO_INTERVAL_MINUTES": ("collect", "interval_minutes"),
    "AI_BAOBAO_KEEP_DAYS": ("collect", "keep_days"),
    "AI_BAOBAO_AUTO_TRANSLATE": ("collect", "auto_translate"),
    "AI_BAOBAO_NUCLEI_FETCH_REMOTE": ("nuclei", "fetch_remote"),
    "AI_BAOBAO_NUCLEI_GEN": ("nuclei", "gen_templates"),
    "AI_BAOBAO_NUCLEI_SYNC": ("nuclei", "sync_enabled"),
    "AI_BAOBAO_NUCLEI_SYNC_LIMIT": ("nuclei", "sync_limit"),
    "AI_BAOBAO_NUCLEI_REPO": ("nuclei", "repo"),
    "AI_BAOBAO_NUCLEI_REF": ("nuclei", "ref"),
    "AI_BAOBAO_NUCLEI_REMOTE_LIMIT": ("nuclei", "remote_limit"),
}

_INT_KEYS = {("llm", "timeout"), ("collect", "interval_minutes"),
             ("collect", "fetch_limit"), ("collect", "keep_days"),
             ("nuclei", "remote_limit"), ("nuclei", "sync_limit")}
_BOOL_KEYS = {("nuclei", "fetch_remote"), ("nuclei", "gen_templates"),
              ("nuclei", "sync_enabled"), ("collect", "auto_translate")}

# 写盘时固定补在文件头的说明（safe_dump 不会输出注释）
_HEADER = (
    "# ai_bobao 运行配置 —— 前端「设置」页保存到这个文件，保存后立即生效，无需重启。\n"
    "# 也可手改；优先级：默认值 < 本文件 < 环境变量（环境变量只在容器/CI 临时覆盖时用）。\n"
    "# 注意：llm.key 是明文密钥，别提交到公开仓库。\n\n"
)

_lock = threading.RLock()   # 可重入：update() 持锁期间还要调 load()
_cache: dict | None = None


def _coerce(path: tuple, value):
    """环境变量都是字符串，按配置项类型转回来。"""
    if path in _BOOL_KEYS:
        return str(value).strip().lower() in ("1", "true", "yes", "on")
    if path in _INT_KEYS:
        return int(value)
    return str(value)


def _deep_merge(base: dict, over: dict) -> dict:
    for k, v in over.items():
        if isinstance(v, dict) and isinstance(base.get(k), dict):
            _deep_merge(base[k], v)
        elif v is not None:
            base[k] = v
    return base


def load(force: bool = False) -> dict:
    """读配置。进程内缓存，保存后调 force=True 或走 save() 自动失效。"""
    global _cache
    with _lock:
        if _cache is not None and not force:
            return _cache
        cfg = {s: dict(v) for s, v in DEFAULTS.items()}   # 深拷贝两层足够，全是标量
        if CONFIG_FILE.exists():
            raw = yaml.safe_load(CONFIG_FILE.read_text(encoding="utf-8")) or {}
            if isinstance(raw, dict):
                _deep_merge(cfg, raw)
        for env, path in _ENV.items():
            if env in os.environ:
                sec, key = path
                cfg.setdefault(sec, {})[key] = _coerce(path, os.environ[env])
        _cache = cfg
        return cfg


def get(section: str, key: str):
    return load().get(section, {}).get(key)


def _validate(section: str, key: str, value):
    """校验并规范一个配置项的值。返回规范化后的值，不合格就抛 ValueError。"""
    path = (section, key)
    if path in _INT_KEYS:
        value = int(value)
        # sync_limit（0=不限）和 keep_days（0=不按日期筛）拿 0 当关闭开关，
        # 其余项 0 没意义。其余项收正整数，这两个只要 nonnegative。
        zero_ok = path in (("nuclei", "sync_limit"), ("collect", "keep_days"))
        if value < 0 or (value == 0 and not zero_ok):
            raise ValueError(f"{key} 不能为负数" if zero_ok else f"{key} 必须是正整数")
    elif path in _BOOL_KEYS:
        value = bool(value)
    elif key in ("base", "key", "model", "repo", "ref"):
        value = str(value).strip()
    if path == ("llm", "base"):
        # 这里只做形状检查，不做 DNS 解析 —— 保存设置不该要求联网。
        # 真正拦内网地址的是 llm.chat 里的 security.check_url，发请求前才查。
        if value and not security.is_http_url(value):
            raise ValueError("接口地址必须是 http:// 或 https:// 开头的完整网址")
    if path == ("llm", "model") and not value:
        raise ValueError("模型名不能为空")
    if path == ("nuclei", "repo") and not security.valid_repo(value):
        raise ValueError("模板库仓库名要写成 owner/repo 的形式")
    if path == ("nuclei", "ref") and not security.valid_ref(value):
        raise ValueError("模板库分支名不合法")
    return value


def _norm_sources(items) -> list[dict]:
    """校验用户接入的源列表。名字重复会让两条记录在库里撞同一个 source 字段。"""
    if not isinstance(items, list):
        raise ValueError("sources.custom 必须是列表")
    out, seen = [], set()
    for it in items:
        if not isinstance(it, dict):
            raise ValueError("每个源必须是 {name, url} 对象")
        url = str(it.get("url", "")).strip()
        if not url.startswith(("http://", "https://")):
            raise ValueError(f"源地址必须以 http:// 或 https:// 开头：{url or '(空)'}")
        name = str(it.get("name", "")).strip() or url
        if name in seen:
            raise ValueError(f"源名重复：{name}")
        seen.add(name)
        out.append({"name": name, "url": url,
                    "enabled": bool(it.get("enabled", True))})
    return out


def update(patch: dict) -> dict:
    """设置页提交：校验后落 config.yaml。空字符串表示"不改"，避免密钥被前端空传清掉。"""
    with _lock:
        cfg = {s: dict(v) for s, v in load(force=True).items()}
        for section, values in (patch or {}).items():
            if section not in DEFAULTS:
                raise ValueError(f"未知配置节：{section}")
            for key, value in values.items():
                if key not in DEFAULTS[section]:
                    raise ValueError(f"未知配置项：{section}.{key}")
                if section == "sources":
                    cfg[section][key] = _norm_sources(value)
                    continue
                if value is None or (isinstance(value, str) and not value.strip()
                                     and key in ("key", "base")):
                    continue                      # 密钥/地址留空 = 保持原值
                cfg[section][key] = _validate(section, key, value)
        # safe_dump 不带注释，每次保存都补回文件头，免得越改越没人看得懂
        text = _HEADER + yaml.safe_dump(cfg, allow_unicode=True, sort_keys=False)
        tmp = CONFIG_FILE.with_suffix(".yaml.tmp")
        tmp.write_text(text, encoding="utf-8")
        tmp.replace(CONFIG_FILE)                # 原子替换，避免半截文件
        return load(force=True)


# ── 固定路径（不随设置页变）────────────────────────────
NUCLEI_TPL_DIR = DATA_DIR / "nuclei_tpl"       # 模板汇总目录（可整体 nuclei -l 跑）
NUCLEI_CACHE_DIR = DATA_DIR / "nuclei_cache"   # 远程模板/索引的磁盘缓存
NUCLEI_REPO_DIR = DATA_DIR / "nuclei_templates"  # 模板仓库 git clone 落点
NUCLEI_SYNC_STATE = DATA_DIR / "nuclei_sync.json"  # 上次同步到的 commit
TPL_REPO_URL = "https://github.com/projectdiscovery/nuclei-templates.git"
