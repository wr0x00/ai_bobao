# ai_bobao

**AI-Powered Vulnerability Intelligence Feed**

简体中文 · [English](README.en.md)

AI 赋能的漏洞播报系统，AI 根据公开的漏洞思路自动生成 PoC、漏洞简介、漏洞原理、攻击范围，自动落库存储，24 小时监控全网漏洞播报，间隔10分��[...] 

---

#### 预览图

![界面预览](https://raw.githubusercontent.com/wr0x00/ai_bobao/main/image.png)

## 特性

- **多源聚合** — 并发抓取 Seebug、先知、Exploit-DB 的 RSS 与正文，单源失败不影响整体，每个请求有硬性超时。
- **自助接入新社区** — 设置页填一个社区地址，系统自动探测其 feed 并由 AI 判断是否为漏洞社区，确认后落配置即抓。
- **AI 补全** — LLM 将文章转为结构化情报：名称、简介、原理、攻击范围；文章已含 PoC 则原样收录，缺失则按公开思路补写 Python PoC。
- **双向 nuclei 通道** — 收录的漏洞可导出为 nuclei v3 模板；上游模板库的新增模板也可增量同步入库。
- **自动中文化** — 英文情报与模板元数据经 LLM 译为中文，CVE 编号、组件名、函数名保留原文。
- **文件式存储** — 无数据库依赖，每条漏洞一个目录，换库只改 `store.py`。
- **内置 Web 控制台** — 漏洞列表、详情、模板库、在线设置，定时后台刷新并展示倒计时。

## 技术栈

Python 3.11 · FastAPI · Vue 3 · Vite

## 快速开始

```bash
# 1. 配置
cd backend
cp config.example.yaml config.yaml
# 编辑 config.yaml 填入 LLM 端点与 API Key（不填则 AI 相关功能不可用）

# 2. 后端（默认端口 8100）
pip install fastapi uvicorn pyyaml feedparser
python main.py

# 3. 前端
cd ../frontend
npm install
npm run dev        # http://localhost:5173
```

打开 `http://localhost:5173` 访问 Web 控制台。后端`http://localhost:8100`。

---

## 配置

配置优先级：**内置默认值 < `config.yaml` < 环境变量**。也可在 Web 控制台的「设置」页修改，保存后立即生效。

| 键 | 默认值 | 说明 |
| --- | --- | --- |
| `llm.base` | `https://api.openai.com` | OpenAI 兼容端点，不含 `/v1` |
| `llm.key` | 空 | API Key。为空时 AI 功能不可用 |
| `llm.model` | `gpt-4o-mini` | 模型名 |
| `llm.timeout` | `60` | 请求超时（秒） |
| `collect.interval_minutes` | `10` | 定时抓取间隔（分钟） |
| `collect.fetch_limit` | `10` | 单个源每轮最多取多少条 |
| `collect.keep_days` | `60` | 情报保留天数，超期自动清理，`0` 表示不限 |
| `collect.auto_translate` | `true` | 入库时自动译为中文 |
| `nuclei.repo` / `nuclei.ref` | `projectdiscovery/nuclei-templates` / `main` | 上游模板库 |
| `nuclei.sync_enabled` | `true` | 定时任务自动同步模板库增量 |
| `nuclei.sync_limit` | `0` | 单次同步入库上限，`0` 表示不限 |

所有配置项均可通过环境变量覆盖，前缀 `AI_BAOBAO_`（如 `AI_BAOBAO_LLM_KEY`），完整映射见 `backend/config.py`。

> `config.yaml` 含明文密钥，已列入 `.gitignore`。请勿提交。

## 项目结构

```
backend/
  main.py         FastAPI 入口与路由、定时调度
  config.py       配置加载 / 校验 / 原子写回
  crawler.py      漏洞文章爬虫：RSS 聚合 + 正文抓取 + PoC 提取
  sources.py      数据源聚合：文章源 + nuclei 模板源
  source_discovery.py  新社区接入：feed 地址探测 + AI 判活
  analyzer.py     AI 生成层：情报补全、PoC 生成、模板同步编排
  translate.py    情报中文化与批量回填
  nuclei_tpl.py   PoC → nuclei 模板生成（结构化 JSON + YAML 组装)
  nuclei_sync.py  nuclei-templates git 增量同步
  store.py        文件存储层
  llm.py          OpenAI 兼容客户端
  data/           运行时数据（已忽略)
frontend/
  src/
    ListView.vue      漏洞列表
    DetailView.vue    漏洞详情
    TemplatesView.vue 模板库
    SettingsView.vue  在线设置
```

## 工作流程

```
RSS 源 ──► crawler ──► analyzer ──► store ──► translate
             │            │                      │
             │            └──► nuclei_tpl ──► data/nuclei_tpl
             └──► nuclei_sync ◄── nuclei-templates
```

每轮任务开始时先同步上游模板库增量，再跑文章流水线，最后按 `keep_days` 清理过期条目。抓取与模板同步各自加锁，避免手动触发与定时任务撞��[...] 

## nuclei 双向通道

**导出** — 把收录漏洞的原理、影响与 PoC 转成 nuclei v3 模板。详情页可单条重新生成，也可通过接口触发；默认只产出只读探测模板。

```bash
curl -X POST localhost:8100/api/vulns/<ID>/nuclei \
  -H 'Content-Type: application/json' -d '{"allow_write": false}'
```

**导入** — 定时增量同步上游 nuclei-templates，也可手动触发或按条件拉取入库。模板汇总在 `data/nuclei_tpl/`，可直接 `nuclei -l` 执行。

```bash
curl localhost:8100/api/nuclei/sync                                  # 同步状态
curl -X POST localhost:8100/api/nuclei/sync                          # 手动触发增量同步
curl 'localhost:8100/api/nuclei/remote?limit=20&severity=critical'  # 预览，不落盘
curl -X POST localhost:8100/api/nuclei/pull -d '{"limit": 20}'      # 拉取入库
```

## 接入新漏洞源

![接入新漏洞源](https://raw.githubusercontent.com/wr0x00/ai_bobao/main/image2.png)

设置页填一个社区首页即可，系统自动完成探测与判活：先按常见路径（`/feed`、`/rss`、`/rss.xml`、`/atom.xml` …）逐个试，解析得出条目的即为 feed；��[...] 

```bash
# 探测（不写配置，先看结果）
curl -X POST localhost:8100/api/sources/discover \
  -H 'Content-Type: application/json' -d '{"url": "https://xz.aliyun.com"}'

# 接入（name 唯一，重复即视为更新）
curl -X POST localhost:8100/api/sources \
  -H 'Content-Type: application/json' \
  -d '{"name": "先知", "url": "https://xz.aliyun.com/feed", "enabled": true}'

# 查看已接入的源 / 移除
curl localhost:8100/api/sources
curl -X DELETE localhost:8100/api/sources/先知
```

几点说明：

- **内置源与自定义源叠加抓取**，自定义源每轮现读配置，改完不用重启。
- **AI 判活不可用时**自动退化为标题关键词匹配，宁可放过也不误杀——把正常社区挡在门外的代价远高于放进一个无关站点。
- **JS 渲染的站点**探测不到 feed（页面由脚本生成），可先在浏览器里找到它的 RSS 地址再直接填进上面的 `POST /api/sources`。
- **平台型 API**（OSV / GitHub Advisory / NVD 这类 JSON 接口）暂未实现，扩展点见 `source_discovery.py` 末尾的 `_API_ADAPTERS`。

## API

| 方法 | 路径 | 说明 |
| --- | --- | --- |
| GET | `/api/vulns` | 漏洞列表（分页） |
| GET | `/api/vulns/{id}` | 漏洞详情（含 PoC 与模板全文） |
| POST | `/api/vulns/{id}/poc` | 生成 / 重新生成 Python PoC |
| POST | `/api/vulns/{id}/translate` | 单条情报译为中文 |
| POST | `/api/vulns/{id}/nuclei` | 生成 nuclei 模板 |
| POST | `/api/vulns/purge` | 按 `keep_days` 清理过期条目 |
| POST | `/api/translate/backfill` | 批量翻译（`ids` 可指定范围） |
| POST | `/api/collect` | 手动触发一轮抓取 |
| GET | `/api/collect/status` | 抓取状态与下次执行时间 |
| GET/POST | `/api/nuclei/sync` | 模板库同步状态 / 触发同步 |
| GET | `/api/nuclei/templates` | 本地模板库列表 |
| GET | `/api/nuclei/remote` | 预览上游模板库 |
| POST | `/api/nuclei/pull` | 从上游拉取入库 |
| GET/POST | `/api/settings` | 读取 / 保存配置（Key 脱敏） |
| POST | `/api/settings/test` | 用当前配置测试 LLM 连通性 |
| GET | `/api/sources` | 已接入的源（内置 + 自定义） |
| POST | `/api/sources/discover` | 探测社区 feed 地址并 AI 判活（不落盘） |
| POST | `/api/sources` | 接入 / 更新一个源 |
| DELETE | `/api/sources/{name}` | 移除一个源 |

## 数据存储

```
backend/data/
├── vulns/{ID}/
│   ├── meta.json       名称、来源、简介、原理、攻击范围、参考链接
│   ├── poc.py          PoC 文本
│   └── nuclei.yaml     对应模板（如有)
├── nuclei_tpl/         全部模板汇总目录，可直接 nuclei -l 执行
├── nuclei_sync.json    模板库同步状态
└── nuclei_cache/       远程模板库索引缓存
```

## 安全声明

本项目仅用于防御性安全研究与授权测试。生成的 PoC 依据公开披露的漏洞思路编写，使用前请确认已获得目标系统所有者授权。
