# ai\_bobao

**AI-Powered Vulnerability Intelligence Feed**

简体中文 · [English](README.en.md)

![AI 漏洞播报](preview.png)

AI 赋能的漏洞播报系统，AI 根据公开的漏洞思路自动生成 PoC、漏洞简介、漏洞原理、攻击范围，自动落库存储，24 小时监控全网漏洞播报，可设置间隔时间自动抓取，默认每隔10分钟全网抓取一次。

一切漏洞数据均源自公开渠道(论坛，社区等)，不涉及法律风险。

***

#### 预览图

![界面预览](image1.png)

## 特性

- **多源聚合** — 并发抓取 Seebug、先知、Exploit-DB 的 RSS 与正文，单源失败不影响整体，每个请求有硬性超时。
- **AI 内容判定** — 抓到的每一篇都先交给 LLM 判断性质：漏洞情报才收，赛事 WriteUp、工具教程、行业新闻一律不收。
- **自助接入新社区** — 设置页填一个社区地址，系统自动探测其 feed 并由 AI 判断是否为漏洞社区，确认后落配置即抓。
- **AI 补全** — LLM 将文章转为结构化情报：名称、简介、原理、攻击范围；文章已含 PoC 则原样收录，缺失则按公开思路补写 Python PoC。
- **双向 nuclei 通道** — 收录的漏洞可导出为 nuclei v3 模板；上游模板库的新增模板也可增量同步入库。
- **内嵌 AI 助手** — 页面右侧的对话面板直接指挥系统干活：查库问数、接入/移除播报源、改采集设置、触发抓取、导出条目下载、**搭复现环境 / 打 PoC / 修环境**。工具就地执行，过程轨迹可见（见[内嵌 AI 助手](#内嵌-ai-助手)）。
- **本地复现环境** — 漏洞详情页点「搭复现环境」，AI 规划出要复现的组件与版本、从哪拿程序本体（Docker Hub / GitHub / 官方发布包），**方案先给用户过目**：点「按此方案搭建」才开拉，「拒绝」即暂停；起真实容器、自动健康检查、给出可直接打开的靶站地址；库里的 PoC 真打靶机给出复现结论，没复现就点「更新 PoC」让 AI 读着失败输出重写，循环到复现为止（见[本地复现环境](#本地复现环境)）。
- **自动中文化** — 英文情报与模板元数据经 LLM 译为中文，CVE 编号、组件名、函数名保留原文。
- **数据总览** — 组件数量横向条形图、平台分布多色环状图，一眼看清库里有什么。
- **一键更新** — 设置页检测 GitHub 上有没有新版本，点一下快进到最新。
- **文件式存储** — 无数据库依赖，每条漏洞一个目录，换库只改 `store.py`。
- **内置 Web 控制台** — 漏洞列表、详情、总览、模板库、在线设置，定时后台刷新并展示倒计时。

## 技术栈

前后端不分离（单进程同端口）Python 3.11 · FastAPI · Vue 3 · Vite

## 快速开始

```bash
# 1. 配置 + 装依赖
cd backend
cp config.example.yaml config.yaml
# 编辑 config.yaml 填入 LLM 端点与 API Key（不填则 AI 相关功能不可用）
pip install -r requirements.txt

# 2. 启动（页面 + 接口同一个进程、同一个端口）
python main.py
```

打开 `http://127.0.0.1:8100`，页面和 API 都在这一个端口上。

> **开箱即用**：前端构建产物（`backend/static/`）已随仓库附带，
> 克隆下来直接跑，**不需要装 Node、不需要 `npm install`、不需要 `npm run build`**。
> 仓库里也只要求 Python 3.11+ 与一条 `pip install`。
>
> **前后端不分离**：FastAPI 直接托管 `backend/static` 里的构建产物，
> 前端所有请求都是相对路径 `/api/...`，天然同源——不用再单独起 vite dev server，
> 也没有跨域和「两个服务端口对不上」的问题。
> 深链（`/envs`、`/vuln/<id>` 等）刷新会回落到 `index.html` 交给前端路由，不会 404。
>
> **前端开发者**：源码仍在 `frontend/`。改完前端后 `cd frontend && npm install && npm run build`
> 会把新产物覆盖回 `backend/static/`（提交时记得一起带上）；开发调试时可用
> `cd frontend && npm run dev`（5173 端口，代理 `/api` 到后端）热更新，正式跑请用上面的单进程模式。

***

## 配置

配置优先级：**内置默认值 <** **`config.yaml`** **< 环境变量**。也可在 Web 控制台的「设置」页修改，保存后立即生效。
![配置](image5.png)
| 键                            | 默认值                                          | 说明                     |
| ---------------------------- | -------------------------------------------- | ---------------------- |
| `llm.base`                   | `https://api.openai.com`                     | OpenAI 兼容端点，不含 `/v1`   |
| `llm.key`                    | 空                                            | API Key。为空时 AI 功能不可用   |
| `llm.model`                  | `gpt-4o-mini`                                | 模型名                    |
| `llm.timeout`                | `60`                                         | 请求超时（秒）                |
| `collect.interval_minutes`   | `10`                                         | 定时抓取间隔（分钟）             |
| `collect.fetch_limit`        | `10`                                         | 单个源每轮最多取多少条            |
| `collect.keep_days`          | `60`                                         | 情报保留天数，超期自动清理，`0` 表示不限 |
| `collect.auto_translate`     | `true`                                       | 入库时自动译为中文              |
| `nuclei.repo` / `nuclei.ref` | `projectdiscovery/nuclei-templates` / `main` | 上游模板库                  |
| `nuclei.sync_enabled`        | `true`                                       | 定时任务自动同步模板库增量          |
| `nuclei.sync_limit`          | `0`                                          | 单次同步入库上限，`0` 表示不限      |
| `lab.root`                   | `backend/data/lab_envs`                      | 复现环境资产根目录（源码/镜像/元数据落这里）|
| `lab.docker_enabled`         | `true`                                       | 允许拉取/构建/运行 Docker 复现环境 |

所有配置项均可通过环境变量覆盖，前缀 `AI_BAOBAO_`（如 `AI_BAOBAO_LLM_KEY`），完整映射见 `backend/config.py`。

## 内嵌 AI 助手
![ai助手](image3.png)
页面右下角的「AI」浮钮展开对话面板。背后是 `agent.py`：一次对话最多 6 轮工具循环，模型按约定回 JSON（`final` 给答复 / `action` 点工具），工具在后端就地执行，返回的操作轨迹显示在气泡下方。

工具白名单（改程序的能力收在这里，参数逐个清洗校验）：

| 工具 | 能力 |
| --- | --- |
| `list_vulns` / `get_vuln` / `get_stats` | 查库：搜索、详情、统计 |
| `list_sources` / `add_source` / `remove_source` | 播报源的增删查（新源地址过 SSRF 网关） |
| `update_settings` | 改采集设置：抓取间隔、单源上限、保留天数、自动翻译 |
| `trigger_collect` | 触发一轮后台抓取（不阻塞对话） |
| `export_vulns` | 按条件导出 JSON 文件，气泡里直接给下载链接 |
| `list_envs` / `plan_env` / `build_env` | 复现环境：列环境 / AI 规划方案 / 真去拉程序本体搭起来 |
| `start_env` / `stop_env` / `delete_env` / `get_env` | 环境操作：起停、删掉重搭、看搭建日志与容器日志（排查失败原因） |
| `verify_poc` | 拿库里 PoC 真打靶机，输出复现结论与证据 |
| `regen_poc` | 参考上次失败输出重写 PoC —— `regen_poc → verify_poc` 循环直到复现 |

```bash
curl -X POST localhost:8100/api/agent/chat                          # 对话（重活限流）
curl localhost:8100/api/agent/export/vulns-20260101-120000-abcd.json  # 下载导出文件
```

导出文件落在 `data/exports/`，文件名正则校验 + `safe_join` 防穿越，目录最多保留 20 个。

**界面感知**：前端每条消息都带上用户当前停留的界面快照（列表页的来源页签/搜索词、详情页的漏洞 ID……），agent 能理解「这一条」「当前页面的这些」这种指代。比如停在详情页说「把这条的 PoC 发我」，它会先查这条详情再导出文件给下载链接。
## POC自动补全
点击详情页的「自动补全」按钮，即可根据漏洞描述自动生成 PoC。

![自动补全](image4.png)

## 本地复现环境

漏洞详情页点「搭复现环境」跳到 `/envs` 页，系统自动完成「查 → 审 → 造 → 打 → 修」闭环，全程无需离开页面：

1. **查（规划）** — LLM 读漏洞情报，判断要复现哪个组件哪个版本、能从公网哪里拿到程序本体；拿不到（闭源固件、无公开下载）直接给放弃理由，不硬造假环境。
2. **审（用户审批）** — 方案展示组件、版本、来源、镜像/仓库、**预估体积**（逐项：基础镜像 + 源码 + 依赖，合计多少 MB）、端口、启动命令，用户说了算：点「按此方案搭建」才开始拉取，点「拒绝，暂停」就挂起（体积太大、来源可疑、不想搭——理由用户自己定），想重新规划随时再点「先看方案」。
3. **造（搭建）** — 按批准的方案真去拉：Docker Hub 现成镜像 / GitHub 源码（主仓库 + 补充仓库 overlay，按 ref 精确到版本）/ 官方发布包。「源码 + 基础镜像」自建路线自动生成 Dockerfile 构建，镜像体积不设上限（方案里能看到大小，由用户审批把关）。
4. **打（验证）** — 搭好自动起容器，健康检查确认服务真在监听（状态：就绪 → 启动中 → 运行中）后，拿库里的 PoC 真打靶机：命中回显特征 + 随机 marker 回显才算「已复现」，结论与完整证据输出落在卡片里。
5. **修（更新 PoC 直到成功）** — 没复现？点「更新 PoC」：上次失败的输出原样喂回 LLM 换路子重写 PoC，写完自动再打一轮，循环到复现为止。环境坏了 AI 助手也能看日志、删掉重搭。

![复现环境：自动搭建 + 打 PoC 验证 + 更新 PoC 闭环](image6.png)

页面上直接给出**可点击的靶站地址**（如 `http://127.0.0.1:9091`），点「预览」还能在卡片里内嵌打开站点，方便手工验证。左下角的固定 AI 框实时播报每一步进度，也可以直接对话指挥（「搭 CVE-2024-xxxx 的复现环境」「打 PoC 验证」「看看为什么失败了」）。

安全边界：**方案必须用户审批才开拉**；所有拉取地址过 SSRF 网关；镜像名走正则白名单；git/docker 命令一律参数数组调用不经 shell；LLM 方案逐字段收敛校验后才执行；环境指纹去重，同组件同版本只建一份、多漏洞共享。

## nuclei 双向通道

**导出** — 把收录漏洞的原理、影响与 PoC 转成 nuclei v3 模板。详情页可单条重新生成，也可通过接口触发；默认只产出只读探测模板。

```bash
curl -X POST localhost:8100/api/vulns/<ID>/nuclei \
  -H 'Content-Type: application/json' -d '{"allow_write": false}'
```

**自动更新nuclei模板库** — 自动定时同步上游 nuclei-templates，执行逻辑：

```bash
curl localhost:8100/api/nuclei/sync                                  # 同步状态
curl -X POST localhost:8100/api/nuclei/sync                          # 手动触发增量同步
curl 'localhost:8100/api/nuclei/remote?limit=20&severity=critical'  # 预览，不落盘
curl -X POST localhost:8100/api/nuclei/pull -d '{"limit": 20}'      # 拉取入库
```
储存在 `data/nuclei_tpl/`，可直接 `nuclei -l` 执行。
```
nuclei -l backend/data/nuclei_tpl/ -u http://target.com
```
## 接入新漏洞源

![接入新漏洞源](image2.png)

设置页填一个社区首页即可，系统自动完成探测与判活：先按常见路径（`/feed`、`/rss`、`/rss.xml`、`/atom.xml` …）逐个试，解析得出条目的即为 feed；再把最新几条标题交给 AI 判断这是不是漏洞技术社区。确认后落入 `sources.custom`，下一轮抓取即生效，不必重启。

没有 feed 的社区也有兜底：探测不到 feed 时，会把用户给的页面本身按 **HTML 列表页** 解析（通用规则：标题字数达标的站内链接 + 紧邻摘要/日期），解析出条目就照样 AI 判活、照常接入。每轮抓取直接抓页面，不走 RSS。补天（`forum.butian.net`）这类列表服务端渲染但全站 JS 的站就是这么接进来的。

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
## 整体架构
```mermaid
flowchart TB
    U["👤 用户（浏览器）"] --> FE

    subgraph FE["🖥️ 前端 Vue 3 · 构建产物 backend/static"]
      UI["漏洞列表 / 详情 / 图表 / 设置<br>EnvView 复现环境页（靶站地址 + 站点预览 + 更新 PoC）<br>右下角 AI 助手面板 / /envs 页左下角环境 AI 框"]
    end

    FE -- "同源相对请求 /api/..." --> BE

    subgraph BE["⚙️ 后端 FastAPI（main.py）· 端口 8100 · 全系统的大脑 · 页面与接口同端口"]
      direction TB
      SPA["🗂️ 静态托管：backend/static + SPA 深链回落 index.html"]
      API["API 接口：处理前端每一个请求"]
      AGENT["🤖 AI 助手 agent.py<br>查库 / 加源 / 改设置 / 导出<br>搭环境 / 打 PoC / 修环境（工具白名单）"]
      SCH["⏰ 定时闹钟：默认每 10 分钟跑一轮"]
      CRW["🕷️ 爬虫 crawler.py：抓标题和正文"]
    end

    BE --> DTA
    BE --> LAB
    SCH --> CRW

    subgraph AI["🧠 AI 层（LLM，OpenAI 兼容接口，config.yaml 里填 Key）"]
      direction LR
      CJ["判决：是不是漏洞情报？<br>不是 → 直接丢弃"]
      GEN["补全：简介 / 原理 / Python PoC / 中文化"]
      NT["生成：漏洞 → nuclei 模板"]
      REG["重写 PoC：上次失败输出喂回去<br>换路子再写（更新 PoC 循环）"]
    end

    subgraph EXT["🌐 外部世界"]
      direction LR
      SRC["漏洞社区 RSS：Seebug / 先知 / Exploit-DB<br>+ 你在设置页自己加的源"]
      GIT["GitHub：上游 nuclei 模板库<br>+ 组件源码仓库（可按 ref 定版本）"]
      REGI["Docker Hub / 官方发布包"]
      LLM["LLM 平台（如 gpt-4o-mini）"]
    end

    SRC --> CRW
    CRW -->|"每篇文章都送审"| CJ
    CJ -->|"是漏洞 → 收"| GEN
    GEN -->|"同一篇也能转成模板"| NT
    subgraph LAB["🧪 本地复现环境 lab_env.py（查 + 审 + 造 + 打 + 修）"]
      direction TB
      PLAN["查·规划：LLM 判断复现哪个组件哪个版本<br>从哪拿程序本体；拿不到 → 放弃并给理由"]
      APPROVE["审·用户审批：方案展示来源/镜像/端口/命令<br>「按此方案搭建」才开拉，「拒绝」即暂停"]
      BUILD["造·搭建：docker pull / git clone / 发布包<br>源码 + 基础镜像自建，体积不设上限"]
      RUN["运行：起容器 + 端口映射 + 健康检查<br>就绪 → 启动中 → 运行中（服务真在监听才算）"]
      VERIFY["打·验证：执行库中 PoC 打靶机<br>回显特征 + 随机 marker → 已复现/未复现"]
    end

    PLAN -->|"用户批准后"| APPROVE
    APPROVE -->|"按方案执行"| BUILD
    BUILD --> RUN
    RUN --> VERIFY
    VERIFY -.->|"未复现：失败输出回喂"| REG
    REG -.->|"重写 PoC 落库"| VERIFY

    subgraph DTA["💾 数据层 backend/data/（纯文件，一条漏洞一个目录）"]
      direction LR
      VULN["vulns/{ID}/<br>meta.json · poc.py · nuclei.yaml<br>poc_verified 复现结论回填"]
      TPL["nuclei_tpl/<br>全部模板汇总"]
      ENVS["lab_envs/envs/{ID}/<br>环境元数据 · 源码 · 验证记录"]
    end

    GEN -->|"结果写成文件"| VULN
    NT --> TPL
    GIT -.->|"增量同步新模板"| TPL
    GIT -.->|"源码拉取"| BUILD
    REGI -.->|"镜像 / 发布包"| BUILD
    VULN -.->|"PoC 与漏洞情报"| PLAN
    VERIFY -->|"结论与证据落盘"| ENVS
    LLM -.->|"提供智能"| AI
```
## 项目结构

```
backend/
  main.py         FastAPI 入口与路由、定时调度
  config.py       配置加载 / 校验 / 原子写回
  agent.py        内嵌 AI Agent：对话循环 + 工具注册（加源/查库/改设置/导出）
  crawler.py      漏洞文章爬虫：RSS 聚合 + 正文抓取 + PoC 提取
  sources.py      数据源聚合：文章源 + nuclei 模板源
  source_discovery.py  新社区接入：feed 地址探测 + AI 判活
  source_manager.py  播报源管理服务：源列表 / 接入 / 移除（统一走 SSRF 网关）
  net.py          出站 HTTP 封装：硬死线超时 + 大小上限
  analyzer.py     AI 生成层：情报补全、PoC 生成（含失败重写）、模板同步编排
  lab_env.py      本地复现环境：AI 规划 → 拉取/自建 → 起容器 → 打 PoC 验证闭环
  content_judge.py  内容性质判定：让 LLM 分清漏洞情报与技术文章
  translate.py    情报中文化与批量回填
  nuclei_tpl.py   PoC → nuclei 模板生成（结构化 JSON + YAML 组装）
  nuclei_sync.py  nuclei-templates git 增量同步
  store.py        文件存储层
  llm.py          OpenAI 兼容客户端
  security.py     出站安全网关（SSRF 防护、XML 解析加固、限流）
  updater.py      自更新：查 GitHub 新版本 + 快进合并
  data/           运行时数据（已忽略）
  static/         前端构建产物（已随仓库附带，后端自己发，开箱即用）
frontend/
  src/
    ListView.vue      漏洞列表（总览面板嵌在搜索栏上方）
    AgentPanel.vue    右侧 AI 助手对话面板
    DetailView.vue    漏洞详情
    OverviewPanel.vue 总览图表（组件条形图 + 来源环状图）
    TemplatesView.vue 模板库
    SettingsView.vue  在线设置
    EnvView.vue       复现环境页（环境列表 / 靶站地址 / 站点预览 / 更新 PoC / 左下角 AI 框）
  vite.config.js 构建配置：outDir 指向 ../backend/static
```

## 工作流程

```
RSS 源 ──► crawler ──► content_judge ──► analyzer ──► store ──► translate
             │              │                │                      │
             │              │                └──► nuclei_tpl ──► data/nuclei_tpl
             │              └──► LLM识别→非漏洞文章 → 直接丢弃
             └──► nuclei_sync ◄── nuclei-templates
```

每轮任务开始时先同步上游模板库增量，再跑文章流水线，最后按 `keep_days` 清理过期条目。抓取与模板同步各自加锁，避免手动触发与定时任务撞车。

## API

| 方法       | 路径                          | 说明                            |
| -------- | --------------------------- | ----------------------------- |
| GET      | `/api/vulns`                | 漏洞列表（分页；`level`、`days` 按评级/最近N天筛）  |
| GET      | `/api/vulns/{id}`           | 漏洞详情（含 PoC 与模板全文）             |
| POST     | `/api/vulns/{id}/poc`       | 生成 / 重新生成 Python PoC          |
| POST     | `/api/vulns/{id}/translate` | 单条情报译为中文                      |
| POST     | `/api/vulns/{id}/nuclei`    | 生成 nuclei 模板                  |
| POST     | `/api/vulns/purge`          | 按 `keep_days` 清理过期条目          |
| POST     | `/api/vulns/rate`           | 给存量条目补 AI 评级（每轮抓取也自动评 20 条）   |
| POST     | `/api/vulns/recheck`        | 存量内容复检：非漏洞条目删除、兜底条目删除         |
| GET      | `/api/stats`                | 库内统计（总数 / 近 7 天 / 带模板 / 已中文化） |
| POST     | `/api/translate/backfill`   | 批量翻译（`ids` 可指定范围）             |
| POST     | `/api/collect`              | 手动触发一轮抓取                      |
| GET      | `/api/collect/status`       | 抓取状态与下次执行时间                   |
| GET      | `/api/update/check`         | 检查 GitHub 上有没有新版本             |
| POST     | `/api/update/apply`         | 拉取最新版本（只快进，本地有改动会拒绝）          |
| GET/POST | `/api/nuclei/sync`          | 模板库同步状态 / 触发同步                |
| GET      | `/api/nuclei/templates`     | 本地模板库列表                       |
| GET      | `/api/nuclei/remote`        | 预览上游模板库                       |
| POST     | `/api/nuclei/pull`          | 从上游拉取入库                       |
| GET/POST | `/api/settings`             | 读取 / 保存配置（Key 脱敏）             |
| POST     | `/api/settings/test`        | 用当前配置测试 LLM 连通性               |
| POST     | `/api/agent/chat`           | 内嵌 AI 助手对话（工具循环）              |
| GET      | `/api/agent/export/{name}`  | 下载 agent 导出的 JSON 文件          |
| GET      | `/api/sources`              | 已接入的源（内置 + 自定义）               |
| POST     | `/api/sources/discover`     | 探测社区 feed 地址并 AI 判活（不落盘）      |
| POST     | `/api/sources`              | 接入 / 更新一个源                    |
| DELETE   | `/api/sources/{name}`       | 移除一个源                         |
| GET      | `/api/envs`                 | 已搭建的复现环境列表                    |
| GET      | `/api/envs/{eid}`           | 环境详情（资源、日志、验证结论）              |
| POST     | `/api/envs/resolve`         | AI 规划复现环境方案（不落盘）              |
| POST     | `/api/envs/build`           | 按方案拉取程序本体并搭建（搭好自动启动）          |
| POST     | `/api/envs/{eid}/start`     | 启动环境（健康检查通过才算运行中）             |
| POST     | `/api/envs/{eid}/stop`      | 停止环境                          |
| POST     | `/api/envs/{eid}/verify`    | 执行库中 PoC 打靶机，回填复现结论           |
| DELETE   | `/api/envs/{eid}`           | 删除环境（容器/镜像/落盘目录全清）            |

## 漏洞评级

每条漏洞带四档中文评级：**严重（红）/ 高危（橙）/ 中危（蓝）/ 低危（天蓝）**，评不了的显示灰色「未评级」。列表卡片标题后是评级色块，悬停可看该档的完整判定标准；列表按 **更新时间新的在前，同一天里评级高的在前** 排，详情页显示精确到分钟的「更新于」。

评级三条来源（`store.level_of` 兜底链）：① AI 生成情报时按 SRC 分级标准直接评（标准写死在 `analyzer._RATE_RULES`）；② nuclei 模板自带 severity（critical/high/…）映射；③ CVSS 分数划线（≥9 严重、≥7 高危、≥4 中危、>0 低危）。老条目没评过级的，每轮抓取结束后由 AI 自动补评 20 条，也可手动触发：

```bash
curl -X POST localhost:8100/api/vulns/rate      # 手动给存量补一轮评级（限流重活）
```

## 数据存储

```
backend/data/
├── vulns/{ID}/
│   ├── meta.json       名称、来源、简介、原理、攻击范围、参考链接
│   ├── poc.py          PoC 文本
│   └── nuclei.yaml     对应模板（如有）
├── nuclei_tpl/         全部模板汇总目录，可直接 nuclei -l 执行
├── nuclei_sync.json    模板库同步状态
└── nuclei_cache/       远程模板库索引缓存
```

## 安全声明

本项目仅用于防御性安全研究与授权测试。生成的 PoC 依据公开披露的漏洞思路编写，使用前请确认已获得目标系统所有者授权。
