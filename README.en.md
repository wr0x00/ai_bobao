# ai_bobao

**AI-Powered Vulnerability Intelligence Feed**

[简体中文](README.md) · English

An AI-powered vulnerability broadcast system that monitors vulnerability disclosures around the clock. AI generates PoCs, summaries, root causes and attack surfaces from publicly disclosed exploitation logic, and stores them automatically.

---

## Features

- **Multi-source aggregation** — Concurrently fetches RSS feeds and article bodies from Seebug, Xianzhi (Aliyun Xianzhi) and Exploit-DB. A single source failure never blocks the pipeline; every request is bounded by a hard timeout.
- **Self-service onboarding** — Paste a community URL in Settings; the system probes its feeds, has the LLM confirm it is a vulnerability community, and starts crawling it once you accept.
- **AI enrichment** — An LLM turns raw articles into structured intelligence: name, summary, root cause and attack surface. Existing PoCs are kept verbatim; missing ones are written from the publicly disclosed exploitation logic.
- **Bidirectional nuclei bridge** — Recorded vulnerabilities can be exported as nuclei v3 templates, and new upstream templates can be synced in incrementally.
- **Automatic localization** — English intelligence and template metadata are translated to Simplified Chinese, preserving CVE IDs, component names and function names.
- **File-based storage** — No database dependency. One directory per vulnerability; swapping the storage engine only touches `store.py`.
- **Web console** — Vulnerability list, detail view, template library and online settings, with a background scheduler and a live countdown.

## Stack

Python 3.11 · FastAPI · Vue 3 · Vite

## Quick Start

```bash
# 1. Configure
cd backend
cp config.example.yaml config.yaml
# Edit config.yaml and set your LLM endpoint and API key (AI features stay disabled without them)

# 2. Backend (default port 8100)
pip install fastapi uvicorn pyyaml feedparser
python main.py

# 3. Frontend
cd ../frontend
npm install
npm run dev        # http://localhost:5173
```

The dev server proxies `/api` to `http://127.0.0.1:8100`.

## Configuration

Precedence: **built-in defaults < `config.yaml` < environment variables**. Everything can also be changed from the Settings page of the web console, which takes effect immediately.

| Key | Default | Description |
| --- | --- | --- |
| `llm.base` | `https://api.openai.com` | OpenAI-compatible endpoint, without `/v1` |
| `llm.key` | empty | API key. AI features are disabled when empty |
| `llm.model` | `gpt-4o-mini` | Model name |
| `llm.timeout` | `60` | Request timeout in seconds |
| `collect.interval_minutes` | `10` | Scheduler interval in minutes |
| `collect.fetch_limit` | `10` | Maximum items fetched per source per round |
| `collect.keep_days` | `60` | Retention in days; `0` disables expiry |
| `collect.auto_translate` | `true` | Translate to Chinese on ingestion |
| `nuclei.repo` / `nuclei.ref` | `projectdiscovery/nuclei-templates` / `main` | Upstream template repository |
| `nuclei.sync_enabled` | `true` | Sync upstream template increments on schedule |
| `nuclei.sync_limit` | `0` | Maximum entries per sync; `0` means unlimited |

Every key can be overridden by an environment variable prefixed with `AI_BAOBAO_` (e.g. `AI_BAOBAO_LLM_KEY`). See `_ENV` in `backend/config.py` for the full mapping.

> `config.yaml` holds a plaintext API key and is listed in `.gitignore`. Do not commit it.

## Project Structure

```
backend/
  main.py         FastAPI app, routes and scheduler
  config.py       Config loading, validation and atomic writes
  crawler.py      Article crawler: RSS aggregation, body extraction, PoC detection
  sources.py      Source aggregation: article feeds + nuclei templates
  source_discovery.py  New community onboarding: feed probing + AI vetting
  analyzer.py     AI layer: enrichment, PoC generation, sync orchestration
  translate.py    Chinese localization and bulk backfill
  nuclei_tpl.py   PoC → nuclei template generation (structured JSON + YAML assembly)
  nuclei_sync.py  Incremental git sync of nuclei-templates
  store.py        File-based storage layer
  llm.py          OpenAI-compatible client
  data/           Runtime data (git-ignored)
frontend/
  src/
    ListView.vue      Vulnerability list
    DetailView.vue    Vulnerability detail
    TemplatesView.vue Template library
    SettingsView.vue  Settings
```

## Pipeline

```
RSS feeds ──► crawler ──► analyzer ──► store ──► translate
                │            │                      │
                │            └──► nuclei_tpl ──► data/nuclei_tpl
                └──► nuclei_sync ◄── nuclei-templates
```

Each cycle syncs upstream template increments first, then runs the article pipeline, and finally purges entries older than `keep_days`. Collection and template sync are individually locked so manual triggers cannot collide with the scheduler.

## nuclei Bridge

**Export** — Turns a recorded vulnerability's root cause, impact and PoC into a nuclei v3 template. Templates can be regenerated per entry from the detail view or triggered through the API; only read-only detection templates are produced by default.

```bash
curl -X POST localhost:8100/api/vulns/<ID>/nuclei \
  -H 'Content-Type: application/json' -d '{"allow_write": false}'
```

**Import** — Incrementally syncs the upstream nuclei-templates repository on a schedule, and can also be triggered manually or pulled on demand. Templates are aggregated under `data/nuclei_tpl/` and can be executed directly with `nuclei -l`.

```bash
curl localhost:8100/api/nuclei/sync                                  # sync status
curl -X POST localhost:8100/api/nuclei/sync                          # trigger a sync
curl 'localhost:8100/api/nuclei/remote?limit=20&severity=critical'  # preview, no writes
curl -X POST localhost:8100/api/nuclei/pull -d '{"limit": 20}'      # pull into the library
```

## Adding a Vulnerability Source

Enter a community homepage in Settings and the system takes it from there: it walks the common feed paths (`/feed`, `/rss`, `/rss.xml`, `/atom.xml`, …) and keeps every URL that parses into entries, then hands the latest titles to the LLM to decide whether this is actually a vulnerability community. Confirmed sources land in `sources.custom` and take effect on the next cycle — no restart.

```bash
# Probe (writes nothing, inspect the result first)
curl -X POST localhost:8100/api/sources/discover \
  -H 'Content-Type: application/json' -d '{"url": "https://xz.aliyun.com"}'

# Attach (name is unique; an existing name is updated)
curl -X POST localhost:8100/api/sources \
  -H 'Content-Type: application/json' \
  -d '{"name": "xz", "url": "https://xz.aliyun.com/feed", "enabled": true}'

# List attached sources / detach
curl localhost:8100/api/sources
curl -X DELETE localhost:8100/api/sources/xz
```

Notes:

- **Built-in and custom sources are both crawled.** Custom sources are re-read from config every cycle, so changes apply without a restart.
- **When the LLM is unavailable**, vetting degrades to keyword matching on titles, and it errs on the side of admitting: blocking a legitimate community costs far more than letting an unrelated site in.
- **JavaScript-rendered sites** expose no feed to probe. Find the RSS URL in the browser first, then post it directly to `/api/sources`.
- **Platform APIs** (OSV, GitHub Advisory, NVD) are not implemented yet. See `_API_ADAPTERS` at the end of `source_discovery.py` for the extension point.

## API

| Method | Path | Description |
| --- | --- | --- |
| GET | `/api/vulns` | Paginated vulnerability list |
| GET | `/api/vulns/{id}` | Vulnerability detail including PoC and template |
| POST | `/api/vulns/{id}/poc` | Generate or regenerate a Python PoC |
| POST | `/api/vulns/{id}/translate` | Translate a single entry to Chinese |
| POST | `/api/vulns/{id}/nuclei` | Generate a nuclei template |
| POST | `/api/vulns/purge` | Purge entries older than `keep_days` |
| POST | `/api/translate/backfill` | Bulk translation; pass `ids` to limit scope |
| POST | `/api/collect` | Trigger a collection cycle |
| GET | `/api/collect/status` | Collection status and next run time |
| GET/POST | `/api/nuclei/sync` | Sync status / trigger a sync |
| GET | `/api/nuclei/templates` | Local template library |
| GET | `/api/nuclei/remote` | Preview the upstream library |
| POST | `/api/nuclei/pull` | Pull templates from upstream |
| GET/POST | `/api/settings` | Read / write configuration (key redacted) |
| POST | `/api/settings/test` | Test LLM connectivity with the current config |
| GET | `/api/sources` | Attached sources (built-in + custom) |
| POST | `/api/sources/discover` | Probe a community's feeds and vet them with the LLM (no writes) |
| POST | `/api/sources` | Attach or update a source |
| DELETE | `/api/sources/{name}` | Detach a source |

## Data Layout

```
backend/data/
├── vulns/{ID}/
│   ├── meta.json       Name, source, summary, root cause, attack surface, references
│   ├── poc.py          PoC source
│   └── nuclei.yaml     Generated or synced template, if any
├── nuclei_tpl/         Aggregated templates, runnable via nuclei -l
├── nuclei_sync.json    Template sync state
└── nuclei_cache/       Remote template index cache
```

## Security Notice

This project is intended for defensive security research and authorized testing only. Generated PoCs are written from publicly disclosed vulnerability logic. Obtain explicit authorization from the asset owner before use.
