// api.js —— 后端接口封装
async function req(url, options) {
    const r = await fetch(url, options)
    if (!r.ok) {
        // FastAPI 把原因放在 detail 里，取出来比干巴巴的 HTTP 400 好用
        let detail = ''
        try {
            detail = (await r.json()).detail || ''
        } catch { /* 非 JSON 响应，跳过 */ }
        if (Array.isArray(detail)) {
            // 422 的 detail 是对象数组，压成 "字段: 原因"
            detail = detail.map((d) => `${(d.loc || []).slice(1).join('.')}: ${d.msg}`).join('; ')
        }
        throw new Error(detail || `HTTP ${r.status}`)
    }
    return r.json()
}

const post = (url, body) => req(url, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(body || {}),
})

export const listVulns = (q = {}) => {
    const p = new URLSearchParams(Object.entries(q).filter(([, v]) => v !== '' && v != null))
    return req(`/api/vulns?${p}`)
}

export const getVuln = (id) => req(`/api/vulns/${encodeURIComponent(id)}`)

export const runCollect = () => post('/api/collect')

export const collectStatus = () => req('/api/collect/status')

// ── nuclei 双向通道 ──────────────────────────────────────
export const listTemplates = () => req('/api/nuclei/templates')

// 模板库增量同步：git diff 出新增/修改的模板，原样入库不过 LLM
export const syncStatus = () => req('/api/nuclei/sync')

export const runSync = (body = {}) => post('/api/nuclei/sync', body)

export const previewRemote = (q = {}) => {
    const p = new URLSearchParams(Object.entries(q).filter(([, v]) => v !== '' && v != null))
    return req(`/api/nuclei/remote?${p}`)
}

export const pullRemote = (body) => post('/api/nuclei/pull', body)

export const genNuclei = (id, allowWrite = false) =>
    post(`/api/vulns/${encodeURIComponent(id)}/nuclei`, { allow_write: allowWrite })

// ── AI 加工：翻译 / PoC 生成 ─────────────────────────────
export const genPoc = (id) => post(`/api/vulns/${encodeURIComponent(id)}/poc`)

export const translateVuln = (id) => post(`/api/vulns/${encodeURIComponent(id)}/translate`)

// 传 ids = 翻译当前页这 10 条（含标题/简介/原理）；不传 = 按 limit 补存量
export const backfillTranslate = (limit = 20, ids = null) =>
    post('/api/translate/backfill', ids ? { limit, ids } : { limit })

export const llmStatus = () => req('/api/llm/status')

export const purgeExpired = () => post('/api/vulns/purge')

// ── 设置 ────────────────────────────────────────────────
export const getSettings = () => req('/api/settings')

export const saveSettings = (body) => post('/api/settings', body)

export const testLlm = (llm) => post('/api/settings/test', { llm: llm || {} })

// ── 漏洞源接入 ──────────────────────────────────────────
export const listSources = () => req('/api/sources')

// 探测社区地址：找 feed + AI 判断是否漏洞社区。不落配置
export const discoverSource = (url, llmJudge = true) =>
    post('/api/sources/discover', { url, llm_judge: llmJudge })

export const addSource = (s) => post('/api/sources', s)

export const delSource = (name) =>
    req(`/api/sources/${encodeURIComponent(name)}`, { method: 'DELETE' })