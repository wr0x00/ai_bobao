// api.js —— 后端接口封装
//
// 后端把每个 /api 都收紧了：必须带 X-AI-BaoBao 标志头，写操作还得再带一个令牌。
// 这套头和令牌都在这里统一拼，不让各个页面各写一遍——漏一处就是一个 403。

// 写操作令牌。第一次 POST / DELETE 时才去要，拿到就一直留在内存里。
let token = ''
    // 正在取令牌的 Promise。并发请求时复用同一个，别一串请求打出去好几个 /api/session。
let tokenTask = null

/** 拉一次写操作令牌。已经有或在拉了就直接用现成的。 */
async function ensureToken() {
    if (token) return token
    if (!tokenTask) {
        // 走统一的 req 而不是裸 fetch：后端要求每个 /api 请求都带 X-AI-BaoBao 头，
        // 漏了这个头 /api/session 会直接 403，令牌就永远拿不到。
        tokenTask = req('/api/session')
            .then((data) => {
                token = (data && data.token) || ''
                tokenTask = null
                return token
            })
            .catch(() => {
                tokenTask = null
                return ''
            })
    }
    return tokenTask
}

/**
 * 发一个请求，把后端的失败原因原样抛出去。
 *
 * @param {string} url 请求地址
 * @param {object} [options] fetch 的选项，会在这里补上安全相关的头
 * @returns {Promise<object>} 后端返回的 JSON
 */
async function req(url, options = {}) {
    const method = (options.method || 'GET').toUpperCase()
    const headers = { 'X-AI-BaoBao': '1', ...(options.headers || {}) }

    // 只有改数据的动作要令牌，读接口不用，省一次往返。
    if (method !== 'GET' && method !== 'HEAD') {
        const t = await ensureToken()
        if (t) headers['X-AI-BaoBao-Token'] = t
    }

    const r = await fetch(url, {
        credentials: 'same-origin',
        cache: 'no-store',
        ...options,
        method,
        headers,
    })

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

/**
 * 发一个写请求。body 会被序列化成 JSON。
 *
 * @param {string} url 请求地址
 * @param {object} [body] 请求体
 * @returns {Promise<object>} 后端返回的 JSON
 */
const post = (url, body) => req(url, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(body || {}),
})

/** 把查询参数对象拼成 query string，空值和 null 直接丢掉。 */
const query = (q = {}) =>
    new URLSearchParams(Object.entries(q).filter(([, v]) => v !== '' && v != null)).toString()

// ── 漏洞列表与详情 ────────────────────────────────────────
export const listVulns = (q = {}) => req(`/api/vulns?${query(q)}`)

export const getVuln = (id) => req(`/api/vulns/${encodeURIComponent(id)}`)

// ── 采集 ──────────────────────────────────────────────────
export const runCollect = () => post('/api/collect')

export const collectStatus = () => req('/api/collect/status')

// ── nuclei 双向通道 ──────────────────────────────────────
export const listTemplates = () => req('/api/nuclei/templates')

// 模板库增量同步：git diff 出新增/修改的模板，原样入库不过 LLM
export const syncStatus = () => req('/api/nuclei/sync')

export const runSync = (body = {}) => post('/api/nuclei/sync', body)

export const previewRemote = (q = {}) => req(`/api/nuclei/remote?${query(q)}`)

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

// 存量复检：模型重判每条的内容性质，删掉赛事 WriteUp、重写「（兜底）」条目。
// limit 传 0 = 全库；后端一次最多接 2000 条，逐条调模型，会跑一会儿。
export const recheckLibrary = (limit = 0) => post('/api/vulns/recheck', { limit })

// ── 总览 ────────────────────────────────────────────────
export const getStats = () => req('/api/stats')

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

// ── 自更新 ──────────────────────────────────────────────
// 检测更新只读：比对本地 HEAD 和 GitHub 远端分支头
export const checkUpdate = () => req('/api/update/check')

// 拉取最新版本：后端只做 --ff-only 快进，本地有未提交改动会拒绝
export const applyUpdate = () => post('/api/update/apply')

// ── AI Agent 右侧对话 ───────────────────────────────────
// messages 只发 user/assistant 的纯文本，工具轨迹在返回的 steps 里；
// ui 是用户当前停留的界面快照，帮 agent 理解「这一条」「当前页面」这类指代
export const agentChat = (messages, ui = "") => post('/api/agent/chat', { messages, ui })

// 导出文件下载。接口要求 X-AI-BaoBao 头，裸 <a href> 带不上，走 blob。
export async function downloadAgentExport(name) {
    const r = await fetch(`/api/agent/export/${encodeURIComponent(name)}`, {
        headers: { 'X-AI-BaoBao': '1' },
        credentials: 'same-origin',
        cache: 'no-store',
    })
    if (!r.ok) {
        let detail = ''
        try { detail = (await r.json()).detail || '' } catch { /* 非 JSON 跳过 */ }
        throw new Error(detail || `下载失败 HTTP ${r.status}`)
    }
    const blob = await r.blob()
    const url = URL.createObjectURL(blob)
    const a = document.createElement('a')
    a.href = url
    a.download = name
    document.body.appendChild(a)
    a.click()
    a.remove()
    setTimeout(() => URL.revokeObjectURL(url), 5000)
}