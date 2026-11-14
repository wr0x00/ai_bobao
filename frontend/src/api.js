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
 * @param {object} [options] 额外的 fetch 选项（比如 AbortController 的 signal）
 * @returns {Promise<object>} 后端返回的 JSON
 */
const post = (url, body, options = {}) => req(url, {
    method: 'POST',
    ...options,
    headers: { 'Content-Type': 'application/json', ...(options.headers || {}) },
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

/**
 * 发一个流式写请求（SSE）。后端每生成一段就推一帧 `data: {json}\n\n`，
 * onEvent 每帧被调一次——模型吐一个字就能上屏，不用等整轮结束。
 *
 * @param {string} url 请求地址
 * @param {object} body 请求体
 * @param {(ev: object) => void} onEvent 每帧回调
 * @param {object} [options] 额外的 fetch 选项（比如 AbortController 的 signal）
 * @returns {Promise<void>} 流走完（收到 done/error 帧或连接关闭）后 resolve
 */
export async function streamPost(url, body, onEvent, options = {}) {
    const headers = { 'X-AI-BaoBao': '1', 'Content-Type': 'application/json' }
    const t = await ensureToken()
    if (t) headers['X-AI-BaoBao-Token'] = t

    const r = await fetch(url, {
        credentials: 'same-origin',
        cache: 'no-store',
        ...options,
        method: 'POST',
        headers,
        body: JSON.stringify(body || {}),
    })
    if (!r.ok) {
        let detail = ''
        try { detail = (await r.json()).detail || '' } catch { /* 非 JSON 跳过 */ }
        if (Array.isArray(detail)) {
            detail = detail.map((d) => `${(d.loc || []).slice(1).join('.')}: ${d.msg}`).join('; ')
        }
        throw new Error(detail || `HTTP ${r.status}`)
    }
    if (!r.body) throw new Error('浏览器不支持流式读取')

    const reader = r.body.getReader()
    const decoder = new TextDecoder('utf-8')
    let buf = ''
    for (;;) {
        const { done, value } = await reader.read()
        if (done) break
        buf += decoder.decode(value, { stream: true })
            // 帧以空行分隔；最后一段可能不完整，留在缓冲区等下一块
        let idx
        while ((idx = buf.indexOf('\n\n')) >= 0) {
            const frame = buf.slice(0, idx)
            buf = buf.slice(idx + 2)
            for (const line of frame.split('\n')) {
                const s = line.trim()
                if (!s.startsWith('data:')) continue
                const payload = s.slice(5).trim()
                if (!payload || payload === '[DONE]') continue
                try {
                    onEvent(JSON.parse(payload))
                } catch { /* 半截 JSON，跳过这帧 */ }
            }
        }
    }
}

// ── 漏洞源接入 ──────────────────────────────────────────
export const listSources = () => req('/api/sources')

// 探测社区地址：找 feed + AI 判断是否漏洞社区。不落配置
export const discoverSource = (url, llmJudge = true) =>
    post('/api/sources/discover', { url, llm_judge: llmJudge })

export const addSource = (s) => post('/api/sources', s)

export const delSource = (name) =>
    req(`/api/sources/${encodeURIComponent(name)}`, { method: 'DELETE' })

// ── 本地复现环境 ─────────────────────────────────────────
// 环境列表：含资产根目录、docker 可用性
export const listEnvs = () => req('/api/envs')

export const getEnv = (id) => req(`/api/envs/${encodeURIComponent(id)}`)

// 只让 LLM 出方案，不拉任何东西。options 用来传 AbortController 的 signal，
// 规划网关挂住时用户点「拒绝，暂停」能真的把它掐掉。
export const resolveEnv = (vid, options = {}) => post('/api/envs/resolve', { vid }, options)

// 为一条漏洞搭环境：拉程序/源码/镜像，找不到就放弃。plan 是用户审批过的方案，
// 带回来就按方案搭、不再问 LLM；不带则视为未审批（后端也会拒绝盲搭）。
// options 可传 AbortController 的 signal，「拒绝，停止」要真的掐断这个请求。
export const buildEnv = (vid, plan = null, options = {}) =>
    post('/api/envs/build', { vid, plan }, options)

export const startEnv = (id) => post(`/api/envs/${encodeURIComponent(id)}/start`)

export const stopEnv = (id) => post(`/api/envs/${encodeURIComponent(id)}/stop`)

// 最高优先级取消：立即终止该漏洞本次环境搭建的一切进行中任务
// （杀正在跑的 docker pull / git clone / docker build，停已起的容器）
export const cancelEnv = (vid) => post('/api/envs/cancel', { vid })

// 拿库里这条漏洞的 PoC 真打这个环境，验证能不能复现
// vid 可选：不传就用环境关联的第一条漏洞
export const verifyEnv = (id, vid = '') => post(`/api/envs/${encodeURIComponent(id)}/verify`, vid ? { vid } : {})

export const delEnv = (id) =>
    req(`/api/envs/${encodeURIComponent(id)}`, { method: 'DELETE' })

// ── 自更新 ──────────────────────────────────────────────
// 检测更新只读：比对本地 HEAD 和 GitHub 远端分支头
export const checkUpdate = () => req('/api/update/check')

// 拉取最新版本：后端只做 --ff-only 快进，本地有未提交改动会拒绝
export const applyUpdate = () => post('/api/update/apply')

// ── AI Agent 右侧对话 ───────────────────────────────────
// messages 只发 user/assistant 的纯文本，工具轨迹在返回的 steps 里；
// ui 是用户当前停留的界面快照，帮 agent 理解「这一条」「当前页面」这类指代。
// 带 sessionId 时，这一轮会存进服务端的会话文件，刷新也还在。
// opts 是面板右侧配的参数：系统提示词、上下文策略、采样参数；
// 后端会把这一轮真正发出去的请求体放在返回的 sent 里。
export const agentChat = (messages, ui = "", sessionId = '', opts = {}) =>
    post('/api/agent/chat', {
        messages,
        ui,
        session_id: sessionId,
        system_prompt: opts.system_prompt || '',
        context_mode: opts.context_mode || 'compress',
        context_rounds: opts.context_rounds === undefined ? 6 : opts.context_rounds,
        history_chars: opts.history_chars === undefined ? 300 : opts.history_chars,
        // 0 也要发出去（temperature=0 是合法取值），只有 undefined/null 才算"不传"
        temperature: opts.temperature === undefined || opts.temperature === null ?
            null : opts.temperature,
        max_tokens: opts.max_tokens === undefined || opts.max_tokens === null ?
            null : opts.max_tokens,
    })

// agentChat 的流式版：走 /api/agent/chat/stream，onEvent 收到的事件有
//   {type:'text', field:'thought'|'final', text}  增量文字（thought=思考，final=答复）
//   {type:'step', step}                           工具执行完一步
//   {type:'done', reply, steps, sent}             收尾（跟 agentChat 的返回值同构）
//   {type:'error', message}                       失败原因
// 其余 opts 语义与 agentChatStream 完全一致；options 传给 fetch，
// 可放 AbortController 的 signal——暂停按钮要能真的掐断流。
export const agentChatStream = (messages, ui = '', sessionId = '', opts = {},
        onEvent = () => {}, options = {}) =>
    streamPost('/api/agent/chat/stream', {
        messages,
        ui,
        session_id: sessionId,
        system_prompt: opts.system_prompt || '',
        context_mode: opts.context_mode || 'compress',
        context_rounds: opts.context_rounds === undefined ? 6 : opts.context_rounds,
        history_chars: opts.history_chars === undefined ? 300 : opts.history_chars,
        temperature: opts.temperature === undefined || opts.temperature === null ?
            null : opts.temperature,
        max_tokens: opts.max_tokens === undefined || opts.max_tokens === null ?
            null : opts.max_tokens,
    }, onEvent, options)

// resolveEnv 的流式版：方案字段一边生成一边播报
//   {type:'field', field, text}  某个字段已生成的完整值
//   {type:'done', plan}          规范化后的完整方案（跟 resolveEnv 返回的 plan 同构）
//   {type:'error', message}      失败原因
export const resolveEnvStream = (vid, onEvent = () => {}, options = {}) =>
    streamPost('/api/envs/resolve/stream', { vid }, onEvent, options)

// ── AI Agent 会话历史 ───────────────────────────────────
// 会话列表：id / 标题 / 时间 / 消息条数
export const listSessions = () => req('/api/agent/sessions')

// 新建一个会话。带 messages 就是「把老对话搬进来」。
export const createSession = (title = '', messages = []) =>
    post('/api/agent/sessions', { title, messages })

// 读一个会话的完整内容（含消息与工具轨迹）
export const getSession = (sid) => req(`/api/agent/sessions/${encodeURIComponent(sid)}`)

// 重命名会话
export const renameSession = (sid, title) =>
    req(`/api/agent/sessions/${encodeURIComponent(sid)}`, {
        method: 'PUT',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ title }),
    })

// 删掉整个会话
export const deleteSession = (sid) =>
    req(`/api/agent/sessions/${encodeURIComponent(sid)}`, { method: 'DELETE' })

// 清空当前会话的消息，会话本身留着
export const clearSession = (sid) =>
    req(`/api/agent/sessions/${encodeURIComponent(sid)}/messages`, { method: 'DELETE' })

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