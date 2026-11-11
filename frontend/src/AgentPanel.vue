<template>
  <aside v-if="open" class="agwrap" :class="{ cfgopen: cfgOpen }">
    <!-- 左侧：会话栏 -->
    <div class="agside">
      <div class="agsidehd">
        <span>会话</span>
        <button class="g sm" title="新建会话" @click="newSession">＋</button>
      </div>

      <div class="agsidelist">
        <div v-for="s in sessions" :key="s.id" class="sitem" :class="{ on: s.id === curId }"
             @click="select(s.id)">
          <template v-if="confirmDel === s.id">
            <span class="sask">删掉？</span>
            <button class="mini danger" @click.stop="doDelete(s)">删</button>
            <button class="mini" @click.stop="confirmDel = ''">算了</button>
          </template>

          <template v-else-if="renaming === s.id">
            <input :ref="(el) => (renameInput = el)" v-model="renameText" class="srename" maxlength="60"
                   @click.stop @keydown.enter.prevent="saveRename(s.id)"
                   @keydown.esc.prevent="renaming = ''" @blur="saveRename(s.id)" />
          </template>

          <template v-else>
            <div class="stop">
              <span class="stitle">{{ s.title }}</span>
              <span class="sops">
                <button class="mini" title="重命名" @click.stop="startRename(s)">✎</button>
                <button class="mini" title="删除会话" @click.stop="confirmDel = s.id">✕</button>
              </span>
            </div>
            <div class="smeta">{{ s.count }} 条 · {{ fmtTime(s.updated_at) }}</div>
          </template>
        </div>

        <div v-if="!sessions.length" class="sempty">还没有会话<br />点右上角 ＋ 开一个</div>
      </div>
    </div>

    <!-- 右侧：对话 -->
    <div class="agmain">
      <div class="aghead">
        <b>AI 助手</b>
        <span class="hint">{{ curTitle || '加源 · 查库 · 导出 · 改设置' }}</span>
        <span class="space"></span>
        <button class="g cfg-toggle" title="显示/隐藏参数面板" @click="cfgOpen = !cfgOpen">参数</button>
        <button class="g" :disabled="pending || !curId" @click="clearChat">清空</button>
        <button class="g" title="收起面板" @click="open = false">收起</button>
      </div>

      <div ref="box" class="aglist">
        <div v-if="!msgs.length" class="agwelcome">
          <p>我可以直接操作这个系统，试试：</p>
          <button v-for="eg in examples" :key="eg" class="eg" @click="ask(eg)">{{ eg }}</button>
          <p class="cap">能力：查询漏洞信息、接入/移除播报源、修改采集设置、
            触发抓取、把库里的条目导出成 JSON 下载。我知道你当前停在哪个页面，
            可以直接说「这一条」「这些条目」。改动类操作会先跟你确认。</p>
        </div>

        <template v-for="(m, i) in msgs" :key="i">
          <div v-if="m.role === 'user'" class="row me">{{ m.content }}</div>
          <div v-else-if="m.role === 'assistant'" class="row ai">
            <div class="bubble">{{ m.content }}</div>
            <details v-if="m.steps && m.steps.length" class="steps" :open="false">
              <summary>执行了 {{ m.steps.length }} 步操作</summary>
              <div v-for="(s, j) in m.steps" :key="j" class="step" :class="{ bad: !s.ok }">
                <code>{{ s.ok ? '✔' : '✘' }} {{ s.tool }}({{ s.argsText }})</code>
                <span class="out">{{ s.out }}</span>
                <a v-if="s.file" href="#" @click.prevent="dl(s.file)">下载 {{ s.file }}</a>
              </div>
            </details>
          </div>
          <div v-else class="row fail">{{ m.error }}</div>
        </template>

        <div v-if="pending" class="row ai wait">AI 正在处理，可能要几十秒…</div>
      </div>

      <div class="agfoot">
        <textarea v-model="draft" rows="2" :disabled="pending"
                  placeholder="输入想做的事，Enter 发送，Shift+Enter 换行"
                  @keydown.enter.exact.prevent="onEnter"></textarea>
        <button class="send" :disabled="pending || !draft.trim()" @click="onEnter">
          {{ pending ? '…' : '发送' }}
        </button>
      </div>
    </div>

    <!-- 最右：参数面板（提示词 / 上下文 / 采样 / 本次实际发送） -->
    <div class="agcfg">
      <div class="agcfghd">对话参数</div>

      <section class="chat-sec">
        <div class="chat-sec-t">提示词配置</div>
        <textarea v-model="cfg.system_prompt" class="cfg-area" rows="4"
                  placeholder="留空 = 使用内置系统提示词"></textarea>
        <div class="cfg-hint">追加在内置提示词之后，用来补充角色、语气或额外规矩</div>
      </section>

      <section class="chat-sec">
        <div class="chat-sec-t">上下文优化</div>
        <label class="cfg-row">
          <span>上下文策略</span>
          <select v-model="cfg.context_mode">
            <option value="drop">丢弃历史（只留本轮）</option>
            <option value="compress">压缩早期轮次</option>
            <option value="keep">完整保留</option>
          </select>
        </label>
        <label class="cfg-row">
          <span>保留轮数</span>
          <input v-model.number="cfg.context_rounds" type="number" min="1" max="50" step="1" />
        </label>
        <label class="cfg-row">
          <span>历史截断长度</span>
          <input v-model.number="cfg.history_chars" type="number" min="50" max="8000" step="50" />
        </label>
        <div class="cfg-hint">压缩时，最近的轮次原样保留，更早的按字数截断后并成摘要</div>
      </section>

      <section class="chat-sec">
        <div class="chat-sec-t">采样参数</div>
        <label class="cfg-row">
          <span>Temperature</span>
          <input v-model.number="cfg.temperature" type="number" min="0" max="2" step="0.1" />
        </label>
        <label class="cfg-row">
          <span>max_tokens</span>
          <input v-model.number="cfg.max_tokens" type="number" min="0" max="32000" step="64" />
        </label>
        <div class="cfg-hint">max_tokens 填 0 表示不限制，由服务端默认</div>
      </section>

      <section class="chat-sec">
        <div class="chat-sec-t">本次实际发送</div>
        <pre class="chat-sent">{{ sentText }}</pre>
      </section>
    </div>
  </aside>

  <button v-else class="agfab" title="AI 助手" @click="show">AI</button>
</template>

<script setup>
// AgentPanel.vue —— 右侧 AI 抽屉，左边一栏会话（session），右边是对话
//
// 后端 agent.py 跑工具循环：模型点工具 → 后端就地执行（加源/查库/导出…）
// → 结果回喂 → 直到给出答复。前端只管把消息和"操作轨迹"渲染出来，
// 每条助手消息带 steps，导出类的 step 附带可下载文件名。
//
// 对话历史存在后端（data/sessions/<id>.json），换浏览器、刷新页面都还在。
// 前端只记"当前是哪个会话"，会话内容每次切换时从后端拉。

import { computed, nextTick, ref, watch } from 'vue'
import { useRoute } from 'vue-router'
import {
    agentChat, clearSession, createSession, deleteSession, downloadAgentExport,
    getSession, listSessions, renameSession,
} from './api'

const SID_KEY = 'ai_bobao_agent_session'   // 当前会话 id
const OLD_KEY = 'ai_bobao_agent_chat'      // 老版本存 localStorage 的对话，迁移用
const CFG_KEY = 'ai_bobao.agent.cfg'       // 右侧参数面板的设置
const MSG_MAX = 6000

const open = ref(false)
const sessions = ref([])
const curId = ref('')
const msgs = ref([])
const draft = ref('')
const pending = ref(false)
const box = ref(null)
const renaming = ref('')
const renameText = ref('')
const confirmDel = ref('')
const cfgOpen = ref(false)                 // 窄屏下参数面板是否展开
let renameInput = null
let loaded = false

// 参数面板的默认值：temperature 不设 = 不发给模型，max_tokens 0 = 不限制
const DEF_CFG = {
    system_prompt: '',
    context_mode: 'compress',
    context_rounds: 6,
    history_chars: 300,
    temperature: '',
    max_tokens: 0,
}

/** 从 localStorage 读参数，读坏了就用默认值。 */
function loadCfg() {
    try {
        const raw = localStorage.getItem(CFG_KEY)
        if (!raw) return { ...DEF_CFG }
        const o = JSON.parse(raw) || {}
        return { ...DEF_CFG, ...o }
    } catch {
        return { ...DEF_CFG }
    }
}

const cfg = ref(loadCfg())
// 本轮真正发给模型的请求体（后端回带），切会话也不清空
const sent = ref(null)

/** 右下角「本次实际发送」那块显示的 JSON。 */
const sentText = computed(() => {
    if (!sent.value) return '（等待发送）'
    try {
        return JSON.stringify(sent.value, null, 2)
    } catch {
        return '（无法序列化）'
    }
})

// 参数改动立刻落盘，下次打开面板还在
watch(cfg, () => {
    try { localStorage.setItem(CFG_KEY, JSON.stringify(cfg.value)) } catch { /* 空间满了就随缘 */ }
}, { deep: true })

const route = useRoute()

const curTitle = ref('')

/** 用户此刻的界面快照，随每条消息带给 agent 当上下文。 */
function uiContext() {
    const p = route.path, q = route.query || {}
    if (p === '/') {
        const bits = [q.source ? `来源：${q.source}` : '来源：全部']
        if (q.q) bits.push(`搜索词「${q.q}」`)
        if (q.page && q.page !== '1') bits.push(`第 ${q.page} 页`)
        return `漏洞列表（${bits.join(' · ')}）`
    }
    if (p.startsWith('/vuln/')) {
        return `漏洞详情页（ID：${decodeURIComponent(p.slice('/vuln/'.length))}）`
    }
    if (p === '/templates') return 'nuclei 模板库页'
    if (p === '/settings') return '设置页'
    return `页面 ${p}`
}

const examples = [
    '最近 3 个漏洞讲一下',
    '把抓取间隔改成 20 分钟',
    '接入一个新播报源',
    '导出全部漏洞条目给我下载',
]

/** 工具轨迹的入参拼成一行人话，模板里直接显示。 */
function stepsView(steps) {
    return (steps || []).map((s) => ({
        ...s,
        argsText: Object.entries(s.args || {})
            .map(([k, v]) => `${k}=${v}`).join(', ').slice(0, 100),
    }))
}

/** 后端存的一条消息 → 气泡用的消息。 */
function toView(m) {
    if (m.role === 'user') return { role: 'user', content: m.content }
    return { role: 'assistant', content: m.content, steps: stepsView(m.steps) }
}

/** 老版本把对话存在浏览器里，第一次用新版本时搬进后端，省得历史丢了。 */
function readLegacy() {
    try {
        const arr = JSON.parse(localStorage.getItem(OLD_KEY) || '[]')
        return Array.isArray(arr)
            ? arr.filter((m) => m && (m.role === 'user' || m.role === 'assistant') && m.content)
            : []
    } catch {
        return []
    }
}

function fmtTime(iso) {
    if (!iso) return ''
    return String(iso).slice(5, 16).replace('T', ' ')
}

/** 打开面板：第一次打开才去后端拉会话列表。 */
function show() {
    open.value = true
    if (!loaded) {
        loaded = true
        load()
    }
}

/** 拉会话列表，并把当前会话的内容载入。 */
async function load() {
    let list = []
    try {
        const d = await listSessions()
        list = d.sessions || []
    } catch { /* 后端还没起来就先空着 */ }

    if (!list.length) {
        // 老对话迁移：浏览器里存的那几十条，搬成第一个会话
        const legacy = readLegacy()
        if (legacy.length) {
            try {
                const s = await createSession('', legacy.map((m) => ({
                    role: m.role,
                    content: String(m.content).slice(0, MSG_MAX),
                    steps: m.steps || [],
                })))
                try { localStorage.removeItem(OLD_KEY) } catch { /* 无所谓 */ }
                list = [{ id: s.id, title: s.title, count: (s.messages || []).length,
                          updated_at: s.updated_at }]
            } catch { /* 迁移失败就算了，不挡着用 */ }
        }
    }

    sessions.value = list
    const want = safeLocal(SID_KEY) || ''
    const target = list.find((s) => s.id === want) || list[0]
    if (target) await select(target.id)
}

/** 刷新列表（改名/发消息后调用）。 */
async function refreshList() {
    try {
        const d = await listSessions()
        sessions.value = d.sessions || []
        // 首句自动起名后，顶栏要跟着换，不然显示的还是旧标题
        const cur = sessions.value.find((s) => s.id === curId.value)
        if (cur) curTitle.value = cur.title
    } catch { /* 列表刷新失败不影响当前对话 */ }
}

function safeLocal(k) {
    try { return localStorage.getItem(k) || '' } catch { return '' }
}

function setLocal(k, v) {
    try { localStorage.setItem(k, v) } catch { /* 空间满了就随缘 */ }
}

/** 切到某个会话：内容从后端拉，不依赖前端缓存。 */
async function select(id) {
    if (!id) return
    curId.value = id
    setLocal(SID_KEY, id)
    renaming.value = ''
    confirmDel.value = ''
    try {
        const d = await getSession(id)
        msgs.value = (d.messages || []).map(toView)
        curTitle.value = d.title || ''
    } catch {
        msgs.value = []
        curTitle.value = ''
    }
}

/** 新建一个空会话并切过去。 */
async function newSession() {
    try {
        const s = await createSession()
        await refreshList()
        curId.value = ''
        msgs.value = []
        await select(s.id)
        draft.value = ''
    } catch (e) {
        msgs.value.push({ role: 'fail', error: e.message })
    }
}

function startRename(s) {
    renaming.value = s.id
    renameText.value = s.title
    confirmDel.value = ''
    nextTick(() => renameInput?.focus?.())
}

async function saveRename(id) {
    if (renaming.value !== id) return
    const t = renameText.value.trim()
    renaming.value = ''
    if (!t) return
    try {
        await renameSession(id, t)
        await refreshList()
    } catch (e) {
        msgs.value.push({ role: 'fail', error: e.message })
    }
}

async function doDelete(s) {
    confirmDel.value = ''
    const wasCur = curId.value === s.id
    try {
        await deleteSession(s.id)
        await refreshList()
        if (wasCur) {
            curId.value = ''
            msgs.value = []
            curTitle.value = ''
            if (sessions.value.length) await select(sessions.value[0].id)
            else await newSession()
        }
    } catch (e) {
        msgs.value.push({ role: 'fail', error: e.message })
    }
}

/** 清空当前会话的消息，会话本身留着。 */
async function clearChat() {
    if (pending.value || !curId.value) return
    const id = curId.value
    try {
        await clearSession(id)
        if (curId.value === id) msgs.value = []
        await refreshList()
    } catch (e) {
        msgs.value.push({ role: 'fail', error: e.message })
    }
}

function onEnter() {
    if (pending.value || !draft.value.trim()) return
    ask(draft.value.trim())
    draft.value = ''
}

/** 把参数面板的设置整理成后端要的形状。temperature 留空 = 不发给模型。 */
function chatOpts() {
    const c = cfg.value
    const t = c.temperature === '' || c.temperature === null ? null : Number(c.temperature)
    const mt = Number(c.max_tokens) || 0
    return {
        system_prompt: c.system_prompt || '',
        context_mode: c.context_mode || 'compress',
        context_rounds: Number(c.context_rounds) || 6,
        history_chars: Number(c.history_chars) || 300,
        temperature: t === null || Number.isNaN(t) ? null : t,
        max_tokens: mt > 0 ? mt : 0,
    }
}

/** 发一句话给 agent。历史存在后端，前端只带这一句。 */
async function ask(text) {
    if (pending.value) return
    if (!curId.value) await newSession()
    if (!curId.value) return
    const body = text.slice(0, MSG_MAX)
    msgs.value.push({ role: 'user', content: body })
    pending.value = true
    try {
        const r = await agentChat([{ role: 'user', content: body }], uiContext(), curId.value, chatOpts())
        msgs.value.push({
            role: 'assistant',
            content: r.reply || '（空回复）',
            steps: stepsView(r.steps),
        })
        // 后端回带这一轮真正发出去的请求体，右下角照着显示
        if (r.sent) sent.value = r.sent
        await refreshList()
    } catch (e) {
        msgs.value.push({ role: 'fail', error: e.message })
    } finally {
        pending.value = false
    }
}

/** 导出的 JSON 走 blob 下载：接口要求自定义头，不能用裸链接。 */
async function dl(file) {
    try {
        await downloadAgentExport(file)
    } catch (e) {
        msgs.value.push({ role: 'fail', error: e.message })
    }
}

watch(msgs, () => {
    nextTick(() => box.value?.scrollTo({ top: box.value.scrollHeight, behavior: 'smooth' }))
}, { deep: true })
</script>

<style scoped>
.agwrap {
  position: fixed; top: 0; right: 0; bottom: 0;
  width: clamp(880px, 60vw, 1160px); max-width: 100vw;
  background: #101319; border-left: 1px solid #262b36; box-shadow: -8px 0 24px rgba(0, 0, 0, .35);
  display: flex; z-index: 60;
}
/* 左侧会话栏 */
.agside { width: 172px; flex: 0 0 172px; border-right: 1px solid #262b36;
         background: #0c0f14; display: flex; flex-direction: column; }
.agsidehd { display: flex; align-items: center; justify-content: space-between;
            padding: 12px 10px; border-bottom: 1px solid #262b36;
            color: #8b93a1; font-size: 12.5px; }
.agsidelist { flex: 1; overflow-y: auto; padding: 6px; display: flex;
              flex-direction: column; gap: 4px; }
.sitem { padding: 7px 8px; border: 1px solid transparent; cursor: pointer; }
.sitem:hover { background: #14171d; }
.sitem.on { background: #171a21; border-color: #1e4964; }
.stop { display: flex; align-items: center; gap: 4px; }
.stitle { flex: 1; font-size: 12.5px; color: #e6e6e6; white-space: nowrap;
          overflow: hidden; text-overflow: ellipsis; }
.smeta { font-size: 11px; color: #6b7280; margin-top: 2px; }
.sops { display: none; gap: 2px; }
.sitem:hover .sops { display: flex; }
.sask { font-size: 11.5px; color: #f87171; margin-right: auto; }
.srename { width: 100%; background: #0c0e12; color: #e6e6e6; border: 1px solid #1e4964;
            font-size: 12px; padding: 3px 5px; outline: none; font-family: inherit; }
.sempty { color: #6b7280; font-size: 11.5px; text-align: center; padding: 18px 6px;
          line-height: 1.8; }

/* 右侧对话区 */
.agmain { flex: 1; min-width: 0; display: flex; flex-direction: column; }
.aghead { display: flex; align-items: center; gap: 10px; padding: 12px 14px;
          border-bottom: 1px solid #262b36; }
.aghead b { font-size: 14px; }
.aghead .hint { color: #6b7280; font-size: 12px; max-width: 190px; white-space: nowrap;
                overflow: hidden; text-overflow: ellipsis; }
.aghead .space { flex: 1; }
/* 按钮基调：方角 + 天蓝主色 */
button { border: 0; border-radius: 0; cursor: pointer; font-size: 12.5px; }
.g { background: #171a21; color: #7dd3fc; border: 1px solid #1e4964; padding: 5px 10px; }
.g:hover { color: #bae6fd; border-color: #38bdf8; }
.g:disabled { opacity: .5; cursor: not-allowed; }
.g.sm { padding: 2px 7px; line-height: 1.2; }
.mini { background: transparent; color: #6b7280; border: 1px solid #262b36;
        font-size: 11px; padding: 1px 4px; }
.mini:hover { color: #bae6fd; border-color: #38bdf8; }
.mini.danger { color: #f87171; border-color: #7f1d1d; }
.mini.danger:hover { color: #fecaca; border-color: #ef4444; }

.aglist { flex: 1; overflow-y: auto; padding: 14px; display: flex;
          flex-direction: column; gap: 12px; }
.agwelcome { color: #8b93a1; font-size: 13px; line-height: 1.7; display: flex;
             flex-direction: column; gap: 8px; align-items: flex-start; }
.eg { background: #171a21; border: 1px solid #1e4964; color: #7dd3fc;
      border-radius: 0; padding: 6px 12px; text-align: left; }
.eg:hover { border-color: #38bdf8; color: #bae6fd; }
.cap { color: #6b7280; font-size: 12px; }

.row { max-width: 92%; font-size: 13px; line-height: 1.65; white-space: pre-wrap; word-break: break-word; }
.row.me { align-self: flex-end; background: #0ea5e9; color: #f1f5f9;
          border-radius: 10px 10px 2px 10px; padding: 8px 12px; }
.row.ai { align-self: flex-start; display: flex; flex-direction: column; gap: 6px; max-width: 100%; }
.row.ai .bubble { background: #171a21; border: 1px solid #262b36; color: #e6e6e6;
                  border-radius: 10px 10px 10px 2px; padding: 8px 12px; }
.row.fail { align-self: stretch; max-width: 100%; color: #f87171; background: #2a1215;
            border: 1px solid #7f1d1d; border-radius: 8px; padding: 8px 12px; font-size: 12.5px; }
.wait { color: #8b93a1; font-size: 12.5px; }

.steps { background: #0c0e12; border: 1px dashed #262b36; border-radius: 8px;
         padding: 6px 10px; font-size: 12px; color: #8b93a1; max-width: 100%; }
.steps summary { cursor: pointer; color: #6b7280; }
.steps .step { display: flex; flex-wrap: wrap; gap: 4px 8px; padding: 3px 0; align-items: baseline; }
.steps code { font-family: Consolas, monospace; font-size: 11.5px; color: #93c5fd; word-break: break-all; }
.steps .step.bad code { color: #f87171; }
.steps .out { color: #6b7280; }
.steps a { font-size: 11.5px; }

.agfoot { display: flex; align-items: flex-end; gap: 8px; padding: 12px 14px;
          border-top: 1px solid #262b36; }
.agfoot textarea { flex: 1; resize: none; background: #171a21; color: #e6e6e6;
                   border: 1px solid #262b36; border-radius: 8px; padding: 8px 10px;
                   font-size: 13px; font-family: inherit; outline: none; }
.agfoot textarea:focus { border-color: #3b82f6; }
.agfoot textarea::placeholder { color: #6b7280; }
.send { background: #0ea5e9; color: #fff; border-radius: 0; padding: 8px 14px; }
.send:hover { background: #38bdf8; }
.send:disabled { background: #374151; cursor: not-allowed; }

/* 浮钮：跟着全站按钮一起走方角天蓝，不再做圆形 */
.agfab { position: fixed; right: 18px; bottom: 18px; width: 52px; height: 52px;
         border-radius: 0; border: 0; background: #0ea5e9; color: #fff;
         font-size: 15px; font-weight: 600; cursor: pointer; z-index: 60;
         box-shadow: 0 6px 18px rgba(14, 165, 233, .4); }
.agfab:hover { background: #38bdf8; }

/* 最右参数面板：跟会话栏区分开，底色更沉、左侧带一道边 */
.agcfg { width: 330px; flex: 0 0 330px; border-left: 1px solid #262b36;
         background: #0d1016; overflow-y: auto; padding-bottom: 16px; }
.agcfghd { position: sticky; top: 0; z-index: 1; padding: 12px 14px;
           background: #0d1016; border-bottom: 1px solid #262b36;
           color: #8b93a1; font-size: 12.5px; }
.chat-sec { padding: 12px 14px; border-bottom: 1px solid #1a1e26; }
.chat-sec-t { font-size: 12.5px; color: #7dd3fc; margin-bottom: 8px; }
.cfg-row { display: flex; align-items: center; justify-content: space-between;
           gap: 8px; font-size: 12px; color: #8b93a1; margin-bottom: 6px; }
.cfg-row input, .cfg-row select { width: 132px; background: #0c0e12; color: #e6e6e6;
           border: 1px solid #262b36; border-radius: 0; padding: 4px 6px;
           font-size: 12px; font-family: inherit; outline: none; }
.cfg-row input:focus, .cfg-row select:focus { border-color: #1e4964; }
.cfg-area { width: 100%; background: #0c0e12; color: #e6e6e6;
            border: 1px solid #262b36; border-radius: 0; padding: 6px 8px;
            font-size: 12px; font-family: inherit; resize: vertical; outline: none; }
.cfg-area:focus { border-color: #1e4964; }
.cfg-hint { font-size: 11px; color: #6b7280; line-height: 1.6; margin-top: 4px; }
/* 本次实际发送的 JSON：等宽字体，能滚，看得清结构 */
.chat-sent { margin: 0; background: #0c0e12; border: 1px solid #262b36; color: #93c5fd;
             font-family: Consolas, monospace; font-size: 11px; line-height: 1.55;
             padding: 8px; max-height: 220px; overflow: auto; white-space: pre-wrap;
             word-break: break-all; }

/* 窄屏：参数面板改成浮层，用「参数」按钮开合 */
.cfg-toggle { display: none; }
@media (max-width: 1100px) {
  .agwrap { width: 100vw; }
  .cfg-toggle { display: inline-block; }
  .agcfg { position: absolute; top: 0; right: 0; bottom: 0; z-index: 2;
           box-shadow: -8px 0 24px rgba(0, 0, 0, .45); transform: translateX(100%);
           transition: transform .18s ease; }
  .agwrap.cfgopen .agcfg { transform: translateX(0); }
}
@media (max-width: 700px) {
  .agwrap { width: 100vw; }
  .agside { width: 128px; flex: 0 0 128px; }
}
</style>
