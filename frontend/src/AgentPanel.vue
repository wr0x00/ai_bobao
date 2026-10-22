<template>
  <aside v-if="open" class="agwrap">
    <div class="aghead">
      <b>AI 助手</b>
      <span class="hint">加源 · 查库 · 导出 · 改设置</span>
      <span class="space"></span>
      <button class="g" :disabled="pending" @click="clearChat">清空</button>
      <button class="g x" title="收起面板" @click="open = false">✕</button>
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
  </aside>

  <button v-else class="agfab" title="AI 助手" @click="open = true">AI</button>
</template>

<script setup>
// AgentPanel.vue —— 右侧 AI 对话抽屉
//
// 后端 agent.py 跑工具循环：模型点工具 → 后端就地执行（加源/查库/导出…）
// → 结果回喂 → 直到给出答复。前端只管把消息和"操作轨迹"渲染出来，
// 每条助手消息带 steps，导出类的 step 附带可下载文件名。
//
// 对话留在 localStorage：刷新不丢，最多 60 条，超出最早的丢。

import { nextTick, ref, watch } from 'vue'
import { useRoute } from 'vue-router'
import { agentChat, downloadAgentExport } from './api'

const STORE_KEY = 'ai_bobao_agent_chat'
const MAX_KEEP = 60

const open = ref(false)
const msgs = ref(load())
const draft = ref('')
const pending = ref(false)
const box = ref(null)

const route = useRoute()

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

function load() {
  try {
    const arr = JSON.parse(localStorage.getItem(STORE_KEY) || '[]')
    return Array.isArray(arr) ? arr.filter((m) => m && m.role && m.content) : []
  } catch {
    return []
  }
}

watch(msgs, (v) => {
  // 错误行不进持久层，下回刷新就干净了
  const keep = v.filter((m) => m.role === 'user' || m.role === 'assistant').slice(-MAX_KEEP)
  try {
    localStorage.setItem(STORE_KEY, JSON.stringify(keep))
  } catch { /* 空间满了就随缘 */ }
  nextTick(() => box.value?.scrollTo({ top: box.value.scrollHeight, behavior: 'smooth' }))
}, { deep: true })

function onEnter() {
  if (pending.value || !draft.value.trim()) return
  ask(draft.value.trim())
  draft.value = ''
}

/** 发一句话给 agent。历史只带 user/assistant 的纯文本，错误行不算数。 */
async function ask(text) {
  msgs.value.push({ role: 'user', content: text })
  pending.value = true
  try {
    const history = msgs.value.filter((m) => m.role === 'user' || m.role === 'assistant')
      .map(({ role, content }) => ({ role, content }))
    const r = await agentChat(history, uiContext())
    msgs.value.push({
      role: 'assistant',
      content: r.reply || '（空回复）',
      steps: (r.steps || []).map((s) => ({
        ...s, argsText: Object.entries(s.args || {})
          .map(([k, v]) => `${k}=${v}`).join(', ').slice(0, 100),
      })),
    })
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

function clearChat() {
  if (pending.value) return
  msgs.value = []
}
</script>

<style scoped>
.agwrap {
  position: fixed; top: 0; right: 0; bottom: 0; width: 400px; max-width: 100vw;
  background: #101319; border-left: 1px solid #262b36; box-shadow: -8px 0 24px rgba(0, 0, 0, .35);
  display: flex; flex-direction: column; z-index: 60;
}
.aghead { display: flex; align-items: center; gap: 10px; padding: 12px 14px;
          border-bottom: 1px solid #262b36; }
.aghead b { font-size: 14px; }
.aghead .hint { color: #6b7280; font-size: 12px; }
.aghead .space { flex: 1; }
/* 按钮基调：方角 + 天蓝主色 */
button { border: 0; border-radius: 0; cursor: pointer; font-size: 12.5px; }
.g { background: #171a21; color: #7dd3fc; border: 1px solid #1e4964; padding: 5px 10px; }
.g:hover { color: #bae6fd; border-color: #38bdf8; }
.g:disabled { opacity: .5; cursor: not-allowed; }
.g.x { padding: 5px 8px; }

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

@media (max-width: 480px) {
  .agwrap { width: 100vw; }
}
</style>
