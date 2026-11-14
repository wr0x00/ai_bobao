<template>
  <div>
    <div class="syncbar">
      <div class="syncinfo">
        <span class="label">本地复现环境</span>
        <span class="stat">
          资产根目录 <code>{{ root || '未配置' }}</code>
          · 共 {{ items.length }} 个环境
          <template v-if="running"> · {{ running }} 个运行中</template>
          <template v-if="!docker"> · 本机没有 Docker</template>
          <template v-else-if="!dockerEnabled"> · 设置里已关闭 Docker 拉取</template>
        </span>
      </div>
      <div class="syncbtns">
        <button @click="load" :disabled="busy">刷新</button>
        <button class="primary" @click="openBuild" :disabled="busy">按漏洞搭环境</button>
      </div>
    </div>

    <!-- 搭环境：填一条漏洞的 ID，让 LLM 判组件、找下载源、真的拉下来 -->
    <div v-if="building" class="panel">
      <div class="panelrow">
        <input v-model="vid" placeholder="漏洞 ID（可从漏洞详情页地址栏复制，如 CVE-2024-1234）" />
        <button @click="doResolve" :disabled="busy">{{ busy ? '处理中…' : '先看方案' }}</button>
        <button class="primary" @click="doBuild" :disabled="busy || !vid || !plan">按此方案搭建</button>
        <button class="danger" @click="rejectPlan">拒绝，暂停</button>
        <button @click="building = false">关闭</button>
      </div>
      <div v-if="plan" class="plan">
        <div class="planrow"><span class="k">组件</span><span>{{ plan.component || '—' }}</span></div>
        <div class="planrow"><span class="k">版本</span><span>{{ plan.version || '—' }}</span></div>
        <div class="planrow"><span class="k">影响设备/型号</span><span>{{ plan.device || '—' }}</span></div>
        <div class="planrow"><span class="k">来源</span><span>{{ sourceText(plan.source) }}</span></div>
        <div class="planrow"><span class="k">资源</span><span class="mono">{{ plan.image || plan.repo || plan.release || '—' }}</span></div>
        <div class="planrow"><span class="k">预估体积</span><span class="mono size">{{ plan.size_estimate || '方案里没给，谨慎起见先问一句再批' }}</span></div>
        <div class="planrow"><span class="k">启动命令</span><span class="mono">{{ plan.cmd || plan.run || '—' }}</span></div>
        <div class="planrow"><span class="k">端口</span><span>{{ (plan.ports || []).join(', ') || '—' }}</span></div>
        <div v-if="!plan.available" class="planwarn">拿不到程序本体：{{ plan.reason || '网上没有公开的可下载程序' }}</div>
      </div>
    </div>

    <!-- 内联 AI 对话框：就摆在漏洞 ID 输入框下面，不浮动、不压住环境卡片。
         能力跟右下角那个 AI 助手一样：LLM 进度自动播报 + 对话输入 + 工具调用轨迹。 -->
    <section class="aichat">
      <header class="aichathd">
        <b>AI 助手 · 环境搭建</b>
        <span class="hint">LLM 每一步都会播出来，也可以直接吩咐我</span>
        <span class="space"></span>
        <button class="mini" :disabled="aiPending" @click="clearAi">清空</button>
      </header>

      <div ref="aiBox" class="aichatlist">
        <div v-if="!aiMsgs.length" class="aichatwelcome">
          <p>我就在这儿盯着环境搭建，LLM 的每一步都会播出来。也可以直接吩咐我：</p>
          <button v-for="eg in aiExamples" :key="eg" class="aieg" @click="aiAsk(eg)">{{ eg }}</button>
          <p class="acap">能做的事：出复现方案、搭建环境、打 PoC 验证、改写 PoC、列出/启动/停止环境。</p>
        </div>

        <template v-for="(m, i) in aiMsgs" :key="i">
          <div v-if="m.role === 'user'" class="airow me">{{ m.content }}</div>
          <div v-else-if="m.role === 'assistant' || m.role === 'ai'" class="airow ai">
            <div class="aibubble">{{ m.content }}</div>
            <details v-if="m.steps && m.steps.length" class="aisteps" :open="false">
              <summary>执行了 {{ m.steps.length }} 步操作</summary>
              <div v-for="(s, j) in m.steps" :key="j" class="astep" :class="{ bad: !s.ok }">
                <code>{{ s.ok ? '✔' : '✘' }} {{ s.tool }}({{ s.argsText }})</code>
                <span class="aout">{{ s.out }}</span>
                <a v-if="s.file" href="#" @click.prevent="dl(s.file)">下载 {{ s.file }}</a>
              </div>
            </details>
          </div>
          <div v-else-if="m.role === 'fail'" class="airow fail">{{ m.content }}</div>
          <div v-else class="airow sys">{{ m.content }}</div>
        </template>

        <div v-if="aiPending" class="airow ai wait">AI 正在处理，可能要几十秒…</div>
      </div>

      <div class="aichatfoot">
        <textarea v-model="aiDraft" rows="2" :disabled="aiPending"
                  placeholder="输入想做的事，Enter 发送，Shift+Enter 换行"
                  @keydown.enter.exact.prevent="aiSend"></textarea>
        <button class="send" :disabled="aiPending || !aiDraft.trim()" @click="aiSend">
          {{ aiPending ? '…' : '发送' }}
        </button>
      </div>

      <details v-if="aiSent" class="aisent">
        <summary>本次实际发送</summary>
        <pre>{{ aiSentText }}</pre>
      </details>
    </section>

    <div v-if="msg" class="msg">{{ msg }}</div>
    <div v-if="error" class="error">出错了：{{ error }}</div>
    <div v-else-if="!items.length" class="empty">
      还没有环境。去漏洞详情页点「搭复现环境」，或者在这里填漏洞 ID。
    </div>

    <div v-for="e in items" :key="e.id" class="card">
      <div class="row">
        <span class="name">{{ e.component || '(未命名组件)' }}</span>
        <span class="ver">{{ e.version || '—' }}</span>
        <span class="tag" :data-st="e.status">{{ statusText(e.status) }}</span>
        <span class="src">{{ sourceText(e.source) }}</span>
      </div>

      <p v-if="e.device" class="desc">影响设备 / 型号：{{ e.device }}</p>
      <p v-if="e.image" class="desc mono">镜像 <code>{{ e.image }}</code></p>
      <p v-if="e.repo" class="desc mono">源码 <code>{{ e.repo }}</code></p>
      <p v-if="e.release" class="desc mono">发布包 <code>{{ e.release }}</code></p>
      <p v-if="e.cmd || e.run" class="desc mono">启动 <code>{{ e.cmd || e.run }}</code></p>
      <p v-if="e.ports && e.ports.length" class="desc">端口 {{ e.ports.join(', ') }}</p>
      <div v-if="e.target_url" class="desc targetrow">
        靶站
        <a class="target" :href="e.target_url" target="_blank" rel="noopener">{{ e.target_url }}</a>
        <button v-if="e.status === 'running'" class="mini" @click="togglePreview(e)">
          {{ previewId === e.id ? '收起预览' : '预览' }}
        </button>
      </div>
      <div v-if="e.verify" class="verify" :data-ok="String(e.verify.reproduced)">
        <span class="vk">PoC 验证</span>
        <span class="vverdict">{{ verifyText(e.verify) }}</span>
        <span class="vtime">{{ (e.verify.at || '').slice(0, 19).replace('T', ' ') }}</span>
        <button v-if="e.verify.reproduced === false && e.vulns && e.vulns.length"
                class="mini regenbtn" @click="doRegenPoc(e)" :disabled="busy">
          更新 PoC
        </button>
        <pre v-if="e.verify.output" class="vout">{{ e.verify.output }}</pre>
      </div>
      <p v-if="e.reason" class="desc warn">{{ e.reason }}</p>

      <div class="vulns">
        <span class="k">关联漏洞</span>
        <template v-if="e.vulns && e.vulns.length">
          <a v-for="v in e.vulns" :key="v" href="#" class="vlink" @click.prevent="openVuln(v)">{{ v }}</a>
          <span class="sharehint">{{ e.vulns.length > 1 ? '（多漏洞共享同一环境）' : '' }}</span>
        </template>
        <span v-else class="dim">—</span>
      </div>

      <div class="ops">
        <button v-if="e.status === 'running' || e.status === 'starting'" @click="doStop(e)" :disabled="busy">停止</button>
        <button v-else-if="e.status === 'ready'" class="primary" @click="doStart(e)" :disabled="busy">启动</button>
        <button v-if="e.vulns && e.vulns.length" class="verifybtn"
                @click="doVerify(e)" :disabled="busy">打 PoC 验证</button>
        <button @click="showDetail(e)">详情</button>
        <button class="danger" @click="doDelete(e)" :disabled="busy">删除</button>
      </div>
      <!-- 站点预览：直接在页面里手工验证，不用切出去开新标签 -->
      <iframe v-if="previewId === e.id && e.status === 'running' && e.target_url"
              class="preview" :src="e.target_url"></iframe>

      <div v-if="detail && detail.id === e.id" class="detail">
        <div class="planrow"><span class="k">落盘目录</span><span class="mono">{{ detail.dir }}</span></div>
        <div class="planrow"><span class="k">源码</span><span class="mono">{{ detail.assets.source || '—' }}</span></div>
        <div class="planrow"><span class="k">程序</span><span class="mono">{{ detail.assets.binary || '—' }}</span></div>
        <div class="planrow"><span class="k">容器</span><span class="mono">{{ detail.container || '—' }}</span></div>
        <div v-if="detail.log" class="planrow"><span class="k">日志</span><span class="mono logtext">{{ detail.log }}</span></div>
      </div>
    </div>

  </div>
</template>

<script setup>
// EnvView.vue —— 本地复现环境
//
// 这里是所有漏洞验证环境的中枢：LLM 按漏洞播报里的「影响设备和型号」去全网或
// Docker 找程序本体，找到就拉下来落到统一目录，找不到（闭源 / 没公开下载）就放弃。
// 环境按「组件+版本+来源」算指纹，同一份程序多条漏洞共用，所以放在这一页集中管。
//
// 本组件被 App.vue 的 <keep-alive include="EnvView"> 缓存：切页面时组件不卸载，
// 进度轮询和 AI 对话框播报照常跑，回来时方案、消息、进行中的搭建全都在。
// keep-alive 靠组件名匹配，所以必须有 defineOptions({ name: 'EnvView' })。

defineOptions({ name: 'EnvView' })

import { computed, nextTick, onMounted, ref, watch } from 'vue'
import { useRoute, useRouter } from 'vue-router'
import { agentChat, buildEnv, clearSession, createSession, delEnv, downloadAgentExport,
         genPoc, getEnv, listEnvs, resolveEnv, startEnv, stopEnv, verifyEnv } from './api'

const route = useRoute()
const router = useRouter()

const items = ref([])
const root = ref('')
const docker = ref(false)
const dockerEnabled = ref(true)
const busy = ref(false)
const error = ref('')
const msg = ref('')
const building = ref(false)
const vid = ref('')
const plan = ref(null)
const detail = ref(null)

// 规划请求的取消器。LLM 网关一挂，规划能卡好几分钟（服务端还会重试），
// 期间 busy 一直为真，面板上所有按钮都会被禁用——用户连「拒绝，暂停」都点不了。
// 留个 AbortController，「拒绝，暂停」就能真的把它掐掉。
let resolveCtrl = null
// 搭建请求是否还在飞。搭建一旦开拉就在服务器那边跑着，浏览器掐不断，
// 所以拒绝时要如实告诉用户：停下来的是规划，不是已经开拉的构建。
let buildInFlight = false

const running = computed(() => items.value.filter((e) => e.status === 'running').length)

/** 状态标签的中文说法。building/starting 是中间态：正在搭/容器起了服务还没监听。 */
function statusText(s) {
  return { ready: '就绪', starting: '启动中', building: '搭建中', running: '运行中',
           failed: '构建失败', abandoned: '已放弃' }[s] || s
}

/** 来源类型的中文说法。 */
function sourceText(s) {
  return { docker: 'Docker 镜像', source: '源码仓库', release: '官方发布包', none: '无' }[s] || s
}

/** PoC 验证结论的中文说法。 */
function verifyText(rec) {
  const v = rec.reproduced
  const tag = v === true ? '✓ 已复现' : v === false ? '✗ 未复现' : '? 待人工确认'
  return `${tag} —— ${rec.verdict || ''}`
}

/** 拿库里这条漏洞的 PoC 真打这个环境（没起会顺手拉起来）。 */
async function doVerify(e) {
  busy.value = true
  error.value = ''
  msg.value = '正在执行 PoC，环境没启动会自动拉起，稍等…'
  aiSay('sys', `开始对 ${e.component || e.id} 执行 PoC 验证（环境没启动会自动拉起）…`)
  try {
    const r = await verifyEnv(e.id)
    const rec = r.verify || {}
    if (rec.reproduced === true) msg.value = `复现成功：${rec.verdict}`
    else if (rec.reproduced === false) msg.value = `未复现：${rec.verdict}`
    else msg.value = `待人工确认：${rec.verdict}`
    aiSay('sys', `${msg.value}`)
    await load()
  } catch (err) {
    error.value = err.message
    aiSay('sys', `验证出错：${err.message}`)
  } finally {
    busy.value = false
  }
}

/** 更新 PoC：让 AI 参考上次失败的输出重写 PoC，写完自动再打一轮，直到复现。 */
async function doRegenPoc(e) {
  const vid = (e.vulns || [])[0]
  if (!vid) return
  busy.value = true
  msg.value = 'AI 正在参考上次失败输出重写 PoC…'
  aiSay('sys', `上次没复现。让 AI 读失败输出重写 ${vid} 的 PoC，写完自动再打一轮。`)
  try {
    await genPoc(vid)
    aiSay('sys', 'PoC 已重写落库，自动开始新一轮验证…')
    busy.value = false
    await doVerify(e)
  } catch (err) {
    error.value = err.message
    aiSay('sys', `更新 PoC 失败：${err.message}`)
    busy.value = false
  }
}

/** 拉环境列表。 */
async function load() {
  error.value = ''
  try {
    const r = await listEnvs()
    items.value = r.items || []
    root.value = r.root || ''
    docker.value = !!r.docker
    dockerEnabled.value = !!r.docker_enabled
  } catch (e) {
    error.value = e.message
  }
}

/** 打开「搭环境」面板。 */
function openBuild() {
  building.value = true
  plan.value = null
  msg.value = ''
  error.value = ''
}

/** 把 LLM 的方案翻译成一句句人话，逐行播进 AI 框——用户不打开方案面板
 *  也能看清 LLM 判定了什么、打算从哪拿程序本体、要占多少磁盘。 */
function planNarrate(p) {
  if (!p) { aiSay('ai', 'LLM 没返回有效方案。'); return }
  const src = { docker: 'Docker Hub 现成镜像', source: 'GitHub 源码仓库',
                release: '官方发布包直链' }[p.source] || p.source
  const res = p.source === 'docker' ? (p.image || '（镜像名缺失）')
    : p.source === 'release' ? (p.release || '（直链缺失）')
    : [p.repo ? `${p.repo}${p.ref ? ' @ ' + p.ref : ''}` : '',
       ...(p.overlay || []).map((o) =>
         `补充仓库 ${o.repo}${o.ref ? ' @ ' + o.ref : ''} → ${o.dest}/`)].filter(Boolean).join('；') || '（仓库缺失）'
  aiSay('ai', `LLM 规划完成：复现 ${p.component || '?'} ${p.version || ''}` +
    (p.device ? `（影响设备：${p.device}）` : ''))
  aiSay('ai', `程序本体来源：${src}——${res}`)
  if (p.size_estimate) aiSay('ai', `预估磁盘占用：${p.size_estimate}`)
  if (p.port_map && p.port_map.length) {
    aiSay('ai', '端口映射：' + p.port_map.map((m) => `宿主机 ${m.host} → 容器 ${m.container}`).join('、'))
  } else if (p.ports && p.ports.length) {
    aiSay('ai', `端口：${p.ports.join('、')}`)
  }
  if (p.reason) aiSay('ai', `LLM 说明：${p.reason}`)
  if (p.available) {
    aiSay('sys', '方案已出，看上面几条就是 LLM 的判断。点「按此方案搭建」我就开拉；不放心点「拒绝，暂停」。')
  } else {
    aiSay('sys', 'LLM 判定拿不到程序本体，规划终止——理由在上面。可以换个漏洞试试。')
  }
}

/** 只出方案，不拉东西。先看看 LLM 打算搭什么再决定要不要真搭。 */
async function doResolve() {
  if (!vid.value.trim()) { error.value = '先填漏洞 ID'; return }
  busy.value = true
  error.value = ''
  msg.value = ''
  aiSay('sys', `正在把漏洞 ${vid.value.trim()} 交给 LLM 规划复现方案（判断组件/版本、从哪拿程序本体、要占多少磁盘）…`)
  const ctrl = new AbortController()
  resolveCtrl = ctrl
  // 最多等 200 秒：服务端单次 60 秒、超时还重试两次，兜住整轮。
  // 再久用户就该以为页面死了，不如早点报失败让人重试。
  const timer = setTimeout(() => ctrl.abort('timeout'), 200000)
  try {
    const r = await resolveEnv(vid.value.trim(), { signal: ctrl.signal })
    plan.value = r.plan
    planNarrate(r.plan)
  } catch (e) {
    if (ctrl.signal.aborted) {
      // 用户点的「拒绝，暂停」不算出错，别拿红色报错吓人
      if (ctrl.signal.reason === 'timeout') {
        error.value = '规划超时（LLM 200 秒没回），点「先看方案」重试'
        aiSay('sys', '规划超时了，已放弃这次规划。点「先看方案」可以重试。')
      }
    } else {
      error.value = e.message
      aiSay('sys', `规划失败：${e.message}`)
    }
  } finally {
    clearTimeout(timer)
    if (resolveCtrl === ctrl) resolveCtrl = null
    busy.value = false
  }
}

/** 拒绝方案：只出方案不动手。体积太大、来源可疑、纯粹不想搭——理由用户自己定，
 *  这里只负责把方案收起来、状态挂起，什么时候想搭了再「先看方案」。
 *
 *  规划还在飞就顺手掐掉：LLM 网关挂住时这一次请求能拖好几分钟，
 *  用户能点的唯一出口就是这里，不能因为「方案还没出来」把按钮禁掉。 */
function rejectPlan() {
  if (resolveCtrl) {
    resolveCtrl.abort('rejected')
    resolveCtrl = null
  }
  busy.value = false
  plan.value = null
  if (buildInFlight) {
    // 搭建已经在服务器那边开跑了，浏览器这边掐不断，得说清楚
    msg.value = '搭建已经在后台继续（服务器那边停不下来），不会自动开打 PoC；想彻底停掉，去下面环境卡片点「停止」。'
    aiSay('sys', msg.value)
    return
  }
  msg.value = '已拒绝方案，搭建暂停。想重新规划就再点「先看方案」。'
  aiSay('sys', '方案已拒绝，搭建暂停。想重新规划随时点「先看方案」。')
}

/** 真去搭环境：按用户审批过的方案拉程序/源码/镜像 → 落盘。
 *  没有审批过的方案就先规划等审批，绝不跳过用户直接开拉。
 *  搭建要几分钟，起一个轮询把 building → ready/failed 的状态变化播进 AI 框。 */
async function doBuild() {
  if (!vid.value.trim()) { error.value = '先填漏洞 ID'; return }
  if (!plan.value) { error.value = '方案还没审批：先「出方案」，看一眼再按此方案搭建'; return }
  busy.value = true
  error.value = ''
  msg.value = ''
  const target = vid.value.trim()
  aiSay('sys', `已批准方案，开始为 ${target} 搭建复现环境，拉源码/构建镜像要几分钟，进展我会随时播报。`)
  startPoll(target)
  buildInFlight = true
  try {
    const r = await buildEnv(target, plan.value)
    stopPoll()
    if (r.abandoned) {
      msg.value = `已放弃：${r.reason}`
      aiSay('sys', `已放弃：${r.reason}`)
      building.value = false
    } else if (r.shared) {
      msg.value = `复用已有环境（${r.env.component || r.env.id}），没有重复拉`
      aiSay('sys', `复用已有环境（${r.env.component || r.env.id}），没有重复拉取。`)
      building.value = false
    } else if (r.ok) {
      const u = r.env.target_url || ''
      msg.value = `靶站已搭好并自动启动：${r.env.component || ''} ${r.env.version || ''}` +
        (u ? `，地址 ${u}` : '')
      aiSay('sys', `搭建完成${u ? `，真实容器已经跑起来了，浏览器打开 ${u} 就能手工验证` : ''}。` +
        `也可以直接让我「打 PoC 验证」，或点卡片上的「预览」在页面里看站点。`)
      building.value = false
      // 自动启动走的是 starting → running，别急着停轮询：等健康检查转正再播一句
      if (u) awaitRunning(target)
      else stopPoll()
    } else {
      error.value = r.reason || '构建失败'
      aiSay('sys', `构建失败：${r.reason || '未知原因'}`)
    }
    await load()
  } catch (e) {
    stopPoll()
    error.value = e.message
    aiSay('sys', `搭建请求出错：${e.message}`)
  } finally {
    buildInFlight = false
    busy.value = false
  }
}

// ── 内联 AI 对话框：进度播报 + 对话指挥 ───────────────────
// 原来挂在左下角做浮动框，会把左下角的环境卡片压住；现在改成页面流里的
// 一个方框，就摆在漏洞 ID 输入框下面：LLM 每一步都往里播，也随时能直接指挥。
// 没有会话栏、没有参数面板，只有播报 + 一个输入框；对话仍走 /api/agent/chat。
const aiMsgs = ref([])
const aiDraft = ref('')
const aiPending = ref(false)
const aiSid = ref('')
const aiBox = ref(null)
const aiSent = ref(null)      // 本轮真正发给模型的请求体（后端回带）
let pollTimer = null

// 欢迎语里的示例，点一下就直接发给 agent
const aiExamples = [
  '列出现在的环境',
  '给当前漏洞出一份复现方案',
  '帮我打一次 PoC 验证',
]

/** 本轮实际发送的请求体，右下角那块「本次实际发送」显示的内容。 */
const aiSentText = computed(() => {
  if (!aiSent.value) return ''
  try { return JSON.stringify(aiSent.value, null, 2) } catch { return '（无法序列化）' }
})

/** 往框里塞一条消息并滚到底。 */
function aiSay(role, content, steps) {
  aiMsgs.value.push({ role, content, steps })
  nextTick(() => aiBox.value?.scrollTo({ top: aiBox.value.scrollHeight, behavior: 'smooth' }))
}

/** 搭建期间轮询环境列表，状态一变就播报。 */
function startPoll(targetVid) {
  stopPoll()
  let last = ''
  pollTimer = setInterval(async () => {
    try {
      const r = await listEnvs()
      const e = (r.items || []).find((x) => (x.vulns || []).includes(targetVid))
      if (!e) return
      const sig = `${e.id}:${e.status}`
      if (sig !== last) {
        const text = { building: '规划完成，正在拉取程序本体/构建镜像…',
                       starting: '容器已创建，等服务真正监听…',
                       ready: `就绪：${e.component || ''} ${e.version || ''}`,
                       running: '服务已监听，能打了',
                       failed: '构建失败', abandoned: '已放弃' }[e.status] || e.status
        if (last) aiSay('sys', `〔进度〕${text}`)
        last = sig
      }
    } catch { /* 轮询失败不打扰用户 */ }
  }, 2000)
}

function stopPoll() {
  if (pollTimer) { clearInterval(pollTimer); pollTimer = null }
}

/** 自动启动后接着盯 starting → running，健康检查一过就播"能打了"。 */
async function awaitRunning(targetVid) {
  for (let i = 0; i < 30; i++) {
    await new Promise((res) => setTimeout(res, 2000))
    try {
      const r = await listEnvs()
      const e = (r.items || []).find((x) => (x.vulns || []).includes(targetVid))
      if (!e) break
      if (e.status === 'running') {
        aiSay('sys', `〔进度〕服务已监听，能打了。靶站 ${e.target_url} 可以打开手工验证。`)
        break
      }
      if (e.status === 'failed' || e.status === 'abandoned') {
        aiSay('sys', `〔进度〕${statusText(e.status)}：${e.reason || ''}`)
        break
      }
    } catch { break }
  }
  stopPoll()
}

// ── 站点预览 ──────────────────────────────────────────────
const previewId = ref('')

function togglePreview(e) {
  previewId.value = previewId.value === e.id ? '' : e.id
}

/** 工具轨迹的入参拼成一行人话，模板里直接显示。 */
function stepsView(steps) {
  return (steps || []).map((s) => ({
    ...s,
    argsText: Object.entries(s.args || {}).map(([k, v]) => `${k}=${v}`).join(', ').slice(0, 100),
  }))
}

/** 发一句话给 agent。会话懒创建，历史存服务端，切页面回来还在。 */
async function aiAsk(text = '') {
  const t = String(text || aiDraft.value || '').trim()
  if (!t || aiPending.value) return
  aiDraft.value = ''
  aiSay('user', t)
  aiPending.value = true
  try {
    if (!aiSid.value) {
      const s = await createSession('复现环境助手')
      aiSid.value = s.id
    }
    const ui = `本地复现环境页（/envs）${vid.value ? `，当前漏洞：${vid.value}` : ''}`
    const r = await agentChat([{ role: 'user', content: t }], ui, aiSid.value)
    aiSent.value = r.sent || null
    aiSay('assistant', r.reply || '（空回复）', stepsView(r.steps))
  } catch (e) {
    aiSay('fail', `出错了：${e.message}`)
  } finally {
    aiPending.value = false
  }
}

/** 发送按钮 / 回车都走这里。 */
function aiSend() {
  aiAsk()
}

/** 清空这个框（服务端的会话消息也一起清，免得 agent 还记着上一轮）。 */
async function clearAi() {
  if (aiPending.value) return
  aiMsgs.value = []
  aiSent.value = null
  if (aiSid.value) {
    try { await clearSession(aiSid.value) } catch { /* 清不掉就算了 */ }
  }
}

/** 导出的 JSON 走 blob 下载：接口要自定义头，裸链接带不上。 */
async function dl(file) {
  try {
    await downloadAgentExport(file)
  } catch (e) {
    aiSay('fail', `下载失败：${e.message}`)
  }
}

/** 启动环境。 */
async function doStart(e) {
  busy.value = true
  error.value = ''
  msg.value = ''
  try {
    const r = await startEnv(e.id)
    msg.value = r.message || '已启动'
    await load()
  } catch (e) {
    error.value = e.message
  } finally {
    busy.value = false
  }
}

/** 停止环境。 */
async function doStop(e) {
  busy.value = true
  error.value = ''
  msg.value = ''
  try {
    const r = await stopEnv(e.id)
    msg.value = r.message || '已停止'
    await load()
  } catch (e) {
    error.value = e.message
  } finally {
    busy.value = false
  }
}

/** 删除环境。容器、源码、程序一起清掉，关联的漏洞也解除关联。 */
async function doDelete(e) {
  if (!confirm(`删除环境「${e.component || e.id}」？源码、程序、容器都会一并清掉。`)) return
  busy.value = true
  error.value = ''
  msg.value = ''
  try {
    await delEnv(e.id)
    msg.value = '已删除'
    if (detail.value && detail.value.id === e.id) detail.value = null
    await load()
  } catch (e) {
    error.value = e.message
  } finally {
    busy.value = false
  }
}

/** 看详情：落盘目录和各类资产的位置。 */
async function showDetail(e) {
  error.value = ''
  try {
    detail.value = await getEnv(e.id)
  } catch (e) {
    error.value = e.message
  }
}

/** 跳到关联的漏洞详情页。 */
function openVuln(v) {
  router.push(`/vuln/${encodeURIComponent(v)}`)
}

/** 从漏洞详情页跳过来时自动开搭：/envs?vid=xxx。 */
function autoBuildFromQuery() {
  const qvid = String(route.query.vid || '').trim()
  if (!qvid) return
  vid.value = qvid
  building.value = true
  // 自动只做到「出方案」这一步：方案必须用户审批后才开拉
  doResolve().then(() => {
    if (plan.value && plan.value.available) {
      aiSay('sys', `方案已出（${plan.value.component || ''} ${plan.value.version || ''}，` +
        `来源：${plan.value.source}，${plan.value.size_estimate || '体积未知'}）。` +
        '看一眼方案，点「按此方案搭建」我就开拉；不放心点「拒绝，暂停」。')
    } else if (plan.value) {
      aiSay('sys', `规划结论：拿不到程序本体。${plan.value.reason || ''}`)
    }
  })
  // 用完就把 query 抹掉：刷新页面不会重走一遍
  router.replace({ query: { ...route.query, vid: undefined } })
}

/** 刷新页面后接管还在进行的搭建：列表里有 building 的环境就把轮询和播报接回去。 */
async function recoverBuilding() {
  try {
    const r = await listEnvs()
    const building = (r.items || []).find((e) => e.status === 'building')
    if (!building) return
    aiSay('sys', `检测到进行中的搭建（${building.component || building.id}，` +
      `关联 ${(building.vulns || []).join(', ') || '未知漏洞'}），已接回播报，进度我会继续跟。`)
    startPoll((building.vulns || [])[0] || building.id)
  } catch { /* 列表都拿不到就算了，别阻塞首屏 */ }
}

onMounted(() => {
  load()
  autoBuildFromQuery()
  recoverBuilding()
})
watch(() => route.query.vid, (nv, ov) => {
  if (nv && nv !== ov && route.path === '/envs') autoBuildFromQuery()
})
</script>

<style scoped>
.syncbar { display: flex; justify-content: space-between; align-items: center; flex-wrap: wrap; gap: 10px;
  background: #171a21; border: 1px solid #262b36; border-radius: 10px; padding: 12px 16px; margin-bottom: 14px; }
.syncinfo { display: flex; flex-direction: column; gap: 4px; }
.syncinfo .label { font-size: 13px; font-weight: 600; }
.syncinfo .stat { font-size: 12px; color: #6b7280; }
.syncinfo code { background: #262b36; padding: 1px 5px; border-radius: 4px; color: #9ca3af; word-break: break-all; }
.syncbtns { display: flex; gap: 8px; }

.panel { background: #171a21; border: 1px solid #262b36; border-radius: 10px; padding: 12px 16px; margin-bottom: 14px; }
.panelrow { display: flex; flex-wrap: wrap; gap: 8px; align-items: center; }
.panelrow input { flex: 1; min-width: 240px; }

.plan { margin-top: 12px; border-top: 1px solid #262b36; padding-top: 10px; }
.planrow { display: flex; gap: 10px; font-size: 12px; padding: 3px 0; }
.planrow .k { color: #6b7280; width: 92px; flex: none; }
.planwarn { margin-top: 8px; color: #fbbf24; font-size: 12px; }

.mono { font-family: ui-monospace, Consolas, monospace; word-break: break-all; }
.logtext { white-space: pre-wrap; max-height: 160px; overflow: auto; display: block; }

.card { background: #171a21; border: 1px solid #262b36; border-radius: 10px; padding: 14px 16px; margin-bottom: 12px; }
.row { display: flex; align-items: center; gap: 10px; flex-wrap: wrap; }
.name { font-weight: 600; font-size: 15px; }
.ver { color: #9ca3af; font-size: 13px; }
.tag { font-size: 11px; padding: 2px 8px; border-radius: 3px; background: #262b36; color: #9ca3af; }
.tag[data-st="ready"] { background: #0c4a6e; color: #bae6fd; }
.tag[data-st="running"] { background: #14532d; color: #86efac; }
.tag[data-st="failed"] { background: #7f1d1d; color: #fca5a5; }
.tag[data-st="abandoned"] { background: #422006; color: #fcd34d; }
.src { font-size: 11px; color: #6b7280; margin-left: auto; }

.desc { margin-top: 7px; color: #9ca3af; font-size: 13px; line-height: 1.6; }
.desc code { background: #262b36; padding: 1px 5px; border-radius: 4px; }
.desc.warn { color: #fbbf24; }

.vulns { margin-top: 9px; display: flex; gap: 8px; align-items: center; flex-wrap: wrap; font-size: 12px; }
.vulns .k { color: #6b7280; }
.vlink { color: #5aa7ff; font-family: ui-monospace, Consolas, monospace; }
.sharehint { color: #6b7280; }
.dim { color: #4b5563; }

.detail { margin-top: 10px; border-top: 1px solid #262b36; padding-top: 10px; }

.verify { margin-top: 9px; border: 1px solid #262b36; border-radius: 6px; padding: 8px 10px;
  display: flex; flex-direction: column; gap: 4px; font-size: 12px; }
.verify .vk { color: #6b7280; }
.verify .vverdict { color: #9ca3af; }
.verify[data-ok="true"] { border-color: #14532d; }
.verify[data-ok="true"] .vverdict { color: #86efac; }
.verify[data-ok="false"] .vverdict { color: #fca5a5; }
.verify .vtime { color: #4b5563; }
.verify .vout { margin: 4px 0 0; background: #0d1017; padding: 8px; border-radius: 4px;
  max-height: 180px; overflow: auto; white-space: pre-wrap; word-break: break-all;
  font-family: ui-monospace, Consolas, monospace; font-size: 11px; color: #8b93a1; }

/* 靶站地址与站点预览 */
.targetrow { display: flex; align-items: center; gap: 8px; flex-wrap: wrap; }
.target { color: #7dd3fc; font-family: ui-monospace, Consolas, monospace; }
.target:hover { text-decoration: underline; }
button.mini { padding: 2px 9px; font-size: 11px; }
.preview { width: 100%; height: 440px; border: 1px solid #262b36; border-radius: 6px;
  margin-top: 10px; background: #fff; }

.ops { margin-top: 12px; display: flex; gap: 8px; flex-wrap: wrap; }
button { background: #171a21; color: #7dd3fc; border: 1px solid #1e4964; border-radius: 0;
  padding: 6px 13px; font-size: 13px; cursor: pointer; }
button:hover { color: #bae6fd; border-color: #38bdf8; }
button.primary { background: #0ea5e9; color: #fff; border-color: #0ea5e9; }
button.primary:hover { background: #38bdf8; }
button.danger { color: #fca5a5; border-color: #7f1d1d; }
button.danger:hover { color: #fecaca; border-color: #ef4444; }
button:disabled { background: #374151; color: #cbd5e1; cursor: wait; border-color: #374151; }

input { background: #171a21; color: #e6e6e6; border: 1px solid #262b36; border-radius: 6px;
  padding: 7px 10px; font-size: 13px; }

.msg { color: #34d399; font-size: 13px; margin-bottom: 10px; }
.error { color: #f87171; margin: 12px 0; }
.empty { color: #8b93a1; padding: 40px 0; text-align: center; }

/* ── 内联 AI 对话框（跟在漏洞 ID 输入框下面） ── */
.aichat { background: #101319; border: 1px solid #262b36; border-radius: 10px;
  margin-bottom: 14px; overflow: hidden; }
.aichathd { display: flex; align-items: center; gap: 10px; padding: 10px 14px;
  border-bottom: 1px solid #262b36; }
.aichathd b { font-size: 13.5px; color: #93c5fd; }
.aichathd .hint { color: #6b7280; font-size: 12px; }
.aichathd .space { flex: 1; }
.aichathd button.mini { padding: 3px 10px; font-size: 12px; }

.aichatlist { max-height: 460px; overflow-y: auto; padding: 12px 14px;
  display: flex; flex-direction: column; gap: 10px; }
.aichatwelcome { color: #8b93a1; font-size: 13px; line-height: 1.7;
  display: flex; flex-direction: column; gap: 8px; align-items: flex-start; }
.aichatwelcome p { margin: 0; }
.aieg { background: #171a21; border: 1px solid #1e4964; color: #7dd3fc;
  padding: 6px 12px; text-align: left; font-size: 12.5px; }
.aieg:hover { border-color: #38bdf8; color: #bae6fd; }
.acap { color: #6b7280; font-size: 12px; }

.airow { max-width: 92%; font-size: 13px; line-height: 1.65;
  white-space: pre-wrap; word-break: break-word; }
.airow.me { align-self: flex-end; background: #0ea5e9; color: #f1f5f9;
  border-radius: 10px 10px 2px 10px; padding: 8px 12px; }
.airow.ai { align-self: flex-start; display: flex; flex-direction: column;
  gap: 6px; max-width: 100%; }
.aibubble { background: #171a21; border: 1px solid #262b36; color: #e6e6e6;
  border-radius: 10px 10px 10px 2px; padding: 8px 12px; }
.airow.sys { align-self: stretch; max-width: 100%; color: #8b93a1; font-size: 12.5px; }
.airow.sys::before { content: '▸ '; color: #4b5563; }
.airow.fail { align-self: stretch; max-width: 100%; color: #f87171; background: #2a1215;
  border: 1px solid #7f1d1d; border-radius: 8px; padding: 8px 12px; font-size: 12.5px; }
.airow.wait { color: #8b93a1; font-size: 12.5px; }

/* 工具调用轨迹：折叠起来是一行摘要，展开看工具名、入参和输出 */
.aisteps { background: #0c0e12; border: 1px dashed #262b36; border-radius: 8px;
  padding: 6px 10px; font-size: 12px; color: #8b93a1; max-width: 100%; }
.aisteps summary { cursor: pointer; color: #6b7280; }
.aisteps .astep { display: flex; flex-wrap: wrap; gap: 4px 8px; padding: 3px 0;
  align-items: baseline; }
.aisteps code { font-family: Consolas, monospace; font-size: 11.5px; color: #93c5fd;
  word-break: break-all; }
.aisteps .astep.bad code { color: #f87171; }
.aisteps .aout { color: #6b7280; }
.aisteps a { font-size: 11.5px; }

.aichatfoot { display: flex; align-items: flex-end; gap: 8px; padding: 10px 14px;
  border-top: 1px solid #262b36; }
.aichatfoot textarea { flex: 1; resize: none; background: #171a21; color: #e6e6e6;
  border: 1px solid #262b36; border-radius: 8px; padding: 8px 10px;
  font-size: 13px; font-family: inherit; outline: none; }
.aichatfoot textarea:focus { border-color: #3b82f6; }
.aichatfoot textarea::placeholder { color: #6b7280; }
.aichatfoot .send { background: #0ea5e9; color: #fff; border: none; padding: 8px 14px; }
.aichatfoot .send:hover { background: #38bdf8; }
.aichatfoot .send:disabled { background: #374151; color: #cbd5e1; cursor: not-allowed; }

.aisent { padding: 0 14px 12px; }
.aisent summary { cursor: pointer; color: #6b7280; font-size: 11.5px; }
.aisent pre { margin: 6px 0 0; background: #0c0e12; border: 1px solid #262b36;
  color: #93c5fd; font-family: Consolas, monospace; font-size: 11px; line-height: 1.55;
  padding: 8px; max-height: 200px; overflow: auto; white-space: pre-wrap; word-break: break-all; }

/* 中间态标签色：building 橙黄（在拉东西）、starting 蓝（容器起了服务还没监听） */
.tag[data-st="building"] { background: #3b2f0b; color: #fde68a; }
.tag[data-st="starting"] { background: #172554; color: #93c5fd; }
</style>
