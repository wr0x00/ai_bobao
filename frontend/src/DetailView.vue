<template>
  <div v-if="error" class="error">加载失败：{{ error }} <a href="#" @click.prevent="back">返回列表</a></div>
  <div v-else-if="!v" class="empty">加载中…</div>
  <div v-else>
    <a href="#" @click.prevent="back">← 返回列表</a>
    <div class="titlerow">
      <h2 class="title">{{ v.name }}</h2>
      <span v-if="v.level && v.level !== '未评级'" class="lvl" :data-lv="v.level" :title="LVLTIP[v.level]">{{ v.level }}</span>
      <button v-if="needZh" class="gen zh" :disabled="!!busy" @click="doTranslate"
              :title="llmOk ? '把漏洞情报译成中文' : '未配置 LLM 密钥，无法翻译'">
        {{ busy === 'zh' ? '翻译中…' : '译成中文' }}
      </button>
    </div>
    <div class="meta">
      <span class="badge">{{ v.source }}</span>
      <span v-if="v.cvss">CVSS {{ v.cvss }}</span>
      <span v-if="v.published">披露 {{ v.published }}</span>
      <span>收录 {{ (v.created_at || '').slice(0, 10) }}</span>
      <span>更新于 {{ fmtTs(v.updated_at || v.created_at) }}</span>
    </div>

    <section><h3>简介</h3><p>{{ v.summary }}</p></section>
    <section><h3>漏洞原理</h3><p class="pre">{{ v.principle }}</p></section>
    <section><h3>攻击范围</h3><p>{{ v.attack_scope }}</p></section>

    <section>
      <h3>
        PoC
        <button class="copy" @click="copy('poc')">{{ copied === 'poc' ? '已复制 ✓' : '复制' }}</button>
        <button class="gen" :disabled="!llmOk || busy !== ''" @click="doGenPoc"
                :title="llmOk ? '按公开思路生成 Python PoC' : '未配置 LLM 密钥，无法生成'">
          {{ busy === 'poc' ? '生成中…' : (v.poc ? '重新生成' : 'AI 生成 PoC') }}
        </button>
      </h3>
      <p v-if="pocMsg" class="err">{{ pocMsg }}</p>
      <template v-if="v.poc">
        <pre class="poc" :class="{ folded: !pocOpen }"><code v-html="pocHtml"></code></pre>
        <button class="fold" @click="pocOpen = !pocOpen">
          {{ pocOpen ? '收起 ▲' : `展开全文（${(v.poc.match(/\n/g) || []).length + 1} 行）▼` }}
        </button>
      </template>
      <p v-else class="none">{{ v.poc_source === 'nuclei'
        ? '该条目来自 nuclei 模板库，只含模板没有独立脚本，可点上方按钮按公开思路生成。'
        : '暂无 PoC。' }}</p>
    </section>

    <section>
      <h3>
        nuclei 模板
        <button class="copy" @click="copy('nuclei')">{{ copied === 'nuclei' ? '已复制 ✓' : '复制' }}</button>
        <button v-if="!v.nuclei_yaml && v.poc_source !== 'nuclei'" class="gen"
                :disabled="genning" @click="gen">
          {{ genning ? '生成中…' : '生成模板' }}
        </button>
      </h3>
      <pre v-if="v.nuclei_yaml" class="yaml"><code v-html="yamlHtml"></code></pre>
      <p v-else class="none">{{ genMsg || '暂无模板。' }}</p>
    </section>

    <section v-if="refLinks.length">
      <h3>原文 / 参考链接</h3>
      <ul class="refs">
        <li v-for="r in refLinks" :key="r.text">
          <!-- href 过不了白名单就只显示文字，宁可点不了也不能让 javascript: 执行 -->
          <a v-if="r.href" :href="r.href" target="_blank" rel="noopener noreferrer">{{ r.text }}</a>
          <span v-else>{{ r.text }}</span>
        </li>
      </ul>
    </section>
  </div>
</template>

<script setup>
// DetailView.vue —— 漏洞详情
//
// 展示一条漏洞的全貌，并挂上三个 AI 加工按钮：译成中文、生成 PoC、生成 nuclei 模板。
// 三者都会改数据，走的都是带令牌的 POST。

import { computed, onMounted, ref, watch } from 'vue'
import { useRoute, useRouter } from 'vue-router'
import { genNuclei, genPoc, getVuln, llmStatus, translateVuln } from './api'
import { safePath, safeUrl } from './safe'
import { LVLTIP } from './rating'

const route = useRoute()
const router = useRouter()
const v = ref(null)
const error = ref('')
const copied = ref('')
const genning = ref(false)
const genMsg = ref('')
const pocMsg = ref('')
const pocOpen = ref(false)       // PoC 默认折叠，长脚本一屏放不下
const busy = ref('')            // '' | 'poc' | 'zh'，区分哪个按钮在转
// 注意 busy 是字符串标记不是布尔，:disabled="busy" 那种写法会恒为真
// （'' 虽然 falsy，但 true || '' 求值成 true，Vue 照样渲染 disabled=""），
// 按钮就永远点不动。判断忙闲一律用 !!busy 或 busy !== ''。
const llmOk = ref(true)         // LLM 不可用时把 AI 按钮置灰
const needZh = ref(false)

// 名称里没有中文字符 = 大概率是 nuclei 英文模板，可以翻译
const hasZh = (s) => /[一-鿿]/.test(s || '')

// ── 更新时间 ─────────────────────────────────────────────
// 后端存的是 UTC ISO（带 +00:00），new Date 解析后按本地时区吐出
// 「2026年10月22日 09:15」；解析失败就把原串兜底展示。
function fmtTs(ts) {
  const d = new Date(String(ts || ''))
  if (isNaN(d)) return String(ts || '—')
  const p = (n) => String(n).padStart(2, '0')
  return `${d.getFullYear()}年${d.getMonth() + 1}月${d.getDate()}日 ` +
    `${p(d.getHours())}:${p(d.getMinutes())}`
}

// ── 代码高亮 ─────────────────────────────────────────────
// PoC（Python/HTTP 混排）和 nuclei 模板（YAML）共用一套轻量着色：
// 注释 / 字符串 / 数字 / 关键字四类。页面 CSP 只放行 self，引第三方
// highlight 库不现实，这几类覆盖九成观感。先整体转义再按 token 包 span，
// 一个 token 都没匹配中也至少是转义过的安全文本，v-html 才敢用。
const HRE = /(#.*|\/\/.*)|("(?:[^"\\\n]|\\.)*"|'(?:[^'\\\n]|\\.)*')|\b(\d+(?:\.\d+)?)\b|\b(import|from|def|class|return|if|elif|else|for|while|try|except|finally|with|as|in|not|and|or|None|True|False|pass|break|continue|lambda|raise|global|assert|yield|exec|eval|open|print|true|false|null|GET|POST|PUT|DELETE|PATCH|OPTIONS)\b/gm

function esc(s) {
  return s.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;')
}

function hilite(src) {
  const s = String(src || '')
  let out = ''
  let last = 0
  for (const m of s.matchAll(HRE)) {
    out += esc(s.slice(last, m.index))
    const cls = m[1] ? 'c' : m[2] ? 's' : m[3] ? 'n' : 'k'
    out += `<span class="h-${cls}">${esc(m[0])}</span>`
    last = m.index + m[0].length
  }
  return out + esc(s.slice(last))
}

const pocHtml = computed(() => hilite(v.value?.poc))
const yamlHtml = computed(() => hilite(v.value?.nuclei_yaml))

// 参考链接要直接进 href，所以每个都过一遍协议白名单。
// safeUrl 返回空串的（比如 javascript:）就只当纯文本显示，不给可点的入口。
const refLinks = computed(() =>
  (v.value?.refs || []).map((text) => ({ text, href: safeUrl(text) })),
)

// 返回列表时回到原来的筛选结果页（搜索词、来源页签、页码都还在）。
// from 来自 URL，必须校验：只接受站内绝对路径，挡掉 //evil.com 这种开放重定向。
const backPath = computed(() => safePath(route.query.from) || '/')

// 优先用浏览器后退，这样详情页不会在历史栈里堆出一串重复的列表页；
// 但直接粘贴 URL 打开详情时没有来路，只能 push 补上。
function back() {
  const prev = String(window.history.state?.back || '')
  if (prev && prev === backPath.value) router.back()
  else router.push(backPath.value)
}

/**
 * 拉一条漏洞的详情。
 *
 * @param {string} id 漏洞 ID
 */
async function load(id) {
  v.value = null
  error.value = ''
  genMsg.value = ''
  pocMsg.value = ''
  pocOpen.value = false
  try {
    v.value = await getVuln(id)
    needZh.value = !hasZh(v.value.name) && !v.value.translated
  } catch (e) {
    error.value = e.message
  }
}

/**
 * 复制一段代码到剪贴板，顺便闪一下「已复制」。
 *
 * @param {'poc'|'nuclei'} which 要复制哪一段
 */
async function copy(which) {
  await navigator.clipboard.writeText(v.value[which === 'poc' ? 'poc' : 'nuclei_yaml'] || '')
  copied.value = which
  setTimeout(() => (copied.value = ''), 1500)
}

/** 让 AI 按公开思路生成一个 Python PoC，写回这条漏洞。 */
async function doGenPoc() {
  busy.value = 'poc'
  pocMsg.value = ''
  try {
    await genPoc(v.value.id)
    await load(v.value.id)
  } catch (e) {
    // 报错落在 PoC 这块，别塞 genMsg —— 那个只在 nuclei 模板区块显示，
    // 写进去的话 PoC 按钮点了跟没点一样，看不出任何异常
    pocMsg.value = e.message
  } finally {
    busy.value = ''
  }
}

/** 把这条漏洞的标题、简介、原理译成中文。 */
async function doTranslate() {
  busy.value = 'zh'
  genMsg.value = ''
  try {
    await translateVuln(v.value.id)
    await load(v.value.id)
  } catch (e) {
    genMsg.value = e.message
  } finally {
    busy.value = ''
  }
}

/** 让 AI 生成 nuclei 模板，生成完自动重载详情。 */
async function gen() {
  genning.value = true
  genMsg.value = ''
  try {
    const r = await genNuclei(v.value.id)
    genMsg.value = r.ok ? '' : r.reason
    if (r.ok) await load(v.value.id)
  } catch (e) {
    genMsg.value = e.message
  } finally {
    genning.value = false
  }
}

onMounted(() => {
  load(route.params.id)
  llmStatus().then((s) => (llmOk.value = s.available)).catch(() => (llmOk.value = false))
})
watch(() => route.params.id, (id) => id && load(id))
</script>

<style scoped>
.error { color: #f87171; }
.empty { color: #8b93a1; padding: 40px 0; text-align: center; }
.title { margin: 14px 0 8px; font-size: 20px; }
.titlerow { display: flex; align-items: center; gap: 12px; flex-wrap: wrap; }
.titlerow .title { margin: 14px 0 8px; }
.meta { display: flex; gap: 14px; color: #8b93a1; font-size: 13px; margin-bottom: 20px; flex-wrap: wrap; align-items: center; }
.badge { background: #262b36; color: #60a5fa; border-radius: 3px; padding: 2px 10px; }
/* 评级标签与列表页同色系（data-lv 定色），悬停 title 出完整标准 */
.lvl { font-size: 12px; padding: 2px 10px; border-radius: 3px; color: #fff; cursor: help; }
.lvl[data-lv="严重"] { background: #dc2626; }
.lvl[data-lv="高危"] { background: #ea580c; }
.lvl[data-lv="中危"] { background: #1d4ed8; }
.lvl[data-lv="低危"] { background: #0ea5e9; }
.lvl[data-lv="未评级"] { background: #262b36; color: #8b93a1; cursor: default; }
section { margin-bottom: 22px; }
section h3 { font-size: 15px; color: #93c5fd; margin-bottom: 8px; display: flex; align-items: center; gap: 10px; }
section p { font-size: 14px; line-height: 1.7; color: #d1d5db; }
.pre { white-space: pre-wrap; }
/* PoC 与 nuclei 模板统一一套代码观感：同底色、同字号同配色基础，
   YAML 长行折行少占横向空间 */
.poc, .yaml { background: #0b0d10; border: 1px solid #262b36; border-radius: 0; padding: 16px;
  overflow-x: auto; font-size: 13px; line-height: 1.6; color: #c9d4e0;
  font-family: Consolas, 'Courier New', monospace; tab-size: 4; }
.yaml { white-space: pre-wrap; }
/* 高亮 token 色（v-html 注入的节点不带 scoped 属性，必须 :deep 穿透） */
.poc :deep(.h-c), .yaml :deep(.h-c) { color: #64748b; font-style: italic; }
.poc :deep(.h-s), .yaml :deep(.h-s) { color: #7ee787; }
.poc :deep(.h-n), .yaml :deep(.h-n) { color: #d2a865; }
.poc :deep(.h-k), .yaml :deep(.h-k) { color: #7dd3fc; }
/* 折叠态：限高 + 底部渐隐，暗示下面还有内容 */
.poc.folded { max-height: 320px; overflow: hidden;
  -webkit-mask-image: linear-gradient(#000 78%, transparent);
  mask-image: linear-gradient(#000 78%, transparent); }
.fold { display: block; margin: 8px auto 0; background: #171a21; border: 1px solid #1e4964;
  color: #7dd3fc; border-radius: 0; padding: 3px 12px; font-size: 12px; cursor: pointer; }
.fold:hover { color: #bae6fd; border-color: #38bdf8; }
.err { color: #f87171; font-size: 13px; }
.none { color: #6b7280; font-size: 13px; }
.copy { background: #171a21; color: #7dd3fc; border: 1px solid #1e4964; border-radius: 0;
  padding: 3px 10px; font-size: 12px; cursor: pointer; }
.copy:hover { color: #bae6fd; border-color: #38bdf8; }
/* 「重新生成」和「生成模板」都只写 class="gen"（后者多个 copy）。
   之前只有 .gen:disabled 有规则，启用态没背景色，浏览器默认灰底灰字，
   看着跟禁用一个样。基础样式补在这，几个 AI 按钮才都有明确配色。 */
.gen { background: #0ea5e9; color: #fff; border: 0; border-radius: 0; padding: 3px 10px;
  font-size: 12px; cursor: pointer; }
.gen:hover { background: #38bdf8; }
.gen:disabled { background: #374151; cursor: not-allowed; opacity: .6; }
.refs { list-style: none; font-size: 12px; color: #8b93a1; word-break: break-all; }
.refs li { margin-bottom: 4px; }
</style>
