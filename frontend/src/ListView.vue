<template>
  <div>
    <div class="toolbar">
      <span>{{ statusText }}</span>
      <div class="btns">
        <button class="ghost" :disabled="!pagePending || !llmOk || translating" @click="translatePage"
                :title="llmOk ? '把本页漏洞的标题、简介、原理全部译成中文' : '未配置 LLM 密钥，无法翻译'">
          {{ translating ? `翻译中 ${done}/${pagePending}` : (pagePending ? `翻译本页 ${pagePending} 条英文漏洞` : '本页已中文化') }}
        </button>
        <button :disabled="collecting" @click="collect">
          {{ collecting ? '抓取中（AI 生成 PoC，约几分钟）…' : '立即抓取' }}
        </button>
      </div>
    </div>

    <!-- 总览：统计图直接嵌在列表页搜索栏上方，不再单独占一页 -->
    <OverviewPanel />

    <div class="searchbar">
      <input v-model="kw" type="search" placeholder="搜索标题、CVE 编号、漏洞原理…（空格分隔多个关键词）"
             @keyup.enter="search" />
      <select v-model="level" class="flt" title="按漏洞评级筛选" @change="applyFilter">
        <option value="">全部评级</option>
        <option v-for="l in LEVELS" :key="l" :value="l">{{ l }}</option>
      </select>
      <select v-model.number="days" class="flt" title="按更新时间筛选（最近 N 天）" @change="applyFilter">
        <option :value="0">全部时间</option>
        <option :value="1">今天</option>
        <option :value="3">近 3 天</option>
        <option :value="7">近 7 天</option>
        <option :value="30">近 30 天</option>
      </select>
      <button class="ghost" :disabled="!kw && !level && !days" @click="clearAll">清空</button>
      <span v-if="kw || level || days" class="hit">命中 {{ total }} 条</span>
    </div>

    <div class="tabs">
      <button v-for="s in sources" :key="s.name" class="tab"
              :class="{ active: cur === s.name }" @click="pick(s.name)">
        {{ s.name }}<i>{{ s.count }}</i>
      </button>
    </div>

    <div v-if="error" class="error">加载失败：{{ error }}</div>
    <div v-else-if="!items.length" class="empty">{{ kw ? `没有匹配「${kw}」的漏洞。` : '该栏目暂无漏洞。' }}</div>

    <div class="vgrid">
      <div v-for="v in items" :key="v.id" class="card" @click="openVuln(v.id)">
        <div class="row">
          <span class="name">{{ v.name }}</span>
          <span class="lvl" :data-lv="v.level" :title="LVLTIP[v.level]">{{ v.level }}</span>
          <span v-if="!v.translated" class="needzh" title="标题/简介还是英文">EN</span>
          <span class="badge" :data-src="v.source">{{ v.source }}</span>
          <span v-if="v.has_nuclei" class="tpl">nuclei</span>
          <span v-if="v.cvss" class="cvss" :class="{ high: v.cvss >= 9 }">CVSS {{ v.cvss }}</span>
          <span class="date">更新 {{ (v.updated || v.entry_date || '').slice(0, 10) }}</span>
        </div>
        <p class="summary">{{ v.summary }}</p>
      </div>
    </div>

    <div v-if="pages > 1" class="pager">
      <button class="ghost" :disabled="page <= 1" @click="go(page - 1)">上一页</button>
      <span>第 <b>{{ page }}</b> / {{ pages }} 页 · 共 {{ total }} 条</span>
      <button class="ghost" :disabled="page >= pages" @click="go(page + 1)">下一页</button>
    </div>
  </div>
</template>

<script setup>
// ListView.vue —— 漏洞列表（首页）
//
// 这一页只干一件事：把筛选状态和地址栏 query 保持同步。
// 搜索词、来源页签、页码三样都写在 URL 上，所以刷新、进详情再返回、
// 浏览器前进后退，结果都能一模一样地还原。

import { computed, onBeforeUnmount, onMounted, ref, watch } from 'vue'
import { useRoute, useRouter } from 'vue-router'
import { backfillTranslate, collectStatus, listVulns, llmStatus, runCollect } from './api'
import OverviewPanel from './OverviewPanel.vue'
import { LVLTIP } from './rating'

const PAGE_SIZE = 20          // 一页 20 条：两列布局下正好 10 行

const route = useRoute()
const router = useRouter()

const items = ref([])
const counts = ref({})
const allTotal = ref(0)
const total = ref(0)
// 初始值从 URL 里取：刷新页面后搜索词、页签、页码都还在
const page = ref(Math.max(1, parseInt(route.query.page, 10) || 1))
const pages = ref(1)
const error = ref('')
const collecting = ref(false)
const cur = ref(String(route.query.source || '全部'))
const kw = ref(String(route.query.q || ''))   // 搜索框内容，回车/清空时才真正拿去查
// 过滤器：评级 + 更新时间范围。初值也从 URL 里取，刷新后筛选状态不丢
const LEVELS = ['严重', '高危', '中危', '低危', '未评级']
const level = ref(String(route.query.level || ''))
const days = ref(Math.max(0, parseInt(route.query.days, 10) || 0))
const st = ref(null)
const llmOk = ref(true)         // LLM 不可用时置灰 AI 按钮
const translating = ref(false)
const done = ref(0)

// 后端已把 translated 算好，这里只数本页还有几条英文
const pagePending = computed(() => items.value.filter((i) => !i.translated).length)
const sources = computed(() => [
  { name: '全部', count: allTotal.value },
  ...Object.entries(counts.value).map(([name, c]) => ({ name, count: c })),
])

// 距下次自动更新还有多久。后端给的 next_run 是「上次开跑时刻 + 间隔」，
// 是静态时间戳，得靠本地 ticker 每秒重算一次，不然数字不会动。
const now = ref(Date.now())
let timer = null

const countdown = computed(() => {
  const target = st.value?.next_run
  if (!target) return ''
  // 后端 isoformat 不带时区，当成本地时间处理（浏览器在同一台机器上）
  const left = new Date(target).getTime() - now.value
  if (left <= 0) return '00:00:00'
  const h = String(Math.floor(left / 3600000)).padStart(2, '0')
  const m = String(Math.floor((left % 3600000) / 60000)).padStart(2, '0')
  const s = String(Math.floor((left % 60000) / 1000)).padStart(2, '0')
  return `${h}:${m}:${s}`
})

const statusText = computed(() => {
  if (!st.value) return `共 ${allTotal.value} 个已收录漏洞`
  const last = st.value.last_run
    ? `上次抓取 ${st.value.last_run.slice(5, 16).replace('T', ' ')}` : '尚未抓取'
  const nxt = countdown.value ? ` · 下次更新 ${countdown.value}` : ''
  return `共 ${allTotal.value} 个已收录漏洞 · ${last} · 每 ${st.value.interval_minutes} 分钟自动更新${nxt}`
})

/**
 * 按当前筛选条件重新拉一页数据。
 * 后端返回的页码是权威的（越界时它会自己纠正），所以拿它覆盖本地的 page。
 */
async function load() {
  try {
    const r = await listVulns({
      page: page.value, page_size: PAGE_SIZE,
      source: cur.value === '全部' ? '' : cur.value,
      q: kw.value.trim(),
      level: level.value,
      days: days.value || undefined,
    })
    items.value = r.items
    counts.value = r.counts || {}
    allTotal.value = r.all_total
    total.value = r.total
    pages.value = r.pages
    page.value = r.page
    syncUrl()
  } catch (e) {
    error.value = e.message
  }
}

// 把当前筛选状态写回地址栏。刷新页面、切详情再返回，都靠这串 query 还原现场。
// 用 replace 而不是 push，免得用户每搜一次就多一条历史记录，按返回键要按好几下。

/**
 * 摊出当前筛选条件对应的 query 对象。
 *
 * @returns {{q?: string, source?: string, page?: string}} 只含需要保留的字段，默认值不带
 */
function currentQuery() {
  const q = {}
  if (kw.value.trim()) q.q = kw.value.trim()
  if (cur.value !== '全部') q.source = cur.value
  if (page.value > 1) q.page = String(page.value)
  if (level.value) q.level = level.value
  if (days.value) q.days = String(days.value)
  return q
}

/** 把筛选状态同步到地址栏。 */
function syncUrl() {
  router.replace({ path: '/', query: currentQuery() })
}

// 进详情页时把当前列表地址带上，详情页的「返回列表」就能原路退回，
// 而不是把用户丢回全量首页。
/**
 * 打开漏洞详情。
 *
 * @param {string} id 漏洞 ID
 */
function openVuln(id) {
  const from = router.resolve({ path: '/', query: currentQuery() }).fullPath
  router.push({ path: `/vuln/${id}`, query: { from } })
}

// 拉状态不阻塞列表渲染：LLM 状态接口慢，不能让它把列表卡住
async function loadStatus() {
  try {
    st.value = await collectStatus()
    const s = await llmStatus()
    llmOk.value = s.available
  } catch (e) {
    llmOk.value = false
  }
}

/**
 * 翻页。顺手把越界的页码夹回有效范围。
 *
 * @param {number} p 目标页码
 */
function go(p) {
  page.value = Math.max(1, Math.min(p, pages.value))
  load()
}

/**
 * 切来源页签。换了来源就回到第一页，不然可能停在新来源里不存在的那一页。
 *
 * @param {string} name 来源名，「全部」也是一个正常的值
 */
function pick(name) {
  cur.value = name
  page.value = 1
  load()
}

/** 按当前搜索词重新查一遍。换关键词后必须回第一页，否则停在新关键词的第 5 页上会是空列表。 */
function search() {
  page.value = 1
  load()
}

/** 切换评级/时间筛选。跟搜索一样要回第一页，不然停在新筛选不存在的那一页。 */
function applyFilter() {
  page.value = 1
  load()
}

/** 清空整条查询栏：关键词 + 评级 + 时间一起复位。 */
function clearAll() {
  kw.value = ''
  level.value = ''
  days.value = 0
  page.value = 1
  load()
}

/** 把本页所有英文漏洞交给后端批量翻译。 */
async function translatePage() {
  translating.value = true
  done.value = 0
  error.value = ''
  const ids = items.value.filter((i) => !i.translated).map((i) => i.id)
  try {
    const r = await backfillTranslate(ids.length, ids)
    done.value = r.ok
    if (r.failed.length) error.value = `${r.ok} 条已译，${r.failed.length} 条失败：${r.failed[0].reason}`
    await load()
  } catch (e) {
    error.value = e.message
  } finally {
    translating.value = false
  }
}

/** 手动触发一次抓取。跑完自动刷新列表。 */
async function collect() {
  collecting.value = true
  try {
    await runCollect()
    await load()
  } catch (e) {
    error.value = e.message
  } finally {
    collecting.value = false
  }
}

onMounted(() => {
  load()
  loadStatus()
  timer = setInterval(() => (now.value = Date.now()), 1000)
})

// 地址栏里的 query 变了（浏览器前进/后退、或用户手改地址）就照着重新拉一次。
// syncUrl 写回的是同一份状态，比较相同就不动，避免自己触发自己死循环。
watch(() => route.query, (q) => {
  const nq = String(q.q || '')
  const nsrc = String(q.source || '全部')
  const np = Math.max(1, parseInt(q.page, 10) || 1)
  const nl = String(q.level || '')
  const nd = Math.max(0, parseInt(q.days, 10) || 0)
  if (nq === kw.value.trim() && nsrc === cur.value && np === page.value
      && nl === level.value && nd === days.value) return
  kw.value = nq
  cur.value = nsrc
  page.value = np
  level.value = nl
  days.value = nd
  load()
})

// 离开页面后 ticker 还在跑的话，既白耗 CPU 又在往已卸载组件上写 ref
onBeforeUnmount(() => clearInterval(timer))
</script>

<style scoped>
.toolbar { display: flex; justify-content: space-between; align-items: center; margin-bottom: 12px; color: #8b93a1; font-size: 13px; gap: 12px; }
.btns { display: flex; gap: 8px; }
/* ── 按钮基调：方角 + 天蓝主色，页面背景仍是黑 ── */
button { background: #0ea5e9; color: #fff; border: 0; border-radius: 0; padding: 8px 14px; cursor: pointer; }
button:hover { background: #38bdf8; }
button.ghost { background: #171a21; color: #7dd3fc; border: 1px solid #1e4964; }
button.ghost:hover { background: #171a21; color: #bae6fd; border-color: #38bdf8; }
button:disabled { background: #374151; cursor: not-allowed; }
.error { color: #f87171; margin: 12px 0; }
.empty { color: #8b93a1; padding: 40px 0; text-align: center; }

.searchbar { display: flex; align-items: center; gap: 10px; margin-bottom: 14px; }
/* 搜索框不要撑满整行：flex:1 会让它拉成 860px，一条短关键词看着像输入栏坏了。
   给个 320px 的上限，窄屏再 flex-shrink 缩下去。 */
.searchbar input { flex: 0 1 320px; min-width: 160px; background: #171a21; color: #e6e6e6;
  border: 1px solid #262b36; border-radius: 6px; padding: 8px 12px; font-size: 13px; outline: none; }
/* 过滤下拉：与搜索框同一套暗底；focus 用天蓝，呼应全站主色 */
.searchbar .flt { background: #171a21; color: #e6e6e6; border: 1px solid #262b36;
  border-radius: 6px; padding: 7px 8px; font-size: 13px; outline: none; cursor: pointer; }
.searchbar .flt:focus, .searchbar input:focus { border-color: #38bdf8; }
.searchbar .flt option { background: #171a21; }
.searchbar input::placeholder { color: #6b7280; }
.searchbar button { padding: 8px 14px; font-size: 13px; }
.hit { color: #8b93a1; font-size: 13px; white-space: nowrap; }

.tabs { display: flex; flex-wrap: wrap; gap: 8px; margin-bottom: 16px; }
.tab { background: #171a21; color: #9ca3af; border: 1px solid #262b36; border-radius: 0;
  padding: 5px 13px; font-size: 13px; cursor: pointer; }
.tab i { font-style: normal; margin-left: 6px; color: #6b7280; font-size: 11px; }
.tab.active { background: #0ea5e9; color: #fff; border-color: #0ea5e9; }
.tab.active i { color: #e0f2fe; }

/* 漏洞卡片两列网格：页面放宽后单列太空，两列一屏能看更多。
   minmax(0,1fr) 防止长标题把列撑破；窄屏退回单列。 */
.vgrid { display: grid; grid-template-columns: repeat(2, minmax(0, 1fr)); gap: 12px; margin-bottom: 12px; }
.card { background: #171a21; border: 1px solid #262b36; border-radius: 10px; padding: 14px 16px; cursor: pointer; transition: border-color .15s; }
.card:hover { border-color: #38bdf8; }
.row { display: flex; align-items: center; gap: 10px; flex-wrap: wrap; }
.name { font-weight: 600; font-size: 15px; flex: 1; min-width: 200px; }
/* 评级色块：小圆角长方形，悬停 title 给出该级完整说明 */
.lvl { font-size: 11px; padding: 2px 8px; border-radius: 3px; color: #fff; flex: none; cursor: help; }
.lvl[data-lv="严重"] { background: #dc2626; }
.lvl[data-lv="高危"] { background: #ea580c; }
.lvl[data-lv="中危"] { background: #1d4ed8; }
.lvl[data-lv="低危"] { background: #0ea5e9; }
.lvl[data-lv="未评级"] { background: #262b36; color: #8b93a1; cursor: default; }
.badge { font-size: 11px; padding: 2px 8px; border-radius: 999px; background: #262b36; color: #9ca3af; }
.badge[data-src="nvd"] { color: #60a5fa; }
.badge[data-src="nuclei-git"] { color: #34d399; }
.badge[data-src="nuclei-remote"] { color: #34d399; }
.badge[data-src="mock"] { color: #fbbf24; }
.badge[data-src="先知"] { color: #f472b6; }
.badge[data-src="freebuf"] { color: #fb923c; }
.badge[data-src="exploit-db"] { color: #a78bfa; }
.needzh { font-size: 10px; padding: 2px 6px; border-radius: 4px; background: #422006; color: #fcd34d; }
.tpl { font-size: 11px; padding: 2px 8px; border-radius: 999px; background: #422006; color: #fcd34d; }
.cvss { font-size: 12px; color: #f87171; font-variant-numeric: tabular-nums; }
.date { font-size: 11px; color: #6b7280; font-variant-numeric: tabular-nums; }
.summary { margin-top: 8px; color: #9ca3af; font-size: 13px; line-height: 1.6;
  display: -webkit-box; -webkit-line-clamp: 2; -webkit-box-orient: vertical; overflow: hidden; }

.pager { display: flex; align-items: center; justify-content: center; gap: 14px; margin: 20px 0 8px; color: #8b93a1; font-size: 13px; }
.pager b { color: #e6e6e6; }
.pager button { padding: 6px 14px; font-size: 13px; }

@media (max-width: 860px) {
  .vgrid { grid-template-columns: 1fr; }
}
</style>
