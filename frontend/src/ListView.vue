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

    <div class="tabs">
      <button v-for="s in sources" :key="s.name" class="tab"
              :class="{ active: cur === s.name }" @click="pick(s.name)">
        {{ s.name }}<i>{{ s.count }}</i>
      </button>
    </div>

    <div v-if="error" class="error">加载失败：{{ error }}</div>
    <div v-else-if="!items.length" class="empty">该栏目暂无漏洞。</div>

    <div v-for="v in items" :key="v.id" class="card" @click="$router.push(`/vuln/${v.id}`)">
      <div class="row">
        <span class="name">{{ v.name }}</span>
        <span v-if="!v.translated" class="needzh" title="标题/简介还是英文">EN</span>
        <span class="badge" :data-src="v.source">{{ v.source }}</span>
        <span v-if="v.has_nuclei" class="tpl">nuclei</span>
        <span v-if="v.cvss" class="cvss" :class="{ high: v.cvss >= 9 }">CVSS {{ v.cvss }}</span>
        <span v-if="v.entry_date" class="date">{{ v.entry_date }}</span>
      </div>
      <p class="summary">{{ v.summary }}</p>
    </div>

    <div v-if="pages > 1" class="pager">
      <button class="ghost" :disabled="page <= 1" @click="go(page - 1)">上一页</button>
      <span>第 <b>{{ page }}</b> / {{ pages }} 页 · 共 {{ total }} 条</span>
      <button class="ghost" :disabled="page >= pages" @click="go(page + 1)">下一页</button>
    </div>
  </div>
</template>

<script setup>
import { computed, onBeforeUnmount, onMounted, ref } from 'vue'
import { backfillTranslate, collectStatus, listVulns, llmStatus, runCollect } from './api'

const PAGE_SIZE = 10          // 一页 10 条

const items = ref([])
const counts = ref({})
const allTotal = ref(0)
const total = ref(0)
const page = ref(1)
const pages = ref(1)
const error = ref('')
const collecting = ref(false)
const cur = ref('全部')
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

async function load() {
  try {
    const r = await listVulns({
      page: page.value, page_size: PAGE_SIZE,
      source: cur.value === '全部' ? '' : cur.value,
    })
    items.value = r.items
    counts.value = r.counts || {}
    allTotal.value = r.all_total
    total.value = r.total
    pages.value = r.pages
    page.value = r.page
  } catch (e) {
    error.value = e.message
  }
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

function go(p) {
  page.value = Math.max(1, Math.min(p, pages.value))
  load()
}

function pick(name) {
  cur.value = name
  page.value = 1
  load()
}

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

// 离开页面后 ticker 还在跑的话，既白耗 CPU 又在往已卸载组件上写 ref
onBeforeUnmount(() => clearInterval(timer))
</script>

<style scoped>
.toolbar { display: flex; justify-content: space-between; align-items: center; margin-bottom: 12px; color: #8b93a1; font-size: 13px; gap: 12px; }
.btns { display: flex; gap: 8px; }
button { background: #2563eb; color: #fff; border: 0; border-radius: 6px; padding: 8px 14px; cursor: pointer; }
button.ghost { background: #171a21; color: #9ca3af; border: 1px solid #262b36; }
button:disabled { background: #374151; cursor: not-allowed; }
.error { color: #f87171; margin: 12px 0; }
.empty { color: #8b93a1; padding: 40px 0; text-align: center; }

.tabs { display: flex; flex-wrap: wrap; gap: 8px; margin-bottom: 16px; }
.tab { background: #171a21; color: #9ca3af; border: 1px solid #262b36; border-radius: 999px;
  padding: 5px 13px; font-size: 13px; cursor: pointer; }
.tab i { font-style: normal; margin-left: 6px; color: #6b7280; font-size: 11px; }
.tab.active { background: #1d4ed8; color: #fff; border-color: #1d4ed8; }
.tab.active i { color: #bfdbfe; }

.card { background: #171a21; border: 1px solid #262b36; border-radius: 10px; padding: 14px 16px; margin-bottom: 12px; cursor: pointer; transition: border-color .15s; }
.card:hover { border-color: #3b82f6; }
.row { display: flex; align-items: center; gap: 10px; flex-wrap: wrap; }
.name { font-weight: 600; font-size: 15px; flex: 1; min-width: 200px; }
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
</style>
