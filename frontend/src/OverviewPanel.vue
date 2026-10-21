<template>
  <section class="ov">
    <div class="head">
      <h2>总览 <small v-if="at">统计于 {{ at }}</small></h2>
      <div class="mini">
        <span>近 7 天新增 <b>{{ s.last7 }}</b></span>
        <span>带 nuclei 模板 <b>{{ s.with_tpl }}</b></span>
        <span>已中文化 <b>{{ s.translated }}</b></span>
      </div>
      <button class="ghost" :disabled="busy" @click="load">{{ busy ? '刷新中…' : '刷新' }}</button>
    </div>

    <div v-if="error" class="error">加载失败：{{ error }}</div>
    <div v-else-if="!s.total" class="empty">{{ busy ? '统计中…' : '库还是空的，抓一轮就有了。' }}</div>

    <div v-else class="cols">
      <!-- 左：各组件漏洞数量。条形图缩小展示，后端拼的「其他（N 项）」汇总行不画 -->
      <div class="col-bars">
        <h3>各组件漏洞数量 <small>Top {{ comp.length }}</small></h3>
        <svg class="bars" :viewBox="`0 0 ${BAR_W} ${barHeight}`" role="img" aria-label="各组件漏洞数量条形图">
          <g v-for="(r, i) in comp" :key="r.name">
            <text class="lab" :x="LABEL_W - 6" :y="barY(i) + 4" text-anchor="end">{{ r.name }}</text>
            <rect class="bg" :x="LABEL_W" :y="barY(i)" :width="BAR_MAX" :height="ROW_H - 7" rx="3" />
            <rect class="bar" :x="LABEL_W" :y="barY(i)" :width="barW(r.n)" :height="ROW_H - 7" rx="3"
                  :fill="r.color" />
            <text class="num" :x="LABEL_W + barW(r.n) + 6" :y="barY(i) + 4">{{ r.n }}</text>
          </g>
        </svg>
      </div>

      <!-- 右：各平台来源占比。鼠标停在色环/图例上浮出名称和占比 -->
      <div class="col-donut">
        <h3>各平台漏洞来源占比 <small>{{ donut.length }} 个来源</small></h3>
        <div class="donut-wrap">
          <svg class="donut" viewBox="0 0 180 180" role="img" aria-label="各平台漏洞来源占比环状图">
            <g transform="rotate(-90 90 90)">
              <circle v-for="d in donut" :key="d.name" cx="90" cy="90" :r="R"
                      fill="none" :stroke="d.color" :stroke-width="SW"
                      :stroke-dasharray="d.dash" :stroke-dashoffset="d.offset"
                      @mouseenter="showTip(d, $event)" @mousemove="moveTip" @mouseleave="hideTip" />
            </g>
            <text class="dtotal" x="90" y="87" text-anchor="middle">{{ s.total }}</text>
            <text class="dsub" x="90" y="103" text-anchor="middle">条漏洞</text>
          </svg>
          <ul class="legend">
            <li v-for="d in donut" :key="d.name">
              <i :style="{ background: d.color }"></i>
              <span class="lname">{{ d.name }}</span>
              <span class="lnum">{{ d.pct }}%</span>
            </li>
          </ul>
        </div>
      </div>
    </div>

    <!-- 悬停提示浮层：fixed 定位跟鼠标走，pointer-events 保证不挡住圆环本身 -->
    <div v-if="tip.on" class="tip" :style="{ left: tip.x + 'px', top: tip.y + 'px' }">
      <b>{{ tip.name }}</b><span>{{ tip.n }} 条 · {{ tip.pct }}%</span>
    </div>
  </section>
</template>

<script setup>
// OverviewPanel.vue —— 总览面板（嵌在列表页搜索栏上方，不再是独立页面）
//
// 左边条形图看「哪些组件的漏洞最多」，右边环状图看「漏洞从哪些平台来」。
// 图表是内联 SVG 手画的，不引图表库：页面 CSP 是 script-src 'self'，
// CDN 引 ECharts/Chart.js 会被直接拦掉；自己算百来行还能精确控配色。

import { computed, onMounted, reactive, ref } from 'vue'
import { getStats } from './api'

// 条形图几何（紧凑版）
const LABEL_W = 118   // 左边标签列宽
const BAR_MAX = 300   // 最长条长度
const ROW_H = 22      // 每行高
const BAR_W = LABEL_W + BAR_MAX + 44

// 环状图几何
const R = 62          // 圆环半径
const SW = 20         // 圆环粗细
const CIRC = 2 * Math.PI * R

// 调色板。来源二十来个，单色系分不开，一次给足颜色轮着上。
const PALETTE = [
  '#60a5fa', '#f472b6', '#34d399', '#fbbf24', '#a78bfa', '#fb923c',
  '#22d3ee', '#f87171', '#4ade80', '#e879f9', '#facc15', '#38bdf8',
  '#c084fc', '#2dd4bf', '#fb7185', '#a3e635', '#f9a8d4', '#7dd3fc',
  '#fdba74', '#c7d2fe',
]

const s = ref({ total: 0, last7: 0, with_tpl: 0, translated: 0,
                by_source: {}, by_component: [] })
const busy = ref(false)
const error = ref('')
const at = ref('')

// 悬停提示状态。坐标用 clientX/Y 配 position:fixed，滚到哪都贴着鼠标。
const tip = reactive({ on: false, x: 0, y: 0, name: '', n: 0, pct: 0 })

/** 取第 i 个颜色。超出调色板长度按取模循环。 */
function colorAt(i) {
  return PALETTE[i % PALETTE.length]
}

/**
 * 条形图数据：后端按数量降序给了 Top 20，末尾会把零散组件并成
 * 「其他（N 项）」一行——这一行数量动辄几百，会把其他条全压扁，
 * 按需求不画它；这里只取前 10 个具体组件。
 */
const comp = computed(() =>
  (s.value.by_component || [])
    .filter((c) => !String(c[0]).startsWith('其他'))
    .slice(0, 10)
    .map((c, i) => ({ name: c[0], n: c[1], color: colorAt(i) })))

/** 条形图每行的 y 坐标。 */
function barY(i) {
  return 5 + i * ROW_H
}

const barHeight = computed(() => 10 + comp.value.length * ROW_H)

/** 某条的长度：按最大值等比缩放，条最大刚好占满 BAR_MAX。 */
function barW(n) {
  const max = comp.value.length ? comp.value[0].n : 1
  return max ? Math.max(3, Math.round((n / max) * BAR_MAX)) : 0
}

/**
 * 环状图分段。每段一段圆弧：stroke-dasharray 给"实线—空白"，
 * stroke-dashoffset 挪到起始位置，从 12 点顺时针排下去。
 */
const donut = computed(() => {
  const entries = Object.entries(s.value.by_source || {}).sort((a, b) => b[1] - a[1])
  const total = entries.reduce((acc, [, n]) => acc + n, 0) || 1
  let acc = 0
  return entries.map(([name, n], i) => {
    const len = (n / total) * CIRC
    const d = {
      name,
      n,
      color: colorAt(i),
      pct: Math.round((n / total) * 1000) / 10,
      dash: `${len} ${CIRC - len}`,
      offset: -acc,
    }
    acc += len
    return d
  })
})

/** 鼠标进入某个色环：记下这段对应的名称与占比，浮层跟着鼠标走。 */
function showTip(d, e) {
  tip.on = true
  tip.name = d.name
  tip.n = d.n
  tip.pct = d.pct
  moveTip(e)
}

/** 鼠标在色环上移动：浮层贴住光标右下角。 */
function moveTip(e) {
  tip.x = e.clientX + 14
  tip.y = e.clientY + 14
}

/** 离开色环：收起浮层。 */
function hideTip() {
  tip.on = false
}

/** 拉一次统计。失败就把后端给的原因显示出来，不静默吞掉。 */
async function load() {
  busy.value = true
  error.value = ''
  try {
    s.value = await getStats()
    at.value = new Date().toLocaleString('zh-CN', { hour12: false })
  } catch (e) {
    error.value = e.message
  } finally {
    busy.value = false
  }
}

onMounted(load)
</script>

<style scoped>
.ov { background: #14171e; border: 1px solid #262b36; border-radius: 10px;
      padding: 14px 18px 16px; margin-bottom: 14px; }
.head { display: flex; align-items: center; gap: 16px; margin-bottom: 12px; }
.head h2 { font-size: 14px; font-weight: 600; color: #e6e6e6; }
.head h2 small { color: #6b7280; font-weight: 400; margin-left: 8px; font-size: 12px; }
.mini { display: flex; gap: 16px; flex: 1; color: #8b93a1; font-size: 12px; white-space: nowrap; }
.mini b { color: #e6e6e6; font-variant-numeric: tabular-nums; margin-left: 2px; }
button { background: #2563eb; color: #fff; border: 0; border-radius: 6px; padding: 5px 12px;
         cursor: pointer; font-size: 12px; }
button.ghost { background: #171a21; color: #9ca3af; border: 1px solid #262b36; }
button:disabled { background: #374151; cursor: not-allowed; }
.error { color: #f87171; margin: 8px 0; }
.empty { color: #8b93a1; padding: 16px 0; text-align: center; font-size: 13px; }

/* 左条形图略窄、右环状图略宽；窄屏叠成单列 */
.cols { display: grid; grid-template-columns: 11fr 10fr; gap: 8px 24px; }
.col-bars { min-width: 0; }
.col-donut { min-width: 0; }
h3 { font-size: 13px; font-weight: 600; color: #e6e6e6; margin-bottom: 10px; }
h3 small { color: #6b7280; font-weight: 400; margin-left: 6px; }

/* 条形图：SVG 宽度撑满容器，viewBox 保持比例 */
.bars { width: 100%; height: auto; overflow: visible; display: block; }
.bars .lab { fill: #9ca3af; font-size: 11px; }
.bars .num { fill: #6b7280; font-size: 10px; }
.bars .bg { fill: #1c212b; }
.bars .bar { transition: width .3s ease; }
.bars g:hover .bar { filter: brightness(1.25); }

.donut-wrap { display: flex; gap: 18px; align-items: center; }
.donut { width: 180px; height: 180px; flex: none; }
.donut .dtotal { fill: #e6e6e6; font-size: 22px; font-weight: 600; }
.donut .dsub { fill: #6b7280; font-size: 10px; }
.donut circle { transition: stroke-width .15s; cursor: default; }
.donut circle:hover { stroke-width: 25; }

.legend { list-style: none; flex: 1; min-width: 0; max-height: 186px; overflow-y: auto; }
.legend li { display: flex; align-items: center; gap: 8px; padding: 2px 0; font-size: 12px; }
.legend i { width: 10px; height: 10px; border-radius: 2px; flex: none; }
.legend .lname { color: #9ca3af; flex: 1; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
.legend .lnum { color: #6b7280; font-variant-numeric: tabular-nums; }

.tip { position: fixed; z-index: 50; pointer-events: none; background: #1f242e;
       border: 1px solid #3b4657; border-radius: 6px; padding: 5px 10px; font-size: 12px;
       color: #9ca3af; white-space: nowrap; box-shadow: 0 4px 14px rgba(0, 0, 0, .4); }
.tip b { color: #e6e6e6; margin-right: 6px; }

@media (max-width: 860px) {
  .cols { grid-template-columns: 1fr; }
  .head { flex-wrap: wrap; }
}
</style>
