<template>
  <div>
    <div class="bar">
      <span class="hint" v-if="at">统计口径：{{ at }}</span>
      <button class="ghost" :disabled="busy" @click="load">
        {{ busy ? '刷新中…' : '刷新' }}
      </button>
    </div>

    <div v-if="error" class="error">加载失败：{{ error }}</div>

    <div class="cards">
      <div class="card"><span class="k">漏洞总数</span><span class="v">{{ s.total }}</span></div>
      <div class="card"><span class="k">近 7 天新增</span><span class="v">{{ s.last7 }}</span></div>
      <div class="card"><span class="k">带 nuclei 模板</span><span class="v">{{ s.with_tpl }}</span></div>
      <div class="card"><span class="k">已中文化</span><span class="v">{{ s.translated }}</span></div>
    </div>

    <div v-if="!s.total" class="empty">
      {{ busy ? '统计中…' : '库还是空的，先去列表页抓一轮。' }}
    </div>

    <template v-else>
      <!-- 各组件漏洞数量：横着的条形图，标签占左边一列，条按数量从多到少排 -->
      <section class="panel">
        <h2>各组件漏洞数量 <small>Top {{ comp.length }}</small></h2>
        <svg class="bars" :viewBox="`0 0 ${BAR_W} ${barHeight}`" role="img"
             aria-label="各组件漏洞数量条形图">
          <g v-for="(r, i) in comp" :key="r.name">
            <text class="lab" :x="LABEL_W - 8" :y="barY(i) + 4" text-anchor="end">{{ r.name }}</text>
            <rect class="bg" :x="LABEL_W" :y="barY(i)" :width="BAR_MAX" :height="ROW_H - 8" rx="4" />
            <rect class="bar" :x="LABEL_W" :y="barY(i)" :width="barW(r.n)" :height="ROW_H - 8" rx="4"
                  :fill="colorAt(i)" />
            <text class="num" :x="LABEL_W + barW(r.n) + 8" :y="barY(i) + 4">{{ r.n }}</text>
          </g>
        </svg>
      </section>

      <!-- 各平台来源占比：环状图，一段一个颜色，图例带数量和占比 -->
      <section class="panel">
        <h2>各平台漏洞来源占比 <small>{{ donut.length }} 个来源</small></h2>
        <div class="donut-wrap">
          <svg class="donut" viewBox="0 0 220 220" role="img" aria-label="各平台漏洞来源占比环状图">
            <g transform="rotate(-90 110 110)">
              <circle v-for="(d, i) in donut" :key="d.name" cx="110" cy="110" :r="R"
                      fill="none" :stroke="d.color" :stroke-width="SW"
                      :stroke-dasharray="d.dash" :stroke-dashoffset="d.offset" />
            </g>
            <text class="dtotal" x="110" y="104" text-anchor="middle">{{ s.total }}</text>
            <text class="dsub" x="110" y="124" text-anchor="middle">条漏洞</text>
          </svg>
          <ul class="legend">
            <li v-for="(d, i) in donut" :key="d.name">
              <i :style="{ background: d.color }"></i>
              <span class="lname">{{ d.name }}</span>
              <span class="lnum">{{ d.n }} 条 · {{ d.pct }}%</span>
            </li>
          </ul>
        </div>
      </section>
    </template>
  </div>
</template>

<script setup>
// OverviewView.vue —— 总览
//
// 两张图：横条形图看「哪些组件的漏洞最多」，环状图看「漏洞都是从哪些平台来的」。
//
// 图表是自己算坐标画的内联 SVG，没引图表库。原因是页面的 CSP 写着
// script-src 'self'，从 CDN 引 ECharts/Chart.js 会被浏览器直接拦掉；
// 自己算也就一百来行，还能精确控制配色。

import { computed, onMounted, ref } from 'vue'
import { getStats } from './api'

// 条形图的几何
const LABEL_W = 210   // 左边标签列的宽度
const BAR_MAX = 420   // 最长条的长度
const ROW_H = 26      // 每行高
const BAR_W = LABEL_W + BAR_MAX + 60

// 环状图的几何
const R = 78          // 圆环半径
const SW = 26         // 圆环粗细
const CIRC = 2 * Math.PI * R

// 调色板。平台有二十来个，单色系分不开，所以一次给足颜色轮着上。
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

/** 取第 i 个颜色。超出调色板长度就按取模循环，色差仍在可接受范围。 */
function colorAt(i) {
  return PALETTE[i % PALETTE.length]
}

/** 条形图数据：后端已经按数量从多到少排好了，这里补上颜色。 */
const comp = computed(() =>
  (s.value.by_component || []).map((c, i) => ({ name: c[0], n: c[1], color: colorAt(i) })))

/** 条形图每行的 y 坐标。 */
function barY(i) {
  return 6 + i * ROW_H
}

const barHeight = computed(() => 12 + comp.value.length * ROW_H)

/** 某条的长度：按最大值等比缩放，条最大刚好占满 BAR_MAX。 */
function barW(n) {
  const max = comp.value.length ? comp.value[0].n : 1
  return max ? Math.max(3, Math.round((n / max) * BAR_MAX)) : 0
}

/**
 * 环状图分段。每段只画一段圆弧：靠 stroke-dasharray 给"实线—空白"，
 * 再用 stroke-dashoffset 把它挪到该在的起始位置，从 12 点顺时针排下去。
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
.bar { display: flex; align-items: center; justify-content: space-between; margin-bottom: 12px; }
.hint { color: #6b7280; font-size: 12px; }
button { background: #2563eb; color: #fff; border: 0; border-radius: 6px; padding: 7px 14px;
         cursor: pointer; font-size: 13px; }
button.ghost { background: #171a21; color: #9ca3af; border: 1px solid #262b36; }
button:disabled { background: #374151; cursor: not-allowed; }
.error { color: #f87171; margin: 12px 0; }
.empty { color: #8b93a1; padding: 40px 0; text-align: center; }

.cards { display: grid; grid-template-columns: repeat(4, 1fr); gap: 12px; margin-bottom: 18px; }
.card { background: #171a21; border: 1px solid #262b36; border-radius: 10px; padding: 14px 16px;
        display: flex; flex-direction: column; gap: 6px; }
.card .k { color: #8b93a1; font-size: 12px; }
.card .v { color: #e6e6e6; font-size: 24px; font-weight: 600; font-variant-numeric: tabular-nums; }

.panel { background: #14171e; border: 1px solid #262b36; border-radius: 10px;
         padding: 16px 18px; margin-bottom: 18px; }
.panel h2 { font-size: 14px; font-weight: 600; color: #e6e6e6; margin-bottom: 14px; }
.panel h2 small { color: #6b7280; font-weight: 400; margin-left: 8px; }

/* 条形图：SVG 宽度撑满容器，viewBox 保持比例，字不会随屏幕变形 */
.bars { width: 100%; height: auto; overflow: visible; }
.bars .lab { fill: #9ca3af; font-size: 12px; }
.bars .num { fill: #6b7280; font-size: 11px; }
.bars .bg { fill: #1c212b; }
.bars .bar { transition: width .3s ease; }
.bars g:hover .bar { filter: brightness(1.25); }

.donut-wrap { display: flex; gap: 28px; align-items: center; flex-wrap: wrap; }
.donut { width: 220px; height: 220px; flex: none; }
.donut .dtotal { fill: #e6e6e6; font-size: 26px; font-weight: 600; }
.donut .dsub { fill: #6b7280; font-size: 11px; }
.donut circle { transition: stroke-width .15s; }
.donut circle:hover { stroke-width: 32; }

.legend { list-style: none; flex: 1; min-width: 220px; max-height: 220px; overflow-y: auto; }
.legend li { display: flex; align-items: center; gap: 8px; padding: 3px 0; font-size: 12px; }
.legend i { width: 10px; height: 10px; border-radius: 2px; flex: none; }
.legend .lname { color: #9ca3af; flex: 1; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
.legend .lnum { color: #6b7280; font-variant-numeric: tabular-nums; }

@media (max-width: 620px) {
  .cards { grid-template-columns: repeat(2, 1fr); }
}
</style>
