<template>
  <div class="wrap">
    <header>
      <!-- 站点图标：跟仓库头像同一套视觉，盾形 + 神经网络节点 -->
      <img class="logo" src="/icon-mini.svg" alt="AI 漏洞播报" width="30" height="30" />
      <h1 @click="goList">AI 漏洞播报</h1>
      <span class="sub">24h 监控 · AI 筛选 · 自动生成 PoC</span>
      <nav>
        <a href="#" :class="{ on: $route.path === '/' }" @click.prevent="goList">漏洞</a>
        <a href="#" :class="{ on: $route.path === '/templates' }" @click.prevent="$router.push('/templates')">nuclei 模板库</a>
        <a href="#" :class="{ on: $route.path === '/settings' }" @click.prevent="$router.push('/settings')">设置</a>
        <!-- 仓库图标：点开 GitHub 项目页。图标自己画，不引外部图床，页面 CSP 只放行 self -->
        <a :href="REPO_URL" target="_blank" rel="noopener noreferrer" title="GitHub 仓库" class="gh">
          <svg width="18" height="18" viewBox="0 0 16 16" fill="currentColor" aria-hidden="true">
            <path d="M8 0C3.58 0 0 3.58 0 8c0 3.54 2.29 6.53 5.47 7.59.4.07.55-.17.55-.38
                     0-.19-.01-.82-.01-1.49-2.01.37-2.53-.49-2.69-.94-.09-.23-.48-.94-.82-1.13-.28-.15-.68-.52-.01-.53.63-.01
                     1.08.58 1.23.82.72 1.21 1.87.87 2.33.66.07-.52.28-.87.51-1.07-1.78-.2-3.64-.89-3.64-3.95
                     0-.87.31-1.59.82-2.15-.08-.2-.36-1.02.08-2.12 0 0 .67-.21 2.2.82a7.4 7.4 0 0 1 2-.27c.68 0
                     1.36.09 2 .27 1.53-1.04 2.2-.82 2.2-.82.44 1.1.16 1.92.08 2.12.51.56.82 1.27.82 2.15 0 3.07-1.87
                     3.75-3.65 3.95.29.25.54.73.54 1.48 0 1.07-.01 1.93-.01 2.2 0 .21.15.46.55.38A8.01 8.01 0 0 0
                     16 8c0-4.42-3.58-8-8-8z" />
          </svg>
        </a>
      </nav>
    </header>
    <router-view />
    <AgentPanel />
  </div>
</template>

<script setup>
import { computed } from 'vue'
import { useRoute, useRouter } from 'vue-router'
import { safePath } from './safe'
import AgentPanel from './AgentPanel.vue'

const route = useRoute()
const router = useRouter()

// 仓库地址。前后端各有一份（后端 updater.REPO），改仓库时两边都要动。
const REPO_URL = 'https://github.com/wr0x00/ai_bobao'

// 点标题/「漏洞」标签回列表时，别把当前筛选条件丢了。
// 详情页用 from 记着来路，其余情况就保留地址栏上已有的 query。
// from 是用户能改的地址栏参数，safePath 负责挡掉被拼成站外地址的写法。
const listLink = computed(() => {
  const back = safePath(route.query.from)
  if (back) return back
  if (route.path === '/') {
    const q = { ...route.query }
    return Object.keys(q).length ? { path: '/', query: q } : '/'
  }
  return '/'
})

/** 回漏洞列表。带上筛选条件的那条路。 */
function goList() {
  router.push(listLink.value)
}
</script>

<style>
* { box-sizing: border-box; margin: 0; padding: 0; }
body { background: #0f1115; color: #e6e6e6; font-family: system-ui, 'Microsoft YaHei', sans-serif; }
/* 页面放宽到 1200px：列表两列 + 总览图表需要更宽的空间 */
.wrap { max-width: 1200px; margin: 0 auto; padding: 24px 16px 60px; }
header { margin-bottom: 24px; cursor: default; }
header h1 { font-size: 22px; cursor: pointer; display: inline-block; }
/* 站点图标：跟标题文字对齐，垂直居中 */
header .logo { width: 30px; height: 30px; vertical-align: -5px; margin-right: 10px; border-radius: 7px; }
header .sub { margin-left: 12px; color: #8b93a1; font-size: 13px; }
header nav { float: right; display: flex; align-items: center; gap: 14px; font-size: 13px; }
header nav a { color: #8b93a1; display: inline-flex; align-items: center; }
header nav a.on { color: #e6e6e6; }
header nav a.gh:hover { color: #e6e6e6; }
a { color: #5aa7ff; text-decoration: none; }

/* ── 全站按钮基调：一律方角，凸显专业 ──
   具体的天蓝配色在各组件里上（主色 #0ea5e9、悬停 #38bdf8；
   次级按钮黑底 + 天蓝描边）。这条是兜底：以后新加按钮忘了写
   border-radius，也自动是方角圆不回去。 */
button { border-radius: 0; }
</style>
