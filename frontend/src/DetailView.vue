<template>
  <div v-if="error" class="error">加载失败：{{ error }} <a href="#" @click.prevent="$router.push('/')">返回列表</a></div>
  <div v-else-if="!v" class="empty">加载中…</div>
  <div v-else>
    <a href="#" @click.prevent="$router.push('/')">← 返回列表</a>
    <div class="titlerow">
      <h2 class="title">{{ v.name }}</h2>
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
        <pre class="poc" :class="{ folded: !pocOpen }"><code>{{ v.poc }}</code></pre>
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
      <pre v-if="v.nuclei_yaml" class="yaml"><code>{{ v.nuclei_yaml }}</code></pre>
      <p v-else class="none">{{ genMsg || '暂无模板。' }}</p>
    </section>

    <section v-if="v.refs && v.refs.length">
      <h3>原文 / 参考链接</h3>
      <ul class="refs">
        <li v-for="r in v.refs" :key="r">
          <a :href="r" target="_blank" rel="noopener noreferrer">{{ r }}</a>
        </li>
      </ul>
    </section>
  </div>
</template>

<script setup>
import { onMounted, ref, watch } from 'vue'
import { useRoute } from 'vue-router'
import { genNuclei, genPoc, getVuln, llmStatus, translateVuln } from './api'

const route = useRoute()
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

async function copy(which) {
  await navigator.clipboard.writeText(v.value[which === 'poc' ? 'poc' : 'nuclei_yaml'] || '')
  copied.value = which
  setTimeout(() => (copied.value = ''), 1500)
}

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
.meta { display: flex; gap: 14px; color: #8b93a1; font-size: 13px; margin-bottom: 20px; }
.badge { background: #262b36; color: #60a5fa; border-radius: 999px; padding: 2px 10px; }
section { margin-bottom: 22px; }
section h3 { font-size: 15px; color: #93c5fd; margin-bottom: 8px; display: flex; align-items: center; gap: 10px; }
section p { font-size: 14px; line-height: 1.7; color: #d1d5db; }
.pre { white-space: pre-wrap; }
.poc { background: #0b0d10; border: 1px solid #262b36; border-radius: 10px; padding: 16px;
  overflow-x: auto; font-size: 13px; line-height: 1.6; color: #a7f3d0; font-family: Consolas, monospace; }
/* 折叠态：限高 + 底部渐隐，暗示下面还有内容 */
.poc.folded { max-height: 320px; overflow: hidden;
  -webkit-mask-image: linear-gradient(#000 78%, transparent);
  mask-image: linear-gradient(#000 78%, transparent); }
.fold { display: block; margin: 8px auto 0; background: none; border: 1px solid #374151;
  color: #9ca3af; border-radius: 6px; padding: 3px 12px; font-size: 12px; cursor: pointer; }
.fold:hover { color: #d1d5db; border-color: #4b5563; }
.err { color: #f87171; font-size: 13px; }
.yaml { background: #0b0d10; border: 1px solid #262b36; border-radius: 10px; padding: 16px;
  overflow-x: auto; font-size: 12.5px; line-height: 1.6; color: #fcd34d; font-family: Consolas, monospace; white-space: pre-wrap; }
.none { color: #6b7280; font-size: 13px; }
.copy { background: #262b36; color: #9ca3af; border: 0; border-radius: 6px; padding: 3px 10px; font-size: 12px; cursor: pointer; }
/* 「重新生成」和「生成模板」都只写 class="gen"（后者多个 copy）。
   之前只有 .gen:disabled 有规则，启用态没背景色，浏览器默认灰底灰字，
   看着跟禁用一个样。基础样式补在这，几个 AI 按钮才都有明确配色。 */
.gen { background: #1d4ed8; color: #fff; border: 0; border-radius: 6px; padding: 3px 10px;
  font-size: 12px; cursor: pointer; }
.gen.zh { background: #047857; color: #fff; }
.copy:disabled { background: #374151; cursor: wait; }
.gen:disabled { background: #374151; cursor: not-allowed; opacity: .6; }
.refs { list-style: none; font-size: 12px; color: #8b93a1; word-break: break-all; }
.refs li { margin-bottom: 4px; }
</style>
