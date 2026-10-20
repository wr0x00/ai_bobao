<template>
  <div>
    <div class="head">
      <h2>设置</h2>
      <p class="tip">配置保存在后端 <code>{{ configFile || 'config.yaml' }}</code>，保存后立即生效，不用重启。</p>
    </div>

    <div v-if="error" class="error">出错了：{{ error }}</div>

    <section>
      <h3>AI 接口<span class="tag">OpenAI 兼容</span></h3>
      <label>
        <span>接口地址</span>
        <input v-model.trim="llm.base" placeholder="https://api.example.com" />
        <i>不带 /v1，系统自动拼</i>
      </label>
      <label>
        <span>API Key</span>
        <input v-model="llm.key" type="password" :placeholder="keyPlaceholder" autocomplete="off" />
        <i>{{ keySet ? '已配置，留空则不改动' : '尚未配置' }}</i>
      </label>
      <label>
        <span>模型名</span>
        <input v-model.trim="llm.model" placeholder="gpt-4o-mini" />
      </label>
      <label>
        <span>超时（秒）</span>
        <input v-model.number="llm.timeout" type="number" min="1" max="600" />
      </label>
      <div class="acts">
        <button class="primary" :disabled="busy" @click="save">保存全部</button>
        <button :disabled="busy || testing" @click="test">{{ testing ? '测试中…' : '测试连通性' }}</button>
      </div>
      <p v-if="testMsg" class="ok">{{ testMsg }}</p>
    </section>

    <section>
      <h3>抓取</h3>
      <label>
        <span>定时间隔（分钟）</span>
        <input v-model.number="collect.interval_minutes" type="number" min="1" max="1440" />
      </label>
      <label>
        <span>单源条数上限</span>
        <input v-model.number="collect.fetch_limit" type="number" min="1" max="100" />
      </label>
      <label>
        <span>漏洞保留天数</span>
        <input v-model.number="collect.keep_days" type="number" min="0" max="3650" />
        <i>只保留最近这些天的漏洞，更早的直接舍弃；每轮抓取后自动清理一次，0 = 不按日期筛</i>
      </label>
      <label class="check">
        <input v-model="collect.auto_translate" type="checkbox" />
        <span>抓取入库时自动译成中文（标题 / 简介 / 原理）</span>
      </label>
      <div class="acts">
        <button class="primary" :disabled="busy" @click="save">保存全部</button>
        <button :disabled="busy" @click="purge" :title="'立刻删除早于保留期的漏洞'">
          {{ purging ? '清理中…' : '立即清理过期漏洞' }}
        </button>
        <button :disabled="busy || rechecking" @click="recheck" :title="'让 AI 重新判断库里每条是不是漏洞情报，不是的直接删掉'">
          {{ rechecking ? '复检中…' : '复检存量内容' }}
        </button>
      </div>
      <p v-if="purgeMsg" class="ok">{{ purgeMsg }}</p>
      <p v-if="recheckMsg" class="ok">{{ recheckMsg }}</p>
    </section>

    <section>
      <h3>版本更新<span class="tag">GitHub</span></h3>
      <label>
        <span>仓库</span>
        <a
          v-if="updateInfo && safeUrl(updateInfo.url)"
          :href="updateInfo.url"
          target="_blank"
          rel="noreferrer"
          class="lnk"
        >{{ updateInfo.repo }}</a>
        <span v-else class="meta">加载后显示仓库地址</span>
        <i>一键检查并拉取 GitHub 上的最新版本</i>
      </label>
      <label v-if="updateInfo">
        <span>版本状态</span>
        <span class="mono">
          本地 {{ short(updateInfo.local) }} → 远端 {{ short(updateInfo.remote) }}
        </span>
        <i>{{ updateInfo.branch }} 分支</i>
      </label>
      <div class="acts">
        <button :disabled="busy || checking" @click="checkUpd">
          {{ checking ? '检测中…' : '检测更新' }}
        </button>
        <button
          class="primary"
          :disabled="busy || updating || !updateInfo || !updateInfo.has_update"
          @click="applyUpd"
        >
          {{ updating ? '拉取中…' : '拉取最新版本' }}
        </button>
      </div>
      <p v-if="updateMsg" class="ok">{{ updateMsg }}</p>
    </section>

    <section>
      <h3>nuclei 模板库</h3>
      <label>
        <span>仓库</span>
        <input v-model.trim="nuclei.repo" placeholder="projectdiscovery/nuclei-templates" />
      </label>
      <label>
        <span>分支</span>
        <input v-model.trim="nuclei.ref" placeholder="main" />
      </label>
      <label class="check">
        <input v-model="nuclei.sync_enabled" type="checkbox" />
        <span>定时任务自动同步模板库增量</span>
      </label>
      <label>
        <span>单次入库上限</span>
        <input v-model.number="nuclei.sync_limit" type="number" min="0" max="5000" />
        <i>0 = 不限</i>
      </label>
      <label>
        <span>每轮拉取上限</span>
        <input v-model.number="nuclei.remote_limit" type="number" min="1" max="200" />
      </label>
      <label class="check">
        <input v-model="nuclei.fetch_remote" type="checkbox" />
        <span>流水线拉取远程模板</span>
      </label>
      <label class="check">
        <input v-model="nuclei.gen_templates" type="checkbox" />
        <span>为收录漏洞生成 nuclei 模板</span>
      </label>
      <div class="acts">
        <button class="primary" :disabled="busy" @click="save">保存全部</button>
      </div>
    </section>

    <section>
      <h3>漏洞源管理<span class="tag">接入新社区</span></h3>
      <label>
        <span>社区地址</span>
        <input v-model.trim="probeUrl" placeholder="https://xz.aliyun.com" />
        <i>填社区首页即可，系统自动探测其 RSS 地址并判断是否为漏洞社区</i>
      </label>
      <label class="check">
        <input v-model="probeJudge" type="checkbox" />
        <span>让 AI 判断探测结果是否为漏洞社区（不勾则只做地址探测）</span>
      </label>
      <div class="acts">
        <button :disabled="busy || probing" @click="probe">
          {{ probing ? '探测中…' : '探测可接入的源' }}
        </button>
      </div>
      <p v-if="probeMsg" :class="cands.length ? 'ok' : 'error'">{{ probeMsg }}</p>

      <ul v-if="cands.length" class="cands">
        <li v-for="c in cands" :key="c.url">
          <div class="cand">
            <b>{{ c.verdict.suggested_name || c.url }}</b>
            <span class="tag" :class="c.verdict.is_vuln_source ? 'yes' : 'no'">
              {{ c.verdict.is_vuln_source ? 'AI 判定：可用' : 'AI 判定：非漏洞源' }}
            </span>
            <span class="meta">{{ c.entries }} 条 · {{ c.verdict.by_llm ? 'AI 判断' : '关键词兜底' }}</span>
          </div>
          <!-- 地址是外部数据，进 href 前先过协议白名单，挡掉 javascript: -->
          <a v-if="safeUrl(c.url)" class="lnk" :href="safeUrl(c.url)" target="_blank" rel="noreferrer">{{ c.url }}</a>
          <span v-else class="lnk">{{ c.url }}</span>
          <p class="why">{{ c.verdict.reason }}</p>
          <ul class="titles">
            <li v-for="t in c.titles.slice(0, 4)" :key="t">{{ t }}</li>
          </ul>
          <div class="acts">
            <input v-model.trim="c.name" placeholder="源名称，如「先知」" />
            <button class="primary" :disabled="busy || !c.name" @click="attach(c)">接入</button>
          </div>
        </li>
      </ul>

      <h4>已接入的源</h4>
      <table class="srcs">
        <tbody>
          <tr v-for="s in sources" :key="s.name">
            <td class="nm">{{ s.name }}</td>
            <td class="ur">
              <a v-if="safeUrl(s.url)" :href="safeUrl(s.url)" target="_blank" rel="noreferrer">{{ s.url }}</a>
              <span v-else>{{ s.url }}</span>
            </td>
            <td class="op">
              <span v-if="s.builtin" class="tag">内置</span>
              <button v-else class="del" @click="remove(s.name)">移除</button>
            </td>
          </tr>
        </tbody>
      </table>
      <p v-if="srcMsg" class="ok">{{ srcMsg }}</p>
    </section>

    <p v-if="msg" class="ok">已保存 → {{ configFile }}</p>
  </div>
</template>

<script setup>
// SettingsView.vue —— 设置页
//
// 四块内容：AI 接口、抓取、nuclei 模板库、漏洞源管理。
// 配置存在后端的 config.yaml，保存后立刻生效，不用重启服务。

import { onMounted, ref } from 'vue'
import { addSource, applyUpdate, checkUpdate, delSource, discoverSource, getSettings, listSources, purgeExpired, recheckLibrary, saveSettings, testLlm } from './api'
import { safeUrl } from './safe'

const llm = ref({ base: '', key: '', model: '', timeout: 60 })
const collect = ref({ interval_minutes: 10, fetch_limit: 10, keep_days: 60, auto_translate: true })
const nuclei = ref({ repo: '', ref: 'main', sync_enabled: true, sync_limit: 0, remote_limit: 20, fetch_remote: true, gen_templates: true })
const configFile = ref('')
const keySet = ref(false)
const busy = ref(false)
const testing = ref(false)
const purging = ref(false)
const msg = ref('')
const testMsg = ref('')
const purgeMsg = ref('')
const rechecking = ref(false)
const recheckMsg = ref('')
const error = ref('')

// ── 版本更新 ────────────────────────────────────────────
const checking = ref(false)
const updating = ref(false)
const updateInfo = ref(null)
const updateMsg = ref('')

/** commit 号太长只显示头 7 位，够认版本就行。 */
function short(sha) {
  if (!sha) return '未知'
  return String(sha).slice(0, 7)
}

// ── 漏洞源管理 ──────────────────────────────────────────
const probeUrl = ref('')
const probeJudge = ref(true)
const probing = ref(false)
const probeMsg = ref('')
const cands = ref([])
const sources = ref([])
const srcMsg = ref('')

/** 拉已接入的漏洞源列表。内置源排在自定义源前面，这个顺序就是抓取顺序。 */
async function loadSources() {
  try {
    const r = await listSources()
    // 内置源在前，自定义源在后，顺序即抓取顺序
    sources.value = [...r.builtin, ...r.custom]
  } catch (e) {
    error.value = e.message
  }
}

/** 探测用户填的社区地址，把可接入的源列成候选让用户挑。 */
async function probe() {
  probing.value = true
  probeMsg.value = ''
  cands.value = []
  srcMsg.value = ''
  error.value = ''
  try {
    const r = await discoverSource(probeUrl.value, probeJudge.value)
    if (!r.ok) {
      probeMsg.value = r.message
      return
    }
    // 让用户改名字，所以预填 AI 建议但允许覆盖
    cands.value = r.candidates.map((c) => ({
      ...c,
      name: c.verdict.suggested_name || '',
    }))
    probeMsg.value = r.message
  } catch (e) {
    probeMsg.value = e.message
  } finally {
    probing.value = false
  }
}

/**
 * 把一个候选源写进配置。
 *
 * @param {object} c 候选源，至少要有 name 和 url
 */
async function attach(c) {
  busy.value = true
  error.value = ''
  try {
    const r = await addSource({ name: c.name, url: c.url, enabled: true })
    srcMsg.value = r.message
    // 接入成功就从候选里去掉，免得重复点同一个
    cands.value = cands.value.filter((x) => x.url !== c.url)
    await loadSources()
  } catch (e) {
    error.value = e.message
  } finally {
    busy.value = false
  }
}

/**
 * 移除一个自定义源。
 *
 * @param {string} name 源名称
 */
async function remove(name) {
  busy.value = true
  error.value = ''
  try {
    const r = await delSource(name)
    srcMsg.value = r.message
    await loadSources()
  } catch (e) {
    error.value = e.message
  } finally {
    busy.value = false
  }
}

// 密钥不回传明文，只提示「已配置」；留空提交即保持原值
const keyPlaceholder = ref('sk-...')

/** 拉配置回填表单。密钥只拿到「有没有配」这个信息，明文不回传。 */
async function load() {
  error.value = ''
  purgeMsg.value = ''
  try {
    const s = await getSettings()
    llm.value = { ...s.llm, key: '' }
    collect.value = s.collect
    nuclei.value = s.nuclei
    configFile.value = s.config_file
    keySet.value = s.key_set
    keyPlaceholder.value = s.key_set ? '已配置，留空则不改动' : 'sk-...'
  } catch (e) {
    error.value = e.message
  }
}

/** 保存三块配置到后端，写完重新拉一遍，用后端的实际值刷新表单。 */
async function save() {
  busy.value = true
  msg.value = ''
  error.value = ''
  try {
    // key 为空串时后端视为「保持原值」，所以表单里永远不塞脱敏串
    await saveSettings({ llm: llm.value, collect: collect.value, nuclei: nuclei.value })
    msg.value = '配置已写入 config.yaml'
    await load()
  } catch (e) {
    error.value = e.message
  } finally {
    busy.value = false
  }
}

/** 立刻删掉早于保留期的漏洞。 */
async function purge() {
  purging.value = true
  purgeMsg.value = ''
  error.value = ''
  try {
    const r = await purgeExpired()
    // 先 load 再写提示：load() 开头会清空 purgeMsg，反过来写就永远显示不出来
    await load()
    const ok = r.removed ? `已清理 ${r.removed} 条过期漏洞` : '没有过期漏洞'
    // 删不掉的多半是文件正被占用，如实说出来，别报个假的成功
    purgeMsg.value = r.failed?.length ? `${ok}，另有 ${r.failed.length} 条删不掉（可能被占用）` : ok
  } catch (e) {
    error.value = e.message
  } finally {
    purging.value = false
  }
}

/** 用表单里当前的地址和密钥测一下模型通不通。 */
async function test() {
  testing.value = true
  testMsg.value = ''
  error.value = ''
  try {
    const r = await testLlm(llm.value)
    testMsg.value = `连通正常：${r.base} → ${r.model}（模型回 ${r.reply}）`
  } catch (e) {
    error.value = e.message
  } finally {
    testing.value = false
  }
}

/**
 * 复检库里已收录的条目，让 AI 重新判断是不是漏洞情报。
 *
 * 早期版本只按日期和 ID 去重，技术文章（WriteUp 之类）会被当成漏洞收进来。
 * 现在改成入库前由 AI 判定，这条按钮就是拿来清理那批历史脏数据的：
 * 判定不是漏洞的直接删掉，判定是漏洞但当初是「兜底」生成的重新出一版。
 */
async function recheck() {
  rechecking.value = true
  recheckMsg.value = ''
  error.value = ''
  try {
    const r = await recheckLibrary(0)
    const parts = [`扫了 ${r.scanned} 条，删掉 ${r.removed} 条非漏洞内容`]
    if (r.regenerated) parts.push(`重写 ${r.regenerated} 条`)
    if (r.failed?.length) parts.push(`有 ${r.failed.length} 条没处理成`)
    recheckMsg.value = parts.join('，')
  } catch (e) {
    error.value = e.message
  } finally {
    rechecking.value = false
  }
}

/** 问一下 GitHub，远端仓库是不是比自己新。 */
async function checkUpd() {
  checking.value = true
  updateMsg.value = ''
  error.value = ''
  try {
    const r = await checkUpdate()
    updateInfo.value = r
    updateMsg.value = r.message
  } catch (e) {
    error.value = e.message
  } finally {
    checking.value = false
  }
}

/** 把远端最新版本拉下来（只允许快进合并，本地有改动会直接拒绝）。 */
async function applyUpd() {
  updating.value = true
  updateMsg.value = ''
  error.value = ''
  try {
    const r = await applyUpdate()
    updateMsg.value = r.message
    // 合并完 commit 号变了，重新问一次让页面显示最新状态
    if (r.ok) {
      try {
        updateInfo.value = await checkUpdate()
      } catch (e) {
        // 只是刷新状态，失败不影响主流程，忽略
      }
    }
  } catch (e) {
    error.value = e.message
  } finally {
    updating.value = false
  }
}

onMounted(() => {
  load()
  loadSources()
})
</script>

<style scoped>
.head { margin-bottom: 18px; }
h2 { font-size: 18px; }
.tip { margin-top: 6px; color: #8b93a1; font-size: 12px; }
.tip code { background: #171a21; padding: 1px 6px; border-radius: 4px; }

section { background: #171a21; border: 1px solid #262b36; border-radius: 10px;
  padding: 16px 18px; margin-bottom: 16px; }
h3 { font-size: 14px; margin-bottom: 14px; display: flex; align-items: center; gap: 8px; }
.tag { font-size: 11px; font-weight: normal; color: #8b93a1;
  background: #262b36; padding: 2px 8px; border-radius: 999px; }

label { display: grid; grid-template-columns: 130px 1fr; gap: 10px;
  align-items: center; margin-bottom: 12px; }
label > span { font-size: 13px; color: #9ca3af; }
label > i { grid-column: 2; font-style: normal; font-size: 11px; color: #6b7280; margin-top: -6px; }
label.check { display: flex; gap: 8px; align-items: center; }
label.check input { width: auto; }
label.check span { color: #e6e6e6; }
/* 版本状态这类纯展示内容，用等宽字体看着像日志 */
label > span.mono { font-family: ui-monospace, Menlo, Consolas, monospace; font-size: 12px; color: #e6e6e6; }
label > span.meta { color: #8b93a1; font-size: 12px; }

input[type="text"], input[type="password"], input:not([type]) {
  background: #0f1115; color: #e6e6e6; border: 1px solid #262b36; border-radius: 6px;
  padding: 8px 10px; font-size: 13px; width: 100%; }
input[type="number"] { background: #0f1115; color: #e6e6e6; border: 1px solid #262b36;
  border-radius: 6px; padding: 8px 10px; font-size: 13px; width: 120px; }
input:focus { outline: none; border-color: #3b82f6; }
input[type="checkbox"] { accent-color: #2563eb; width: 15px; height: 15px; }

.acts { display: flex; gap: 8px; margin-top: 14px; }
button { background: #262b36; color: #e6e6e6; border: 0; border-radius: 6px;
  padding: 8px 16px; font-size: 13px; cursor: pointer; }
button.primary { background: #2563eb; color: #fff; }
button:disabled { background: #374151; cursor: wait; }

.ok { color: #34d399; font-size: 13px; margin-top: 10px; }
.error { color: #f87171; font-size: 13px; margin-bottom: 12px; }

h4 { font-size: 12px; color: #8b93a1; margin: 18px 0 8px; font-weight: normal; }

/* 探测结果卡片 */
.cands { list-style: none; padding: 0; margin: 12px 0 0; }
.cands > li { border: 1px solid #262b36; border-radius: 8px; padding: 12px; margin-bottom: 10px; }
.cand { display: flex; align-items: center; gap: 8px; margin-bottom: 4px; }
.cand b { font-size: 13px; }
.cand .meta { margin-left: auto; font-size: 11px; color: #6b7280; }
.tag.yes { background: #064e3b; color: #6ee7b7; }
.tag.no { background: #4c1d1d; color: #fca5a5; }
.lnk { font-size: 12px; color: #60a5fa; word-break: break-all; }
.why { font-size: 12px; color: #9ca3af; margin: 6px 0; }
.titles { list-style: none; padding: 0 0 0 4px; margin: 6px 0 10px; }
.titles li { font-size: 11px; color: #6b7280; padding: 2px 0 2px 10px;
  border-left: 2px solid #262b36; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
.cands .acts { margin-top: 0; }
.cands .acts input { flex: 1; }

/* 已接入源表格 */
.srcs { width: 100%; border-collapse: collapse; font-size: 13px; }
.srcs td { padding: 7px 8px; border-bottom: 1px solid #1e222b; vertical-align: middle; }
.srcs .nm { white-space: nowrap; width: 1%; }
.srcs .ur a { color: #60a5fa; word-break: break-all; font-size: 12px; }
.srcs .op { text-align: right; width: 1%; white-space: nowrap; }
button.del { background: #3f1d1d; color: #fca5a5; padding: 4px 12px; font-size: 12px; }
button.del:hover { background: #5b2626; }
</style>
