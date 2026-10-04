<template>
  <div>
    <div class="syncbar">
      <div class="syncinfo">
        <span class="label">nuclei-templates 增量同步</span>
        <span class="stat">
          <template v-if="sync.cloned">
            上次同步 <code>{{ sync.last_commit_short || '—' }}</code>
            <template v-if="sync.last_sync"> · {{ sync.last_sync.replace('T', ' ') }}</template>
            · 本地 {{ sync.local_templates }} 个模板
            <template v-if="sync.last_imported"> · 入库 {{ sync.last_imported }}</template>
          </template>
          <template v-else>模板仓库尚未克隆，首次同步需下载约 1.5w 个模板</template>
        </span>
      </div>
      <div class="syncbtns">
        <button class="primary" @click="doSync({})" :disabled="busy">
          {{ syncing ? '同步中…' : '同步增量' }}
        </button>
        <button @click="doSync({ full: true })" :disabled="busy" title="忽略上次进度，重新扫全量">全量重扫</button>
      </div>
    </div>

    <div class="toolbar">
      <div class="tabs">
        <button class="tab" :class="{ active: mode === 'local' }" @click="switchMode('local')">
          本地模板库 <i>{{ local.length }}</i>
        </button>
        <button class="tab" :class="{ active: mode === 'remote' }" @click="switchMode('remote')">
          远程模板库
        </button>
      </div>
      <span v-if="mode === 'local'" class="hint">目录 <code>{{ dir }}</code> 可直接 <code>nuclei -l</code> 跑</span>
    </div>

    <div v-if="mode === 'remote'" class="filters">
      <select v-model="severity" @change="preview">
        <option value="">全部严重性</option>
        <option v-for="s in severities" :key="s" :value="s">{{ s }}</option>
      </select>
      <input v-model="tag" placeholder="tag / 关键字（作用于路径）" @keyup.enter="preview" />
      <input v-model.number="limit" type="number" min="1" max="50" />
      <button @click="preview" :disabled="busy">预览</button>
      <button class="primary" @click="pull" :disabled="busy">
        {{ busy ? '拉取中（首次要拉索引，1-2 分钟）…' : '拉取入库' }}
      </button>
    </div>

    <div v-if="msg" class="msg">{{ msg }}</div>
    <div v-if="error" class="error">出错了：{{ error }}</div>
    <div v-else-if="!rows.length" class="empty">
      {{ mode === 'local' ? '模板库还是空的，去详情页生成或从远程拉一批。' : '点「预览」从远程模板库取样。' }}
    </div>

    <div v-for="t in rows" :key="t.id" class="card" :class="{ link: mode === 'local' }" @click="open(t)">
      <div class="row">
        <span class="name">{{ t.name }}</span>
        <span class="sev" :data-sev="t.severity">{{ t.severity }}</span>
        <span v-if="t.requests != null" class="req">{{ t.requests }} 个请求</span>
      </div>
      <p class="desc">{{ t.description || t.path || t.file }}</p>
    </div>
  </div>
</template>

<script setup>
import { computed, onMounted, ref } from 'vue'
import { useRouter } from 'vue-router'
import { listTemplates, previewRemote, pullRemote, runSync, syncStatus } from './api'

const severities = ['critical', 'high', 'medium', 'low', 'info']
const router = useRouter()

const mode = ref('local')
const local = ref([])
const remote = ref([])
const dir = ref('')
const limit = ref(10)
const severity = ref('')
const tag = ref('')
const busy = ref(false)
const syncing = ref(false)
const error = ref('')
const msg = ref('')
const sync = ref({ cloned: false, local_templates: 0, last_imported: 0 })

const rows = computed(() => (mode.value === 'local' ? local.value : remote.value))

async function loadSync() {
  try {
    sync.value = await syncStatus()
  } catch (e) {
    // 状态条是辅助信息，取不到不打断主流程
  }
}

async function doSync(body) {
  busy.value = true
  syncing.value = true
  error.value = ''
  msg.value = ''
  try {
    const r = await runSync(body)
    if (r.error) {
      error.value = r.error
    } else if (r.skipped) {
      msg.value = r.reason
    } else {
      msg.value = `变更 ${r.changed} 个模板 → 入库 ${r.imported} 条` +
        (r.skipped ? `，跳过已存在 ${r.skipped} 条` : '') +
        (r.failed ? `，解析失败 ${r.failed} 条` : '')
    }
    await Promise.all([loadSync(), loadLocal()])
  } catch (e) {
    error.value = e.message
  } finally {
    busy.value = false
    syncing.value = false
  }
}

async function loadLocal() {
  error.value = ''
  try {
    const r = await listTemplates()
    local.value = r.items
    dir.value = r.dir
  } catch (e) {
    error.value = e.message
  }
}

function switchMode(m) {
  mode.value = m
  msg.value = ''
  error.value = ''
}

async function preview() {
  busy.value = true
  error.value = ''
  msg.value = ''
  try {
    const r = await previewRemote({ limit: limit.value, severity: severity.value, tag: tag.value })
    remote.value = r.items
    msg.value = `${r.repo}@${r.ref} → ${r.items.length} 条`
  } catch (e) {
    error.value = e.message
  } finally {
    busy.value = false
  }
}

async function pull() {
  busy.value = true
  error.value = ''
  msg.value = ''
  try {
    const r = await pullRemote({ limit: limit.value, severity: severity.value, tag: tag.value })
    msg.value = `拉取 ${r.fetched} 条 → 入库 ${r.saved.length} 条` +
      (r.skipped.length ? `，跳过已存在 ${r.skipped.length} 条` : '')
    await loadLocal()
  } catch (e) {
    error.value = e.message
  } finally {
    busy.value = false
  }
}

// 本地条目文件名即漏洞 id，可直接回详情页；远程条目还没入库，点不动
function open(t) {
  if (mode.value === 'local' && t.vid) router.push(`/vuln/${t.vid}`)
}

onMounted(() => { loadLocal(); loadSync() })
</script>

<style scoped>
.syncbar { display: flex; justify-content: space-between; align-items: center; flex-wrap: wrap; gap: 10px;
  background: #171a21; border: 1px solid #262b36; border-radius: 10px; padding: 12px 16px; margin-bottom: 14px; }
.syncinfo { display: flex; flex-direction: column; gap: 4px; }
.syncinfo .label { font-size: 13px; font-weight: 600; }
.syncinfo .stat { font-size: 12px; color: #6b7280; }
.syncinfo code { background: #262b36; padding: 1px 5px; border-radius: 4px; color: #9ca3af; }
.syncbtns { display: flex; gap: 8px; }

.toolbar { display: flex; justify-content: space-between; align-items: center; flex-wrap: wrap; gap: 10px; margin-bottom: 12px; }
.tabs { display: flex; gap: 8px; }
.tab { background: #171a21; color: #9ca3af; border: 1px solid #262b36; border-radius: 999px;
  padding: 5px 13px; font-size: 13px; cursor: pointer; }
.tab i { font-style: normal; margin-left: 6px; color: #6b7280; font-size: 11px; }
.tab.active { background: #1d4ed8; color: #fff; border-color: #1d4ed8; }
.tab.active i { color: #bfdbfe; }
.hint { color: #6b7280; font-size: 12px; }
.hint code { background: #171a21; padding: 1px 5px; border-radius: 4px; }

.filters { display: flex; flex-wrap: wrap; gap: 8px; margin-bottom: 14px; }
select, input { background: #171a21; color: #e6e6e6; border: 1px solid #262b36; border-radius: 6px;
  padding: 7px 10px; font-size: 13px; }
input[type="number"] { width: 76px; }
button { background: #262b36; color: #e6e6e6; border: 0; border-radius: 6px; padding: 7px 14px; font-size: 13px; cursor: pointer; }
button.primary { background: #2563eb; color: #fff; }
button:disabled { background: #374151; cursor: wait; }

.msg { color: #34d399; font-size: 13px; margin-bottom: 10px; }
.error { color: #f87171; margin: 12px 0; }
.empty { color: #8b93a1; padding: 40px 0; text-align: center; }

.card { background: #171a21; border: 1px solid #262b36; border-radius: 10px; padding: 14px 16px; margin-bottom: 12px; }
.card.link { cursor: pointer; }
.card.link:hover { border-color: #3b82f6; }
.row { display: flex; align-items: center; gap: 10px; }
.name { font-weight: 600; font-size: 15px; flex: 1; }
.sev { font-size: 11px; padding: 2px 8px; border-radius: 999px; background: #262b36; color: #9ca3af; text-transform: uppercase; }
.sev[data-sev="critical"] { color: #f87171; }
.sev[data-sev="high"] { color: #fb923c; }
.sev[data-sev="medium"] { color: #fbbf24; }
.sev[data-sev="low"] { color: #60a5fa; }
.sev[data-sev="info"] { color: #9ca3af; }
.req { font-size: 11px; color: #6b7280; }
.desc { margin-top: 8px; color: #9ca3af; font-size: 13px; line-height: 1.6;
  display: -webkit-box; -webkit-line-clamp: 2; -webkit-box-orient: vertical; overflow: hidden; }
</style>
