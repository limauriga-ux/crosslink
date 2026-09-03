<script setup lang="ts">
import { computed, ref } from 'vue'
import * as Service from '../bindings/github.com/limauriga-ux/crosslink/internal/gui/service'
import { useAppStore } from '../stores/app'
import type { TestResult, TestTarget } from '../types'

const store = useAppStore()

const defaultTargets: TestTarget[] = [
  { name: 'Baidu',    url: 'https://www.baidu.com' },
  { name: 'Bing',     url: 'https://www.bing.com' },
  { name: 'QQ',       url: 'https://www.qq.com' },
  { name: 'Google',   url: 'https://www.google.com/generate_204' },
  { name: 'GitHub',   url: 'https://github.com' },
  { name: 'YouTube',  url: 'https://www.youtube.com/generate_204' },
  { name: 'X',        url: 'https://x.com' },
]

type CellState = 'idle' | 'running' | 'done' | 'unavailable'
interface Cell { state: CellState; result: TestResult | null }
interface Row {
  name: string
  url: string
  custom: boolean
  direct: Cell
  tunnel: Cell
}

const idleCell = (): Cell => ({ state: 'idle', result: null })
const mkRow = (t: TestTarget, custom: boolean): Row => ({
  name: t.name, url: t.url ?? '', custom, direct: idleCell(), tunnel: idleCell(),
})
// Defaults minus the ones the user deleted (persisted by name); customs
// always come after.
const freshRows = (): Row[] => [
  ...defaultTargets.filter(t => !store.removedTestTargets.includes(t.name)).map(t => mkRow(t, false)),
  ...store.customTestTargets.map(t => mkRow(t, true)),
]

const rows = ref<Row[]>(freshRows())
const running = ref(false)

// The second probe explicitly uses the sing-box mixed listener; the first
// follows the normal macOS path and is therefore captured by TUN when active.
const tunnelAddr = computed(() => store.vpnMixedAddr)

const newName = ref('')
const newUrl = ref('')
const addError = ref('')

function normalizeUrl(raw: string): string {
  const v = raw.trim()
  if (!v) return ''
  return /^https?:\/\//i.test(v) ? v : `https://${v}`
}

function addTarget() {
  addError.value = ''
  const name = newName.value.trim()
  const url = normalizeUrl(newUrl.value)
  if (!name) { addError.value = '请填写名称'; return }
  if (!url) { addError.value = '请填写网址'; return }
  try { new URL(url) } catch { addError.value = '网址格式不正确'; return }
  if (rows.value.some(r => r.url === url)) { addError.value = '该网址已在列表中'; return }
  const target: TestTarget = { name, url }
  store.setCustomTestTargets([...store.customTestTargets, target])
  rows.value.push(mkRow(target, true))
  newName.value = ''
  newUrl.value = ''
}

function removeTarget(row: Row) {
  if (row.custom) {
    store.setCustomTestTargets(store.customTestTargets.filter(t => !(t.name === row.name && t.url === row.url)))
  } else {
    store.setRemovedTestTargets([...store.removedTestTargets, row.name])
  }
  rows.value = rows.value.filter(r => r !== row)
}

function restoreDefaults() {
  store.setRemovedTestTargets([])
  const missing = defaultTargets.filter(t => !rows.value.some(r => !r.custom && r.name === t.name))
  rows.value = [...missing.map(t => mkRow(t, false)), ...rows.value]
}

const SAMPLES = 3

async function probe(target: TestTarget, proxyAddr: string): Promise<TestResult> {
  try {
    return await Service.RunSingleTest(target, proxyAddr, SAMPLES)
  } catch (e) {
    return { name: target.name, url: target.url, reachable: false, duration_millis: 0, samples: SAMPLES, successes: 0, error: String(e) }
  }
}

async function runAll() {
  if (running.value) return
  running.value = true
  const addr = tunnelAddr.value
  rows.value = freshRows().map(r => ({
    ...r,
    direct: { state: 'running', result: null },
    tunnel: addr ? { state: 'running', result: null } : { state: 'unavailable', result: null },
  }))

  await Promise.all(rows.value.map(async (row, i) => {
    const target: TestTarget = { name: row.name, url: row.url }
    const jobs: Promise<void>[] = [
      probe(target, '').then(res => { rows.value[i].direct = { state: 'done', result: res } }),
    ]
    if (addr) {
      jobs.push(probe(target, addr).then(res => { rows.value[i].tunnel = { state: 'done', result: res } }))
    }
    await Promise.all(jobs)
  }))

  running.value = false
}
</script>

<template>
  <section class="page-stack">
    <div class="page-header">
      <div>
        <h2>连通性测试</h2>
        <p class="page-subtitle">同一目标并排探测直连与经隧道两条路径，每格连测 {{ SAMPLES }} 次取均值</p>
      </div>
      <div class="page-actions">
        <n-button type="primary" :loading="running" @click="runAll">一键测试</n-button>
      </div>
    </div>

    <div class="panel">
      <div class="add-row">
        <n-input v-model:value="newName" size="small" placeholder="名称，如：内网 Wiki" style="max-width: 180px" @keyup.enter="addTarget" />
        <n-input v-model:value="newUrl" size="small" placeholder="网址，如：wiki.corp.example" style="flex: 1" @keyup.enter="addTarget" />
        <n-button size="small" @click="addTarget">添加</n-button>
        <n-button v-if="store.removedTestTargets.length" size="small" tertiary @click="restoreDefaults">
          恢复默认
        </n-button>
      </div>
      <p v-if="addError" class="add-error">{{ addError }}</p>
    </div>

    <div class="panel" style="overflow-x: auto">
      <div v-if="rows.every(r => r.direct.state === 'idle')" class="empty-hint">
        点击「一键测试」开始探测
      </div>
      <table class="data-table">
        <thead>
          <tr>
            <th>名称</th>
            <th>目标</th>
            <th>系统路径</th>
            <th>
              显式 Mixed Port
              <span class="tunnel-addr">{{ tunnelAddr || '统一核心未连接' }}</span>
            </th>
            <th></th>
          </tr>
        </thead>
        <tbody>
          <tr v-for="row in rows" :key="row.custom ? 'c:' + row.url : 'd:' + row.name">
            <td>{{ row.name }}</td>
            <td class="url-cell">{{ row.url }}</td>
            <td v-for="cell of [row.direct, row.tunnel]" :key="cell === row.direct ? 'direct' : 'tunnel'">
              <n-tag v-if="cell.state === 'idle'" size="small">待测试</n-tag>
              <n-spin v-else-if="cell.state === 'running'" :size="14" />
              <n-tag v-else-if="cell.state === 'unavailable'" size="small">—</n-tag>
              <template v-else>
                <n-tag :type="cell.result?.reachable ? 'success' : 'error'" size="small">
                  {{ cell.result?.reachable ? '可达' : '失败' }}{{ cell.result?.samples ? ` ${cell.result.successes ?? 0}/${cell.result.samples}` : '' }}
                </n-tag>
                <span class="cell-meta">
                  {{ cell.result?.http_status || '' }}
                  {{ cell.result ? cell.result.duration_millis + ' ms' : '' }}{{ (cell.result?.samples ?? 1) > 1 ? '均' : '' }}
                </span>
                <div v-if="cell.result?.error" class="err-cell" :title="cell.result.error">{{ cell.result.error }}</div>
              </template>
            </td>
            <td>
              <n-button size="tiny" quaternary type="error" @click="removeTarget(row)">移除</n-button>
            </td>
          </tr>
        </tbody>
      </table>
    </div>
  </section>
</template>

<style scoped>
.url-cell { font-size: 12px; color: var(--ec-text-2); max-width: 220px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
.err-cell { font-size: 11px; color: var(--ec-danger); max-width: 200px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
.empty-hint { text-align: center; color: var(--ec-text-3); font-size: 13px; padding: 24px 0 8px; }
.add-row { display: flex; gap: 8px; align-items: center; }
.add-error { margin: 8px 0 0; font-size: 12px; color: var(--ec-danger); }
.tunnel-addr { display: block; font-size: 11px; font-weight: 400; color: var(--ec-text-3); }
.cell-meta { font-size: 11px; color: var(--ec-text-3); margin-left: 4px; }
</style>
