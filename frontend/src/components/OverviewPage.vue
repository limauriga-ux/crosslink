<script setup lang="ts">
import { computed, onMounted, onUnmounted, ref, watch } from 'vue'
import { BarChart3, Eye, EyeOff, Globe2, MapPin, Power, RefreshCw, Server, SlidersHorizontal, Zap } from '@lucide/vue'
import { useMessage } from 'naive-ui'
import { api } from '../api/client'
import { useAppStore } from '../stores/app'
import type { IPInfoResult, ProxyGroupResult, VPNNode } from '../types'

const emit = defineEmits<{ 'select-node': [node: VPNNode] }>()
const store = useAppStore()
const message = useMessage()

const connecting = ref(false)
const cancellingReconnect = ref(false)
const error = ref('')
const connectedAt = ref<number | null>(null)
const duration = ref('')
const txTotal = ref('')
const rxTotal = ref('')
const txRate = ref('')
const rxRate = ref('')
let durationTimer: number | undefined
let statsTimer: number | undefined
let reconnectTimer: number | undefined
let prevTx = 0, prevRx = 0, prevStatsAt = 0
const reconnectClock = ref(Date.now())
const publicGroups = ref<ProxyGroupResult[]>([])
const publicGroupsRuntime = ref(false)

const publicRouteSummary = computed(() => publicGroups.value
  .map(group => `${group.tag} → ${group.selected || '—'}`)
  .join(' · '))


const publicProxyStatus = computed(() => {
  const status = store.vpnDiagnostics
  if (!status?.core_running) {
    if (store.vpnMixedAddr) {
      return { label: '状态未知', type: 'warning' as const, detail: '当前 daemon 版本不支持公网状态判断，请先更新并重启 daemon' }
    }
    return { label: '未启用', type: 'error' as const, detail: 'sing-box 公网代理核心未运行' }
  }
  if (status.public_route_conflicts?.length) {
    return {
      label: 'TUN 冲突',
      type: 'error' as const,
      detail: `外部 TUN ${status.public_route_conflicts.join('、')} 正在接管公网路由；CrossLink 不能声称系统流量已走所选节点`,
    }
  }
  if (status.public_proxy_enabled) {
    return { label: '已启用', type: 'success' as const, detail: 'CrossLink TUN 已接管流量，默认公网出口使用代理节点' }
  }
  if (status.proxy_available) {
    return { label: '仅 Mixed Port', type: 'warning' as const, detail: '代理节点可用，但 CrossLink 系统 TUN 未接管；只有显式配置 Mixed Port 的应用走代理' }
  }
  return { label: '默认直连', type: 'default' as const, detail: '核心正在运行，但默认公网出口没有使用代理节点' }
})
async function loadPublicGroups() {
  try {
    const response = await api.getProxyGroups()
    publicGroups.value = response.ok ? (response.groups ?? []) : []
    publicGroupsRuntime.value = response.ok && (response.runtime ?? false)
  } catch {
    publicGroups.value = []
    publicGroupsRuntime.value = false
  }
}
onMounted(loadPublicGroups)

const ipDisplay = computed(() => store.vpnIP || '—')
const dnsDisplay = computed(() => store.vpnDNS || '—')
const protocolDisplay = computed(() => store.vpnProtocol || '—')
const durationDisplay = computed(() => duration.value || '—')

// Backoff countdown is driven by reconnect_backoff_to alone, NOT gated on
// reconnecting: in State E the retry loop keeps refreshing backoff_to while
// reconnecting is stuck false, and the countdown must keep running there.
const reconnectRemainingSeconds = computed(() => {
  const backoffTo = store.vpnReconnectBackoffTo
  if (backoffTo <= 0) return 0
  return Math.max(0, Math.ceil(backoffTo - reconnectClock.value / 1000))
})

const reconnectStatusText = computed(() => {
  const seconds = reconnectRemainingSeconds.value
  if (seconds <= 0) return '正在尝试恢复连接...'
  return `网络暂不可用，${formatWait(seconds)} 后自动重试`
})

function formatWait(seconds: number): string {
  if (seconds >= 60) {
    const minutes = Math.floor(seconds / 60)
    const rest = seconds % 60
    return rest > 0 ? `${minutes} 分 ${rest} 秒` : `${minutes} 分钟`
  }
  return `${seconds} 秒`
}

function formatDuration(ms: number): string {
  const s = Math.floor(ms / 1000)
  const h = Math.floor(s / 3600)
  const m = Math.floor((s % 3600) / 60)
  const sec = s % 60
  if (h > 0) return `${h}h ${m}m ${sec}s`
  if (m > 0) return `${m}m ${sec}s`
  return `${sec}s`
}

function formatRate(bytesPerSec: number): string {
  if (bytesPerSec < 1024) return `${bytesPerSec.toFixed(0)} B/s`
  if (bytesPerSec < 1024 * 1024) return `${(bytesPerSec / 1024).toFixed(1)} KB/s`
  return `${(bytesPerSec / 1024 / 1024).toFixed(2)} MB/s`
}

function formatBytes(bytes: number): string {
  if (bytes < 1024) return `${bytes.toFixed(0)} B`
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`
  if (bytes < 1024 * 1024 * 1024) return `${(bytes / 1024 / 1024).toFixed(2)} MB`
  return `${(bytes / 1024 / 1024 / 1024).toFixed(2)} GB`
}

// Relative time for diagnostics timestamps ("3 分钟前").
function timeAgo(unixSec: number | undefined): string {
  if (!unixSec || unixSec <= 0) return '—'
  const delta = Math.max(0, Math.floor(Date.now() / 1000 - unixSec))
  if (delta < 60) return `${delta} 秒前`
  if (delta < 3600) return `${Math.floor(delta / 60)} 分钟前`
  if (delta < 86400) return `${Math.floor(delta / 3600)} 小时前`
  return `${Math.floor(delta / 86400)} 天前`
}

async function pollStats() {
  try {
    const s = await api.getVPNStats()
    if (!s.ok) return
    const now = Date.now()
    txTotal.value = formatBytes(s.tx_bytes)
    rxTotal.value = formatBytes(s.rx_bytes)
    if (prevStatsAt > 0) {
      const dt = (now - prevStatsAt) / 1000
      if (dt > 0) {
        const txBps = (s.tx_bytes - prevTx) / dt
        const rxBps = (s.rx_bytes - prevRx) / dt
        txRate.value = formatRate(txBps)
        rxRate.value = formatRate(rxBps)
        txHistory.value = [...txHistory.value.slice(-(RATE_HISTORY - 1)), txBps]
        rxHistory.value = [...rxHistory.value.slice(-(RATE_HISTORY - 1)), rxBps]
      }
    }
    prevTx = s.tx_bytes
    prevRx = s.rx_bytes
    prevStatsAt = now
  } catch { /* ignore */ }
}

// Rate history feeding the traffic sparkline (last 60 one-second samples).
const RATE_HISTORY = 60
const txHistory = ref<number[]>([])
const rxHistory = ref<number[]>([])

const sparkMax = computed(() => Math.max(1024, ...txHistory.value, ...rxHistory.value))

function sparkPoints(hist: number[], max: number): string {
  if (hist.length < 2) return ''
  const w = 300, h = 56, pad = 4
  const step = w / (RATE_HISTORY - 1)
  const offset = RATE_HISTORY - hist.length
  return hist
    .map((v, i) => `${((i + offset) * step).toFixed(1)},${(pad + (1 - v / max) * (h - pad * 2)).toFixed(1)}`)
    .join(' ')
}

const txSpark = computed(() => sparkPoints(txHistory.value, sparkMax.value))
const rxSpark = computed(() => sparkPoints(rxHistory.value, sparkMax.value))

function startTimers() {
  // Use daemon's connectedAt if available, otherwise fall back to now
  connectedAt.value = store.vpnConnectedAt > 0 ? store.vpnConnectedAt * 1000 : Date.now()
  duration.value = formatDuration(Date.now() - connectedAt.value)
  txTotal.value = ''
  rxTotal.value = ''
  txRate.value = ''
  rxRate.value = ''
  txHistory.value = []
  rxHistory.value = []
  prevStatsAt = 0
  durationTimer = window.setInterval(() => {
    if (connectedAt.value) duration.value = formatDuration(Date.now() - connectedAt.value)
  }, 1000)
  statsTimer = window.setInterval(pollStats, 1000)
}

function stopTimers() {
  connectedAt.value = null
  duration.value = ''
  txTotal.value = ''
  rxTotal.value = ''
  txRate.value = ''
  rxRate.value = ''
  txHistory.value = []
  rxHistory.value = []
  prevStatsAt = 0
  if (durationTimer) { window.clearInterval(durationTimer); durationTimer = undefined }
  if (statsTimer) { window.clearInterval(statsTimer); statsTimer = undefined }
}

function startReconnectTimer() {
  if (reconnectTimer) return
  reconnectClock.value = Date.now()
  reconnectTimer = window.setInterval(() => {
    reconnectClock.value = Date.now()
  }, 1000)
}

function stopReconnectTimer() {
  if (reconnectTimer) {
    window.clearInterval(reconnectTimer)
    reconnectTimer = undefined
  }
}

watch(() => store.vpnConnected, (v) => {
  if (v) startTimers()
  else stopTimers()
}, { immediate: true })

// The menu-bar tray now embodies the "closing the window keeps the proxy
// running" disclosure, so no toast is needed here; the detail card keeps a
// single hint line pointing at the tray icon.

// When we get a connectedAt from daemon (e.g. app re-opened while VPN already running),
// update the connectedAt so duration reflects actual connection time.
watch(() => store.vpnConnectedAt, (ts) => {
  if (ts > 0 && store.vpnConnected) {
    connectedAt.value = ts * 1000 // convert to ms
  }
})

watch(() => store.vpnInFlight, (v) => {
  if (v) startReconnectTimer()
  else stopReconnectTimer()
}, { immediate: true })

onUnmounted(() => {
  stopTimers()
  stopReconnectTimer()
  if (pingTimer) { window.clearInterval(pingTimer); pingTimer = undefined }
})

const powerLabel = computed(() => {
  if (store.vpnConnected) return '企业已连接'
  if (cancellingReconnect.value) return '取消中...'
  if (store.vpnInFlight) return '企业重连中...'
  if (connecting.value) return '企业连接中...'
  if (store.selectedNodeId) return '连接企业网络'
  return '企业未连接'
})

// Visual state of the power button: off | working (connecting/reconnecting) | on.
const powerState = computed(() => {
  if (store.vpnConnected) return 'on'
  if (connecting.value || store.vpnInFlight || cancellingReconnect.value) return 'working'
  return 'off'
})

// The system TUN and public proxy graph remain active while only the corporate
// endpoint reconnects.
const statusLine = computed(() => {
  const publicLabel = `公网代理${publicProxyStatus.value.label}`
  if (store.vpnConnected) return `${publicLabel} · 企业链路已连接`
  if (store.vpnInFlight) return `${publicLabel} · 企业链路重连中`
  return `${publicLabel} · 企业链路未连接`
})

// ── Node list (inline, replaces the old selection dialog) ───────────────────
const nodes = ref<VPNNode[]>([])
const nodesError = ref('')
const nodesBusy = ref(false)
const pinging = ref(false)
let pingTimer: number | undefined

// Public proxy traffic and the system TUN survive every corporate node swap.
const switchingLive = computed(() => store.vpnConnected || store.vpnInFlight)

watch(() => store.isAuthenticated, (v) => {
  if (v && !nodes.value.length) loadNodes()
}, { immediate: true })

async function loadNodes() {
  nodesBusy.value = true
  nodesError.value = ''
  try {
    const res = await api.listVPNNodes()
    if (!res.ok) { nodesError.value = res.error || '获取节点失败'; return }
    nodes.value = (res.nodes || []).map(n => ({ ...n, latency_ms: -1 }))
    pingAllStreaming()
    // Keep the displayed latency fresh while the page is open.
    if (!pingTimer) {
      pingTimer = window.setInterval(() => { if (!pinging.value) pingAllStreaming() }, 60000)
    }
  } catch (e) {
    nodesError.value = String(e)
  } finally {
    nodesBusy.value = false
  }
}

function applyPingResult(index: number, latency: number) {
  const node = nodes.value[index]
  if (!node) return
  nodes.value[index] = { ...node, latency_ms: latency }
  // Keep the selected node's persisted latency from going stale.
  if (node.id === store.selectedNodeId) store.selectedNodeLatency = latency
}

function pingAllStreaming() {
  if (!nodes.value.length) return
  pinging.value = true
  let done = 0
  nodes.value.forEach((node, i) => {
    api.pingSingleNode(node.id).then(pr => {
      if (pr.ok && pr.nodes && pr.nodes[0]) applyPingResult(i, pr.nodes[0].latency_ms)
    }).catch(() => {}).finally(() => {
      done++
      if (done === nodes.value.length) pinging.value = false
    })
  })
}

function pingNodes() {
  nodes.value = nodes.value.map(n => ({ ...n, latency_ms: -1 }))
  pingAllStreaming()
}

function selectNode(node: VPNNode) {
  emit('select-node', node)
}

// Pick the fastest node among those with a valid measurement.
function selectFastest() {
  const measured = nodes.value.filter(n => n.latency_ms > 0 && n.latency_ms < 9999)
  if (!measured.length) return
  const fastest = measured.reduce((a, b) => (a.latency_ms <= b.latency_ms ? a : b))
  selectNode(fastest)
}

function isCurrent(node: VPNNode): boolean {
  return store.selectedNodeId === node.id
}

// latency_ms >= 9999 is the daemon's "unmeasured/timeout" sentinel.
function latencyLabel(ms: number): string {
  if (ms < 0) return '测速中'
  if (ms === 0 || ms >= 9999) return '超时'
  return `${ms} ms`
}

// Signal strength: 4 bars excellent … 1 bar poor, 0 when unknown.
function latencyBars(ms: number): number {
  if (ms <= 0 || ms >= 9999) return 0
  if (ms < 60) return 4
  if (ms < 120) return 3
  if (ms < 300) return 2
  return 1
}

function latencyClass(ms: number): string {
  if (ms < 0) return 'lat-pinging'
  if (ms === 0 || ms >= 9999) return 'lat-unknown'
  if (ms < 100) return 'lat-good'
  if (ms < 300) return 'lat-ok'
  return 'lat-bad'
}

async function handlePowerClick() {
  // connected is checked first on purpose: on the 253c6eb daemon baseline a
  // manual Connect could leave `reconnecting` stuck true after a successful
  // connect (fixed in 57e1e0b). In that state the right action is disconnect,
  // not cancel-reconnect.
  if (store.vpnConnected) {
    await store.disconnectVPN()
  } else if (store.vpnInFlight) {
    // Cancel the in-flight reconnect campaign — including State E, where
    // reconnecting reads false but the retry loop is still running.
    cancellingReconnect.value = true
    error.value = ''
    try {
      await store.disconnectVPN()
    } finally {
      cancellingReconnect.value = false
    }
  } else if (store.selectedNodeId) {
    connecting.value = true
    error.value = ''
    try {
      const res = await api.connectVPN(store.selectedNodeId, store.followSplitRoutes)
      if (res.ok) {
        await store.refreshVPNStatus()
      } else {
        error.value = res.summary || '连接失败'
      }
    } finally {
      connecting.value = false
    }
  } else {
    message.info('请先在下方服务器列表中选择节点')
  }
}

async function onFollowSplitRoutesChange(v: boolean) {
  const previous = store.followSplitRoutes
  store.followSplitRoutes = v
  // Apply in real time, then read the mode back from the daemon. The persisted
  // GUI preference is not evidence that the running route table changed.
  if (store.vpnConnected || store.vpnInFlight) {
    try {
      const res = await api.setFollowSplitRoutes(v)
      if (!res.ok) throw new Error(res.summary || '切换失败')
      await store.refreshVPNStatus()
      const live = store.vpnDiagnostics
      if (live?.route_mode_known && live.follow_split_routes !== v) {
        throw new Error('daemon 未采用请求的企业路由模式')
      }
      await refreshIPInfo()
      message.success(v ? '已生效：仅企业规则走公司链路' : '已生效：企业全隧道')
    } catch (error) {
      await store.refreshVPNStatus()
      if (!store.vpnDiagnostics?.route_mode_known) store.followSplitRoutes = previous
      message.error(error instanceof Error ? error.message : '切换失败，请重试')
    }
  }
  try {
    await store.persistWindowState()
  } catch { /* no-op outside Wails */ }
}


// Single mixed-port address used for all three proxy env vars.
const proxyEnvText = computed(() => {
  const addr = store.vpnMixedAddr
  if (!addr) return ''
  return `export https_proxy=http://${addr} http_proxy=http://${addr} all_proxy=socks5://${addr}`
})

const copied = ref(false)
async function copyProxyEnv() {
  const text = proxyEnvText.value
  if (!text) return
  try {
    await navigator.clipboard.writeText(text)
  } catch {
    // Fallback for environments without the async clipboard API.
    const ta = document.createElement('textarea')
    ta.value = text
    document.body.appendChild(ta)
    ta.select()
    try { document.execCommand('copy') } catch { /* ignore */ }
    document.body.removeChild(ta)
  }
  copied.value = true
  window.setTimeout(() => { copied.value = false }, 1500)
}

// Compare three measured facts: the actual system path, a probe forced through
// the selected public outbound, and a probe forced through CorpLink. Never
// infer route ownership from a toggle or from the enterprise node address.
const ipInfo = ref<IPInfoResult | null>(null)
const publicIPInfo = ref<IPInfoResult | null>(null)
const corporateIPInfo = ref<IPInfoResult | null>(null)
const ipInfoLoading = ref(false)
const ipVisible = ref(false)
const liveFollowSplitRoutes = computed(() => store.vpnDiagnostics?.route_mode_known
  ? Boolean(store.vpnDiagnostics.follow_split_routes)
  : store.followSplitRoutes)
const routeModeLabel = computed(() => store.vpnDiagnostics?.route_mode_known
  ? (liveFollowSplitRoutes.value ? '企业规则分流' : '企业全隧道')
  : '模式未回读')

function sameExit(left: IPInfoResult | null, right: IPInfoResult | null): boolean {
  if (!left?.ok || !right?.ok) return false
  if (left.ip && left.ip === right.ip) return true
  return Boolean(left.org && right.org && left.org === right.org && left.country === right.country)
}

const exitComparison = computed(() => {
  if (!ipInfo.value?.ok) return null
  const viaPublic = sameExit(ipInfo.value, publicIPInfo.value)
  const viaCorporate = sameExit(ipInfo.value, corporateIPInfo.value)
  if (viaPublic && viaCorporate) return { same: true, label: '系统出口与公司、ISP 探测属于同一出口网络' }
  if (viaPublic) return { same: true, label: '系统当前走所选 ISP 公网节点' }
  if (viaCorporate) return { same: false, label: '系统当前走公司外网出口' }
  return { same: false, label: '系统出口与公司、ISP 两条独立探测均不同' }
})

watch(() => store.vpnMixedAddr, (addr) => {
  if (addr) {
    refreshIPInfo()
    loadPublicGroups()
  } else {
    ipInfo.value = null
    publicIPInfo.value = null
    corporateIPInfo.value = null
    publicGroups.value = []
  }
}, { immediate: true })

async function refreshIPInfo() {
  if (!store.vpnMixedAddr) return
  ipInfoLoading.value = true
  try {
    const requests: Promise<IPInfoResult>[] = [api.getIPInfo(''), api.getPublicIPInfo()]
    if (store.vpnConnected) requests.push(api.getCorporateIPInfo())
    const [systemResult, publicResult, corporateResult] = await Promise.allSettled(requests)
    ipInfo.value = systemResult.status === 'fulfilled'
      ? systemResult.value
      : { ok: false, error: String(systemResult.reason) }
    publicIPInfo.value = publicResult.status === 'fulfilled'
      ? publicResult.value
      : { ok: false, error: String(publicResult.reason) }
    corporateIPInfo.value = corporateResult
      ? (corporateResult.status === 'fulfilled' ? corporateResult.value : { ok: false, error: String(corporateResult.reason) })
      : null
  } finally {
    ipInfoLoading.value = false
  }
}

// "AS3257 GTT Americas, LLC" → ASN + ISP name.
function splitOrg(org: string | undefined): { asn: string; isp: string } {
  const parts = (org || '').split(' ')
  return { asn: parts[0] || '—', isp: parts.slice(1).join(' ') || '—' }
}

const ipInfoAsn = computed(() => splitOrg(ipInfo.value?.org).asn)
const ipInfoIsp = computed(() => splitOrg(ipInfo.value?.org).isp)
const ipInfoLocation = computed(() => {
  const info = ipInfo.value
  if (!info) return '—'
  return [info.city, info.region].filter(Boolean).join(', ') || '—'
})
const publicIPInfoAsn = computed(() => splitOrg(publicIPInfo.value?.org).asn)
const publicIPInfoIsp = computed(() => splitOrg(publicIPInfo.value?.org).isp)
const corporateIPInfoAsn = computed(() => splitOrg(corporateIPInfo.value?.org).asn)
const corporateIPInfoIsp = computed(() => splitOrg(corporateIPInfo.value?.org).isp)

// ISO country code → flag emoji via regional indicator symbols.
function countryFlag(cc: string | undefined): string {
  if (!cc || cc.length !== 2) return ''
  return String.fromCodePoint(...[...cc.toUpperCase()].map(c => 0x1F1E6 + c.charCodeAt(0) - 65))
}

const maskedIP = '••••••••'

// ── Diagnostics (fields mirrored from daemonipc.VPNStatusDTO) ────────────────
const diag = computed(() => store.vpnDiagnostics)

const probeOutcome = computed(() => {
  const outcome = diag.value?.probe_last_outcome || ''
  const map: Record<string, { label: string; cls: string }> = {
    ok: { label: '正常', cls: 'diag-ok' },
    'dns-flaky': { label: 'DNS 抖动（已豁免）', cls: 'diag-warn' },
    'host-stalled': { label: '直连受阻（已否决）', cls: 'diag-warn' },
    dead: { label: '判死', cls: 'diag-bad' },
  }
  return map[outcome] ?? { label: outcome || '—', cls: '' }
})

const diagRows = computed(() => {
  const d = diag.value
  if (!d) return []
  const threshold = d.probe_threshold ?? 3
  const consecutive = d.probe_threshold
    ? `${d.probe_consecutive ?? 0}/${d.probe_threshold}`
    : `${d.probe_consecutive ?? 0}`
  const failures = d.probe_total_failures ?? d.probe_failures ?? 0
  return [
    { label: '探针状态', value: probeOutcome.value.label, cls: probeOutcome.value.cls },
    { label: '连续失败', value: consecutive },
    // Probe failures are common and mostly self-healing; only a full streak of
    // `threshold` consecutive failures triggers a reconnect. Word accordingly.
    { label: '探针失败累计', value: `${failures} 次（连续 ${threshold} 次才判死）` },
    { label: '流量否决', value: `${d.probe_total_traffic_vetoes ?? d.probe_traffic_vetoes ?? 0} 次` },
    { label: '累计重连', value: `${d.reconnect_total ?? 0} 次` },
    { label: '上次判死', value: d.last_dead_reason ? `${d.last_dead_reason}（${timeAgo(d.last_dead_at)}）` : '—' },
    { label: '最近探针', value: timeAgo(d.probe_last_at) },
    { label: 'Daemon 版本', value: d.daemon_version || '—' },
  ]
})
</script>

<template>
  <section class="page-stack overview-page">
    <div class="page-header">
      <div>
        <h2>概览</h2>
        <p class="page-subtitle" :class="{ 'status-serving': store.vpnInFlight && !store.vpnConnected && store.vpnMixedAddr }">
          {{ statusLine }}
        </p>
      </div>
    </div>

    <!-- 重连提示（inFlight = reconnecting || 退避在推进；connected 优先，容忍 reconnecting 残留） -->
    <n-alert v-if="store.vpnInFlight && !store.vpnConnected" type="warning" :bordered="false" class="reconnect-alert">
      <div class="reconnect-content">
        <span>
          WireGuard 隧道已断开，{{ reconnectStatusText }}。
        </span>
        <n-button
          size="small"
          tertiary
          :loading="cancellingReconnect"
          @click="handlePowerClick"
        >
          取消重连
        </n-button>
      </div>
    </n-alert>

    <div class="overview-grid">
      <!-- 企业连接 -->
      <div class="card home-card">
        <div class="home-card-title"><Zap :size="15" /> 企业连接</div>
        <div class="conn-body">
          <div class="power-ring" :class="powerState">
            <button
              class="power-btn"
              :class="powerState"
              :disabled="connecting || cancellingReconnect"
              @click="handlePowerClick"
            >
              <Power :size="26" />
            </button>
          </div>
          <div class="conn-info">
            <div class="conn-action">{{ powerLabel }}</div>
            <div v-if="store.vpnConnected" class="conn-kvs">
              <div class="conn-kv"><span>IP 地址</span><strong>{{ ipDisplay }}</strong></div>
              <div class="conn-kv"><span>DNS</span><strong>{{ dnsDisplay }}</strong></div>
              <div class="conn-kv"><span>传输协议</span><strong>{{ protocolDisplay }}</strong></div>
              <div class="conn-kv"><span>在线时长</span><strong>{{ durationDisplay }}</strong></div>
            </div>
            <div v-else class="conn-hint">{{ store.selectedNodeId ? '点击按钮连接所选企业节点' : '请先在右侧选择企业节点' }}</div>
          </div>
        </div>
      </div>

      <!-- 服务器列表（内联节点选择，替代原弹窗；半宽卡片，内部滚动） -->
      <div v-if="store.isAuthenticated" class="card home-card nodes-card">
        <div class="home-card-title nodes-card-head">
          <span class="nodes-title"><Server :size="15" /> 企业节点</span>
          <span class="nodes-head-actions">
            <n-button size="tiny" tertiary :disabled="pinging || !nodes.length" @click="selectFastest">
              <template #icon><Zap :size="13" /></template>
              选最快
            </n-button>
            <n-button size="tiny" tertiary :loading="pinging" @click="pingNodes">测速</n-button>
          </span>
        </div>
        <n-alert v-if="nodesError" type="error" :show-icon="false" class="nodes-alert">{{ nodesError }}</n-alert>
        <div v-else-if="switchingLive" class="nodes-mode-hint">
          统一核心：切换企业节点时，系统 TUN 与公网代理保持运行
        </div>
        <n-spin :show="nodesBusy">
          <div v-if="!nodes.length && !nodesBusy" class="nodes-empty">暂无节点，请检查账号或网络</div>
          <div class="nodes-grid">
            <button
              v-for="node in nodes"
              :key="node.id"
              class="node-row"
              :class="{ current: isCurrent(node) }"
              @click="selectNode(node)"
            >
              <div class="node-info">
                <strong>
                  {{ node.name }}
                  <n-tag v-if="isCurrent(node)" size="tiny" type="success" class="current-tag">当前</n-tag>
                </strong>
                <span :class="['node-latency', latencyClass(node.latency_ms)]">
                  {{ latencyLabel(node.latency_ms) }}
                </span>
              </div>
              <div class="signal-bars" :class="latencyClass(node.latency_ms)">
                <span
                  v-for="bar in 4"
                  :key="bar"
                  class="bar"
                  :class="{ filled: bar <= latencyBars(node.latency_ms) }"
                />
              </div>
            </button>
          </div>
        </n-spin>
      </div>

      <!-- 企业路由模式：显示 daemon 回读值，而不是仅显示本地偏好。 -->
      <div v-if="store.isAuthenticated" class="card home-card">
        <div class="home-card-title route-mode-title">
          <span><SlidersHorizontal :size="15" /> 企业路由模式</span>
          <n-tag size="small" :type="store.vpnDiagnostics?.route_mode_known ? 'success' : 'warning'">{{ routeModeLabel }}</n-tag>
        </div>
        <div class="option-row">
          <div class="option-text">
            <span class="option-title">按企业规则分流</span>
            <span class="option-desc">{{ liveFollowSplitRoutes ? '仅企业命中的网段和域名走公司链路' : '企业端点优先匹配所有目的地' }}</span>
          </div>
          <n-switch :value="store.followSplitRoutes" size="small" @update:value="onFollowSplitRoutesChange" />
        </div>
        <div class="route-ownership">
          <div><span>公司链路</span><strong>{{ liveFollowSplitRoutes ? `${store.vpnDiagnostics?.corporate_route_count ?? 0} 网段 + ${store.vpnDiagnostics?.corporate_domain_count ?? 0} 域名` : '全隧道优先' }}</strong></div>
          <div><span>公网规则默认</span><strong>{{ store.vpnDiagnostics?.public_selected || '—' }}</strong></div>
        </div>
        <n-alert
          v-if="liveFollowSplitRoutes && ((store.vpnDiagnostics?.corporate_ignored_public_routes ?? 0) > 0 || (store.vpnDiagnostics?.corporate_ignored_public_domains ?? 0) > 0)"
          class="route-mode-warning"
          type="info"
          :show-icon="false"
        >
          已忽略企业下发的 {{ store.vpnDiagnostics?.corporate_ignored_public_routes ?? 0 }} 条公网 IP 路由和 {{ store.vpnDiagnostics?.corporate_ignored_public_domains ?? 0 }} 条公共后缀，防止 CDN 共享地址把 IPPure 等无关网站带到公司出口。
        </n-alert>
        <n-alert v-if="!liveFollowSplitRoutes" class="route-mode-warning" type="warning" :show-icon="false">
          全隧道预期使用公司出口；下方“系统实际出口”会独立检测，不再根据开关推断。
        </n-alert>
      </div>

      <!-- 公网代理状态独立于企业连接。 -->
      <div class="card home-card proxy-card">
        <div class="home-card-title public-title">
          <span><Globe2 :size="15" /> 公网代理</span>
          <n-tag size="small" :type="publicProxyStatus.type">{{ publicProxyStatus.label }}</n-tag>
        </div>
        <div class="public-status-detail">{{ publicProxyStatus.detail }}</div>
        <div v-if="publicRouteSummary" class="public-route">
          {{ publicGroupsRuntime ? '实时路由' : '配置预览' }}：{{ publicRouteSummary }}
        </div>
        <div class="public-kvs dns-kvs">
          <div><span>CrossLink TUN</span><strong>{{ store.vpnDiagnostics?.system_tun_interface ? `${store.vpnDiagnostics.system_tun_interface} 已运行` : '未运行' }}</strong></div>
          <div><span>默认出口</span><strong>{{ store.vpnDiagnostics?.public_selected || '—' }}</strong></div>
          <div><span>出口类型</span><strong>{{ store.vpnDiagnostics?.public_selected_type || '—' }}</strong></div>
          <div :class="{ protected: store.vpnDiagnostics?.dns_protected }"><span>公网 DNS</span><strong>{{ store.vpnDiagnostics?.dns_protected ? '代理 DoH 已保护' : store.vpnDiagnostics?.dns_mode === 'direct-doh' ? 'DoH 直连' : '状态未知' }}</strong></div>
          <div :class="{ protected: store.vpnDiagnostics?.domestic_direct }"><span>国内流量</span><strong>{{ store.vpnDiagnostics?.domestic_direct ? '域名 + IP 规则集直连' : '跟随 Profile' }}</strong></div>
        </div>
        <n-alert v-if="store.vpnDiagnostics?.dns_mode && !store.vpnDiagnostics?.dns_protected" class="tun-conflict-alert" type="warning" :show-icon="false">
          公网 DNS 尚未经代理：{{ store.vpnDiagnostics.dns_servers?.join('、') || 'DoH 未就绪' }}。只有默认代理出口与 CrossLink TUN 均生效时才会标记为已保护。
        </n-alert>
        <n-alert v-if="store.vpnDiagnostics?.public_route_conflicts?.length" class="tun-conflict-alert" type="error" :show-icon="false">
          检测到外部 TUN 正在接管公网：{{ store.vpnDiagnostics.public_route_conflicts.join('、') }}。这会与 CrossLink 的公网捕获路由冲突；请关闭该 VPN 的全隧道 / redirect-gateway / TUN 模式，或退出对应客户端。
        </n-alert>
        <n-alert v-else-if="store.vpnDiagnostics?.compatible_tuns?.length" class="tun-conflict-alert" type="info" :show-icon="false">
          检测到可共存的分流 VPN：{{ store.vpnDiagnostics.compatible_tuns.join('、') }}。未发现其接管公网；更具体的企业网段路由会优先于 CrossLink 公网路由，utun 序号不影响优先级。
        </n-alert>
        <n-alert v-else-if="store.vpnDiagnostics?.external_tuns?.length" class="tun-conflict-alert" type="warning" :show-icon="false">
          检测到其他 IPv4 VPN TUN：{{ store.vpnDiagnostics.external_tuns.join('、') }}，但暂未观察到可确认的分流路由或公网冲突。utun 序号本身不代表优先级；请检查该 VPN 的路由与 DNS 模式。
        </n-alert>
        <div class="proxy-body">
          <div class="option-text">
            <span class="option-title">{{ store.vpnMixedAddr || 'Mixed Port 未监听' }}</span>
            <span class="option-desc">{{ store.vpnMixedAddr ? 'SOCKS5 + HTTP 显式代理入口' : 'daemon 或 sing-box 核心尚未运行' }}</span>
          </div>
          <n-button size="tiny" tertiary :disabled="!store.vpnMixedAddr" @click="copyProxyEnv">
            {{ copied ? '已复制 ✓' : '复制环境变量' }}
          </n-button>
        </div>

        <div v-if="store.vpnMixedAddr" class="ipinfo">
          <div class="ipinfo-head">
            <span class="ipinfo-title"><MapPin :size="13" /> 系统实际出口 · {{ routeModeLabel }}</span>
            <n-button size="tiny" quaternary circle :loading="ipInfoLoading" @click="refreshIPInfo">
              <template #icon><RefreshCw :size="12" /></template>
            </n-button>
          </div>
          <div v-if="ipInfoLoading && !ipInfo" class="ipinfo-hint">查询中...</div>
          <div v-else-if="!ipInfo || !ipInfo.ok" class="ipinfo-hint ipinfo-error">
            {{ ipInfo?.error || '查询失败' }}，点右上角重试
          </div>
          <template v-else>
            <div class="ipinfo-grid">
              <div class="ipinfo-col">
                <div class="ipinfo-row"><span class="ipinfo-flag">{{ countryFlag(ipInfo.country) }}</span><strong class="ipinfo-country">{{ ipInfo.country || '—' }}</strong></div>
                <div class="ipinfo-row"><span class="detail-label">IP</span><span class="ipinfo-value">{{ ipVisible ? ipInfo.ip : maskedIP }}</span><n-button size="tiny" quaternary circle @click="ipVisible = !ipVisible"><template #icon><Eye v-if="!ipVisible" :size="12" /><EyeOff v-else :size="12" /></template></n-button></div>
                <div class="ipinfo-row"><span class="detail-label">自治域</span><span class="ipinfo-value">{{ ipInfoAsn }}</span></div>
              </div>
              <div class="ipinfo-col">
                <div class="ipinfo-row"><span class="detail-label">服务商</span><span class="ipinfo-value">{{ ipInfoIsp }}</span></div>
                <div class="ipinfo-row"><span class="detail-label">位置</span><span class="ipinfo-value">{{ ipInfoLocation }}</span></div>
                <div class="ipinfo-row"><span class="detail-label">时区</span><span class="ipinfo-value">{{ ipInfo.timezone || '—' }}</span></div>
              </div>
            </div>
          </template>

          <div v-if="exitComparison" :class="['egress-verdict', exitComparison.same ? 'same' : 'different']">
            {{ exitComparison.label }}
          </div>
          <div class="public-egress-proof">
            <div class="public-egress-head">
              <span>所选公网节点出口 · {{ store.vpnDiagnostics?.public_selected || '—' }}</span>
              <n-tag v-if="publicIPInfo?.ok" size="small" type="info">独立直连探测</n-tag>
            </div>
            <div v-if="ipInfoLoading && !publicIPInfo" class="ipinfo-hint">正在经所选节点查询...</div>
            <div v-else-if="!publicIPInfo?.ok" class="ipinfo-hint ipinfo-error">{{ publicIPInfo?.error || '公网节点出口查询失败' }}</div>
            <div v-else class="public-egress-values">
              <strong>{{ countryFlag(publicIPInfo.country) }} {{ publicIPInfo.country || '—' }}</strong>
              <span>{{ ipVisible ? publicIPInfo.ip : maskedIP }}</span>
              <span>{{ publicIPInfoAsn }} · {{ publicIPInfoIsp }}</span>
            </div>
          </div>
          <div v-if="store.vpnConnected" class="public-egress-proof corporate-egress-proof">
            <div class="public-egress-head">
              <span>公司链路外网出口 · {{ store.vpnNodeName || '—' }}</span>
              <n-tag v-if="corporateIPInfo?.ok" size="small" type="warning">WireGuard 独立探测</n-tag>
            </div>
            <div v-if="ipInfoLoading && !corporateIPInfo" class="ipinfo-hint">正在经公司链路查询...</div>
            <div v-else-if="!corporateIPInfo?.ok" class="ipinfo-hint ipinfo-error">{{ corporateIPInfo?.error || '公司链路不提供公网出口' }}</div>
            <div v-else class="public-egress-values">
              <strong>{{ countryFlag(corporateIPInfo.country) }} {{ corporateIPInfo.country || '—' }}</strong>
              <span>{{ ipVisible ? corporateIPInfo.ip : maskedIP }}</span>
              <span>{{ corporateIPInfoAsn }} · {{ corporateIPInfoIsp }}</span>
            </div>
          </div>
        </div>
      </div>

      <!-- 流量统计 -->
      <div class="card home-card traffic-card">
        <div class="home-card-title"><BarChart3 :size="15" /> 流量统计</div>
        <template v-if="store.vpnConnected">
          <div class="spark-wrap">
            <svg class="spark" viewBox="0 0 300 56" preserveAspectRatio="none">
              <polyline v-if="rxSpark" :points="rxSpark" class="spark-line spark-rx" />
              <polyline v-if="txSpark" :points="txSpark" class="spark-line spark-tx" />
            </svg>
            <div class="spark-legend">
              <span class="lg lg-tx">上传</span>
              <span class="lg lg-rx">下载</span>
            </div>
          </div>
          <div class="stat-grid">
            <div class="stat-item">
              <span class="stat-label">上传速度</span>
              <strong class="stat-num stat-up">{{ txRate || '—' }}</strong>
            </div>
            <div class="stat-item">
              <span class="stat-label">下载速度</span>
              <strong class="stat-num stat-down">{{ rxRate || '—' }}</strong>
            </div>
            <div class="stat-item">
              <span class="stat-label">上传总量</span>
              <strong class="stat-num">{{ txTotal || '—' }}</strong>
            </div>
            <div class="stat-item">
              <span class="stat-label">下载总量</span>
              <strong class="stat-num">{{ rxTotal || '—' }}</strong>
            </div>
          </div>
        </template>
        <p v-else class="traffic-empty">连接后显示实时流量</p>
      </div>
    </div>

    <p v-if="store.vpnConnected" class="bg-hint">关闭窗口后代理继续在后台运行，可从菜单栏图标查看或退出</p>

    <!-- 连接诊断（daemon 透传的探针/重连状态） -->
    <n-collapse v-if="store.vpnServing && diagRows.length" class="card diag-card">
      <n-collapse-item title="连接诊断" name="diag">
        <div class="diag-grid">
          <div v-for="row in diagRows" :key="row.label" class="diag-row">
            <span class="detail-label">{{ row.label }}</span>
            <span class="diag-value" :class="row.cls">{{ row.value }}</span>
          </div>
        </div>
      </n-collapse-item>
    </n-collapse>

    <n-alert v-if="error" type="error" :bordered="false" class="overview-alert">{{ error }}</n-alert>
  </section>
</template>

<style scoped>
.overview-page {
  min-height: 100%;
  align-content: start;
}

.page-subtitle.status-serving {
  color: var(--ec-warning);
  font-weight: 500;
}

/* ── Verge 式卡片网格 ── */
.overview-grid {
  display: grid;
  grid-template-columns: 1fr 1fr;
  gap: 16px;
}

.card {
  min-width: 0;
  background: var(--ec-panel);
  border: 1px solid var(--ec-border);
  border-radius: var(--ec-radius);
  box-shadow: var(--ec-shadow-sm);
  padding: 16px 18px;
}

.home-card-title {
  display: flex;
  align-items: center;
  gap: 6px;
  font-size: 14px;
  font-weight: 700;
  color: var(--ec-text-1);
  margin-bottom: 12px;
}

.home-card-title svg {
  color: var(--ec-primary);
}

/* ── 连接卡 ── */
.conn-body {
  display: flex;
  align-items: center;
  gap: 18px;
}

/* 只有虚线环在转：旋转放在伪元素上，按钮本体永远不旋转，
   避免环与按钮两条动画相位错开导致的歪斜。
   pointer-events: none 是必须的 —— 定位的伪元素绘制在静态按钮之上，
   没有它整个圆形区域会拦截掉落在按钮上的点击。 */
.power-ring {
  position: relative;
  width: 88px;
  height: 88px;
  display: flex;
  align-items: center;
  justify-content: center;
  flex-shrink: 0;
}

.power-ring::before {
  content: "";
  position: absolute;
  inset: 0;
  border-radius: 50%;
  border: 2px dashed var(--ec-inactive);
  transition: border-color 0.3s;
  pointer-events: none;
}

.power-ring.on::before {
  border-color: var(--ec-primary);
  animation: spin 8s linear infinite;
}

.power-ring.working::before {
  border-color: var(--ec-warning);
  animation: ring-pulse 1.6s ease-in-out infinite;
}

@keyframes spin {
  from { transform: rotate(0deg); }
  to { transform: rotate(360deg); }
}

@keyframes ring-pulse {
  0%, 100% { opacity: 1; }
  50% { opacity: 0.4; }
}

.power-btn {
  position: relative;
  width: 64px;
  height: 64px;
  border-radius: 50%;
  border: none;
  background: var(--ec-inactive);
  color: white;
  cursor: pointer;
  display: flex;
  align-items: center;
  justify-content: center;
  transition: background 0.3s, box-shadow 0.3s, transform 0.1s;
}

.power-btn:active { transform: scale(0.95); }

.power-btn.on {
  background: var(--ec-primary);
  box-shadow: 0 0 20px rgba(47, 111, 237, 0.35);
}

.power-btn.working {
  background: var(--ec-warning);
}

.conn-info {
  min-width: 0;
  flex: 1;
}

.conn-action {
  font-size: 15px;
  font-weight: 600;
  color: var(--ec-text-1);
  margin-bottom: 8px;
}

.conn-kvs {
  display: grid;
  grid-template-columns: 1fr 1fr;
  gap: 8px 14px;
}

.conn-kv {
  min-width: 0;
}

.conn-kv span {
  display: block;
  font-size: 11px;
  color: var(--ec-text-3);
}

.conn-kv strong {
  display: block;
  font-size: 13px;
  font-weight: 600;
  color: var(--ec-text-1);
  overflow-wrap: anywhere;
}

.conn-hint {
  font-size: 13px;
  color: var(--ec-text-3);
}

/* ── 服务器列表卡（半宽，与原服务器卡同槽位，列表内部滚动） ── */
.nodes-card {
  display: flex;
  flex-direction: column;
}

.nodes-card-head {
  justify-content: space-between;
  width: 100%;
}

.nodes-title {
  display: flex;
  align-items: center;
  gap: 6px;
}

.nodes-title svg {
  color: var(--ec-primary);
}

.nodes-head-actions {
  display: flex;
  gap: 8px;
}

.nodes-alert {
  margin-bottom: 10px;
}

.nodes-mode-hint {
  font-size: 12px;
  color: var(--ec-text-3);
  margin: -4px 0 10px;
}

.nodes-empty {
  text-align: center;
  color: var(--ec-text-3);
  font-size: 13px;
  padding: 24px 0;
}

.nodes-grid {
  display: grid;
  grid-template-columns: 1fr;
  gap: 6px;
  max-height: 168px;
  overflow-y: auto;
}

.node-row {
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 12px;
  width: 100%;
  padding: 9px 12px;
  border: 1px solid var(--ec-border-soft);
  border-radius: var(--ec-radius-sm);
  background: var(--ec-panel);
  cursor: pointer;
  text-align: left;
  transition: border-color 0.15s, box-shadow 0.15s;
}

.node-row:hover {
  border-color: var(--ec-primary);
  box-shadow: var(--ec-shadow-sm);
}

.node-row.current {
  border-color: var(--ec-primary);
  background: var(--ec-primary-soft);
}

.node-info {
  display: flex;
  flex-direction: column;
  gap: 2px;
  min-width: 0;
}

.node-info strong {
  font-size: 13px;
  display: flex;
  align-items: center;
  gap: 6px;
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
}

.current-tag {
  flex-shrink: 0;
}

.node-latency {
  font-size: 12px;
  font-weight: 500;
}

.signal-bars {
  display: flex;
  align-items: flex-end;
  gap: 2px;
  height: 14px;
  flex-shrink: 0;
}

.signal-bars .bar {
  width: 3px;
  border-radius: 1px;
  background: var(--ec-border);
}

.signal-bars .bar:nth-child(1) { height: 4px; }
.signal-bars .bar:nth-child(2) { height: 7px; }
.signal-bars .bar:nth-child(3) { height: 10px; }
.signal-bars .bar:nth-child(4) { height: 13px; }

.signal-bars.lat-good .bar.filled { background: var(--ec-success); }
.signal-bars.lat-ok .bar.filled { background: var(--ec-warning); }
.signal-bars.lat-bad .bar.filled { background: var(--ec-danger); }

.lat-good { color: var(--ec-success); }
.lat-ok   { color: var(--ec-warning); }
.lat-bad  { color: var(--ec-danger); }
.lat-unknown { color: var(--ec-text-3); }
.lat-pinging { color: var(--ec-text-3); font-style: italic; }

/* ── 连接选项 ── */
.option-row {
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 12px;
  padding: 8px 0;
}

.option-row + .option-row {
  border-top: 1px solid var(--ec-border-soft);
}

.option-text {
  display: flex;
  flex-direction: column;
  gap: 2px;
  min-width: 0;
}

.option-title {
  font-size: 14px;
  font-weight: 600;
  color: var(--ec-text-1);
}

.option-desc {
  font-size: 12px;
  color: var(--ec-text-3);
}

.route-mode-title,
.route-mode-title > span {
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 6px;
}

.route-ownership {
  display: grid;
  grid-template-columns: 1fr 1fr;
  gap: 8px;
  margin-top: 6px;
}

.route-ownership > div {
  display: flex;
  flex-direction: column;
  gap: 3px;
  padding: 8px 10px;
  background: var(--ec-bg);
  border-radius: 8px;
}

.route-ownership span {
  color: var(--ec-text-3);
  font-size: 11px;
}

.route-ownership strong {
  color: var(--ec-text-1);
  font-size: 12px;
}

.route-mode-warning {
  margin-top: 6px;
}

/* ── 公网代理 ── */
.public-title {
  display: flex;
  align-items: center;
  justify-content: space-between;
}

.public-title > span {
  display: flex;
  align-items: center;
  gap: 6px;
}

.public-status-detail {
  margin-bottom: 10px;
  color: var(--ec-text-2);
  font-size: 13px;
  line-height: 1.5;
}

.tun-conflict-alert {
  margin-bottom: 12px;
}

.public-kvs {
  display: grid;
  grid-template-columns: repeat(3, minmax(0, 1fr));
  gap: 8px;
  margin-bottom: 12px;
}

.dns-kvs {
  grid-template-columns: repeat(2, minmax(0, 1fr));
}

.public-kvs > div.protected {
  background: color-mix(in srgb, var(--ec-success) 10%, white);
}

.public-kvs > div.protected strong {
  color: var(--ec-success);
}

.public-kvs > div {
  display: flex;
  flex-direction: column;
  gap: 3px;
  padding: 8px 10px;
  background: var(--ec-bg);
  border-radius: 8px;
}

.public-kvs span {
  color: var(--ec-text-3);
  font-size: 11px;
}

.public-kvs strong {
  overflow: hidden;
  color: var(--ec-text-1);
  font-size: 12px;
  text-overflow: ellipsis;
  white-space: nowrap;
}

.public-route {
  margin-bottom: 10px;
  padding: 8px 10px;
  overflow: hidden;
  color: var(--ec-primary);
  font-size: 12px;
  font-weight: 600;
  text-overflow: ellipsis;
  white-space: nowrap;
  background: color-mix(in srgb, var(--ec-primary) 8%, white);
  border-radius: 8px;
}

.proxy-body {
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 12px;
}

/* ── IP 信息 ── */
.ipinfo {
  margin-top: 12px;
  padding-top: 12px;
  border-top: 1px solid var(--ec-border-soft);
}

.ipinfo-head {
  display: flex;
  align-items: center;
  justify-content: space-between;
  margin-bottom: 8px;
}

.ipinfo-title {
  display: flex;
  align-items: center;
  gap: 5px;
  font-size: 12px;
  font-weight: 600;
  color: var(--ec-text-2);
}

.ipinfo-title svg {
  color: var(--ec-primary);
}

.ipinfo-hint {
  font-size: 12px;
  color: var(--ec-text-3);
}

.ipinfo-error {
  color: var(--ec-danger);
}

.ipinfo-grid {
  display: grid;
  grid-template-columns: 1fr 1fr;
  gap: 4px 16px;
}

.ipinfo-col {
  display: flex;
  flex-direction: column;
  gap: 6px;
  min-width: 0;
}

.ipinfo-row {
  display: flex;
  align-items: center;
  gap: 6px;
  min-width: 0;
}

.ipinfo-row .detail-label {
  margin-bottom: 0;
  flex-shrink: 0;
}

.ipinfo-flag {
  font-size: 16px;
  line-height: 1;
}

.ipinfo-country {
  font-size: 13px;
  font-weight: 600;
  color: var(--ec-text-1);
}

.ipinfo-value {
  font-size: 12px;
  color: var(--ec-text-1);
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
}

.ipinfo-company {
  margin-top: 8px;
  padding-top: 8px;
  border-top: 1px dashed var(--ec-border-soft);
  font-size: 12px;
  color: var(--ec-text-3);
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
}

.egress-verdict {
  margin-top: 10px;
  padding: 7px 9px;
  font-size: 12px;
  font-weight: 600;
  border-radius: 8px;
}

.egress-verdict.same {
  color: var(--ec-success);
  background: color-mix(in srgb, var(--ec-success) 10%, white);
}

.egress-verdict.different {
  color: var(--ec-warning);
  background: color-mix(in srgb, var(--ec-warning) 12%, white);
}

.public-egress-proof {
  margin-top: 10px;
  padding-top: 10px;
  border-top: 1px dashed var(--ec-border-soft);
}

.public-egress-head,
.public-egress-values {
  display: flex;
  align-items: center;
  gap: 8px;
}

.public-egress-head {
  justify-content: space-between;
  margin-bottom: 7px;
  color: var(--ec-text-2);
  font-size: 12px;
  font-weight: 600;
}

.public-egress-values {
  flex-wrap: wrap;
  color: var(--ec-text-2);
  font-size: 12px;
}

.public-egress-values span + span {
  padding-left: 8px;
  border-left: 1px solid var(--ec-border-soft);
}

/* ── 流量统计 ── */
.traffic-card {
  grid-column: 1 / -1;
}

.spark-wrap {
  position: relative;
}

.spark {
  display: block;
  width: 100%;
  height: 64px;
  background: var(--ec-bg-soft);
  border-radius: var(--ec-radius-sm);
}

.spark-line {
  fill: none;
  stroke-width: 1.5;
}

.spark-tx { stroke: var(--ec-warning); }
.spark-rx { stroke: var(--ec-primary); }

.spark-legend {
  position: absolute;
  top: 6px;
  right: 10px;
  display: flex;
  gap: 10px;
  font-size: 11px;
  color: var(--ec-text-3);
}

.lg::before {
  content: "";
  display: inline-block;
  width: 8px;
  height: 2px;
  margin-right: 4px;
  vertical-align: middle;
}

.lg-tx::before { background: var(--ec-warning); }
.lg-rx::before { background: var(--ec-primary); }

.stat-grid {
  display: grid;
  grid-template-columns: repeat(4, 1fr);
  gap: 12px;
  margin-top: 14px;
}

.stat-item {
  min-width: 0;
  background: var(--ec-bg-soft);
  border-radius: var(--ec-radius-sm);
  padding: 10px 12px;
}

.stat-label {
  display: block;
  font-size: 11px;
  color: var(--ec-text-3);
  margin-bottom: 2px;
}

.stat-num {
  display: block;
  font-family: ui-monospace, SFMono-Regular, Menlo, monospace;
  font-size: 16px;
  font-weight: 700;
  color: var(--ec-text-1);
}

.stat-up { color: var(--ec-warning); }
.stat-down { color: var(--ec-primary); }

.traffic-empty {
  margin: 0;
  padding: 20px 0;
  text-align: center;
  font-size: 13px;
  color: var(--ec-text-3);
}

/* ── 诊断 ── */
.diag-card {
  padding: 4px 18px;
}

.diag-grid {
  display: grid;
  grid-template-columns: 1fr 1fr;
  gap: 10px 16px;
  padding-bottom: 10px;
}

.detail-label {
  display: block;
  font-size: 12px;
  color: var(--ec-text-3);
  margin-bottom: 2px;
}

.diag-value {
  font-size: 13px;
  font-weight: 500;
  color: var(--ec-text-1);
  overflow-wrap: anywhere;
}

.diag-ok { color: var(--ec-success); }
.diag-warn { color: var(--ec-warning); }
.diag-bad { color: var(--ec-danger); }

/* ── 提示 ── */
.bg-hint {
  margin: 0;
  font-size: 12px;
  color: var(--ec-text-3);
  text-align: center;
}

.reconnect-content {
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 12px;
}

@media (max-width: 760px) {
  .overview-grid {
    grid-template-columns: 1fr;
  }

  .stat-grid {
    grid-template-columns: 1fr 1fr;
  }
}
</style>
