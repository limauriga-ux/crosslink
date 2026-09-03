import { defineStore } from 'pinia'
import { computed, ref } from 'vue'
import { Window } from '@wailsio/runtime'
import { api } from '../api/client'
import type { AppState, CommandResult, ConfigDocument, DaemonStatus, OpenVPNStatusResult, TestReport, TestTarget, VPNStatusResult } from '../types'

export const useAppStore = defineStore('app', () => {
  const appState = ref<AppState | null>(null)
  const config = ref<ConfigDocument | null>(null)
  const configPath = ref('config.json')
  const status = ref<DaemonStatus>({ state: 'unknown' })
  const lastError = ref('')
  const lastMessage = ref('')
  const busy = ref(false)
  const testReport = ref<TestReport | null>(null)
  let messageTimer: number | undefined

  // VPN / corplink state
  const vpnConnected = ref(false)
  const vpnReconnecting = ref(false)
  const vpnReconnectBackoffTo = ref(0)
  const vpnNodeName = ref('')
  const vpnIP = ref('')
  const vpnDNS = ref('')
  const vpnProtocol = ref('')
  const vpnConnectedAt = ref(0)
  const vpnMixedAddr = ref('')
  const isAuthenticated = ref(false)

  // Last full VPNStatusResult, kept for the diagnostics fields the individual
  // refs above don't cover (probe state, dead verdicts, daemon version...).
  const vpnDiagnostics = ref<VPNStatusResult | null>(null)
	const openVPNStatus = ref<OpenVPNStatusResult | null>(null)

  // True while the local proxy is usable. Judged on mixedAddr alone, NOT on
  // reconnecting: mixedAddr is non-empty iff the mixed listener is published
  // and serving (publishConnectedLocked, or the preserved generation during a
  // reconnect backoff), and Disconnect() zeroes it.
  const vpnServing = computed(() => vpnConnected.value || vpnMixedAddr.value !== '')

  // True while a reconnect campaign is in flight. reconnecting alone LIES in
  // State E: a failed ActionConnect clears it (without touching status) and
  // the retry loop can never set it back, yet the loop keeps refreshing
  // reconnect_backoff_to on every failed attempt. So OR both signals; each
  // poll re-evaluates the backoff half, which is enough for indicators.
  const vpnInFlight = computed(
    () => vpnReconnecting.value || vpnReconnectBackoffTo.value * 1000 > Date.now()
  )

  // Selected node — persisted to ~/.crosslink/gui_state.json via Wails binding
  const selectedNodeId = ref<number | null>(null)
  const selectedNodeName = ref('')
  const selectedNodeLatency = ref(0)

  // Whether to respect server split-routes (true = split-tunnel, default)
  const followSplitRoutes = ref(true)


  // User-added connectivity test sites, persisted alongside the toggles.
  const customTestTargets = ref<TestTarget[]>([])

  // Built-in default test targets the user deleted (by name), persisted so
  // the deletion survives restarts.
  const removedTestTargets = ref<string[]>([])

  // Single writer for ~/.crosslink/gui_state.json. Every persisted field
  async function persistWindowState(): Promise<void> {
    try {
      const size = await Window.Size()
      await api.saveWindowState({
        width: size.width,
        height: size.height,
        selected_node_id: selectedNodeId.value ?? undefined,
        selected_node_name: selectedNodeName.value || undefined,
        selected_node_latency: selectedNodeLatency.value || undefined,
        follow_split_routes: followSplitRoutes.value,
        custom_test_targets: customTestTargets.value.length ? customTestTargets.value : undefined,
        removed_test_targets: removedTestTargets.value.length ? removedTestTargets.value : undefined,
      })
    } catch { /* no-op outside Wails */ }
  }

  function setCustomTestTargets(list: TestTarget[]): void {
    customTestTargets.value = list
    persistWindowState()
  }

  function setRemovedTestTargets(list: string[]): void {
    removedTestTargets.value = list
    persistWindowState()
  }

  const isRunning = computed(() => status.value.state === 'running')
  async function refresh() {
    try {
      appState.value = await api.getAppState()
      status.value = appState.value.status
      configPath.value = appState.value.config_path || configPath.value
      if (lastError.value.startsWith('后端调用失败：GetAppState')) {
        lastError.value = ''
      }
    } catch (error) {
      lastError.value = errorText(error)
    }
  }

  async function loadConfig(path = '') {
    const res = await api.loadConfig(path)
    if (!res.ok || !res.config) {
      lastError.value = res.error || '配置加载失败'
      return
    }
    config.value = res.config
    configPath.value = res.path
  }

  async function saveConfig() {
    if (!config.value) return false
    try {
      const res = await api.saveConfig(configPath.value, config.value)
      lastError.value = res.ok ? '' : (res.errors || []).join('\n')
      return res.ok
    } catch (error) {
      lastError.value = errorText(error)
      return false
    }
  }

  async function toggleDaemon() {
    busy.value = true
    lastError.value = ''
    const stopping = isRunning.value
    lastMessage.value = stopping ? '正在断开...' : '正在连接...'
    try {
      const res = stopping ? await api.stopDaemon() : await api.startDaemon(configPath.value)
      await refresh()
      if (res.ok) {
        lastError.value = ''
        lastMessage.value = !stopping && status.value.state === 'running'
          ? `已连接${status.value.pid ? ` · PID ${status.value.pid}` : ''}`
          : `已断开${res.summary ? `：${res.summary}` : ''}`
        clearMessageLater()
      } else {
        lastMessage.value = ''
        lastError.value = commandErrorText(res)
      }
    } catch (error) {
      lastMessage.value = ''
      lastError.value = errorText(error)
    } finally {
      busy.value = false
    }
  }

  async function runTests() {
    busy.value = true
    try {
      testReport.value = await api.runConnectivityTests()
    } finally {
      busy.value = false
    }
  }

  async function refreshVPNStatus(): Promise<void> {
    try {
      const st = await api.getVPNStatus()
      vpnConnected.value = st.connected
      vpnReconnecting.value = st.reconnecting ?? false
      vpnReconnectBackoffTo.value = st.reconnect_backoff_to ?? 0
      vpnNodeName.value = st.node_name || ''
      vpnIP.value = st.vpn_ip || ''
      vpnDNS.value = st.dns || ''
      vpnProtocol.value = st.protocol || ''
      vpnConnectedAt.value = st.connected_at || 0
      vpnMixedAddr.value = st.mixed_addr || ''
      if (st.route_mode_known && typeof st.follow_split_routes === 'boolean') {
        const changed = followSplitRoutes.value !== st.follow_split_routes
        followSplitRoutes.value = st.follow_split_routes
        if (changed) persistWindowState()
      }
      vpnDiagnostics.value = st
    } catch {
      // ignore
    }
  }

	async function refreshOpenVPNStatus(): Promise<void> {
		try {
			openVPNStatus.value = await api.getOpenVPNStatus()
		} catch {
			// The next poll converges after daemon startup/reload.
		}
	}

  async function connectVPN(nodeID: number): Promise<boolean> {
    try {
		const res = await api.connectVPN(nodeID, followSplitRoutes.value)
      if (res.ok) {
        await refreshVPNStatus()
        return true
      }
      lastError.value = res.summary || '连接失败'
      return false
    } catch (error) {
      lastError.value = errorText(error)
      return false
    }
  }

  async function disconnectVPN(): Promise<void> {
    try {
      await api.disconnectVPN()
      vpnConnected.value = false
      vpnReconnecting.value = false
      vpnReconnectBackoffTo.value = 0
      vpnNodeName.value = ''
      vpnIP.value = ''
      vpnDNS.value = ''
      vpnProtocol.value = ''
      vpnConnectedAt.value = 0
      vpnMixedAddr.value = ''
      vpnDiagnostics.value = null
    } catch (error) {
      lastError.value = errorText(error)
    }
  }

  function clearMessageLater() {
    if (messageTimer) window.clearTimeout(messageTimer)
    messageTimer = window.setTimeout(() => {
      lastMessage.value = ''
    }, 4000)
  }

  return {
    appState,
    config,
    configPath,
    status,
    lastError,
    lastMessage,
    busy,
    testReport,
    isRunning,
    // VPN / corplink
    vpnConnected,
    vpnReconnecting,
    vpnReconnectBackoffTo,
    vpnNodeName,
    vpnIP,
    vpnDNS,
    vpnProtocol,
    vpnConnectedAt,
    vpnMixedAddr,
    vpnDiagnostics,
		openVPNStatus,
    vpnServing,
    vpnInFlight,
    isAuthenticated,
    // selected node
    selectedNodeId,
    selectedNodeName,
    selectedNodeLatency,
    followSplitRoutes,
    customTestTargets,
    removedTestTargets,
    persistWindowState,
    setCustomTestTargets,
    setRemovedTestTargets,
    refresh,
    loadConfig,
    saveConfig,
    toggleDaemon,
    runTests,
    refreshVPNStatus,
		refreshOpenVPNStatus,
    connectVPN,
    disconnectVPN,
  }
})

function commandErrorText(res: CommandResult): string {
  const summary = res.summary || '命令执行失败'
  if (!res.details || res.details === summary) {
    return summary
  }
  return `${summary}\n\n${res.details}`
}

function errorText(error: unknown): string {
  if (error instanceof Error) {
    return error.message
  }
  if (typeof error === 'string') {
    return error
  }
  return '操作失败'
}
