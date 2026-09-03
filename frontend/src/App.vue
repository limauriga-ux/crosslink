<script setup lang="ts">
import { onMounted, onUnmounted, ref } from 'vue'
import {
  BriefcaseBusiness,
  FlaskConical,
  Globe2,
  Home,
  Settings,
} from '@lucide/vue'
import type { GlobalThemeOverrides } from 'naive-ui'
import { api } from './api/client'
import { useAppStore } from './stores/app'
import LoginDialog from './components/LoginDialog.vue'
import OverviewPage from './components/OverviewPage.vue'
import ProfilesPage from './components/ProfilesPage.vue'
import OpenVPNPage from './components/OpenVPNPage.vue'
import TestsPage from './components/TestsPage.vue'
import SettingsPage from './components/SettingsPage.vue'
import type { VPNNode } from './types'

type PageKey = 'overview' | 'profiles' | 'openvpn' | 'tests' | 'settings'

const page = ref<PageKey>('overview')
const store = useAppStore()
const showLogin = ref(false)
const startingMsg = ref('正在启动 CrossLink 服务...')
const starting = ref(true)
const version = ref('')

// Keep Naive UI components on the same brand color as the custom shell.
const themeOverrides: GlobalThemeOverrides = {
  common: {
    primaryColor: '#2f6fed',
    primaryColorHover: '#4b87f1',
    primaryColorPressed: '#235ed6',
    primaryColorSuppl: '#2f6fed',
    borderRadius: '10px',
    borderRadiusSmall: '8px',
  },
}

let statusTimer: number | undefined
let saveWindowTimer: number | undefined

const nav = [
  { key: 'overview' as PageKey, label: '概览', icon: Home },
	{ key: 'profiles' as PageKey, label: '公网代理', icon: Globe2 },
	{ key: 'openvpn' as PageKey, label: 'OpenVPN', icon: BriefcaseBusiness },
  { key: 'tests' as PageKey, label: '测试', icon: FlaskConical },
  { key: 'settings' as PageKey, label: '设置', icon: Settings },
]

onMounted(async () => {
  window.addEventListener('resize', saveWindowSizeSoon)
  document.addEventListener('visibilitychange', onVisibilityChange)
  window.addEventListener('focus', onWindowFocus)
  saveWindowSizeSoon()

  try { version.value = await api.getVersion() } catch { /* ignore outside Wails */ }

  // Load persisted window state (includes selected node + toggle)
  try {
    const ws = await api.getWindowState()
    if (ws.selected_node_id) {
      store.selectedNodeId = ws.selected_node_id
      store.selectedNodeName = ws.selected_node_name ?? ''
      store.selectedNodeLatency = ws.selected_node_latency ?? 0
    }
    if (ws.follow_split_routes !== undefined) {
      store.followSplitRoutes = ws.follow_split_routes
    }
    if (ws.custom_test_targets) {
      store.customTestTargets = ws.custom_test_targets.filter(t => t.name && t.url)
    }
    if (ws.removed_test_targets) {
      store.removedTestTargets = ws.removed_test_targets
    }
  } catch { /* ignore outside Wails */ }

  await ensureDaemon()

  // Check VPN status — pull the daemon's full live state so the GUI reflects
  // a connection that the (always-on, launchd-managed) daemon already holds,
  // even if the window was closed and reopened mid-session.
  try {
    await store.refreshVPNStatus()
		await store.refreshOpenVPNStatus()
  } catch { /* ignore */ }

  // Check if already authenticated
  try {
    const authed = await api.isAuthenticated()
    if (authed) {
      store.isAuthenticated = true
    } else {
      showLogin.value = true
    }
  } catch {
    showLogin.value = true
  }

  // Load config and state
  try {
    await store.loadConfig()
    await store.refresh()
  } catch { /* ignore */ }

  starting.value = false
  startPolling()
})

onUnmounted(() => {
  window.removeEventListener('resize', saveWindowSizeSoon)
  document.removeEventListener('visibilitychange', onVisibilityChange)
  window.removeEventListener('focus', onWindowFocus)
  if (saveWindowTimer) window.clearTimeout(saveWindowTimer)
  if (statusTimer) window.clearInterval(statusTimer)
})

// Re-sync the daemon's live state the moment the window becomes visible or
// focused again, so a connection made (or dropped) while the window was hidden
// shows up immediately instead of after the next 5s poll tick.
function onVisibilityChange() {
  if (document.visibilityState === 'visible' && !starting.value) {
    store.refreshVPNStatus().catch(() => {})
		store.refreshOpenVPNStatus().catch(() => {})
    store.refresh().catch(() => {})
  }
}

function onWindowFocus() {
  if (!starting.value) {
    store.refreshVPNStatus().catch(() => {})
		store.refreshOpenVPNStatus().catch(() => {})
  }
}

function saveWindowSizeSoon() {
  if (saveWindowTimer) window.clearTimeout(saveWindowTimer)
  saveWindowTimer = window.setTimeout(() => store.persistWindowState(), 300)
}

// ── Daemon auto-start ─────────────────────────────────────────────────────────
async function ensureDaemon(): Promise<void> {
  // Always check the launch service first. The previous version short-circuited
  // when the IPC socket responded, but a freshly installed GUI bundles a newer
  // daemon binary while launchd keeps running the old one from memory — the
  // socket is up, yet the running code is stale. Skipping this check meant the
  // stale-daemon kickstart branch was never reached.
  let svc: Awaited<ReturnType<typeof api.getLaunchServiceStatus>> | null = null
  try {
    startingMsg.value = '正在检查服务状态...'
    svc = await api.getLaunchServiceStatus()
    if (!svc.installed) {
      startingMsg.value = '首次启动，正在安装服务（需要管理员权限）...'
      await api.installLaunchService({ label: '', binary_path: '', config_path: '', work_dir: '' })
    } else if (svc.needs_update) {
      startingMsg.value = '检测到更新，正在重新安装服务（需要管理员权限）...'
      await api.installLaunchService({ label: '', binary_path: '', config_path: '', work_dir: '' })
    } else if (!svc.running) {
      startingMsg.value = '正在启动服务（需要管理员权限）...'
      await api.startLaunchService({ label: '', binary_path: '', config_path: '', work_dir: '' })
    } else if (svc.stale_daemon) {
      // GUI extracted a newer daemon binary on this run, but launchd is still
      // running the previous one from memory. Kickstart so the new code
      // takes effect — otherwise users see "did not get fixed" after every
      // upgrade until they manually restart the helper.
      startingMsg.value = '检测到守护进程版本过旧，正在重启（需要管理员权限）...'
      await api.startLaunchService({ label: '', binary_path: '', config_path: '', work_dir: '' })
    }
  } catch { /* ignore */ }

  // Fast path: nothing to do — service is installed, fresh, and running.
  if (svc && svc.installed && !svc.needs_update && svc.running && !svc.stale_daemon) {
    try {
      const st = await api.getVPNStatus()
      if (st.ok !== false) return
    } catch { /* fall through to wait loop */ }
  }

  startingMsg.value = '等待服务就绪...'
  for (let i = 0; i < 30; i++) {
    await new Promise(r => setTimeout(r, 500))
    try {
      const st = await api.getVPNStatus()
      if (st.ok !== false) return
    } catch { /* keep waiting */ }
  }
}

function startPolling() {
  if (statusTimer) window.clearInterval(statusTimer)
  statusTimer = window.setInterval(async () => {
    try {
      await store.refreshVPNStatus()
      await store.refresh()
    } catch { /* ignore */ }
  }, 5000)
}

async function onLoggedIn() {
  store.isAuthenticated = true
  showLogin.value = false
  // Refresh state after login
  try {
    await store.refresh()
    await store.loadConfig()
  } catch { /* ignore */ }
}

async function onNodeSelected(node: VPNNode) {
  store.selectedNodeId = node.id
  store.selectedNodeName = node.name
  store.selectedNodeLatency = node.latency_ms
  // Persist selected node to ~/.crosslink/gui_state.json
  await store.persistWindowState()

	// The public sing-box graph stays active while the corporate endpoint is
	// replaced, so node changes no longer tear down the system TUN.
  if ((store.vpnConnected || store.vpnInFlight) && node.name !== store.vpnNodeName) {
    try {
		  await api.connectVPN(node.id, store.followSplitRoutes)
      await store.refreshVPNStatus()
    } catch { /* next poll converges the state */ }
  }
}

function logout() {
  // SettingsPage already sent the logout IPC; reset local UI state only.
  store.isAuthenticated = false
  store.vpnConnected = false
  store.vpnReconnecting = false
  store.vpnReconnectBackoffTo = 0
  store.vpnNodeName = ''
  store.vpnIP = ''
  showLogin.value = true
}
</script>

<template>
  <n-config-provider :theme-overrides="themeOverrides">
    <n-message-provider>
      <n-dialog-provider>

      <!-- Starting overlay -->
      <div v-if="starting" class="center-page">
        <div class="starting-card">
          <div class="starting-logo">CrossLink</div>
          <n-spin size="medium" />
          <p class="starting-msg">{{ startingMsg }}</p>
        </div>
      </div>

      <!-- Main shell (shown after daemon is ready) -->
      <div v-else class="app-shell">

        <!-- Login modal (not closable) -->
        <LoginDialog v-model="showLogin" @logged-in="onLoggedIn" />

        <!-- Sidebar -->
        <aside class="sidebar">
          <!-- Brand + live connection dot -->
          <div class="brand">
            <span
              class="brand-dot"
              :class="store.vpnConnected ? 'dot-on' : store.vpnInFlight ? 'dot-reconnect' : 'dot-off'"
              :title="store.vpnConnected ? '已连接' : store.vpnInFlight ? '重连中' : '未连接'"
            />
            <span class="brand-text">CrossLink</span>
          </div>

          <!-- Navigation -->
          <nav class="sidebar-nav">
            <button
              v-for="item in nav"
              :key="item.key"
              class="nav-item"
              :class="{ active: page === item.key }"
              @click="page = item.key"
            >
              <component :is="item.icon" :size="20" class="nav-icon" />
              <span>{{ item.label }}</span>
            </button>
          </nav>

          <!-- Spacer -->
          <div class="sidebar-spacer" />

          <!-- Version -->
          <div v-if="version" class="sidebar-version">{{ version }}</div>
        </aside>

        <!-- Main content -->
        <main class="main">
          <n-alert
            v-if="store.lastError"
            type="error"
            closable
            class="error-banner"
            @close="store.lastError = ''"
          >
            {{ store.lastError }}
          </n-alert>

          <OverviewPage v-if="page === 'overview'" @select-node="onNodeSelected" />
		  <ProfilesPage v-else-if="page === 'profiles'" />
          <OpenVPNPage v-else-if="page === 'openvpn'" />
          <TestsPage v-else-if="page === 'tests'" />
          <SettingsPage v-else-if="page === 'settings'" @logout="logout" />
        </main>
      </div>

      </n-dialog-provider>
    </n-message-provider>
  </n-config-provider>
</template>

<style scoped>
/* ── Shared ── */
.center-page {
  display: flex;
  align-items: center;
  justify-content: center;
  min-height: 100vh;
  background: var(--ec-bg);
}

.starting-card {
  display: flex;
  flex-direction: column;
  align-items: center;
  justify-content: center;
  gap: 16px;
  width: 320px;
  padding: 40px 28px;
  background: var(--ec-panel);
  border-radius: var(--ec-radius);
  box-shadow: var(--ec-shadow-md);
}

.starting-logo {
  font-size: 22px;
  font-weight: 800;
  color: var(--ec-text-1);
  letter-spacing: -0.5px;
}

.starting-msg {
  margin: 0;
  font-size: 13px;
  color: var(--ec-text-2);
  text-align: center;
}

/* ── App shell ── */
.app-shell {
  display: grid;
  grid-template-columns: 184px minmax(0, 1fr);
  height: 100vh;
  overflow: hidden;
  background: var(--ec-bg);
}

/* ── Sidebar — light rail with horizontal icon+label rows, à la Clash Verge ── */
.sidebar {
  width: 184px;
  background: var(--ec-panel);
  border-right: 1px solid var(--ec-border-soft);
  display: flex;
  flex-direction: column;
  align-items: stretch;
  padding: 18px 12px 12px;
  gap: 0;
  flex-shrink: 0;
  overflow: hidden;
}

.brand {
  display: flex;
  flex-direction: row;
  align-items: center;
  gap: 8px;
  padding: 2px 10px 18px;
}

.brand-dot {
  width: 8px;
  height: 8px;
  border-radius: 50%;
  background: #c4ccd9;
  flex-shrink: 0;
  transition: background 0.3s;
}

.brand-dot.dot-on {
  background: #4ade80;
  box-shadow: 0 0 6px rgba(74, 222, 128, 0.8);
}

.brand-dot.dot-reconnect {
  background: #fbbf24;
  box-shadow: 0 0 6px rgba(251, 191, 36, 0.8);
  animation: dot-pulse 1.2s ease-in-out infinite;
}

@keyframes dot-pulse {
  0%, 100% { opacity: 1; }
  50% { opacity: 0.35; }
}

.brand-text {
  font-size: 15px;
  font-weight: 700;
  letter-spacing: 0;
  color: var(--ec-text-1);
}

/* Nav */
.sidebar-nav {
  display: flex;
  flex-direction: column;
  gap: 2px;
  width: 100%;
}

.nav-item {
  width: 100%;
  display: flex;
  flex-direction: row;
  align-items: center;
  justify-content: flex-start;
  gap: 10px;
  padding: 9px 12px;
  border: none;
  border-radius: 10px;
  background: none;
  color: var(--ec-text-2);
  cursor: pointer;
  font-size: 13px;
  font-weight: 500;
  transition: background 0.15s, color 0.15s;
}

.nav-item:hover {
  background: var(--ec-bg-soft);
  color: var(--ec-text-1);
}

.nav-item.active {
  background: var(--ec-primary-soft);
  color: var(--ec-primary);
  font-weight: 600;
}

.nav-icon {
  flex-shrink: 0;
}

.nav-item span {
  display: block;
  color: inherit;
  font-size: 13px;
  font-weight: inherit;
  line-height: 1.2;
  text-align: left;
  white-space: nowrap;
  overflow: hidden;
  text-overflow: ellipsis;
}

.sidebar-spacer {
  flex: 1;
}

.sidebar-version {
  font-size: 11px;
  color: var(--ec-text-3);
  padding: 0 12px;
  white-space: nowrap;
  overflow: hidden;
  text-overflow: ellipsis;
}

/* ── Main area ── */
.main {
  display: flex;
  flex-direction: column;
  overflow-y: auto;
  overflow-x: hidden;
  background: var(--ec-bg);
}

.error-banner {
  margin: 12px 16px 0;
  flex-shrink: 0;
}

@media (max-width: 760px) {
  .app-shell {
    grid-template-columns: 64px minmax(0, 1fr);
  }

  .sidebar {
    width: 64px;
    padding: 14px 8px 10px;
    align-items: center;
  }

  .brand {
    padding: 2px 0 14px;
  }

  .brand-text,
  .sidebar-version {
    display: none;
  }

  .nav-item {
    justify-content: center;
    padding: 10px 0;
  }

  .nav-item span {
    display: none;
  }
}
</style>
