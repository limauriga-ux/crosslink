<script setup lang="ts">
import { computed, onMounted, onUnmounted, ref, watch } from 'vue'
import { BriefcaseBusiness, ExternalLink, FileKey2, FileLock2, FileText, RefreshCw, ShieldCheck, Trash2 } from '@lucide/vue'
import { Browser, Dialogs } from '@wailsio/runtime'
import { useMessage } from 'naive-ui'
import { api } from '../api/client'
import { useAppStore } from '../stores/app'
import type { OpenVPNProfileResult, OpenVPNStatusResult } from '../types'

const message = useMessage()
const store = useAppStore()
const profile = ref<OpenVPNProfileResult | null>(null)
const profileLoading = ref(false)
const importBusy = ref(false)
const connectionBusy = ref(false)
const challengeBusy = ref(false)
const ovpnPath = ref('')
const caPath = ref('')
const pkcs12Path = ref('')
const pkcs12Password = ref('')
const legacyBFCompat = ref(false)
const username = ref('')
const password = ref('')
const challengeUsername = ref('')
const challengePassword = ref('')
const challengeSecret = ref('')
const clock = ref(Date.now())
const challengeGenerationNotice = ref('')
let lastBrowserChallengeID = ''
let statusTimer: number | undefined
let clockTimer: number | undefined

const status = computed<OpenVPNStatusResult>(() => store.openVPNStatus ?? {
  ok: true,
  configured: profile.value?.exists ?? false,
  active: false,
  state: 'disconnected',
})

const statusView = computed(() => {
  switch (status.value.state) {
    case 'connected':
      return { label: '已连接', type: 'success' as const, detail: '企业流量按 OpenVPN 路由和 split DNS 规则进入内嵌端点' }
    case 'auth-pending':
      return { label: '等待认证', type: 'warning' as const, detail: 'OpenVPN 服务器要求完成额外认证' }
    case 'connecting':
      return { label: '连接中', type: 'warning' as const, detail: '正在建立 OpenVPN 控制通道；公网核心已运行时切换期间会短暂重建' }
    case 'error':
      return { label: '连接错误', type: 'error' as const, detail: 'OpenVPN 端点连接失败' }
    case 'unavailable':
      return { label: '服务不可用', type: 'error' as const, detail: '无法读取 daemon 状态' }
    default:
      return { label: '未连接', type: 'default' as const, detail: profile.value?.exists ? 'Profile 已就绪，凭据不会写入磁盘' : '先导入企业 OpenVPN Profile' }
  }
})

const profileSummary = computed(() => {
  if (!profile.value?.exists) return '尚未导入'
  const parts = [profile.value.name || 'OpenVPN', profile.value.server || '服务器未知']
  if (profile.value.network) parts.push(profile.value.network.toUpperCase())
  return parts.join(' · ')
})

const challenge = computed(() => status.value.challenge ?? null)
const challengeRemaining = computed(() => {
  const deadline = challenge.value?.deadline ?? 0
  if (!deadline) return ''
  const seconds = Math.max(0, Math.ceil(deadline - clock.value / 1000))
  return seconds > 0 ? `${seconds} 秒后过期` : '已过期'
})
const challengeExpired = computed(() => {
  const deadline = challenge.value?.deadline ?? 0
  return deadline > 0 && deadline <= clock.value / 1000
})
const safeChallengeURL = computed(() => {
  const raw = challenge.value?.url?.trim() || ''
  if (!raw) return ''
  try {
    const parsed = new URL(raw)
    return parsed.protocol === 'https:' ? parsed.toString() : ''
  } catch {
    return ''
  }
})
// URL ownership is attested by the daemon beside the managed profile. Local
// parsing is only a second gate; HTTPS alone is not sufficient.
const challengeURLTrusted = computed(() => challenge.value?.url_allowed === true)
const canOpenChallengeURL = computed(() => {
  const deadline = challenge.value?.deadline ?? 0
  return safeChallengeURL.value !== '' && challengeURLTrusted.value && (!deadline || deadline > clock.value / 1000)
})
const challengePrompt = computed(() => {
  if (!challenge.value) return ''
  if (challenge.value.kind === 'credentials') return challenge.value.secret_message || '请输入 OpenVPN 登录凭据'
  if (challenge.value.kind === 'secret') return challenge.value.message || '请输入动态验证码或挑战响应'
  if (challenge.value.kind === 'open-url') return '请在浏览器中完成认证，CrossLink 会继续等待服务器确认'
  return challenge.value.message || 'OpenVPN 服务器通知'
})
const canSubmitChallenge = computed(() => {
  if (!challenge.value) return false
  if (challenge.value.kind === 'credentials') {
    return challengeUsername.value.trim() !== '' && challengePassword.value !== ''
  }
  return challenge.value.kind === 'secret' && challengeSecret.value !== ''
})

watch(() => challenge.value?.id, () => {
  challengeUsername.value = challenge.value?.username || ''
  challengePassword.value = ''
  challengeSecret.value = ''
})

watch(
  () => [challenge.value?.id ?? '', challenge.value?.kind ?? '', status.value.state] as const,
  ([id, kind, state]) => {
    if (state === 'connected' || state === 'disconnected') {
      lastBrowserChallengeID = ''
      challengeGenerationNotice.value = ''
      return
    }
    if (kind !== 'open-url' || !id) return
    if (lastBrowserChallengeID && lastBrowserChallengeID !== id) {
      challengeGenerationNotice.value = '认证链接已更新，旧链接和旧标签页已经失效；请使用下方最新链接重新认证。'
    } else if (!lastBrowserChallengeID) {
      challengeGenerationNotice.value = ''
    }
    lastBrowserChallengeID = id
  },
)

onMounted(async () => {
  await Promise.all([loadProfile(), refreshStatus()])
  statusTimer = window.setInterval(refreshStatus, 2000)
  clockTimer = window.setInterval(() => { clock.value = Date.now() }, 1000)
})

onUnmounted(() => {
  if (statusTimer) window.clearInterval(statusTimer)
  if (clockTimer) window.clearInterval(clockTimer)
  password.value = ''
  pkcs12Password.value = ''
  challengePassword.value = ''
  challengeSecret.value = ''
})

async function loadProfile() {
  profileLoading.value = true
  try {
    const response = await api.getOpenVPNProfile()
    profile.value = response
    if (!response.ok) throw new Error(response.error || '读取 OpenVPN Profile 失败')
  } catch (error) {
    message.error(errorText(error))
  } finally {
    profileLoading.value = false
  }
}

let statusRefreshing = false
async function refreshStatus() {
  // Core restarts hold the daemon lifecycle lock, so a status call can wait
  // for seconds. Never queue another interval tick behind an in-flight call.
  if (statusRefreshing) return
  statusRefreshing = true
  try {
    store.openVPNStatus = await api.getOpenVPNStatus()
  } catch {
    // The next page-local poll converges after daemon startup or reload.
  } finally {
    statusRefreshing = false
  }
}

async function refreshAll() {
	await Promise.all([loadProfile(), refreshStatus()])
}

async function chooseFile(kind: 'ovpn' | 'ca' | 'pkcs12') {
  const filters = kind === 'ovpn'
    ? [{ DisplayName: 'OpenVPN Profile', Pattern: '*.ovpn' }]
    : kind === 'ca'
      ? [{ DisplayName: 'CA Certificate', Pattern: '*.crt;*.cer;*.pem' }]
      : [{ DisplayName: 'PKCS#12 Identity', Pattern: '*.p12;*.pfx' }]
  const selected = await Dialogs.OpenFile({
    Title: kind === 'ovpn' ? '选择 OpenVPN Profile' : kind === 'ca' ? '选择 CA 证书' : '选择客户端 PKCS#12',
    CanChooseFiles: true,
    CanChooseDirectories: false,
    AllowsMultipleSelection: false,
    Filters: filters,
  })
  if (!selected || Array.isArray(selected)) return
  if (kind === 'ovpn') ovpnPath.value = selected
  if (kind === 'ca') caPath.value = selected
  if (kind === 'pkcs12') pkcs12Path.value = selected
}

async function importProfile() {
  if (!ovpnPath.value.trim()) {
    message.warning('请选择 .ovpn Profile')
    return
  }
  importBusy.value = true
  try {
    const response = await api.importOpenVPNProfile({
      ovpn_path: ovpnPath.value.trim(),
      ca_path: caPath.value.trim() || undefined,
      pkcs12_path: pkcs12Path.value.trim() || undefined,
      pkcs12_password: pkcs12Password.value || undefined,
      legacy_bf_compat: legacyBFCompat.value,
    })
    profile.value = response
    if (!response.ok) throw new Error(response.error || '导入 OpenVPN Profile 失败')
    message.success('OpenVPN Profile 已验证并安全导入')
    await refreshStatus()
  } catch (error) {
    message.error(errorText(error))
  } finally {
    pkcs12Password.value = ''
    importBusy.value = false
  }
}

async function removeProfile() {
  if (status.value.active) {
    message.warning('请先断开 OpenVPN，再删除 Profile')
    return
  }
  try {
    const response = await api.removeOpenVPNProfile()
    profile.value = response
    if (!response.ok) throw new Error(response.error || '删除 OpenVPN Profile 失败')
    ovpnPath.value = ''
    caPath.value = ''
    pkcs12Path.value = ''
    message.success('已删除受管 OpenVPN Profile')
    await refreshStatus()
  } catch (error) {
    message.error(errorText(error))
  }
}

async function connect() {
  if (!profile.value?.exists) {
    message.warning('请先导入 OpenVPN Profile')
    return
  }
  if (profile.value.requires_credentials && (!username.value.trim() || !password.value)) {
    message.warning('请输入 OpenVPN 用户名和密码')
    return
  }
  connectionBusy.value = true
  try {
    const response = await api.connectOpenVPN(username.value.trim(), password.value)
    store.openVPNStatus = response
    if (!response.ok) throw new Error(response.error || 'OpenVPN 连接失败')
    if (response.state === 'connected') message.success('OpenVPN 已连接')
    else if (response.state === 'auth-pending') message.info('请完成 OpenVPN 额外认证')
    else message.info('OpenVPN 正在连接')
    if (response.state !== 'error') username.value = ''
  } catch (error) {
    message.error(errorText(error))
  } finally {
    password.value = ''
    connectionBusy.value = false
  }
}

async function disconnect() {
  connectionBusy.value = true
  try {
    const response = await api.disconnectOpenVPN()
    store.openVPNStatus = response
    if (!response.ok) throw new Error(response.error || '断开 OpenVPN 失败')
    message.success('OpenVPN 已断开；公网代理配置已恢复')
  } catch (error) {
    message.error(errorText(error))
  } finally {
    connectionBusy.value = false
  }
}

async function submitChallenge() {
  if (!challenge.value || !canSubmitChallenge.value) return
  challengeBusy.value = true
  try {
    const response = await api.completeOpenVPNChallenge(
      challenge.value.id,
      challengeUsername.value.trim(),
      challengePassword.value,
      challengeSecret.value,
    )
    store.openVPNStatus = response
    if (!response.ok) throw new Error(response.error || '提交 OpenVPN 认证失败')
    message.success('认证响应已提交')
  } catch (error) {
    message.error(errorText(error))
  } finally {
    challengePassword.value = ''
    challengeSecret.value = ''
    challengeBusy.value = false
  }
}

async function cancelChallenge() {
  if (!challenge.value) return
  challengeBusy.value = true
  try {
    const response = await api.cancelOpenVPNChallenge(challenge.value.id)
    if (!response.ok) throw new Error(response.summary || response.details || '取消认证失败')
    await refreshStatus()
  } catch (error) {
    message.error(errorText(error))
  } finally {
    challengePassword.value = ''
    challengeSecret.value = ''
    challengeBusy.value = false
  }
}

async function openChallengeURL() {
  const activeChallenge = challenge.value
  const challengeURL = safeChallengeURL.value
  if (!activeChallenge || !challengeURL) {
    message.error('仅允许打开有效的 HTTPS 认证地址')
    return
  }
  if (!challengeURLTrusted.value) {
    message.warning('认证地址不属于已配置的 OpenVPN 服务器，已拒绝自动打开；如确认可信请手动复制访问')
    return
  }
  challengeBusy.value = true
  try {
    const response = await api.prepareOpenVPNChallenge(activeChallenge.id)
    if (!response.ok) throw new Error(response.summary || response.details || '准备 OpenVPN 认证跳转失败')
    if (challenge.value?.id !== activeChallenge.id || challenge.value?.url !== activeChallenge.url) {
      throw new Error('OpenVPN 认证请求已变化，请重试')
    }
    await Browser.OpenURL(challengeURL)
  } catch (error) {
    message.error(errorText(error))
  } finally {
    challengeBusy.value = false
  }
}

function formatTime(unix: number | undefined): string {
  if (!unix) return '—'
  return new Date(unix * 1000).toLocaleString()
}

function errorText(error: unknown): string {
  return error instanceof Error ? error.message : String(error)
}
</script>

<template>
  <section class="page-stack openvpn-page">
    <div class="page-header">
      <div>
        <h2>OpenVPN 企业接入</h2>
        <p class="page-subtitle">作为统一 sing-box 核心内的企业 Endpoint 运行，不创建第二个系统 TUN；公网核心已运行时连接或断开会短暂重建核心</p>
      </div>
      <div class="page-actions">
        <n-tag :type="statusView.type" round>{{ statusView.label }}</n-tag>
		<n-button :loading="profileLoading" @click="refreshAll">
          <template #icon><RefreshCw :size="16" /></template>
          刷新
        </n-button>
      </div>
    </div>

    <n-alert :type="statusView.type === 'default' ? 'info' : statusView.type" :show-icon="false">
      {{ statusView.detail }}
      <template v-if="status.error">：{{ status.error }}</template>
    </n-alert>

    <div class="form-grid openvpn-grid">
      <div class="panel profile-panel">
        <div class="panel-title-row">
          <h3><FileLock2 :size="17" /> 受管 Profile</h3>
          <n-tag :type="profile?.exists ? 'success' : 'default'" size="small">{{ profileSummary }}</n-tag>
        </div>

        <template v-if="profile?.exists">
          <div class="kv"><span>受管文件</span><strong>{{ profile.path }}</strong></div>
          <div class="kv"><span>证书到期</span><strong>{{ formatTime(profile.certificate_expires_at) }}</strong></div>
          <div class="kv"><span>分流策略</span><strong>{{ profile.routes ?? 0 }} 条网段 · {{ profile.domains ?? 0 }} 个域 · {{ profile.dns_servers ?? 0 }} 个 DNS</strong></div>
          <div class="kv"><span>登录凭据</span><strong>{{ profile.requires_credentials ? '每次连接输入，仅驻留内存' : 'Profile 不要求用户名密码' }}</strong></div>
          <n-alert v-if="profile.legacy_cipher_fallback" type="warning" :show-icon="false" class="section-alert">
            已为此端点启用旧式 BF-CBC 兼容。公网代理和其他端点不受影响。
          </n-alert>
          <n-alert v-for="warning in profile.warnings ?? []" :key="warning" type="warning" :show-icon="false" class="section-alert">{{ warning }}</n-alert>
          <div class="button-row service-actions">
            <n-popconfirm :disabled="status.active" @positive-click="removeProfile">
              <template #trigger>
                <n-button type="error" ghost :disabled="status.active">
                  <template #icon><Trash2 :size="15" /></template>
                  删除 Profile
                </n-button>
              </template>
              删除本机受管 OpenVPN Profile？源文件不会被修改。
            </n-popconfirm>
            <span v-if="status.active" class="muted inline-hint">断开后才能删除</span>
          </div>
        </template>
        <n-empty v-else-if="!profileLoading" description="尚未导入 OpenVPN Profile" />
      </div>

      <div class="panel connection-panel">
        <div class="panel-title-row">
          <h3><BriefcaseBusiness :size="17" /> 连接</h3>
          <n-tag :type="statusView.type" size="small">{{ statusView.label }}</n-tag>
        </div>
        <template v-if="status.active">
          <div class="kv"><span>Profile</span><strong>{{ status.profile_name || profile?.name || 'OpenVPN' }}</strong></div>
          <div class="kv"><span>服务器</span><strong>{{ status.server || profile?.server || '连接中' }}{{ status.network ? ` · ${status.network.toUpperCase()}` : '' }}</strong></div>
          <div class="kv"><span>隧道地址</span><strong>{{ [...(status.ipv4 ?? []), ...(status.ipv6 ?? [])].join('、') || '连接中' }}</strong></div>
          <div class="kv"><span>DNS</span><strong>{{ (status.dns ?? []).join('、') || '按 Profile / 服务器 split DNS' }}</strong></div>
          <div class="kv"><span>加密</span><strong>{{ status.cipher || '协商中' }}{{ status.mtu ? ` · MTU ${status.mtu}` : '' }}</strong></div>
          <div class="kv"><span>连接时间</span><strong>{{ formatTime(status.connected_at) }}</strong></div>
          <div class="button-row service-actions">
            <n-button type="error" ghost :loading="connectionBusy" @click="disconnect">断开 OpenVPN</n-button>
          </div>
        </template>
        <template v-else>
          <n-form label-placement="top">
            <n-form-item v-if="profile?.requires_credentials" label="用户名">
              <n-input v-model:value="username" autocomplete="off" placeholder="仅用于本次 daemon 会话" :disabled="connectionBusy" />
            </n-form-item>
            <n-form-item v-if="profile?.requires_credentials" label="密码">
              <n-input v-model:value="password" type="password" show-password-on="click" autocomplete="new-password" placeholder="不会写入 config.json 或日志" :disabled="connectionBusy" @keyup.enter="connect" />
            </n-form-item>
            <n-button type="primary" block :disabled="!profile?.exists" :loading="connectionBusy" @click="connect">
              <template #icon><ShieldCheck :size="16" /></template>
              连接 OpenVPN
            </n-button>
          </n-form>
        </template>
      </div>
    </div>

    <div v-if="challenge" class="panel challenge-panel">
      <div class="panel-title-row">
        <h3><FileKey2 :size="17" /> 额外认证</h3>
        <n-tag type="warning" size="small">{{ challenge.kind }}{{ challengeRemaining ? ` · ${challengeRemaining}` : '' }}</n-tag>
      </div>
      <p class="challenge-message">{{ challengePrompt }}</p>
      <n-alert v-if="challenge.previous_error" type="error" :show-icon="false" class="section-alert">上次认证失败：{{ challenge.previous_error }}</n-alert>
      <n-alert v-if="challengeGenerationNotice" type="warning" :show-icon="false" class="section-alert">{{ challengeGenerationNotice }}</n-alert>
      <n-alert v-if="challengeExpired" type="warning" :show-icon="false" class="section-alert">当前认证链接已过期；等待服务器生成新链接后，关闭旧标签页并从这里重新打开。</n-alert>

      <n-form v-if="challenge.kind === 'credentials'" label-placement="top" class="challenge-form">
        <n-form-item label="用户名"><n-input v-model:value="challengeUsername" autocomplete="off" /></n-form-item>
        <n-form-item label="密码"><n-input v-model:value="challengePassword" type="password" show-password-on="click" autocomplete="new-password" /></n-form-item>
        <n-form-item v-if="challenge.secret_message" :label="challenge.secret_message">
          <n-input v-model:value="challengeSecret" :type="challenge.echo ? 'text' : 'password'" :show-password-on="challenge.echo ? undefined : 'click'" autocomplete="one-time-code" />
        </n-form-item>
      </n-form>
      <n-form v-else-if="challenge.kind === 'secret'" label-placement="top" class="challenge-form">
        <n-form-item :label="challenge.message || '挑战响应'">
          <n-input v-model:value="challengeSecret" :type="challenge.echo ? 'text' : 'password'" :show-password-on="challenge.echo ? undefined : 'click'" autocomplete="one-time-code" @keyup.enter="submitChallenge" />
        </n-form-item>
      </n-form>
      <div v-else-if="challenge.kind === 'open-url'" class="challenge-url">
        <code>{{ challenge.url }}</code>
        <n-alert v-if="challenge.url && !safeChallengeURL" type="error" :show-icon="false">认证地址不是有效的 HTTPS URL，已拒绝自动打开。</n-alert>
        <n-alert v-else-if="challenge.url && !challengeURLTrusted" type="warning" :show-icon="false">认证地址不属于已配置的 OpenVPN 服务器域名，已拒绝自动打开；如确认可信，请手动复制到浏览器访问。</n-alert>
      </div>

      <div class="button-row service-actions">
        <n-button v-if="challenge.kind === 'credentials' || challenge.kind === 'secret'" type="primary" :disabled="!canSubmitChallenge" :loading="challengeBusy" @click="submitChallenge">提交认证</n-button>
        <n-button v-if="challenge.kind === 'open-url'" type="primary" :disabled="!canOpenChallengeURL" :loading="challengeBusy" @click="openChallengeURL">
          <template #icon><ExternalLink :size="15" /></template>
          在浏览器中认证
        </n-button>
        <n-button :loading="challengeBusy" @click="cancelChallenge">取消认证</n-button>
      </div>
    </div>

    <n-collapse class="import-collapse">
      <n-collapse-item :title="profile?.exists ? '重新导入 / 替换 Profile' : '导入 OpenVPN Profile'" name="import">
        <div class="panel import-panel">
          <p class="muted import-hint">源路径只用于本次导入。CrossLink 验证并内嵌 CA、客户端证书和私钥后写入 0600 受管文件，不保存 P12 密码。</p>
          <n-form label-placement="top">
            <n-form-item label="OpenVPN Profile（必选）">
              <div class="file-row">
                <n-input v-model:value="ovpnPath" readonly placeholder="选择 .ovpn" />
                <n-button @click="chooseFile('ovpn')"><template #icon><FileText :size="15" /></template>选择</n-button>
              </div>
            </n-form-item>
            <n-form-item label="CA 证书（Profile 未内嵌 CA 时选择）">
              <div class="file-row">
                <n-input v-model:value="caPath" readonly placeholder="选择 .crt / .cer / .pem" />
                <n-button @click="chooseFile('ca')">选择</n-button>
                <n-button v-if="caPath" quaternary @click="caPath = ''">清除</n-button>
              </div>
            </n-form-item>
            <n-form-item label="客户端 PKCS#12（Profile 未内嵌证书和私钥时选择）">
              <div class="file-row">
                <n-input v-model:value="pkcs12Path" readonly placeholder="选择 .p12 / .pfx" />
                <n-button @click="chooseFile('pkcs12')">选择</n-button>
                <n-button v-if="pkcs12Path" quaternary @click="pkcs12Path = ''; pkcs12Password = ''">清除</n-button>
              </div>
            </n-form-item>
            <n-form-item v-if="pkcs12Path" label="PKCS#12 密码">
              <n-input v-model:value="pkcs12Password" type="password" show-password-on="click" autocomplete="new-password" placeholder="仅在内存中用于解密本次导入" @keyup.enter="importProfile" />
            </n-form-item>
            <n-form-item label="旧式 BF-CBC 兼容">
              <div class="switch-line">
                <n-switch v-model:value="legacyBFCompat" />
                <span class="muted">仅当旧服务器明确要求 BF-CBC 时开启</span>
              </div>
            </n-form-item>
            <n-alert v-if="legacyBFCompat" type="warning" :show-icon="false" class="section-alert">BF-CBC 是旧式数据通道密码。该开关只影响此 OpenVPN Endpoint。</n-alert>
            <n-button type="primary" :loading="importBusy" @click="importProfile">验证并导入</n-button>
          </n-form>
        </div>
      </n-collapse-item>
    </n-collapse>

    <n-alert type="info" :show-icon="false">
      优先级：系统保护 → 前置规则 → 公网 Profile 规则 → 后置规则 → OpenVPN 静态/服务器推送分流 → 国内直连 → 公网最终出口。规则编辑器中的 OPENVPN 目标在断开时会拒绝连接，绝不会回落到公网代理。
    </n-alert>
  </section>
</template>

<style scoped>
.openvpn-page {
  max-width: 1180px;
}
.openvpn-grid {
  grid-template-columns: minmax(0, 1.2fr) minmax(280px, 0.8fr);
}
.panel-title-row {
  display: flex;
  align-items: flex-start;
  justify-content: space-between;
  gap: 12px;
  margin-bottom: 12px;
}
.panel-title-row h3 {
  display: flex;
  align-items: center;
  gap: 7px;
  margin: 0;
}
.section-alert {
  margin-top: 12px;
}
.inline-hint,
.import-hint {
  font-size: 12px;
}
.import-hint {
  margin: 0 0 14px;
  line-height: 1.6;
}
.import-collapse {
  margin-top: 2px;
}
.import-panel {
  box-shadow: none;
}
.file-row {
  display: flex;
  gap: 8px;
  width: 100%;
  min-width: 0;
}
.file-row .n-input {
  flex: 1 1 auto;
  min-width: 0;
}
.switch-line {
  display: flex;
  align-items: center;
  gap: 10px;
}
.challenge-panel {
  border-color: color-mix(in srgb, var(--ec-warning) 45%, var(--ec-border));
}
.challenge-message {
  color: var(--ec-text-1);
  line-height: 1.6;
  margin: 0 0 12px;
}
.challenge-form {
  max-width: 560px;
}
.challenge-url {
  display: grid;
  gap: 10px;
}
.challenge-url code {
  display: block;
  padding: 10px 12px;
  overflow-wrap: anywhere;
  border: 1px solid var(--ec-border-soft);
  border-radius: 8px;
  background: var(--ec-bg);
  color: var(--ec-text-2);
}
@media (max-width: 960px) {
  .openvpn-grid {
    grid-template-columns: 1fr;
  }
}
@media (max-width: 620px) {
  .file-row {
    flex-wrap: wrap;
  }
  .file-row .n-input {
    flex-basis: 100%;
  }
}
</style>
