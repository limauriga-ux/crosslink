<script setup lang="ts">
import { computed, ref, onMounted, watchEffect } from 'vue'
import { api } from '../api/client'
import { useAppStore } from '../stores/app'
import type { CommandResult, ServiceStatus } from '../types'

const emit = defineEmits<{
  (e: 'logout'): void
}>()

const store = useAppStore()
const service = ref<ServiceStatus | null>(null)
const result = ref('')
const resultDetails = ref('')
const version = ref('')
const cleanupBusy = ref(false)
const cleanupMsg = ref('')
const configSaveMsg = ref('')
const tunIndex = computed<number | null>({
  get() {
    const match = /^utun(\d+)$/.exec(store.config?.tun.name?.trim() || '')
    return match ? Number(match[1]) : null
  },
  set(value) {
    if (!store.config) return
    store.config.tun.name = value == null ? '' : `utun${Math.trunc(value)}`
  }
})

// Normalize nullable config fields the low-level form binds into (same
// guards the standalone config page had).
watchEffect(() => {
  if (!store.config) return
  store.config.dns.upstream ||= []
  store.config.corplink ||= { company_name: '', insecure_skip_verify: false, debug_http_body: false }
  store.config.corplink.insecure_skip_verify ??= false
  store.config.corplink.debug_http_body ??= false
	store.config.openvpn ||= { profile: '~/.crosslink/openvpn/profile.json' }
  store.config.core ||= { profile: '~/.crosslink/proxy.json', rules: '~/.crosslink/rules.json', rule_set_dir: '~/.crosslink/rulesets', state_file: '~/.crosslink/proxy-state.json', domestic_direct: true, tun_enabled: true, mixed_port: 7890, log_level: 'info' }
	store.config.core.rules ||= '~/.crosslink/rules.json'
	store.config.core.rule_set_dir ||= '~/.crosslink/rulesets'
	store.config.core.domestic_direct ??= true
})

function addDNS() {
  if (!store.config) return
  store.config.dns.upstream ||= []
  store.config.dns.upstream.push('https://cloudflare-dns.com/dns-query')
}

async function doSaveConfig() {
  configSaveMsg.value = ''
  const ok = await store.saveConfig()
  configSaveMsg.value = ok ? '配置已保存并重载' : '保存失败'
}

onMounted(async () => {
  await refreshService()
  try { version.value = await api.getVersion() } catch { /* ignore */ }
})

async function refreshService() {
  service.value = await api.getLaunchServiceStatus()
}

async function installService() {
  const res = await api.installLaunchService({
    label: 'io.github.limauriga.crosslink.daemon',
    binary_path: store.appState?.daemon_path || '',
    config_path: store.configPath,
    work_dir: ''
  })
  setResult(res)
  await refreshService()
}

async function uninstallService() {
  const res = await api.uninstallLaunchService()
  setResult(res)
  await refreshService()
}

function setResult(res: CommandResult) {
  result.value = res.summary || res.details || ''
  resultDetails.value = res.details && res.details !== result.value ? res.details : ''
}

async function doCleanupRoutes() {
  cleanupBusy.value = true
  cleanupMsg.value = ''
  try {
    const res = await api.cleanupRoutes()
    cleanupMsg.value = res.ok ? '路由和 DNS 已重置' : (res.summary || '操作失败')
  } catch (e) {
    cleanupMsg.value = String(e)
  } finally {
    cleanupBusy.value = false
  }
}

async function doLogout() {
  try { await api.logout() } catch { /* ignore */ }
  emit('logout')
}
</script>

<template>
  <section class="page-stack">
    <div class="page-header">
      <div>
        <h2>设置</h2>
        <p class="page-subtitle">系统服务、账号与高级配置</p>
      </div>
      <div class="page-actions">
        <n-button @click="refreshService">刷新服务</n-button>
      </div>
    </div>
    <div class="form-grid">
      <div class="panel">
        <h3>系统服务</h3>
        <div class="kv"><span>安装状态</span><strong>{{ service?.installed ? '已安装' : '未安装' }}</strong></div>
        <div class="kv"><span>运行状态</span><strong>{{ service?.running ? '运行中' : '未运行' }}</strong></div>
        <div class="button-row service-actions">
          <n-button type="primary" @click="installService">安装</n-button>
          <n-button @click="uninstallService">卸载</n-button>
        </div>
        <p v-if="result" class="muted service-result">{{ result }}</p>
        <details v-if="resultDetails" class="command-details">
          <summary>查看详情</summary>
          <pre>{{ resultDetails }}</pre>
        </details>
      </div>
    </div>

    <!-- Recovery tools and informational paths: rarely needed, folded away so
         the destructive reset button is never clicked by accident. -->
    <n-collapse class="advanced-collapse">
      <n-collapse-item title="高级 / 故障恢复" name="advanced">
        <div class="form-grid">
          <div class="panel">
            <h3>网络诊断</h3>
            <p class="muted hint">清除残留的 TUN 捕获路由（0/1、128/1）并重置系统 DNS，可在未连接时使用。</p>
            <div class="button-row">
              <n-button :loading="cleanupBusy" @click="doCleanupRoutes">重置路由 / DNS</n-button>
            </div>
            <p v-if="cleanupMsg" :class="['muted', 'service-result', cleanupMsg.includes('失败') ? 'err' : '']">
              {{ cleanupMsg }}
            </p>
          </div>
          <div class="panel">
            <h3>路径</h3>
            <div class="kv"><span>版本</span><strong>{{ version || '—' }}</strong></div>
            <div class="kv"><span>Daemon</span><strong>{{ store.appState?.daemon_path || '~/.crosslink/bin/crosslink-daemon' }}</strong></div>
            <div class="kv"><span>配置文件</span><strong>{{ store.configPath }}</strong></div>
            <div class="kv"><span>日志文件</span><strong>{{ store.appState?.log_path || '~/.crosslink/crosslink.log' }}</strong></div>
            <p class="muted hint">详细日志需要管理员权限读取，关键诊断信息见概览页「连接诊断」。</p>
          </div>
        </div>
      </n-collapse-item>
      <n-collapse-item v-if="store.config" title="底层配置（config.json）" name="config">
        <p class="muted hint">TUN、DNS、出口与日志等底层参数，保存后立即重载。日常不需要改动。</p>
        <div class="form-grid">
          <div class="panel">
            <h3>TUN</h3>
            <n-form label-placement="top">
              <n-form-item label="CrossLink utun 序号（可选）">
                <n-input-number v-model:value="tunIndex" clearable :min="0" :max="65535" :precision="0" placeholder="留空自动分配；故障排查时可填 12" />
                <template #feedback>推荐留空：自动选择当前最高 utun 序号之后的空闲接口。手动序号只决定接口名称，不决定路由优先级；若已被 OpenVPN 等占用，保存会失败并保持旧核心运行。</template>
              </n-form-item>
              <n-form-item label="IP"><n-input v-model:value="store.config.tun.ip" /></n-form-item>
              <n-form-item label="Mask"><n-input-number v-model:value="store.config.tun.mask" :min="1" :max="32" /></n-form-item>
              <n-form-item label="MTU"><n-input-number v-model:value="store.config.tun.mtu" :min="576" :max="9000" /></n-form-item>
            </n-form>
          </div>

          <div class="panel">
            <h3>DNS / 统一核心</h3>
            <n-form label-placement="top">
              <n-form-item label="系统 TUN"><n-switch v-model:value="store.config.core.tun_enabled" /></n-form-item>
              <n-form-item label="本地 Mixed Port"><n-input-number v-model:value="store.config.core.mixed_port" :min="0" :max="65535" /></n-form-item>
              <n-form-item label="Profile 文件"><n-input v-model:value="store.config.core.profile" /></n-form-item>
              <n-form-item label="规则编排文件"><n-input v-model:value="store.config.core.rules" /></n-form-item>
              <n-form-item label="国内域名 / IP 规则集直连"><n-switch v-model:value="store.config.core.domestic_direct" /></n-form-item>
              <n-form-item label="规则集缓存目录"><n-input v-model:value="store.config.core.rule_set_dir" placeholder="必须位于 config.json 所在目录的子目录" /></n-form-item>
              <n-form-item label="核心日志等级"><n-select v-model:value="store.config.core.log_level" :options="['debug', 'info', 'warn', 'error'].map((v) => ({ label: v, value: v }))" /></n-form-item>
              <n-form-item label="公网 DNS（经所选代理的 DoH）">
                <div class="list-editor">
                  <n-input v-for="(_, index) in store.config.dns.upstream" :key="index" v-model:value="store.config.dns.upstream[index]" placeholder="https://cloudflare-dns.com/dns-query" />
                  <n-button size="small" @click="addDNS">添加 DoH</n-button>
                </div>
              </n-form-item>
              <n-alert type="info" :show-icon="false">公网域名经当前代理节点访问 DoH；企业域名仍经 CorpLink 内网 DNS。旧 UDP DNS 配置会自动迁移。</n-alert>
            </n-form>
          </div>

          <div class="panel">
            <h3>出口 / 安全</h3>
            <n-form label-placement="top">
              <n-form-item label="DIRECT 出口网卡"><n-input v-model:value="store.config.direct_outbound.interface" placeholder="留空自动探测" /></n-form-item>
              <n-form-item label="兼容私有 CA（跳过 TLS 校验）"><n-switch v-model:value="store.config.corplink.insecure_skip_verify" /></n-form-item>
              <n-alert v-if="store.config.corplink.insecure_skip_verify" type="warning" :show-icon="false">仅在企业网关使用无法导入的私有证书时开启。</n-alert>
			  <n-form-item label="OpenVPN 受管 Profile"><n-input v-model:value="store.config.openvpn.profile" placeholder="必须位于 config.json 所在目录下" /></n-form-item>
              <n-form-item label="记录脱敏 HTTP Body"><n-switch v-model:value="store.config.corplink.debug_http_body" /></n-form-item>
              <n-form-item label="日志等级"><n-select v-model:value="store.config.log.level" :options="['debug', 'info', 'warn', 'error'].map((v) => ({ label: v, value: v }))" /></n-form-item>
              <n-form-item label="非 root 调试日志文件"><n-input v-model:value="store.config.log.file" /><template #feedback>系统服务以 root 运行时固定写入 /var/log/crosslink.log，此路径不会传给 root daemon。</template></n-form-item>
              <n-form-item label="保留天数"><n-input-number v-model:value="store.config.log.max_age" :min="1" :max="365" /></n-form-item>
            </n-form>
          </div>
        </div>
        <div class="button-row config-save-row">
          <n-button type="primary" @click="doSaveConfig">保存配置</n-button>
          <span v-if="configSaveMsg" :class="['muted', configSaveMsg.includes('失败') ? 'err' : '']">{{ configSaveMsg }}</span>
        </div>
      </n-collapse-item>
    </n-collapse>

    <div class="logout-section">
      <n-button type="error" ghost @click="doLogout">退出登录</n-button>
    </div>
  </section>
</template>

<style scoped>
.logout-section {
  margin-top: 24px;
  padding-top: 16px;
  border-top: 1px solid var(--ec-border-soft);
}
.advanced-collapse {
  margin-top: 8px;
}
.config-save-row {
  margin-top: 12px;
}
.hint {
  font-size: 12px;
  margin: 0 0 10px;
}
.err { color: var(--ec-danger); }
</style>
