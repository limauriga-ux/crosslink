<script setup lang="ts">
import { computed, onMounted, reactive, ref } from 'vue'
import { ArrowDown, ArrowUp, Download, FileJson, Gauge, ListTree, Plus, RefreshCw, Save, Trash2 } from '@lucide/vue'
import { useMessage } from 'naive-ui'
import { api } from '../api/client'
import type { ProxyGroupResult, ProxyProfileResult, RulePlanResult } from '../types'

const message = useMessage()
const loading = ref(false)
const saving = ref(false)
const importing = ref(false)
const subscriptionURL = ref('')
const content = ref('')
const result = ref<ProxyProfileResult | null>(null)
const groups = ref<ProxyGroupResult[]>([])
const groupsLoading = ref(false)
const testingGroup = ref('')
const selecting = ref('')
const groupsRuntime = ref(false)
const restartingDaemon = ref(false)


interface RoutePreviewRow {
  expression: string
  target: string
}
type RuleStage = 'prepend' | 'append'

const ruleLoading = ref(false)
const ruleSaving = ref(false)
const ruleMeta = ref<RulePlanResult | null>(null)
const rulePlan = reactive<{ prepend: string[]; append: string[] }>({ prepend: [], append: [] })
const draftStage = ref<RuleStage>('prepend')
const draftType = ref('DOMAIN-SUFFIX')
const draftValue = ref('')
const draftTarget = ref('')

const ruleTypeOptions = [
  'DOMAIN', 'DOMAIN-SUFFIX', 'DOMAIN-KEYWORD', 'DOMAIN-REGEX',
  'IP-CIDR', 'IP-CIDR6', 'SRC-IP-CIDR',
  'PROCESS-NAME', 'PROCESS-PATH', 'DST-PORT', 'SRC-PORT', 'NETWORK',
].map(value => ({ label: value, value }))

const ruleStageOptions = [
  { label: '前置注入', value: 'prepend' },
  { label: '后置注入', value: 'append' },
]

const ruleTargetOptions = computed(() => (ruleMeta.value?.targets ?? []).map(value => ({
  value,
  label: ruleTargetLabel(value),
})))

const ruleValuePlaceholder = computed(() => {
  switch (draftType.value) {
    case 'DOMAIN': return 'api.example.com'
    case 'DOMAIN-SUFFIX': return 'example.com'
    case 'DOMAIN-KEYWORD': return 'keyword'
    case 'DOMAIN-REGEX': return '^api\\..*\\.com$'
    case 'IP-CIDR': return '203.0.113.0/24'
    case 'IP-CIDR6': return '2001:db8::/32'
    case 'SRC-IP-CIDR': return '192.168.1.0/24'
    case 'PROCESS-NAME': return 'Safari'
    case 'PROCESS-PATH': return '/Applications/App.app/Contents/MacOS/App'
    case 'DST-PORT':
    case 'SRC-PORT': return '443'
    case 'NETWORK': return 'tcp 或 udp'
    default: return '匹配值'
  }
})

const routeTargetFilter = ref('all')
const profileRouteRows = computed<RoutePreviewRow[]>(() => {
  try {
    const root = JSON.parse(content.value) as { route?: { rules?: unknown[] } }
    return (root.route?.rules ?? []).map(formatProfileRule)
  } catch {
    return []
  }
})

const routeTargetOptions = computed(() => {
  const counts = new Map<string, number>()
  for (const row of profileRouteRows.value) counts.set(row.target, (counts.get(row.target) ?? 0) + 1)
  return [
    { value: 'all', label: `全部订阅规则 · ${profileRouteRows.value.length}` },
    ...[...counts.entries()].map(([target, count]) => ({
      value: target,
      label: `${effectiveTargetLabel(target)} · ${count}`,
    })),
  ]
})

const visibleProfileRouteRows = computed(() => routeTargetFilter.value === 'all'
  ? profileRouteRows.value
  : profileRouteRows.value.filter(row => row.target === routeTargetFilter.value))

function formatProfileRule(raw: unknown): RoutePreviewRow {
  if (!raw || typeof raw !== 'object') return { expression: String(raw), target: '—' }
  const rule = raw as Record<string, unknown>
  const fields: Array<[string, string]> = [
    ['domain', 'DOMAIN'], ['domain_suffix', 'DOMAIN-SUFFIX'],
    ['domain_keyword', 'DOMAIN-KEYWORD'], ['domain_regex', 'DOMAIN-REGEX'],
    ['ip_cidr', 'IP-CIDR'], ['source_ip_cidr', 'SRC-IP-CIDR'],
    ['process_name', 'PROCESS-NAME'], ['process_path', 'PROCESS-PATH'],
    ['port', 'DST-PORT'], ['source_port', 'SRC-PORT'], ['network', 'NETWORK'],
  ]
  const parts: string[] = []
  for (const [field, label] of fields) {
    const rawValue = rule[field]
    const values = Array.isArray(rawValue) ? rawValue : (rawValue === undefined ? [] : [rawValue])
    if (values.length) parts.push(`${label},${values.join(' | ')}`)
  }
  if (rule.ip_is_private === true) parts.push('IP-PRIVATE')
  const target = rule.action === 'reject' ? 'REJECT' : String(rule.outbound ?? '—')
  return {
    expression: parts.join(' + ') || JSON.stringify(rule),
    target,
  }
}

function effectiveTargetLabel(target: string): string {
  if (target === 'corp' || target === 'CORP') return 'CORP · 企业链路'
  if (target === 'direct' || target === 'DIRECT') return 'DIRECT · 本地出口'
  if (target === 'block' || target === 'REJECT') return 'REJECT · 拒绝'
  const group = groups.value.find(item => item.tag === target)
  return group?.selected ? `${target} → ${group.selected}` : target
}

const profileSummary = computed(() => {
  if (!result.value?.exists) return '尚未导入公网代理配置'
  const format = result.value.format === 'clash' ? 'Clash YAML' : 'sing-box JSON'
  return `${format} · ${result.value.nodes ?? 0} 个节点 · ${result.value.endpoints ?? 0} 个端点`
})

onMounted(async () => {
  await loadProfile()
  await loadGroups()
  await loadRulePlan()
})

async function loadProfile() {
  loading.value = true
  try {
    const response = await api.getProxyProfile()
    result.value = response
    if (!response.ok) throw new Error(response.error || '读取 Profile 失败')
    content.value = response.content ?? ''
		routeTargetFilter.value = 'all'
  } catch (error) {
    message.error(error instanceof Error ? error.message : String(error))
  } finally {
    loading.value = false
  }
}

async function loadGroups() {
  groupsLoading.value = true
  try {
    const response = await api.getProxyGroups()
    if (!response.ok) throw new Error(response.error || '读取代理组失败')
    groups.value = response.groups ?? []
    groupsRuntime.value = response.runtime ?? false
  } catch (error) {
    groups.value = []
    groupsRuntime.value = false
  } finally {
    groupsLoading.value = false
  }
}

async function restartDaemon() {
  restartingDaemon.value = true
  try {
    const response = await api.restartDaemon('')
    if (!response.ok) throw new Error(response.summary || response.details || '重启 daemon 失败')
    await new Promise(resolve => setTimeout(resolve, 600))
    await loadGroups()
    if (!groupsRuntime.value) throw new Error('daemon 已重启，但公网核心仍未运行，请查看设置中的服务状态')
    message.success('CrossLink daemon 已更新并恢复实时控制')
  } catch (error) {
    message.error(error instanceof Error ? error.message : String(error))
  } finally {
    restartingDaemon.value = false
  }
}
async function chooseProxy(groupTag: string, outboundTag: string) {
  selecting.value = `${groupTag}:${outboundTag}`
  try {
    const response = await api.selectProxy(groupTag, outboundTag)
    if (!response.ok) throw new Error(response.summary || '切换节点失败')
    await loadGroups()
    message.success(`已切换到 ${outboundTag}`)
  } catch (error) {
    message.error(error instanceof Error ? error.message : String(error))
  } finally {
    selecting.value = ''
  }
}

async function testGroup(groupTag: string) {
  testingGroup.value = groupTag
  try {
    const response = await api.testProxyGroup(groupTag)
    if (!response.ok) throw new Error(response.error || '测速失败')
    await loadGroups()
  } catch (error) {
    message.error(error instanceof Error ? error.message : String(error))
  } finally {
    testingGroup.value = ''
  }
}

function delayLabel(delay: number): string {
  if (delay < 0) return '未测试'
  if (delay === 0 || delay >= 65535) return '失败'
  return `${delay} ms`
}

function delayType(delay: number): 'success' | 'warning' | 'error' | 'default' {
  if (delay < 0) return 'default'
  if (delay < 150) return 'success'
  if (delay < 500) return 'warning'
  return 'error'
}

function ruleTargetLabel(value: string): string {
  if (value === 'DIRECT') return 'DIRECT · 直连'
  if (value === 'REJECT') return 'REJECT · 拒绝'
  if (value === 'CORP') return 'CORP · 企业链路'
	if (value === 'OPENVPN') return 'OPENVPN · 企业 OpenVPN（断开时拒绝）'
  return value
}

async function loadRulePlan() {
  ruleLoading.value = true
  try {
    const response = await api.getRulePlan()
    ruleMeta.value = response
    rulePlan.prepend = [...(response.prepend ?? [])]
    rulePlan.append = [...(response.append ?? [])]
    const targets = response.targets ?? []
    if (!targets.includes(draftTarget.value)) {
      draftTarget.value = response.final && targets.includes(response.final)
        ? response.final
        : (targets[0] ?? 'DIRECT')
    }
    if (!response.ok) throw new Error(response.error || '读取规则编排失败')
  } catch (error) {
    message.error(error instanceof Error ? error.message : String(error))
  } finally {
    ruleLoading.value = false
  }
}

function addRule() {
  const value = draftValue.value.trim()
  const target = draftTarget.value.trim()
  if (!value || !target) {
    message.warning('请填写匹配值并选择出口')
    return
  }
  rulePlan[draftStage.value].push(`${draftType.value},${value},${target}`)
  draftValue.value = ''
}

function moveRule(stage: RuleStage, index: number, delta: number) {
  const rules = rulePlan[stage]
  const destination = index + delta
  if (destination < 0 || destination >= rules.length) return
  const [rule] = rules.splice(index, 1)
  rules.splice(destination, 0, rule)
}

function removeRule(stage: RuleStage, index: number) {
  rulePlan[stage].splice(index, 1)
}

async function saveRulePlan() {
  ruleSaving.value = true
  try {
    const response = await api.saveRulePlan([...rulePlan.prepend], [...rulePlan.append])
    ruleMeta.value = response
    if (!response.ok) throw new Error(response.error || '应用规则编排失败')
    rulePlan.prepend = [...(response.prepend ?? [])]
    rulePlan.append = [...(response.append ?? [])]
    message.success('规则已校验、保存并按新顺序应用')
  } catch (error) {
    message.error(error instanceof Error ? error.message : String(error))
  } finally {
    ruleSaving.value = false
  }
}

async function saveProfile() {
  if (!content.value.trim()) {
    message.warning('请粘贴 sing-box JSON 或 Clash YAML')
    return
  }
  saving.value = true
  try {
    const response = await api.saveProxyProfile(content.value)
    result.value = response
    if (!response.ok) throw new Error(response.error || '保存 Profile 失败')
    content.value = response.content ?? content.value
		routeTargetFilter.value = 'all'
    message.success('Profile 已校验、保存并应用')
    await loadGroups()
    await loadRulePlan()
  } catch (error) {
    message.error(error instanceof Error ? error.message : String(error))
  } finally {
    saving.value = false
  }
}

async function importSubscription() {
  if (!subscriptionURL.value.trim()) {
    message.warning('请输入 HTTPS 订阅地址')
    return
  }
  importing.value = true
  try {
    const response = await api.importProxyProfileURL(subscriptionURL.value.trim())
    result.value = response
    if (!response.ok) throw new Error(response.error || '导入订阅失败')
    content.value = response.content ?? ''
		routeTargetFilter.value = 'all'
    message.success('订阅已在本机转换并应用')
    await loadGroups()
    await loadRulePlan()
  } catch (error) {
    message.error(error instanceof Error ? error.message : String(error))
  } finally {
    importing.value = false
  }
}
</script>

<template>
  <section class="page profile-page">
    <header class="page-header">
      <div>
        <h1>公网代理</h1>
        <p>导入 Clash YAML 或 sing-box JSON。CrossLink 只读取节点、端点和路由规则，不接受订阅中的 TUN、DNS 或控制接口设置。</p>
      </div>
      <n-tag :type="result?.exists ? 'success' : 'default'" round>{{ profileSummary }}</n-tag>
    </header>

    <n-card class="profile-card" :bordered="false">
      <template #header>
        <div class="editor-header">
          <div class="card-title"><Gauge :size="18" /> 代理组与节点</div>
          <n-button size="small" quaternary circle :loading="groupsLoading" @click="loadGroups">
            <template #icon><RefreshCw :size="15" /></template>
          </n-button>
        </div>
      </template>
      <n-empty v-if="!groupsLoading && !groups.length" description="连接统一核心并导入 Profile 后显示代理组" />
      <n-spin :show="groupsLoading">
        <div class="group-list">
          <n-alert v-if="groups.length && !groupsRuntime" type="info" :show-icon="false" class="preview-alert">
            <div class="preview-content">
              <span>当前仅显示已导入配置，公网代理核心没有提供实时状态；这不代表公网代理已经启用。</span>
              <n-button size="small" type="primary" :loading="restartingDaemon" @click="restartDaemon">更新并重启 daemon</n-button>
            </div>
          </n-alert>
          <section v-for="group in groups" :key="group.tag" class="group-section">
            <header class="group-header">
              <div>
                <strong>{{ group.tag }}</strong>
                <span>{{ group.type }} · 当前 {{ group.selected || '—' }}</span>
              </div>
              <n-button
                size="small"
                tertiary
                :loading="testingGroup === group.tag"
                :disabled="!groupsRuntime"
                @click="testGroup(group.tag)"
              >
                全部测速
              </n-button>
            </header>
            <div class="proxy-grid">
              <button
                v-for="item in group.items"
                :key="item.tag"
                class="proxy-node"
                :class="{ selected: item.selected }"
                :disabled="!groupsRuntime || group.type !== 'selector' || selecting !== ''"
                @click="chooseProxy(group.tag, item.tag)"
              >
                <span class="proxy-main">
                  <strong>{{ item.tag }}</strong>
                  <small>{{ item.type }}</small>
                </span>
                <n-tag size="small" :type="delayType(item.delay_ms)">{{ delayLabel(item.delay_ms) }}</n-tag>
              </button>
            </div>
          </section>
        </div>
      </n-spin>
    </n-card>

    <n-card class="profile-card rules-card" :bordered="false">
      <template #header>
        <div class="editor-header">
          <div class="card-title"><ListTree :size="18" /> 规则编排</div>
          <span v-if="ruleMeta?.path" class="path">{{ ruleMeta.path }}</span>
        </div>
      </template>
      <n-spin :show="ruleLoading">
        <n-alert type="info" :show-icon="false" class="rules-info">
          注入规则独立保存，更新订阅不会覆盖。按首条匹配：前置注入 → 订阅规则 → 后置注入 → 默认出口。
        </n-alert>
        <n-alert v-if="ruleMeta && !ruleMeta.ok" type="error" :show-icon="false" class="rules-error">
          {{ ruleMeta.error }}
        </n-alert>

        <div class="rule-composer">
          <n-select v-model:value="draftStage" :options="ruleStageOptions" />
          <n-select v-model:value="draftType" filterable :options="ruleTypeOptions" />
          <n-input v-model:value="draftValue" clearable :placeholder="ruleValuePlaceholder" @keyup.enter="addRule" />
          <n-select
            v-model:value="draftTarget"
            filterable
            :options="ruleTargetOptions"
            placeholder="选择出口"
          />
          <n-button type="primary" :disabled="!draftValue.trim() || !draftTarget" @click="addRule">
            <template #icon><Plus :size="15" /></template>
            添加
          </n-button>
        </div>

        <div class="rule-pipeline" aria-label="最终规则顺序">
          <div class="pipeline-step system"><strong>系统保护</strong><span>3 条</span></div>
          <span class="pipeline-arrow">→</span>
          <div class="pipeline-step prepend"><strong>前置注入</strong><span>{{ rulePlan.prepend.length }} 条</span></div>
          <span class="pipeline-arrow">→</span>
          <div class="pipeline-step profile"><strong>订阅规则</strong><span>{{ ruleMeta?.profile_rule_count ?? 0 }} 条</span></div>
          <span class="pipeline-arrow">→</span>
          <div class="pipeline-step append"><strong>后置注入</strong><span>{{ rulePlan.append.length }} 条</span></div>
          <span class="pipeline-arrow">→</span>
          <div class="pipeline-step final"><strong>默认出口</strong><span>{{ ruleMeta?.final || 'direct' }}</span></div>
        </div>

        <section class="route-preview">
          <header class="route-preview-header">
            <div>
              <strong>订阅规则归属（只读）</strong>
              <span>选择“节点选择”即可查看实际落到的 ISP 公网节点</span>
            </div>
            <n-select v-model:value="routeTargetFilter" size="small" :options="routeTargetOptions" />
          </header>
          <n-empty v-if="!visibleProfileRouteRows.length" size="small" description="当前筛选没有订阅规则" />
          <div v-else class="route-preview-list">
            <div v-for="(row, index) in visibleProfileRouteRows" :key="`${row.target}-${index}-${row.expression}`" class="route-preview-row">
              <span class="rule-index">{{ index + 1 }}</span>
              <code>{{ row.expression }}</code>
              <n-tag size="small" :type="row.target === 'corp' ? 'warning' : row.target === 'block' || row.target === 'REJECT' ? 'error' : row.target === 'direct' ? 'default' : 'info'">
                {{ effectiveTargetLabel(row.target) }}
              </n-tag>
            </div>
          </div>
        </section>

        <div class="rule-stage-grid">
          <section class="rule-stage-card">
            <header class="rule-stage-header">
              <div><strong>前置注入</strong><span>覆盖订阅规则</span></div>
              <n-tag size="small" type="info">{{ rulePlan.prepend.length }}</n-tag>
            </header>
            <n-empty v-if="!rulePlan.prepend.length" size="small" description="暂无前置规则" />
            <div v-else class="rule-list">
              <div v-for="(_, index) in rulePlan.prepend" :key="`prepend-${index}`" class="rule-row">
                <span class="rule-index">{{ index + 1 }}</span>
                <n-input v-model:value="rulePlan.prepend[index]" size="small" />
                <div class="rule-actions">
                  <n-button size="tiny" quaternary circle :disabled="index === 0" @click="moveRule('prepend', index, -1)"><template #icon><ArrowUp :size="13" /></template></n-button>
                  <n-button size="tiny" quaternary circle :disabled="index === rulePlan.prepend.length - 1" @click="moveRule('prepend', index, 1)"><template #icon><ArrowDown :size="13" /></template></n-button>
                  <n-button size="tiny" quaternary circle type="error" @click="removeRule('prepend', index)"><template #icon><Trash2 :size="13" /></template></n-button>
                </div>
              </div>
            </div>
          </section>

          <section class="rule-stage-card">
            <header class="rule-stage-header">
              <div><strong>后置注入</strong><span>补充订阅未命中的流量</span></div>
              <n-tag size="small" type="warning">{{ rulePlan.append.length }}</n-tag>
            </header>
            <n-empty v-if="!rulePlan.append.length" size="small" description="暂无后置规则" />
            <div v-else class="rule-list">
              <div v-for="(_, index) in rulePlan.append" :key="`append-${index}`" class="rule-row">
                <span class="rule-index">{{ index + 1 }}</span>
                <n-input v-model:value="rulePlan.append[index]" size="small" />
                <div class="rule-actions">
                  <n-button size="tiny" quaternary circle :disabled="index === 0" @click="moveRule('append', index, -1)"><template #icon><ArrowUp :size="13" /></template></n-button>
                  <n-button size="tiny" quaternary circle :disabled="index === rulePlan.append.length - 1" @click="moveRule('append', index, 1)"><template #icon><ArrowDown :size="13" /></template></n-button>
                  <n-button size="tiny" quaternary circle type="error" @click="removeRule('append', index)"><template #icon><Trash2 :size="13" /></template></n-button>
                </div>
              </div>
            </div>
          </section>
        </div>

        <div class="rule-footer">
          <p class="hint">支持 Clash 条件规则；MATCH、GEOIP 与 RULE-SET 不会注入。CORP 表示企业链路，REJECT 表示拒绝。</p>
          <div class="rule-footer-actions">
            <n-button :disabled="ruleSaving" @click="loadRulePlan">重新读取</n-button>
            <n-button type="primary" :loading="ruleSaving" @click="saveRulePlan">
              <template #icon><Save :size="15" /></template>
              校验并应用
            </n-button>
          </div>
        </div>
      </n-spin>
    </n-card>

    <n-card class="profile-card" :bordered="false">
      <template #header>
        <div class="card-title"><Download :size="18" /> HTTPS 订阅</div>
      </template>
      <div class="subscription-row">
        <n-input
          v-model:value="subscriptionURL"
          clearable
          placeholder="https://example.com/subscription"
          @keyup.enter="importSubscription"
        />
        <n-button type="primary" :loading="importing" @click="importSubscription">
          本地导入
        </n-button>
      </div>
      <p class="hint">订阅内容只在本机解析；地址不会发送给在线转换服务，也不会写入日志。</p>
    </n-card>

    <n-collapse class="profile-collapse">
      <n-collapse-item title="Profile 原始内容（高级）" name="profile-content">
        <n-card class="profile-card editor-card" :bordered="false">
          <template #header>
            <div class="editor-header">
              <div class="card-title"><FileJson :size="18" /> Profile 内容</div>
              <span v-if="result?.path" class="path">{{ result.path }}</span>
            </div>
          </template>
          <n-spin :show="loading">
            <n-input
              v-model:value="content"
              type="textarea"
              class="profile-editor"
              placeholder="粘贴 sing-box JSON 或 Clash YAML"
              :autosize="false"
              spellcheck="false"
            />
          </n-spin>
          <div class="editor-actions">
            <n-button :disabled="loading" @click="loadProfile">重新读取</n-button>
            <n-button type="primary" :loading="saving" @click="saveProfile">
              <template #icon><Save :size="16" /></template>
              校验并应用
            </n-button>
          </div>
        </n-card>
      </n-collapse-item>
    </n-collapse>
  </section>
</template>

<style scoped>
.profile-page {
  display: flex;
  flex-direction: column;
  gap: 16px;
}

.page-header {
  display: flex;
  align-items: flex-start;
  justify-content: space-between;
  gap: 20px;
}

.page-header h1 {
  margin: 0 0 6px;
  font-size: 24px;
  color: var(--ec-text);
}

.page-header p,
.hint {
  margin: 0;
  color: var(--ec-text-muted);
  line-height: 1.6;
}

.profile-card {
  border-radius: 14px;
  box-shadow: var(--ec-shadow);
}

.profile-collapse {
  padding: 4px 12px;
  background: var(--ec-panel);
  border-radius: 12px;
  box-shadow: var(--ec-shadow);
}

.profile-collapse .profile-card {
  box-shadow: none;
}

.group-list {
  display: flex;
  flex-direction: column;
  gap: 18px;
}

.group-section + .group-section {
  padding-top: 18px;
  border-top: 1px solid var(--ec-border-soft);
}

.preview-content {
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 12px;
}

.preview-content span {
  line-height: 1.5;
}

.group-header {
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 12px;
  margin-bottom: 10px;
}

.group-header div {
  display: flex;
  align-items: baseline;
  gap: 10px;
}

.group-header span,
.proxy-main small {
  color: var(--ec-text-muted);
  font-size: 12px;
}

.proxy-grid {
  display: grid;
  grid-template-columns: repeat(2, minmax(0, 1fr));
  gap: 8px;
}

.proxy-node {
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 10px;
  min-width: 0;
  padding: 11px 12px;
  color: var(--ec-text);
  text-align: left;
  background: var(--ec-bg);
  border: 1px solid var(--ec-border-soft);
  border-radius: 10px;
  cursor: pointer;
}

.proxy-node:hover:not(:disabled),
.proxy-node.selected {
  background: color-mix(in srgb, var(--ec-primary) 8%, white);
  border-color: color-mix(in srgb, var(--ec-primary) 55%, white);
}

.proxy-node:disabled {
  cursor: default;
}

.proxy-main {
  display: flex;
  flex-direction: column;
  min-width: 0;
}

.proxy-main strong {
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
}

@media (max-width: 760px) {
  .proxy-grid {
    grid-template-columns: 1fr;
  }
}


.card-title,
.editor-header {
  display: flex;
  align-items: center;
  gap: 8px;
}

.editor-header {
  justify-content: space-between;
  width: 100%;
}

.path {
  max-width: 55%;
  overflow: hidden;
  color: var(--ec-text-muted);
  font-family: ui-monospace, SFMono-Regular, Menlo, monospace;
  font-size: 12px;
  text-overflow: ellipsis;
  white-space: nowrap;
}

.rules-info,
.rules-error {
  margin-bottom: 12px;
}

.rule-composer {
  display: grid;
  grid-template-columns: 130px 160px minmax(180px, 1fr) 190px auto;
  gap: 8px;
  align-items: center;
}

.rule-pipeline {
  display: flex;
  align-items: stretch;
  gap: 7px;
  margin: 16px 0;
  overflow-x: auto;
}

.pipeline-step {
  display: flex;
  flex: 1 0 112px;
  flex-direction: column;
  gap: 2px;
  min-width: 0;
  padding: 9px 10px;
  border: 1px solid var(--ec-border-soft);
  border-radius: 9px;
  background: var(--ec-bg);
}

.pipeline-step strong {
  color: var(--ec-text);
  font-size: 12px;
}

.pipeline-step span {
  overflow: hidden;
  color: var(--ec-text-muted);
  font-size: 11px;
  text-overflow: ellipsis;
  white-space: nowrap;
}

.pipeline-step.prepend {
  border-color: color-mix(in srgb, var(--ec-primary) 45%, var(--ec-border-soft));
  background: color-mix(in srgb, var(--ec-primary) 6%, white);
}

.pipeline-step.append {
  border-color: color-mix(in srgb, var(--ec-warning) 45%, var(--ec-border-soft));
  background: color-mix(in srgb, var(--ec-warning) 7%, white);
}

.pipeline-arrow {
  display: grid;
  place-items: center;
  color: var(--ec-text-muted);
  font-size: 12px;
}

.route-preview {
  margin-bottom: 16px;
  padding: 12px;
  border: 1px solid var(--ec-border-soft);
  border-radius: 10px;
}

.route-preview-header {
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 12px;
  margin-bottom: 10px;
}

.route-preview-header > div {
  display: flex;
  flex-direction: column;
  gap: 2px;
}

.route-preview-header strong {
  color: var(--ec-text);
  font-size: 13px;
}

.route-preview-header span {
  color: var(--ec-text-muted);
  font-size: 11px;
}

.route-preview-header :deep(.n-select) {
  width: min(320px, 42%);
}

.route-preview-list {
  display: flex;
  flex-direction: column;
  gap: 5px;
  max-height: 280px;
  padding-right: 4px;
  overflow-y: auto;
}

.route-preview-row {
  display: grid;
  grid-template-columns: 24px minmax(0, 1fr) auto;
  align-items: center;
  gap: 7px;
  padding: 6px 7px;
  background: var(--ec-bg);
  border-radius: 7px;
}

.route-preview-row code {
  overflow: hidden;
  color: var(--ec-text-2);
  font-family: ui-monospace, SFMono-Regular, Menlo, monospace;
  font-size: 11px;
  text-overflow: ellipsis;
  white-space: nowrap;
}

.rule-stage-grid {
  display: grid;
  grid-template-columns: repeat(2, minmax(0, 1fr));
  gap: 12px;
}

.rule-stage-card {
  min-width: 0;
  padding: 12px;
  border: 1px solid var(--ec-border-soft);
  border-radius: 10px;
  background: var(--ec-bg);
}

.rule-stage-header,
.rule-footer,
.rule-footer-actions,
.rule-actions {
  display: flex;
  align-items: center;
}

.rule-stage-header {
  justify-content: space-between;
  gap: 8px;
  margin-bottom: 10px;
}

.rule-stage-header > div {
  display: flex;
  flex-direction: column;
  gap: 2px;
}

.rule-stage-header strong {
  color: var(--ec-text);
  font-size: 13px;
}

.rule-stage-header span {
  color: var(--ec-text-muted);
  font-size: 11px;
}

.rule-list {
  display: flex;
  flex-direction: column;
  gap: 7px;
}

.rule-row {
  display: grid;
  grid-template-columns: 22px minmax(0, 1fr) auto;
  gap: 6px;
  align-items: center;
}

.rule-index {
  color: var(--ec-text-muted);
  font-family: ui-monospace, SFMono-Regular, Menlo, monospace;
  font-size: 11px;
  text-align: center;
}

.rule-row :deep(input) {
  font-family: ui-monospace, SFMono-Regular, Menlo, monospace;
  font-size: 11px;
}

.rule-actions {
  gap: 1px;
}

.rule-footer {
  justify-content: space-between;
  gap: 16px;
  margin-top: 14px;
}

.rule-footer .hint {
  max-width: 70%;
  font-size: 12px;
}

.rule-footer-actions {
  flex-shrink: 0;
  gap: 8px;
}

.subscription-row {
  display: grid;
  grid-template-columns: minmax(0, 1fr) auto;
  gap: 10px;
  margin-bottom: 8px;
}

.warnings {
  white-space: pre-wrap;
}

.profile-editor :deep(textarea) {
  min-height: 360px !important;
  font-family: ui-monospace, SFMono-Regular, Menlo, monospace;
  font-size: 12px;
  line-height: 1.55;
}

.editor-actions {
  display: flex;
  justify-content: flex-end;
  gap: 10px;
  margin-top: 14px;
}

@media (max-width: 900px) {
  .rule-composer {
    grid-template-columns: repeat(2, minmax(0, 1fr));
  }

  .rule-composer :deep(.n-input),
  .rule-composer :deep(.n-button) {
    grid-column: 1 / -1;
  }

  .rule-stage-grid {
    grid-template-columns: 1fr;
  }
}

@media (max-width: 760px) {
	.page-header,
	.subscription-row,
	.rule-footer,
	.route-preview-header {
		display: flex;
		flex-direction: column;
		align-items: stretch;
	}

  .subscription-row :deep(.n-button),
  .rule-footer-actions,
  .rule-footer .hint {
    width: 100%;
    max-width: none;
  }

	.route-preview-header :deep(.n-select) {
		width: 100%;
	}
}
</style>
