<script setup lang="ts">
import { computed, ref } from 'vue'
import QRCode from 'qrcode'
import { Browser } from '@wailsio/runtime'
import { api } from '../api/client'

const props = defineProps<{
  modelValue: boolean
}>()

const emit = defineEmits<{
  (e: 'update:modelValue', value: boolean): void
  (e: 'logged-in'): void
}>()

// Step state
const company = ref('')
const loginMethods = ref<string[]>([])
const verifyTypes = ref<string[]>([])
const selectedMethod = ref('')
const account = ref('')
const code = ref('')
const password = ref('')
const qrUrl = ref('')
const qrToken = ref('')
const qrDataURL = ref('')
const loginError = ref('')
const loginBusy = ref(false)
const codeSent = ref(false)
const qrPolling = ref(false)
let qrPollTimer: number | undefined

const isQRMethod = computed(() => selectedMethod.value === 'lark')
const isPasswordVerify = computed(() => verifyTypes.value.includes('password'))

function methodLabel(m: string): string {
  const labels: Record<string, string> = {
    email: '邮箱验证码',
    mobile: '手机验证码',
    lark: '飞书扫码登录',
  }
  return labels[m] ?? m
}

async function discoverAndFetchMethods() {
  loginBusy.value = true
  loginError.value = ''
  try {
    const res = await api.discoverCompany(company.value.trim())
    if (!res.ok) { loginError.value = res.summary || '公司代码无效'; return }
    const lr = await api.getLoginMethods()
    if (!lr.ok) { loginError.value = lr.error || '获取登录方式失败'; return }
    loginMethods.value = lr.methods || []
    verifyTypes.value = lr.verify_types || []
    if (!lr.methods?.length) {
      loginError.value = '当前公司暂无支持的登录方式'
      return
    }
    selectedMethod.value = lr.methods[0]
  } catch (e) {
    loginError.value = String(e)
  } finally {
    loginBusy.value = false
  }
}

async function sendCode() {
  loginBusy.value = true
  loginError.value = ''
  try {
    const res = await api.sendVerifyCode(selectedMethod.value, account.value.trim())
    if (!res.ok) { loginError.value = res.summary || '发送验证码失败'; return }
    codeSent.value = true
  } catch (e) {
    loginError.value = String(e)
  } finally {
    loginBusy.value = false
  }
}

async function verifyAndLogin() {
  loginBusy.value = true
  loginError.value = ''
  try {
    const res = await api.verifyCode(selectedMethod.value, account.value.trim(), code.value.trim())
    if (!res.ok) { loginError.value = res.summary || '验证码错误'; return }
    onLoginSuccess()
  } catch (e) {
    loginError.value = String(e)
  } finally {
    loginBusy.value = false
  }
}

async function doPasswordLogin() {
  loginBusy.value = true
  loginError.value = ''
  try {
    const res = await api.loginWithPassword(account.value.trim(), password.value)
    if (!res.ok) { loginError.value = res.summary || '密码错误'; return }
    onLoginSuccess()
  } catch (e) {
    loginError.value = String(e)
  } finally {
    loginBusy.value = false
  }
}

async function startQRLogin() {
  loginBusy.value = true
  loginError.value = ''
  qrUrl.value = ''
  qrToken.value = ''
  qrDataURL.value = ''
  try {
    const res = await api.getQRCode()
    if (!res.ok) { loginError.value = res.error || '获取登录链接失败'; return }
    qrUrl.value = res.login_url || ''
    qrToken.value = res.token || ''
    qrDataURL.value = await QRCode.toDataURL(qrUrl.value, { width: 220, margin: 2 })
    qrPolling.value = true
    qrPollTimer = window.setInterval(pollQR, 2000)
  } catch (e) {
    loginError.value = String(e)
  } finally {
    loginBusy.value = false
  }
}

async function pollQR() {
  if (!qrPolling.value) return
  try {
    const res = await api.pollQRStatus(qrToken.value)
    if (res.ok) {
      stopQRPoll()
      onLoginSuccess()
    }
  } catch { /* keep polling */ }
}

function stopQRPoll() {
  qrPolling.value = false
  if (qrPollTimer) { window.clearInterval(qrPollTimer); qrPollTimer = undefined }
}

function openInBrowser() {
  if (qrUrl.value) Browser.OpenURL(qrUrl.value)
}

function onLoginSuccess() {
  stopQRPoll()
  // Reset state for next time
  loginMethods.value = []
  selectedMethod.value = ''
  account.value = ''
  code.value = ''
  codeSent.value = false
  qrUrl.value = ''
  qrToken.value = ''
  qrDataURL.value = ''
  loginError.value = ''
  emit('logged-in')
  emit('update:modelValue', false)
}

function goBack() {
  loginMethods.value = []
  verifyTypes.value = []
  selectedMethod.value = ''
  account.value = ''
  code.value = ''
  password.value = ''
  codeSent.value = false
  stopQRPoll()
  qrUrl.value = ''
  qrToken.value = ''
  qrDataURL.value = ''
  loginError.value = ''
}
</script>

<template>
  <n-modal
    :show="props.modelValue"
    :closable="false"
    :mask-closable="false"
    preset="card"
    title="登录 CrossLink"
    class="login-modal"
    style="width: 400px"
  >
    <div class="login-body">
      <!-- Step 1: company discovery -->
      <template v-if="!loginMethods.length">
        <p class="step-hint">请输入公司代码以发现登录方式</p>
        <n-input
          v-model:value="company"
          placeholder="公司代码"
          :disabled="loginBusy"
          @keyup.enter="discoverAndFetchMethods"
        />
        <n-button type="primary" :loading="loginBusy" @click="discoverAndFetchMethods" block>
          下一步
        </n-button>
      </template>

      <!-- Step 2: method selection + credentials -->
      <template v-else>
        <n-select
          v-model:value="selectedMethod"
          :options="loginMethods.map(m => ({ label: methodLabel(m), value: m }))"
          placeholder="选择登录方式"
        />

        <!-- QR / Lark login -->
        <template v-if="isQRMethod">
          <template v-if="!qrUrl">
            <n-button type="primary" :loading="loginBusy" @click="startQRLogin" block>
              获取二维码
            </n-button>
          </template>
          <template v-else>
            <div class="qr-box">
              <img v-if="qrDataURL" :src="qrDataURL" alt="飞书扫码登录" class="qr-img" />
              <div v-else class="qr-loading">生成中...</div>
              <p class="qr-hint">{{ qrPolling ? '用飞书扫码登录' : '已完成扫码' }}</p>
              <n-button size="small" @click="openInBrowser">在浏览器中打开</n-button>
            </div>
            <n-button quaternary @click="stopQRPoll">取消</n-button>
          </template>
        </template>

        <!-- Account-based login (password or code) -->
        <template v-else>
          <n-input
            v-model:value="account"
            :placeholder="selectedMethod === 'mobile' ? '手机号' : '邮箱'"
            :disabled="loginBusy"
          />

          <!-- Password login (e.g. bytedance) -->
          <template v-if="isPasswordVerify">
            <n-input
              v-model:value="password"
              type="password"
              placeholder="密码"
              :disabled="loginBusy"
              @keyup.enter="doPasswordLogin"
            />
            <n-button type="primary" :loading="loginBusy" @click="doPasswordLogin" block>
              登录
            </n-button>
          </template>

          <!-- Code verification login -->
          <template v-else>
            <template v-if="!codeSent">
              <n-button type="primary" :loading="loginBusy" @click="sendCode" block>
                发送验证码
              </n-button>
            </template>
            <template v-else>
              <n-input
                v-model:value="code"
                placeholder="验证码"
                :disabled="loginBusy"
                @keyup.enter="verifyAndLogin"
              />
              <n-button type="primary" :loading="loginBusy" @click="verifyAndLogin" block>
                登录
              </n-button>
              <n-button quaternary @click="codeSent = false">重新发送</n-button>
            </template>
          </template>
        </template>

        <n-button quaternary size="small" @click="goBack">← 返回</n-button>
      </template>

      <n-alert v-if="loginError" type="error" :show-icon="false" class="login-alert">
        {{ loginError }}
      </n-alert>
    </div>
  </n-modal>
</template>

<style scoped>
.login-body {
  display: flex;
  flex-direction: column;
  gap: 12px;
}

.step-hint {
  margin: 0;
  font-size: 13px;
  color: var(--ec-text-2);
}

.qr-box {
  display: flex;
  flex-direction: column;
  align-items: center;
  gap: 8px;
}

.qr-img {
  width: 220px;
  height: 220px;
  border: 1px solid var(--ec-border);
  border-radius: 8px;
}

.qr-loading {
  width: 220px;
  height: 220px;
  display: flex;
  align-items: center;
  justify-content: center;
  border: 1px solid var(--ec-border);
  border-radius: 8px;
  color: var(--ec-text-3);
  font-size: 13px;
}

.qr-hint {
  margin: 0;
  font-size: 13px;
  color: var(--ec-text-1);
  font-weight: 500;
}

.login-alert {
  margin-top: 4px;
}
</style>
