<script setup lang="ts">
import { computed, onMounted, ref } from 'vue'

interface TaskEvent {
  id: number
  attempt: number
  sequence: number
  stage?: string
  status?: string
  progress?: number
  reason_code?: string
  message?: string
}

interface SecurityEvent {
  id: number
  app_package: string
  kind: string
  rule_id?: string
  confidence: number
  created_at: string
}

const file = ref<File | null>(null)
const splits = ref<File[]>([])
const deviceSpecs = ref<File[]>([])
const profile = ref('basic')
const signingMode = ref('customer_local')
const aabMode = ref('universal')
const inMemoryLibs = ref('')
const authUrl = ref('')
const eventUrl = ref('')
const eventToken = ref('')
const noKeyAsset = ref(false)
const selfDecryptCore = ref(true)
const decoyDynamic = ref(true)
const corruptSectionNames = ref(true)
const selfDecryptText = ref(true)
const detection = ref(true)
const responseMode = ref('toast')
const alg = ref('ecdsa-p256-sha256')
const shellVersion = ref('0.1.0')
const maxNativeFileMb = ref(128)
const advancedOpen = ref(['advanced'])

const taskId = ref('')
const status = ref('')
const events = ref<TaskEvent[]>([])
const securityEvents = ref<SecurityEvent[]>([])
const eventKind = ref('')
const knownKinds = ref<string[]>([])
const progress = ref(0)
const error = ref('')
const busy = ref(false)

const artifactUrl = computed(() =>
  taskId.value && status.value === 'succeeded'
    ? `/api/v1/tasks/${taskId.value}/artifact`
    : '',
)
const sourceIsAab = computed(() =>
  file.value?.name.toLowerCase().endsWith('.aab') ?? false,
)

function onFileChange(event: Event) {
  const input = event.target as HTMLInputElement
  file.value = input.files?.[0] ?? null
  if (sourceIsAab.value) {
    splits.value = []
  } else {
    deviceSpecs.value = []
    aabMode.value = 'universal'
  }
}

function onSplitsChange(event: Event) {
  const input = event.target as HTMLInputElement
  splits.value = Array.from(input.files ?? [])
}

function onSpecsChange(event: Event) {
  const input = event.target as HTMLInputElement
  deviceSpecs.value = Array.from(input.files ?? [])
}

async function loadSecurityEvents() {
  try {
    const params = new URLSearchParams({ limit: '50' })
    if (eventKind.value) {
      params.set('kind', eventKind.value)
    }
    const response = await fetch(`/api/v1/events?${params}`)
    if (response.ok) {
      const payload = await response.json()
      securityEvents.value = payload.events ?? []
      if (!eventKind.value) {
        knownKinds.value = [
          ...new Set(securityEvents.value.map((event) => event.kind)),
        ]
      }
    }
  } catch {
    // The panel is best-effort; keep the last successful snapshot.
  }
}

onMounted(loadSecurityEvents)

async function upload() {
  error.value = ''
  events.value = []
  status.value = ''
  progress.value = 0
  if (!file.value) {
    error.value = '请选择 APK 或 AAB 文件'
    return
  }
  const extension = file.value.name.toLowerCase().slice(file.value.name.lastIndexOf('.'))
  if (extension !== '.apk' && extension !== '.aab') {
    error.value = '只支持 .apk 或 .aab'
    return
  }
  if (extension === '.aab' && splits.value.length > 0) {
    error.value = 'AAB 输入不能再附加 split APK'
    return
  }
  if (deviceSpecs.value.length > 0 &&
      (extension !== '.aab' || aabMode.value !== 'split')) {
    error.value = 'device spec 只能用于 AAB 的 split 模式'
    return
  }
  if (aabMode.value === 'split' && extension !== '.aab') {
    error.value = 'split 模式需要 AAB 输入'
    return
  }
  if (aabMode.value === 'split' && deviceSpecs.value.length === 0) {
    error.value = 'AAB split 模式至少需要一个 device spec JSON'
    return
  }

  busy.value = true
  const form = new FormData()
  form.append('file', file.value)
  form.append('profile', profile.value)
  form.append('signing_mode', signingMode.value)
  form.append('aab_mode', aabMode.value)
  form.append('in_memory_libs', inMemoryLibs.value)
  form.append('auth_url', authUrl.value)
  form.append('event_url', eventUrl.value)
  form.append('event_token', eventToken.value)
  form.append('no_key_asset', String(noKeyAsset.value))
  form.append('self_decrypt_core', String(selfDecryptCore.value))
  form.append('decoy_dynamic', String(decoyDynamic.value))
  form.append('corrupt_section_names', String(corruptSectionNames.value))
  form.append('self_decrypt_text', String(selfDecryptText.value))
  form.append('detection', String(detection.value))
  form.append('response', responseMode.value)
  form.append('alg', alg.value)
  form.append('shell_version', shellVersion.value)
  form.append('max_native_file_mb', String(maxNativeFileMb.value))
  for (const split of splits.value) {
    form.append('splits', split)
  }
  for (const spec of deviceSpecs.value) {
    form.append('device_specs', spec)
  }
  try {
    const response = await fetch('/api/v1/tasks', { method: 'POST', body: form })
    const payload = await response.json()
    if (!response.ok) {
      throw new Error(payload.error ?? `HTTP ${response.status}`)
    }
    taskId.value = payload.task.id
    status.value = payload.task.status
    subscribe()
  } catch (failure) {
    error.value = String(failure)
    busy.value = false
  }
}

function subscribe() {
  const source = new EventSource(`/api/v1/tasks/${taskId.value}/events?after=0`)
  source.onmessage = (message) => {
    const event: TaskEvent = JSON.parse(message.data)
    events.value.push(event)
    if (event.progress !== undefined) {
      progress.value = event.progress
    }
    if (event.status) {
      status.value = event.status
    }
  }
  source.addEventListener('done', (message) => {
    const payload = JSON.parse((message as MessageEvent).data)
    status.value = payload.status
    progress.value = 100
    busy.value = false
    source.close()
    loadSecurityEvents()
  })
  source.onerror = () => {
    source.close()
    if (status.value !== 'succeeded' && status.value !== 'failed') {
      status.value = 'disconnected'
    }
    busy.value = false
  }
}

async function cancel() {
  if (!taskId.value) return
  await fetch(`/api/v1/tasks/${taskId.value}/cancel`, { method: 'POST' })
  status.value = 'canceled'
  busy.value = false
}
</script>

<template>
  <main class="page">
    <header>
      <h1>ForgeMirror</h1>
      <p class="subtitle">APK/AAB 加固流水线 · 上传 → 任务 → 产物</p>
    </header>

    <section class="card">
      <div class="row">
        <label class="label">输入</label>
        <input type="file" accept=".apk,.aab" @change="onFileChange" />
        <span class="hint">{{ sourceIsAab ? 'AAB' : 'APK' }}</span>
      </div>
      <div v-if="!sourceIsAab" class="row">
        <label class="label">Split APK</label>
        <input type="file" accept=".apk" multiple @change="onSplitsChange" />
        <span class="hint">可选，base APK 对应的 config/feature split</span>
      </div>
      <div class="row">
        <label class="label">Device spec</label>
        <input type="file" accept=".json" multiple @change="onSpecsChange" />
        <span class="hint">仅 AAB split 模式，每个 JSON 生成一套产物</span>
      </div>
      <div class="row">
        <label class="label">Profile</label>
        <el-select v-model="profile" style="width: 180px">
          <el-option label="basic" value="basic" />
          <el-option label="enhanced" value="enhanced" />
          <el-option label="financial" value="financial" />
        </el-select>
        <label class="label">签名</label>
        <el-select v-model="signingMode" style="width: 200px">
          <el-option label="客户本地签名" value="customer_local" />
          <el-option label="平台 HSM" value="hsm" />
        </el-select>
        <label class="label">AAB 模式</label>
        <el-select v-model="aabMode" style="width: 180px">
          <el-option label="universal" value="universal" />
          <el-option label="split（按设备拆分）" value="split" />
        </el-select>
      </div>

      <el-collapse v-model="advancedOpen" class="advanced">
        <el-collapse-item title="高级加固选项" name="advanced">
          <div class="grid">
            <label class="field">
              <span class="label">内存加载库</span>
              <el-input v-model="inMemoryLibs" placeholder="libfoo.so,libbar.so" />
            </label>
            <label class="field">
              <span class="label">签名算法</span>
              <el-select v-model="alg">
                <el-option label="ECDSA P-256" value="ecdsa-p256-sha256" />
                <el-option label="Ed25519" value="ed25519" />
              </el-select>
            </label>
            <label class="field">
              <span class="label">响应模式</span>
              <el-select v-model="responseMode">
                <el-option label="log" value="log" />
                <el-option label="toast" value="toast" />
                <el-option label="degrade" value="degrade" />
                <el-option label="block" value="block" />
              </el-select>
            </label>
            <label class="field">
              <span class="label">Shell 版本</span>
              <el-input v-model="shellVersion" />
            </label>
            <label class="field">
              <span class="label">单文件 native 上限 (MB)</span>
              <el-input-number v-model="maxNativeFileMb" :min="1" :max="4096" />
            </label>
            <label class="field">
              <span class="label">授权服务 URL</span>
              <el-input v-model="authUrl" placeholder="https://..." />
            </label>
            <label class="field">
              <span class="label">事件服务 URL</span>
              <el-input v-model="eventUrl" placeholder="https://..." />
            </label>
            <label class="field">
              <span class="label">事件 Token</span>
              <el-input v-model="eventToken" type="password" show-password />
            </label>
          </div>
          <div class="toggles">
            <el-checkbox v-model="selfDecryptCore">Core 自解密</el-checkbox>
            <el-checkbox v-model="decoyDynamic">双 PT_DYNAMIC 诱饵</el-checkbox>
            <el-checkbox v-model="corruptSectionNames">破坏 section 名表</el-checkbox>
            <el-checkbox v-model="selfDecryptText">Text 段自解密</el-checkbox>
            <el-checkbox v-model="detection">运行时检测</el-checkbox>
            <el-checkbox v-model="noKeyAsset">不内置内容密钥</el-checkbox>
          </div>
        </el-collapse-item>
      </el-collapse>

      <div class="row actions">
        <el-button type="primary" :loading="busy" @click="upload">开始加固</el-button>
        <el-button v-if="busy" @click="cancel">取消</el-button>
        <el-button v-if="artifactUrl" tag="a" :href="artifactUrl" type="success">
          下载加固产物
        </el-button>
      </div>
      <el-alert v-if="error" :title="error" type="error" show-icon :closable="false" />
    </section>

    <section v-if="taskId" class="card">
      <div class="meta">
        <span>任务：{{ taskId }}</span>
        <span>状态：<b>{{ status }}</b></span>
      </div>
      <el-progress :percentage="progress" :status="status === 'failed' ? 'exception' : undefined" />
      <ul class="events">
        <li v-for="event in events" :key="event.id">
          <span class="seq">#{{ event.sequence }}</span>
          <span class="stage">{{ event.stage ?? '-' }}</span>
          <span class="state">{{ event.status ?? '' }}</span>
          <span class="msg">{{ event.message ?? event.reason_code ?? '' }}</span>
        </li>
      </ul>
    </section>

    <section class="card">
      <div class="meta">
        <span>安全事件</span>
        <el-select
          v-model="eventKind"
          size="small"
          style="width: 150px"
          clearable
          placeholder="全部类型"
          @change="loadSecurityEvents"
        >
          <el-option v-for="kind in knownKinds" :key="kind" :label="kind" :value="kind" />
        </el-select>
        <el-button size="small" @click="loadSecurityEvents">刷新</el-button>
      </div>
      <el-table :data="securityEvents" size="small" empty-text="暂无事件">
        <el-table-column prop="created_at" label="时间" width="210" />
        <el-table-column prop="app_package" label="应用" min-width="160" />
        <el-table-column prop="kind" label="类型" width="110" />
        <el-table-column prop="rule_id" label="规则" width="140" />
        <el-table-column prop="confidence" label="置信度" width="90" />
      </el-table>
    </section>
  </main>
</template>

<style>
:root {
  color-scheme: light dark;
  font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif;
}
body {
  margin: 0;
  background: #f6f7f9;
  color: #1f2328;
}
.page {
  max-width: 960px;
  margin: 0 auto;
  padding: 48px 20px 80px;
}
header h1 {
  margin: 0;
  font-size: 28px;
  letter-spacing: -0.02em;
}
.subtitle {
  margin: 6px 0 28px;
  color: #6a737d;
}
.card {
  background: #fff;
  border: 1px solid #e5e7eb;
  border-radius: 12px;
  padding: 20px;
  margin-bottom: 20px;
  box-shadow: 0 1px 2px rgb(0 0 0 / 4%);
}
.row {
  display: flex;
  align-items: center;
  gap: 12px;
  flex-wrap: wrap;
  margin-bottom: 14px;
}
.label {
  color: #57606a;
  font-size: 13px;
}
.hint {
  color: #9aa4af;
  font-size: 12px;
}
.advanced {
  margin: 8px 0 16px;
}
.grid {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(240px, 1fr));
  gap: 14px 18px;
}
.field {
  display: flex;
  flex-direction: column;
  gap: 6px;
}
.toggles {
  display: flex;
  flex-wrap: wrap;
  gap: 8px 18px;
  margin-top: 16px;
}
.actions {
  margin-top: 16px;
}
.meta {
  display: flex;
  gap: 24px;
  margin-bottom: 12px;
  font-size: 13px;
  color: #57606a;
  word-break: break-all;
}
.events {
  list-style: none;
  margin: 16px 0 0;
  padding: 0;
  font-size: 13px;
}
.events li {
  display: flex;
  gap: 12px;
  padding: 6px 0;
  border-bottom: 1px dashed #eef0f2;
}
.seq {
  color: #9aa4af;
  min-width: 28px;
}
.stage {
  min-width: 70px;
  color: #0969da;
}
.state {
  min-width: 80px;
  color: #1a7f37;
}
.msg {
  color: #57606a;
  word-break: break-all;
}
@media (prefers-color-scheme: dark) {
  body {
    background: #0d1117;
    color: #e6edf3;
  }
  .card {
    background: #161b22;
    border-color: #30363d;
  }
  .subtitle,
  .label,
  .meta,
  .msg,
  .hint {
    color: #8b949e;
  }
}
</style>
