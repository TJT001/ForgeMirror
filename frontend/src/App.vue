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

type DropKind = 'source' | 'splits' | 'specs'

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
const whitebox = ref(true)
const aiDecoy = ref(false)
const responseMode = ref('toast')
const alg = ref('ecdsa-p256-sha256')
const shellVersion = ref('0.1.0')
const maxNativeFileMb = ref(128)

const taskId = ref('')
const status = ref('')
const events = ref<TaskEvent[]>([])
const securityEvents = ref<SecurityEvent[]>([])
const eventKind = ref('')
const knownKinds = ref<string[]>([])
const progress = ref(0)
const error = ref('')
const busy = ref(false)
const dragging = ref<Record<DropKind, boolean>>({
  source: false,
  splits: false,
  specs: false,
})

const artifactUrl = computed(() =>
  taskId.value && status.value === 'succeeded'
    ? `/api/v1/tasks/${taskId.value}/artifact`
    : '',
)
const sourceIsAab = computed(() =>
  file.value?.name.toLowerCase().endsWith('.aab') ?? false,
)
const sourceName = computed(() => file.value?.name ?? '')
const embeddedKey = computed({
  get: () => !noKeyAsset.value,
  set: (value: boolean) => {
    noKeyAsset.value = !value
  },
})
const stageLabels: Record<string, string> = {
  queue: '队列',
  s0: 'S0 准入',
  s1: 'S1 清点',
  s2: 'S2 容器',
  s3: 'S3 策略',
  s4: 'S4 授权',
  s5: 'S5 Native',
  s6: 'S6 注入',
  s7: 'S7 签名',
  s8: 'S8 闸门',
  done: '完成',
  failed: '失败',
}
const stageLabel = (stage?: string) => (stage ? stageLabels[stage] ?? stage : 'pipeline')
const recentEvents = computed(() => events.value.slice(-24))
const selectedLibs = computed(() =>
  inMemoryLibs.value.split(',').map((value) => value.trim()).filter(Boolean),
)
const statusLabel = computed(() => {
  switch (status.value) {
    case 'queued': return '排队中'
    case 'running': return '运行中'
    case 'succeeded': return '已完成'
    case 'failed': return '失败'
    case 'canceled': return '已取消'
    case 'disconnected': return '连接中断'
    default: return '未开始'
  }
})
const statusTone = computed(() => {
  if (status.value === 'succeeded') return 'ok'
  if (status.value === 'failed') return 'bad'
  if (status.value === 'running') return 'live'
  return 'idle'
})

function selectSource(next: File | null) {
  file.value = next
  if (sourceIsAab.value) {
    splits.value = []
  } else {
    deviceSpecs.value = []
    aabMode.value = 'universal'
  }
}

function onFileChange(event: Event) {
  const input = event.target as HTMLInputElement
  selectSource(input.files?.[0] ?? null)
}

function onSplitsChange(event: Event) {
  const input = event.target as HTMLInputElement
  splits.value = Array.from(input.files ?? [])
}

function onSpecsChange(event: Event) {
  const input = event.target as HTMLInputElement
  deviceSpecs.value = Array.from(input.files ?? [])
}

function onDrop(kind: DropKind, event: DragEvent) {
  event.preventDefault()
  dragging.value[kind] = false
  if (kind === 'splits' && sourceIsAab.value) {
    return
  }
  if (kind === 'specs' && aabMode.value !== 'split') {
    return
  }
  const files = Array.from(event.dataTransfer?.files ?? [])
  if (kind === 'source') {
    selectSource(files[0] ?? null)
  } else if (kind === 'splits') {
    splits.value = files
  } else {
    deviceSpecs.value = files
  }
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
    error.value = '请先选择 APK 或 AAB 主包'
    return
  }
  const extension = file.value.name.toLowerCase().slice(file.value.name.lastIndexOf('.'))
  if (extension !== '.apk' && extension !== '.aab') {
    error.value = '只支持 .apk 或 .aab'
    return
  }
  if (extension === '.aab' && splits.value.length > 0) {
    error.value = 'AAB 输入不能附加 split APK'
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
  if (maxNativeFileMb.value < 1 || maxNativeFileMb.value > 4096) {
    error.value = 'native 上限需在 1–4096 MB 之间'
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
  form.append('whitebox', String(whitebox.value))
  form.append('ai_decoy', String(aiDecoy.value))
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
  <div class="app">
    <header class="topbar">
      <div class="brand">
        <svg class="brand-mark" viewBox="0 0 44 44" aria-hidden="true">
          <path d="M4 8h14l8 10-8 10H4z" />
          <path d="M40 8H26l-8 10 8 10h14z" class="mirror" />
          <path d="M8 36h28" class="rule" />
        </svg>
        <div class="brand-text">
          <span class="brand-name">ForgeMirror</span>
          <span class="brand-sub">Android应用加固平台</span>
        </div>
      </div>
      <div class="topbar-meta">
        <span class="signal"></span>
        <span>本地构建通道</span>
        <span class="slash">/</span>
        <span class="mono">v0.1</span>
      </div>
    </header>

    <main class="workspace">
      <aside class="rail">
        <p class="rail-label">运行摘要</p>
        <h1 class="rail-title">{{ taskId ? '加固任务' : '尚未开始' }}</h1>
        <p v-if="taskId" class="rail-id">{{ taskId }}</p>

        <dl class="summary">
          <div>
            <dt>主包</dt>
            <dd>{{ sourceName || '未选择' }}</dd>
          </div>
          <div>
            <dt>输入类型</dt>
            <dd>{{ sourceIsAab ? 'AAB' : 'APK' }}</dd>
          </div>
          <div>
            <dt>Split</dt>
            <dd>{{ splits.length }} 个</dd>
          </div>
          <div>
            <dt>Device spec</dt>
            <dd>{{ deviceSpecs.length }} 个</dd>
          </div>
          <div>
            <dt>Profile</dt>
            <dd>{{ profile }}</dd>
          </div>
          <div>
            <dt>签名</dt>
            <dd>{{ signingMode === 'hsm' ? '平台 HSM' : '客户本地' }}</dd>
          </div>
          <div>
            <dt>内存库</dt>
            <dd>{{ selectedLibs.length ? selectedLibs.join(', ') : '未指定' }}</dd>
          </div>
        </dl>

        <div class="rail-status">
          <div class="status-line">
            <span class="status-dot" :class="statusTone"></span>
            <span>{{ statusLabel }}</span>
            <span v-if="taskId" class="mono status-percent">{{ progress }}%</span>
          </div>
          <div class="meter"><span :style="{ width: `${progress}%` }"></span></div>
        </div>

        <div v-if="artifactUrl" class="artifact">
          <span class="artifact-label">产物已封装</span>
          <a class="download" :href="artifactUrl">下载加固产物</a>
          <p class="artifact-note">split/AAB 任务为 ZIP 集合，单 APK 为安装包。</p>
        </div>

        <div class="ledger-wrap">
          <p class="rail-label">构建进度</p>
          <ol v-if="recentEvents.length" class="ledger">
            <li v-for="event in recentEvents" :key="event.id">
              <span class="ledger-seq">#{{ event.sequence }}</span>
              <span class="ledger-stage">{{ stageLabel(event.stage) }}</span>
              <span class="ledger-msg">{{ event.message ?? event.reason_code ?? event.status }}</span>
            </li>
          </ol>
          <p v-else class="rail-empty">开始加固后，各阶段与产物状态会在这里依次出现。</p>
        </div>
      </aside>

      <section class="stage">
        <div class="hero">
          <h2>新建加固任务</h2>
          <p>上传主包与拆分资源，选择保护层和运行时策略；任务会进入构建队列并产出可验证的受保护安装包。</p>
        </div>

        <form @submit.prevent="upload">
          <section class="block">
            <div class="block-head">
              <h3>输入与产物</h3>
              <p>主包是 APK 或 AAB。APK 可附加已有 split；AAB split 模式使用 device spec 生成分设备产物。</p>
            </div>

            <div class="dropgrid">
              <label
                class="drop"
                :class="{ active: dragging.source, filled: !!file }"
                @dragover.prevent="dragging.source = true"
                @dragleave.prevent="dragging.source = false"
                @drop="onDrop('source', $event)"
              >
                <input type="file" accept=".apk,.aab" @change="onFileChange" />
                <span class="drop-kicker">主包</span>
                <strong class="drop-title">{{ sourceName || '拖入 APK / AAB' }}</strong>
                <span class="drop-note">{{ file ? '点击可更换主包' : '或点击选择文件' }}</span>
              </label>

              <label
                class="drop"
                :class="{ active: dragging.splits, filled: splits.length > 0, disabled: sourceIsAab }"
                @dragover.prevent="!sourceIsAab && (dragging.splits = true)"
                @dragleave.prevent="dragging.splits = false"
                @drop="onDrop('splits', $event)"
              >
                <input
                  type="file"
                  accept=".apk"
                  multiple
                  :disabled="sourceIsAab"
                  @change="onSplitsChange"
                />
                <span class="drop-kicker">Split APK</span>
                <strong class="drop-title">{{ splits.length ? `${splits.length} 个附加包` : '可选的 config / feature split' }}</strong>
                <span class="drop-note">{{ sourceIsAab ? 'AAB 输入不使用 Split APK' : '拖入或点击选择多个文件' }}</span>
              </label>

              <label
                class="drop"
                :class="{ active: dragging.specs, filled: deviceSpecs.length > 0, disabled: aabMode !== 'split' }"
                @dragover.prevent="aabMode === 'split' && (dragging.specs = true)"
                @dragleave.prevent="dragging.specs = false"
                @drop="onDrop('specs', $event)"
              >
                <input
                  type="file"
                  accept=".json"
                  multiple
                  :disabled="aabMode !== 'split'"
                  @change="onSpecsChange"
                />
                <span class="drop-kicker">Device spec</span>
                <strong class="drop-title">{{ deviceSpecs.length ? `${deviceSpecs.length} 个设备规格` : 'AAB split 的设备规格' }}</strong>
                <span class="drop-note">{{ aabMode === 'split' ? '拖入或点击选择 JSON' : '先选择 AAB split 模式' }}</span>
              </label>
            </div>

            <div class="field-grid">
              <label class="field">
                <span>应用 profile</span>
                <select v-model="profile">
                  <option value="basic">basic</option>
                  <option value="enhanced">enhanced</option>
                  <option value="financial">financial</option>
                </select>
              </label>
              <label class="field">
                <span>签名方式</span>
                <select v-model="signingMode">
                  <option value="customer_local">客户本地签名</option>
                  <option value="hsm">平台 HSM</option>
                </select>
              </label>
              <label class="field">
                <span>AAB 拆分方式</span>
                <select v-model="aabMode">
                  <option value="universal">universal</option>
                  <option value="split">split · 按设备规格</option>
                </select>
              </label>
            </div>
          </section>

          <section class="block">
            <div class="block-head">
              <h3>保护层</h3>
              <p>选择壳的静态变换、运行时检测和 native 库加载方式。关闭某个保护层会直接反映到注入配置。</p>
            </div>

            <div class="matrix">
              <label class="toggle">
                <input v-model="selfDecryptCore" type="checkbox" />
                <span class="toggle-box"></span>
                <span class="toggle-copy">
                  <strong>Core 自解密</strong>
                  <small>运行时恢复加密核心库</small>
                </span>
              </label>
              <label class="toggle">
                <input v-model="decoyDynamic" type="checkbox" />
                <span class="toggle-box"></span>
                <span class="toggle-copy">
                  <strong>双 PT_DYNAMIC 诱饵</strong>
                  <small>保留伪动态表，扰动静态还原</small>
                </span>
              </label>
              <label class="toggle">
                <input v-model="corruptSectionNames" type="checkbox" />
                <span class="toggle-box"></span>
                <span class="toggle-copy">
                  <strong>破坏 section 名表</strong>
                  <small>移除 ELF section 名可读性</small>
                </span>
              </label>
              <label class="toggle">
                <input v-model="selfDecryptText" type="checkbox" />
                <span class="toggle-box"></span>
                <span class="toggle-copy">
                  <strong>Text 段自解密</strong>
                  <small>壳库文本段构建期压缩加密</small>
                </span>
              </label>
              <label class="toggle">
                <input v-model="detection" type="checkbox" />
                <span class="toggle-box"></span>
                <span class="toggle-copy">
                  <strong>运行时检测</strong>
                  <small>启用环境、注入和规则扫描</small>
                </span>
              </label>
              <label class="toggle">
                <input v-model="embeddedKey" type="checkbox" />
                <span class="toggle-box"></span>
                <span class="toggle-copy">
                  <strong>内置内容密钥</strong>
                  <small>关闭后由授权服务在线取钥</small>
                </span>
              </label>
              <label class="toggle">
                <input v-model="whitebox" type="checkbox" :disabled="noKeyAsset" />
                <span class="toggle-box"></span>
                <span class="toggle-copy">
                  <strong>白盒密钥库</strong>
                  <small>用 Chow 白盒 AES 表包裹内容密钥</small>
                </span>
              </label>
              <label class="toggle">
                <input v-model="aiDecoy" type="checkbox" />
                <span class="toggle-box"></span>
                <span class="toggle-copy">
                  <strong>语义诱饵</strong>
                  <small>注入未使用的安全域 decoy 类名，增加分析噪音</small>
                </span>
              </label>
            </div>

            <div class="field-grid">
              <label class="field wide">
                <span>内存加载库</span>
                <input v-model="inMemoryLibs" type="text" placeholder="libfoo.so, libbar.so" />
                <small>逗号分隔；这些 so 会从 APK 移除并加密到 assets。</small>
              </label>
              <label class="field">
                <span>清单签名算法</span>
                <select v-model="alg">
                  <option value="ecdsa-p256-sha256">ECDSA P-256</option>
                  <option value="ed25519">Ed25519</option>
                </select>
              </label>
            </div>
          </section>

          <section class="block">
            <div class="block-head">
              <h3>运行时通道</h3>
              <p>授权与事件服务、响应模式、native 文件上限和壳版本。空白 URL 会回退 worker 的环境默认值。</p>
            </div>

            <div class="field-grid">
              <label class="field">
                <span>响应模式</span>
                <select v-model="responseMode">
                  <option value="log">log · 仅记录</option>
                  <option value="toast">toast · 提示</option>
                  <option value="degrade">degrade · 限制写入</option>
                  <option value="block">block · 阻断受保护路径</option>
                </select>
              </label>
              <label class="field">
                <span>单文件 native 上限</span>
                <div class="number-wrap">
                  <input v-model.number="maxNativeFileMb" type="number" min="1" max="4096" />
                  <span>MB</span>
                </div>
              </label>
              <label class="field">
                <span>Shell 版本</span>
                <input v-model="shellVersion" type="text" />
              </label>
              <label class="field wide">
                <span>授权服务 URL</span>
                <input v-model="authUrl" type="url" placeholder="https://auth.example" />
              </label>
              <label class="field wide">
                <span>事件服务 URL</span>
                <input v-model="eventUrl" type="url" placeholder="https://events.example" />
              </label>
              <label class="field">
                <span>事件 Token</span>
                <input v-model="eventToken" type="password" autocomplete="off" />
              </label>
            </div>
          </section>

          <div class="actions">
            <button class="primary" type="submit" :disabled="busy">
              {{ busy ? '构建中…' : '开始加固' }}
            </button>
            <button v-if="busy" class="secondary" type="button" @click="cancel">取消任务</button>
            <a v-if="artifactUrl" class="secondary download-inline" :href="artifactUrl">
              下载加固产物
            </a>
            <span class="action-note">产物仅在授权环境中分发。</span>
          </div>
          <p v-if="error" class="error" role="alert">{{ error }}</p>
        </form>

        <section class="block events-block">
          <div class="block-head events-head">
            <div>
              <h3>安全事件</h3>
              <p>已上报的规则命中与运行时检测记录。</p>
            </div>
            <div class="event-tools">
              <select v-model="eventKind" @change="loadSecurityEvents">
                <option value="">全部类型</option>
                <option v-for="kind in knownKinds" :key="kind" :value="kind">{{ kind }}</option>
              </select>
              <button class="quiet" type="button" @click="loadSecurityEvents">刷新</button>
            </div>
          </div>
          <div class="table-wrap">
            <table>
              <thead>
                <tr>
                  <th>时间</th>
                  <th>应用</th>
                  <th>类型</th>
                  <th>规则</th>
                  <th class="num">置信度</th>
                </tr>
              </thead>
              <tbody>
                <tr v-for="item in securityEvents" :key="item.id">
                  <td class="mono">{{ item.created_at }}</td>
                  <td>{{ item.app_package }}</td>
                  <td><span class="tag">{{ item.kind }}</span></td>
                  <td class="mono">{{ item.rule_id || '—' }}</td>
                  <td class="num mono">{{ item.confidence.toFixed(2) }}</td>
                </tr>
                <tr v-if="securityEvents.length === 0">
                  <td colspan="5" class="empty">暂无安全事件</td>
                </tr>
              </tbody>
            </table>
          </div>
        </section>
      </section>
    </main>
  </div>
</template>

<style>
@import url('https://fonts.googleapis.com/css2?family=IBM+Plex+Mono:wght@400;500;600&family=IBM+Plex+Sans:wght@400;500;600;700&display=swap');

:root {
  color-scheme: light;
  --shell: #d8ddd9;
  --surface: #eef1ec;
  --surface-raised: #f6f7f2;
  --ink: #16211f;
  --ink-soft: #4b5853;
  --rule: #a9b3ac;
  --rule-dark: #7f8c85;
  --oxide: #b0472f;
  --oxide-dark: #85311f;
  --patina: #24685a;
  --brass: #9a7540;
  --rail: #17211f;
  --rail-soft: #27332f;
  --rail-ink: #dce4df;
  --font: 'IBM Plex Sans', 'Avenir Next', 'Segoe UI', sans-serif;
  --mono: 'IBM Plex Mono', 'SFMono-Regular', Menlo, monospace;
  font-family: var(--font);
  background: var(--shell);
  color: var(--ink);
}
* { box-sizing: border-box; }
body { margin: 0; background: var(--shell); }
button, input, select { font: inherit; }
button, a { -webkit-tap-highlight-color: transparent; }

.app {
  min-height: 100vh;
  background:
    radial-gradient(900px 520px at 92% -8%, rgb(176 71 47 / 10%), transparent 60%),
    linear-gradient(90deg, transparent 49.85%, rgb(22 33 31 / 5%) 50%, transparent 50.15%),
    var(--shell);
}
.topbar {
  position: sticky;
  top: 0;
  z-index: 10;
  height: 68px;
  padding: 0 30px;
  display: flex;
  align-items: center;
  justify-content: space-between;
  border-bottom: 1px solid var(--ink);
  background: rgb(238 241 236 / 88%);
  backdrop-filter: blur(12px);
}
.brand { display: flex; align-items: center; gap: 12px; }
.brand-mark { width: 34px; height: 34px; fill: var(--ink); }
.brand-mark .mirror { fill: var(--oxide); opacity: 0.9; }
.brand-mark .rule { fill: none; stroke: var(--ink); stroke-width: 1.4; }
.brand-text { display: flex; align-items: baseline; gap: 12px; }
.brand-name { font-size: 18px; font-weight: 700; letter-spacing: -0.03em; }
.brand-sub { font-size: 11px; color: var(--ink-soft); }
.topbar-meta {
  display: flex; align-items: center; gap: 8px;
  font-size: 11px; color: var(--ink-soft);
}
.signal {
  width: 7px; height: 7px; border-radius: 50%;
  background: var(--patina); box-shadow: 0 0 0 3px rgb(36 104 90 / 14%);
}
.slash { color: var(--rule-dark); }
.mono { font-family: var(--mono); }

.workspace {
  max-width: 1440px;
  margin: 0 auto;
  display: grid;
  grid-template-columns: 306px minmax(0, 1fr);
  align-items: start;
  background: linear-gradient(90deg, var(--rail) 0 306px, transparent 306px);
}
.rail {
  position: sticky;
  top: 68px;
  height: calc(100vh - 68px);
  overflow: auto;
  padding: 30px 24px 40px;
  background: transparent;
  color: var(--rail-ink);
  border-right: 1px solid var(--ink);
}
.rail-label {
  margin: 0 0 10px;
  font-family: var(--mono);
  font-size: 10px;
  letter-spacing: 0.08em;
  color: #93a29b;
}
.rail-title { margin: 0; font-size: 22px; font-weight: 600; letter-spacing: -0.03em; }
.rail-id {
  margin: 7px 0 22px;
  font-family: var(--mono);
  font-size: 10px;
  color: #8b9a93;
  word-break: break-all;
}
.summary { margin: 22px 0 24px; padding: 0; }
.summary div {
  display: grid;
  grid-template-columns: 82px minmax(0, 1fr);
  gap: 10px;
  padding: 9px 0;
  border-top: 1px solid rgb(220 228 223 / 13%);
}
.summary div:last-child { border-bottom: 1px solid rgb(220 228 223 / 13%); }
.summary dt { color: #8b9a93; font-size: 11px; }
.summary dd {
  margin: 0; font-size: 12px; color: var(--rail-ink);
  text-align: right; overflow-wrap: anywhere;
}
.rail-status { margin: 22px 0 26px; }
.status-line { display: flex; align-items: center; gap: 9px; font-size: 12px; }
.status-dot { width: 8px; height: 8px; border-radius: 50%; background: #718079; }
.status-dot.live { background: var(--brass); box-shadow: 0 0 0 4px rgb(154 117 64 / 17%); }
.status-dot.ok { background: #78b9a8; }
.status-dot.bad { background: #d2765e; }
.status-percent { margin-left: auto; color: #93a29b; font-size: 10px; }
.meter { height: 4px; margin-top: 10px; background: rgb(220 228 223 / 13%); overflow: hidden; }
.meter span { display: block; height: 100%; background: var(--brass); transition: width 240ms ease; }
.artifact { margin: 24px 0; padding: 14px; border: 1px solid rgb(220 228 223 / 22%); }
.artifact-label { display: block; font-family: var(--mono); font-size: 10px; color: #93a29b; }
.download {
  display: block; margin-top: 8px; color: #f4c7a8;
  font-size: 14px; font-weight: 600; text-decoration: none;
}
.download:hover { color: #fff1e4; }
.artifact-note { margin: 8px 0 0; color: #8b9a93; font-size: 10px; line-height: 1.45; }
.ledger-wrap { margin-top: 28px; }
.ledger { list-style: none; margin: 0; padding: 0; }
.ledger li {
  display: grid;
  grid-template-columns: 34px 62px minmax(0, 1fr);
  gap: 8px;
  padding: 8px 0;
  border-top: 1px solid rgb(220 228 223 / 10%);
  font-size: 10px;
  line-height: 1.45;
}
.ledger-seq { font-family: var(--mono); color: #718079; }
.ledger-stage { color: #d2b184; font-family: var(--mono); }
.ledger-msg { color: #aab8b1; overflow-wrap: anywhere; }
.rail-empty { margin: 0; color: #718079; font-size: 11px; line-height: 1.6; }

.stage { padding: 36px 42px 80px; min-width: 0; }
.hero { max-width: 720px; margin-bottom: 32px; }
.hero h2 {
  margin: 0 0 9px;
  font-size: clamp(24px, 2.4vw, 32px);
  line-height: 1.08;
  letter-spacing: -0.032em;
  font-weight: 600;
}
.hero p { margin: 0; max-width: 62ch; color: var(--ink-soft); font-size: 14px; line-height: 1.7; }
.block {
  padding: 26px 0 34px;
  border-top: 2px solid var(--ink);
}
.block-head { display: flex; align-items: flex-end; justify-content: space-between; gap: 30px; margin-bottom: 22px; }
.block-head h3 { margin: 0; font-size: 20px; letter-spacing: -0.03em; font-weight: 600; }
.block-head p { max-width: 58ch; margin: 0; color: var(--ink-soft); font-size: 12px; line-height: 1.65; }
.dropgrid { display: grid; grid-template-columns: 1.15fr 1fr 1fr; gap: 12px; margin-bottom: 18px; }
.drop {
  position: relative;
  min-height: 118px;
  display: flex;
  flex-direction: column;
  gap: 7px;
  padding: 15px 16px;
  background: rgb(246 247 242 / 55%);
  border: 1px dashed var(--rule-dark);
  cursor: pointer;
  transition: border-color 120ms ease, background 120ms ease;
}
.drop:hover, .drop:focus-within { border-color: var(--ink); background: var(--surface-raised); }
.drop.active { border-color: var(--oxide); background: rgb(176 71 47 / 6%); }
.drop.filled { border-style: solid; border-color: var(--patina); }
.drop.disabled { opacity: 0.48; cursor: not-allowed; }
.drop input { position: absolute; inset: 0; width: 100%; height: 100%; opacity: 0; cursor: pointer; }
.drop.disabled input { cursor: not-allowed; }
.drop-kicker { font-family: var(--mono); font-size: 10px; color: var(--ink-soft); }
.drop-title { font-size: 13px; line-height: 1.35; overflow-wrap: anywhere; }
.drop-note { margin-top: auto; font-family: var(--mono); font-size: 10px; color: var(--ink-soft); }

.field-grid { display: grid; grid-template-columns: repeat(3, minmax(0, 1fr)); gap: 16px 18px; }
.field { display: flex; flex-direction: column; gap: 7px; min-width: 0; }
.field.wide { grid-column: span 2; }
.field > span { color: var(--ink-soft); font-size: 11px; }
.field small { color: var(--ink-soft); font-size: 10px; line-height: 1.45; }
.field input, .field select, .event-tools select {
  width: 100%;
  height: 40px;
  padding: 0 11px;
  color: var(--ink);
  background: var(--surface-raised);
  border: 1px solid var(--rule);
  border-radius: 2px;
  outline: none;
}
.field select, .event-tools select {
  appearance: none;
  padding-right: 30px;
  background-image: linear-gradient(45deg, transparent 50%, var(--ink-soft) 50%), linear-gradient(135deg, var(--ink-soft) 50%, transparent 50%);
  background-position: calc(100% - 15px) 17px, calc(100% - 10px) 17px;
  background-size: 5px 5px, 5px 5px;
  background-repeat: no-repeat;
}
.field input:focus, .field select:focus, .event-tools select:focus {
  border-color: var(--oxide);
  box-shadow: 0 0 0 2px rgb(176 71 47 / 14%);
}
.number-wrap { display: flex; align-items: center; gap: 8px; }
.number-wrap input { flex: 1; }
.number-wrap span { color: var(--ink-soft); font-family: var(--mono); font-size: 11px; }

.matrix { display: grid; grid-template-columns: repeat(3, minmax(0, 1fr)); gap: 10px; margin-bottom: 20px; }
.toggle {
  position: relative;
  display: grid;
  grid-template-columns: 18px minmax(0, 1fr);
  gap: 11px;
  min-height: 66px;
  padding: 12px;
  border: 1px solid var(--rule);
  background: rgb(246 247 242 / 42%);
  cursor: pointer;
}
.toggle:hover { border-color: var(--rule-dark); background: var(--surface-raised); }
.toggle input { position: absolute; opacity: 0; pointer-events: none; }
.toggle-box {
  width: 18px; height: 18px; margin-top: 2px;
  border: 1px solid var(--rule-dark); background: transparent;
  position: relative;
}
.toggle input:checked + .toggle-box { background: var(--patina); border-color: var(--patina); }
.toggle input:checked + .toggle-box::after {
  content: "";
  position: absolute; left: 5px; top: 1px;
  width: 4px; height: 9px;
  border: solid #f2f5ef; border-width: 0 2px 2px 0;
  transform: rotate(42deg);
}
.toggle input:focus-visible + .toggle-box { outline: 2px solid var(--oxide); outline-offset: 3px; }
.toggle-copy { display: flex; flex-direction: column; gap: 4px; }
.toggle-copy strong { font-size: 12px; font-weight: 600; }
.toggle-copy small { color: var(--ink-soft); font-size: 10px; line-height: 1.45; }

.actions { display: flex; align-items: center; gap: 14px; flex-wrap: wrap; padding-top: 26px; border-top: 2px solid var(--ink); }
.primary, .secondary, .quiet {
  border-radius: 2px; cursor: pointer; text-decoration: none; text-align: center;
}
.primary {
  min-width: 150px; height: 44px; padding: 0 22px;
  color: #fff4ea; background: var(--oxide); border: 1px solid var(--oxide-dark);
  box-shadow: 3px 3px 0 var(--ink);
  font-weight: 600; font-size: 13px;
  transition: transform 100ms ease, box-shadow 100ms ease;
}
.primary:hover:not(:disabled) { transform: translate(-1px, -1px); box-shadow: 4px 4px 0 var(--ink); }
.primary:active:not(:disabled) { transform: translate(2px, 2px); box-shadow: 1px 1px 0 var(--ink); }
.primary:disabled { opacity: 0.55; cursor: wait; }
.secondary {
  display: inline-flex; align-items: center; justify-content: center;
  height: 42px; padding: 0 16px;
  color: var(--ink); background: transparent; border: 1px solid var(--ink);
  font-size: 12px;
}
.secondary:hover { background: var(--ink); color: var(--surface); }
.action-note { color: var(--ink-soft); font-size: 11px; }
.error {
  margin: 14px 0 0; padding: 11px 13px;
  border-left: 3px solid var(--oxide);
  background: rgb(176 71 47 / 8%);
  color: var(--oxide-dark); font-size: 12px;
}
.events-block { margin-top: 14px; }
.events-head { align-items: center; }
.event-tools { display: flex; gap: 8px; }
.event-tools select { width: 150px; height: 34px; font-size: 11px; }
.quiet { height: 34px; padding: 0 12px; background: transparent; border: 1px solid var(--rule); font-size: 11px; }
.quiet:hover { border-color: var(--ink); }
.table-wrap { max-height: 390px; overflow: auto; border-top: 1px solid var(--rule); }
table { width: 100%; border-collapse: collapse; font-size: 11px; }
th {
  position: sticky; top: 0; z-index: 1;
  padding: 9px 8px; text-align: left; font-weight: 500;
  color: var(--ink-soft); background: var(--surface);
  border-bottom: 1px solid var(--rule);
}
td { padding: 9px 8px; border-bottom: 1px solid rgb(169 179 172 / 45%); vertical-align: top; }
td.num, th.num { text-align: right; }
td.mono { font-family: var(--mono); font-size: 10px; color: var(--ink-soft); }
.tag { display: inline-block; padding: 2px 6px; border: 1px solid var(--rule); font-family: var(--mono); font-size: 9px; }
.empty { padding: 30px 8px; text-align: center; color: var(--ink-soft); }
.download-inline { border-color: var(--patina); color: var(--patina); }

@media (max-width: 1080px) {
  .workspace { grid-template-columns: 1fr; background: none; }
  .rail {
    position: relative; top: 0; height: auto; overflow: visible;
    background: var(--rail);
    display: grid; grid-template-columns: 1fr 1fr; gap: 0 28px;
    border-right: 0; border-bottom: 1px solid var(--ink);
  }
  .rail > .rail-label:first-child, .rail-title, .rail-id { grid-column: 1 / -1; }
  .summary { margin-top: 8px; }
  .rail-status, .artifact, .ledger-wrap { grid-column: 1 / -1; }
  .stage { padding: 32px 28px 64px; }
}
@media (max-width: 760px) {
  .topbar { padding: 0 18px; }
  .brand-sub { display: none; }
  .topbar-meta { font-size: 10px; }
  .rail { display: block; padding: 24px 20px; }
  .stage { padding: 26px 18px 60px; }
  .hero h2 { font-size: 27px; }
  .dropgrid, .field-grid, .matrix { grid-template-columns: 1fr; }
  .field.wide { grid-column: auto; }
  .block-head { display: block; }
  .block-head p { margin-top: 8px; }
  .events-head { display: flex; align-items: flex-start; }
  .event-tools { flex-direction: column; }
  .actions { align-items: stretch; }
  .primary, .secondary { width: 100%; }
  .table-wrap { margin-right: -18px; margin-left: -18px; }
}
@media (prefers-reduced-motion: reduce) {
  *, *::before, *::after { transition: none !important; animation: none !important; }
}
</style>
