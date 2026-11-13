<script setup lang="ts">
import { computed, ref } from 'vue'

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

const file = ref<File | null>(null)
const profile = ref('basic')
const signingMode = ref('customer_local')
const taskId = ref('')
const status = ref('')
const events = ref<TaskEvent[]>([])
const progress = ref(0)
const error = ref('')
const busy = ref(false)

const artifactUrl = computed(() =>
  taskId.value && status.value === 'succeeded'
    ? `/api/v1/tasks/${taskId.value}/artifact`
    : '',
)

function onFileChange(event: Event) {
  const input = event.target as HTMLInputElement
  file.value = input.files?.[0] ?? null
}

async function upload() {
  error.value = ''
  events.value = []
  status.value = ''
  progress.value = 0
  if (!file.value) {
    error.value = '请选择 APK 文件'
    return
  }
  busy.value = true
  const form = new FormData()
  form.append('file', file.value)
  form.append('profile', profile.value)
  form.append('signing_mode', signingMode.value)
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
      <p class="subtitle">APK 加固流水线 · 上传 → 任务 → 产物</p>
    </header>

    <section class="card">
      <div class="row">
        <label class="label">APK</label>
        <input type="file" accept=".apk" @change="onFileChange" />
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
      </div>
      <div class="row">
        <el-button type="primary" :loading="busy" @click="upload">开始加固</el-button>
        <el-button v-if="busy" @click="cancel">取消</el-button>
        <el-button v-if="artifactUrl" tag="a" :href="artifactUrl" type="success">
          下载产物
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
  max-width: 860px;
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
  .msg {
    color: #8b949e;
  }
}
</style>
