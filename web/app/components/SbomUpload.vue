<script setup lang="ts">
// Copyright (c) 2026 Vassel Goleyu. MIT License.
// SBOM upload: drag and drop, progress, import warnings and match status (with polling and retry).
import { id } from '~/i18n/id'
import { ApiError, messageFor } from '~/lib/errors'
import type { MatchStatusInfo, Sbom, Upload } from '~/lib/types'

const props = defineProps<{ slug: string; version: string; status: MatchStatusInfo['status'] }>()
const emit = defineEmits<{ changed: [] }>()
const api = useApi()
const notify = useNotify()

const over = ref(false)
const busy = ref(false)
const progress = ref(0)
const error = ref<ApiError | null>(null)
const result = ref<Upload | null>(null)
const match = ref<MatchStatusInfo | null>(null)
const input = ref<HTMLInputElement | null>(null)
const inputId = useId()
let timer: ReturnType<typeof setInterval> | null = null

const current = computed(() => match.value?.status ?? result.value?.match_status ?? props.status)
const sbom = computed<Sbom | null>(() => result.value?.sbom ?? null)

function stopPolling(): void {
  if (timer) clearInterval(timer)
  timer = null
}
async function poll(): Promise<void> {
  try {
    match.value = await api.matchStatus(props.slug, props.version)
    if (match.value.status !== 'MATCH_PENDING') {
      stopPolling()
      emit('changed')
    }
  } catch (e) {
    stopPolling()
    error.value = e instanceof ApiError ? e : null
  }
}
function startPolling(): void {
  stopPolling()
  void poll()
  timer = setInterval(() => void poll(), 3000)
}
watch(
  current,
  (s) => {
    if (s === 'MATCH_PENDING' && !timer) startPolling()
  },
  { immediate: true },
)
onBeforeUnmount(stopPolling)

async function send(file: File | undefined): Promise<void> {
  if (!file) return
  error.value = null
  if (!file.name.toLowerCase().endsWith('.json')) {
    error.value = new ApiError({ status: 0, code: 'sbom_not_json' })
    return
  }
  busy.value = true
  progress.value = 0
  try {
    result.value = await api.uploadSbom(
      props.slug,
      props.version,
      file,
      (f) => (progress.value = f),
    )
    match.value = null
    notify.success(result.value.created ? id.product.uploaded : id.product.alreadyImported)
    emit('changed')
    if (result.value.match_status === 'MATCH_PENDING') startPolling()
  } catch (e) {
    error.value = e instanceof ApiError ? e : new ApiError({ status: 0, code: 'unknown' })
  } finally {
    busy.value = false
  }
}
function onDrop(ev: DragEvent): void {
  over.value = false
  void send(ev.dataTransfer?.files?.[0])
}
function onPick(ev: Event): void {
  const el = ev.target as HTMLInputElement
  void send(el.files?.[0])
  el.value = ''
}
</script>

<template>
  <div class="stack">
    <div
      class="dropzone"
      :class="{ over }"
      @dragover.prevent="over = true"
      @dragleave="over = false"
      @drop.prevent="onDrop"
    >
      <p>{{ id.product.dropHint }}</p>
      <input
        :id="inputId"
        ref="input"
        type="file"
        accept=".json,application/json"
        :disabled="busy"
        @change="onPick"
      />
      <label :for="inputId" class="sr-only">{{ id.product.choose }}</label>
    </div>
    <div v-if="busy" role="status">
      <progress
        max="1"
        :value="progress"
        :aria-label="id.product.uploadProgress(Math.round(progress * 100))"
      ></progress>
      <span>{{ id.product.uploadProgress(Math.round(progress * 100)) }}</span>
    </div>
    <p v-if="error" class="notice bad" role="alert">{{ messageFor(error) }}</p>

    <div
      v-if="current !== 'MATCHED' || result"
      class="notice"
      :class="current === 'MATCH_FAILED' ? 'bad' : current === 'MATCH_PENDING' ? 'warn' : 'ok'"
    >
      <p><ReleaseStatusBadge :status="current" /></p>
      <p>{{ id.releaseStatusHelp[current] }}</p>
      <p v-if="current === 'MATCH_PENDING'" class="muted">{{ id.product.pollingNote }}</p>
      <template v-if="current === 'MATCH_FAILED'">
        <p v-if="match?.error">
          {{ id.product.matchError }}{{ id.common.separator }}
          <span class="mono">{{ match.error }}</span>
        </p>
        <p>{{ id.product.retryHint }}</p>
        <button type="button" @click="input?.click()">{{ id.product.retryMatch }}</button>
      </template>
      <p v-if="result">{{ result.queued ? id.product.queuedYes : id.product.queuedNo }}</p>
      <ul v-if="match?.notes.length" :aria-label="id.product.matchNotes">
        <li v-for="n in match.notes" :key="n" class="plain-text">{{ n }}</li>
      </ul>
    </div>

    <section v-if="sbom" class="card">
      <h3>{{ id.product.sbomInfo }}</h3>
      <dl class="kv">
        <dt>{{ id.product.specVersion }}</dt>
        <dd>{{ sbom.spec_version }}</dd>
        <dt>{{ id.product.components }}</dt>
        <dd>{{ sbom.component_count }}</dd>
        <dt>{{ id.product.edges }}</dt>
        <dd>{{ sbom.edge_count }}</dd>
        <dt>{{ id.product.noPurl }}</dt>
        <dd>{{ sbom.no_purl_count }}</dd>
        <dt>{{ id.product.unsupported }}</dt>
        <dd>{{ sbom.unsupported_ecosystem_count }}</dd>
      </dl>
      <template v-if="sbom.warnings.length">
        <h3>{{ id.product.importWarnings }}</h3>
        <ul>
          <li v-for="(w, i) in sbom.warnings.slice(0, 100)" :key="i" class="plain-text">
            <span class="mono">{{ w.code }}</span>{{ id.common.separator }} {{ w.message }}
          </li>
        </ul>
      </template>
    </section>
  </div>
</template>
