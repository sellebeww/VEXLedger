<script setup lang="ts">
// Copyright (c) 2026 Vassel Goleyu. MIT License.
import { id } from '~/i18n/id'
import { ApiError } from '~/lib/errors'
import { formatDateTime, shortHash } from '~/lib/format'
import { useSessionStore } from '~/stores/session'

const route = useRoute()
const slug = String(route.params.slug)
const version = String(route.params.version)
const api = useApi()
const session = useSessionStore()
const notify = useNotify()

const gate = useLoad(() => api.gate(slug, version))
const history = useLoad(() => api.exports(slug, version))
const busy = ref(false)
const confirmOpen = ref(false)
const agreed = ref(false)
const error = ref<ApiError | null>(null)

function save(text: string, name: string): void {
  const url = URL.createObjectURL(new Blob([text], { type: 'application/json' }))
  const a = document.createElement('a')
  a.href = url
  a.download = name
  document.body.append(a)
  a.click()
  a.remove()
  URL.revokeObjectURL(url)
}

async function run(allowIncomplete: boolean): Promise<void> {
  busy.value = true
  error.value = null
  try {
    const out = await api.exportRelease(slug, version, allowIncomplete)
    save(out.text, `vex-${slug}-${version}-v${out.version}.json`)
    notify.success(id.exportPage.exported(out.version, out.isNew))
    confirmOpen.value = false
    agreed.value = false
    await Promise.all([gate.reload(), history.reload()])
  } catch (e) {
    error.value = e instanceof ApiError ? e : null
    notify.failure(e)
    // The gate may have changed since it was read: show the fresh numbers.
    await gate.reload()
  } finally {
    busy.value = false
  }
}
const g = computed(() => gate.data.value)
const canExport = computed(() => session.can('analyst'))
</script>

<template>
  <div>
    <AppBreadcrumbs
      :items="[
        { label: id.products.title, to: '/products' },
        { label: slug, to: `/products/${slug}` },
        { label: version, to: `/products/${slug}/releases/${version}` },
        { label: id.exportPage.title },
      ]"
    />
    <h1>{{ id.exportPage.title }}</h1>
    <div class="notice warn">
      <strong>{{ id.exportPage.unsignedTitle }}</strong>
      <p>{{ id.exportPage.unsigned }}</p>
      <ul>
        <li v-for="line in id.honest" :key="line">{{ line }}</li>
      </ul>
    </div>

    <AsyncBlock :loading="gate.loading.value" :error="gate.error.value" @retry="gate.reload">
      <section v-if="g" class="card">
        <h2 style="margin-top: 0">{{ id.exportPage.gate }}</h2>
        <p>
          <ReleaseStatusBadge :status="g.match_status" />
        </p>
        <p v-if="g.match_status !== 'MATCHED'" class="notice bad" role="alert">
          {{ id.exportPage.notMatched }}
        </p>
        <p v-else-if="g.complete" class="notice ok">{{ id.exportPage.complete }}</p>
        <p v-else class="notice warn">{{ id.exportPage.incomplete }}</p>
        <dl class="kv">
          <dt>{{ id.exportPage.totalFindings }}</dt>
          <dd>{{ g.total }}</dd>
          <dt>{{ id.exportPage.open }}</dt>
          <dd>{{ g.open_count }}</dd>
          <dt>{{ id.exportPage.investigatingCount }}</dt>
          <dd>{{ g.investigating_count }}</dd>
        </dl>
        <template v-if="g.open.length">
          <h3>{{ id.exportPage.openList }}</h3>
          <ul>
            <li v-for="(o, i) in g.open" :key="i" class="mono">
              {{ o.vulnerability_id }} {{ o.component_ref }}
            </li>
          </ul>
        </template>
        <p class="muted">{{ id.exportPage.onlyLive }}</p>
        <div v-if="canExport && g.match_status === 'MATCHED'" class="row">
          <button
            v-if="g.complete"
            type="button"
            class="primary"
            :disabled="busy"
            @click="run(false)"
          >
            {{ id.exportPage.download }}
          </button>
          <button v-else type="button" :disabled="busy" @click="confirmOpen = true">
            {{ id.exportPage.downloadAnyway }}
          </button>
        </div>
        <p v-if="error" class="notice bad" role="alert">
          {{ id.errors[error.code] ?? id.errors.unknown }}
        </p>
      </section>
    </AsyncBlock>

    <section class="card">
      <h2 style="margin-top: 0">{{ id.exportPage.history }}</h2>
      <AsyncBlock
        :loading="history.loading.value"
        :error="history.error.value"
        :empty="history.data.value?.length === 0"
        :empty-text="id.exportPage.historyEmpty"
        @retry="history.reload"
      >
        <DataTable
          v-if="history.data.value"
          :caption="id.exportPage.history"
          :columns="[
            { id: 'version', header: id.exportPage.colVersion },
            { id: 'content_sha256', header: id.exportPage.colHash },
            { id: 'created_at', header: id.exportPage.colCreated },
          ]"
          :rows="history.data.value.map((h) => ({ ...h, id: String(h.version) }))"
        >
          <template #cell-content_sha256="{ row }"
            ><span class="mono" :title="row.content_sha256">{{
              shortHash(row.content_sha256)
            }}</span></template
          >
          <template #cell-created_at="{ row }">{{ formatDateTime(row.created_at) }}</template>
        </DataTable>
      </AsyncBlock>
    </section>

    <AppModal :open="confirmOpen" :title="id.exportPage.confirmTitle" @close="confirmOpen = false">
      <p class="notice warn">
        {{ id.exportPage.confirmBody(g?.open_count ?? 0, g?.investigating_count ?? 0) }}
      </p>
      <label>
        <input v-model="agreed" type="checkbox" />
        {{ id.exportPage.confirmCheckbox }}
      </label>
      <div class="row end">
        <button type="button" @click="confirmOpen = false">{{ id.common.cancel }}</button>
        <button type="button" class="primary" :disabled="!agreed || busy" @click="run(true)">
          {{ id.exportPage.confirmGo }}
        </button>
      </div>
    </AppModal>
  </div>
</template>
