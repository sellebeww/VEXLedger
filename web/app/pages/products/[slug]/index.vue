<script setup lang="ts">
// Copyright (c) 2026 Vassel Goleyu. MIT License.
import { id } from '~/i18n/id'
import { messageFor } from '~/lib/errors'
import type { ReleaseDetail } from '~/lib/types'
import { useSessionStore } from '~/stores/session'

const route = useRoute()
const slug = String(route.params.slug)
const api = useApi()
const session = useSessionStore()
const notify = useNotify()

const product = useLoad(() => api.product(slug))
const releases = useLoad(async (): Promise<ReleaseDetail[]> => {
  const list = await api.releases(slug)
  return Promise.all(list.map((r) => api.release(slug, r.version)))
})

const version = ref('')
const versionError = ref<string | null>(null)
const busy = ref(false)
const uploadFor = ref<string | null>(null)
const VERSION = /^[A-Za-z0-9][A-Za-z0-9._+-]{0,63}$/

async function createRelease(): Promise<void> {
  versionError.value = VERSION.test(version.value) ? null : id.fieldErrors.version
  if (versionError.value) return
  busy.value = true
  try {
    const created = await api.createRelease(slug, version.value)
    version.value = ''
    await releases.reload()
    uploadFor.value = created.version
  } catch (e) {
    versionError.value = messageFor(e)
  } finally {
    busy.value = false
  }
}
async function onChanged(): Promise<void> {
  try {
    await releases.reload()
  } catch (e) {
    notify.failure(e)
  }
}
const uploadStatus = computed(
  () => releases.data.value?.find((r) => r.version === uploadFor.value)?.status ?? 'MATCH_PENDING',
)
</script>

<template>
  <div>
    <AppBreadcrumbs
      :items="[
        { label: id.products.title, to: '/products' },
        { label: product.data.value?.name ?? slug },
      ]"
    />
    <div class="row">
      <h1 class="grow">{{ product.data.value?.name ?? slug }}</h1>
      <NuxtLink class="btn" :to="`/products/${slug}/diff`">{{ id.product.compare }}</NuxtLink>
      <NuxtLink class="btn" :to="`/products/${slug}/settings`">{{ id.products.settings }}</NuxtLink>
    </div>
    <p v-if="product.data.value" class="muted mono">{{ product.data.value.purl }}</p>

    <section v-if="session.can('analyst')" class="card">
      <h2>{{ id.product.newRelease }}</h2>
      <form class="row" @submit.prevent="createRelease">
        <FormField v-slot="f" :label="id.product.versionLabel" :error="versionError">
          <input
            :id="f.id"
            v-model="version"
            :aria-describedby="f.describedBy"
            :aria-invalid="f.invalid"
            autocomplete="off"
          />
        </FormField>
        <button type="submit" class="primary" :disabled="busy">
          {{ id.product.createRelease }}
        </button>
      </form>
    </section>

    <h2>{{ id.product.releaseList }}</h2>
    <AsyncBlock
      :loading="releases.loading.value"
      :error="releases.error.value"
      :empty="releases.data.value?.length === 0"
      :empty-text="id.product.noReleases"
      :empty-hint="id.product.noReleasesHint"
      @retry="releases.reload"
    >
      <DataTable
        v-if="releases.data.value"
        :caption="id.product.releaseList"
        :columns="[
          { id: 'version', header: id.common.version },
          { id: 'status', header: id.triage.status },
          { id: 'finding_total', header: id.product.findingsTotal },
          { id: 'open_count', header: id.product.open },
          { id: 'actions', header: id.common.actions },
        ]"
        :rows="releases.data.value"
      >
        <template #cell-version="{ row }">
          <NuxtLink :to="`/products/${slug}/releases/${row.version}`">{{ row.version }}</NuxtLink>
        </template>
        <template #cell-status="{ row }">
          <ReleaseStatusBadge :status="row.status" />
          <div v-if="!row.has_sbom" class="muted">{{ id.product.sbomMissing }}</div>
        </template>
        <template #cell-finding_total="{ row }">
          <ul v-if="row.finding_total" style="margin: 0; padding-left: 1rem">
            <li v-for="(n, s) in row.findings_by_state" v-show="n" :key="s">
              {{ id.state[s as keyof typeof id.state] }}{{ id.common.separator }} {{ n }}
            </li>
          </ul>
          <span v-else>{{ row.finding_total }}</span>
        </template>
        <template #cell-actions="{ row }">
          <button v-if="session.can('analyst')" type="button" @click="uploadFor = row.version">
            {{ id.product.uploadFor(row.version) }}
          </button>
        </template>
      </DataTable>
    </AsyncBlock>

    <AppModal
      :open="uploadFor !== null"
      :title="id.product.uploadFor(uploadFor ?? '')"
      @close="uploadFor = null"
    >
      <SbomUpload
        v-if="uploadFor"
        :slug="slug"
        :version="uploadFor"
        :status="uploadStatus"
        @changed="onChanged"
      />
    </AppModal>
  </div>
</template>
