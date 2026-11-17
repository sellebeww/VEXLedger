<script setup lang="ts">
// Copyright (c) 2026 Vassel Goleyu. MIT License.
import { id } from '~/i18n/id'
import { ApiError } from '~/lib/errors'
import type { Diff } from '~/lib/types'

const route = useRoute()
const router = useRouter()
const slug = String(route.params.slug)
const api = useApi()

const releases = useLoad(() => api.releases(slug))
const from = ref(typeof route.query.from === 'string' ? route.query.from : '')
const to = ref(typeof route.query.to === 'string' ? route.query.to : '')
const result = ref<Diff | null>(null)
const error = ref<ApiError | null>(null)
const busy = ref(false)
const sameChoice = computed(() => !from.value || !to.value || from.value === to.value)

async function run(): Promise<void> {
  if (sameChoice.value) return
  busy.value = true
  error.value = null
  try {
    await router.replace({ query: { from: from.value, to: to.value } })
    result.value = await api.diff(slug, from.value, to.value)
  } catch (e) {
    result.value = null
    error.value = e instanceof ApiError ? e : null
  } finally {
    busy.value = false
  }
}
// Releases come newest first: default to "previous vs newest" once they load.
watch(
  () => releases.data.value,
  (list) => {
    if (!list || list.length < 2) return
    if (!from.value) from.value = list[1]!.version
    if (!to.value) to.value = list[0]!.version
    if (route.query.from && route.query.to) void run()
  },
  { immediate: true },
)
const d = computed(() => result.value?.diff ?? null)
const empty = computed(
  () =>
    !!d.value &&
    !d.value.components_added.length &&
    !d.value.components_removed.length &&
    !d.value.version_changed.length &&
    !d.value.hash_changed.length &&
    !d.value.findings_new.length &&
    !d.value.findings_resolved.length &&
    !d.value.findings_persisting.length,
)
</script>

<template>
  <div>
    <AppBreadcrumbs
      :items="[
        { label: id.products.title, to: '/products' },
        { label: slug, to: `/products/${slug}` },
        { label: id.diff.title },
      ]"
    />
    <h1>{{ id.diff.title }}</h1>
    <AsyncBlock
      :loading="releases.loading.value"
      :error="releases.error.value"
      :empty="(releases.data.value?.length ?? 0) < 2 && !releases.loading.value"
      :empty-text="id.diff.needTwo"
      @retry="releases.reload"
    >
      <form class="card row" @submit.prevent="run">
        <FormField v-slot="f" :label="id.diff.from">
          <select :id="f.id" v-model="from">
            <option v-for="r in releases.data.value" :key="r.id" :value="r.version">
              {{ r.version }}
            </option>
          </select>
        </FormField>
        <FormField v-slot="f" :label="id.diff.to">
          <select :id="f.id" v-model="to">
            <option v-for="r in releases.data.value" :key="r.id" :value="r.version">
              {{ r.version }}
            </option>
          </select>
        </FormField>
        <button type="submit" class="primary" :disabled="sameChoice || busy">
          {{ id.diff.run }}
        </button>
        <span v-if="from && from === to" class="error" role="alert">{{ id.diff.pickTwo }}</span>
      </form>
      <AsyncBlock :loading="busy" :error="error" @retry="run">
        <template v-if="d">
          <p v-if="empty" class="notice info">{{ id.diff.nothing }}</p>
          <section class="card">
            <h2 style="margin-top: 0">{{ id.diff.statements }}</h2>
            <p>
              <span class="badge info"
                >{{ id.diff.inherited }}{{ id.common.separator }} {{ d.statements.inherited }}</span
              >
              <span class="badge warn"
                >{{ id.diff.needsReview }}{{ id.common.separator }}
                {{ d.statements.needs_review }}</span
              >
            </p>
          </section>
          <section class="card">
            <h2 style="margin-top: 0">{{ id.diff.components }}</h2>
            <h3>{{ id.diff.added }} ({{ d.components_added.length }})</h3>
            <ul>
              <li v-for="c in d.components_added" :key="c" class="mono">{{ c }}</li>
            </ul>
            <h3>{{ id.diff.removed }} ({{ d.components_removed.length }})</h3>
            <ul>
              <li v-for="c in d.components_removed" :key="c" class="mono">{{ c }}</li>
            </ul>
            <h3>{{ id.diff.versionChanged }} ({{ d.version_changed.length }})</h3>
            <ul>
              <li v-for="c in d.version_changed" :key="c.component_key" class="mono">
                {{ c.component_key }}{{ id.common.separator }} {{ c.from_versions.join(', ') }}
                {{ id.diff.arrow }} {{ c.to_versions.join(', ') }}
              </li>
            </ul>
            <h3>{{ id.diff.hashChanged }} ({{ d.hash_changed.length }})</h3>
            <ul>
              <li v-for="c in d.hash_changed" :key="c.component_key" class="mono">
                {{ c.component_key }} {{ c.versions.join(', ') }}
              </li>
            </ul>
          </section>
          <section class="card">
            <h2 style="margin-top: 0">{{ id.diff.findings }}</h2>
            <h3>{{ id.diff.newFindings }} ({{ d.findings_new.length }})</h3>
            <ul>
              <li v-for="x in d.findings_new" :key="x.canonical_vuln_id + x.component_key">
                <span class="mono">{{ x.canonical_vuln_id }} {{ x.component_key }}</span>
                <StateBadge :state="x.state" />
              </li>
            </ul>
            <h3>{{ id.diff.resolved }} ({{ d.findings_resolved.length }})</h3>
            <ul>
              <li v-for="x in d.findings_resolved" :key="x.canonical_vuln_id + x.component_key">
                <span class="mono">{{ x.canonical_vuln_id }} {{ x.component_key }}</span>
                <StateBadge :state="x.state" />
              </li>
            </ul>
            <h3>{{ id.diff.persisting }} ({{ d.findings_persisting.length }})</h3>
            <ul>
              <li v-for="x in d.findings_persisting" :key="x.canonical_vuln_id + x.component_key">
                <span class="mono">{{ x.canonical_vuln_id }} {{ x.component_key }}</span>
                <StateBadge :state="x.state_a" /> {{ id.diff.arrow }}
                <StateBadge :state="x.state_b" />
              </li>
            </ul>
          </section>
        </template>
      </AsyncBlock>
    </AsyncBlock>
  </div>
</template>
