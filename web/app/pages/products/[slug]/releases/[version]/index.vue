<script setup lang="ts">
// Copyright (c) 2026 Vassel Goleyu. MIT License.
import { id } from '~/i18n/id'
import { failedFindingId, fieldErrorsOf, messageFor } from '~/lib/errors'
import { DEFAULT_QUERY, type FindingQuery, parseFindingQuery, toRouteQuery } from '~/lib/query'
import type { Draft, FindingItem, FindingState } from '~/lib/types'
import { FINDING_STATES } from '~/lib/types'
import { useSessionStore } from '~/stores/session'

const route = useRoute()
const router = useRouter()
const slug = String(route.params.slug)
const version = String(route.params.version)
const api = useApi()
const session = useSessionStore()
const notify = useNotify()
const assignees = useAssignees()

const query = computed(() => parseFindingQuery(route.query as Record<string, string | string[]>))
const release = useLoad(() => api.release(slug, version))
const product = useLoad(() => api.product(slug))
const findings = useLoad(() => api.findings(slug, version, query.value))
watch(query, () => void findings.reload())

function update(patch: Partial<FindingQuery>, resetPage = true): void {
  const next = { ...query.value, ...patch, page: resetPage ? 1 : (patch.page ?? query.value.page) }
  selection.value = {}
  void router.push({ query: toRouteQuery(next) })
}
function sortBy(key: string): void {
  const k = key as FindingQuery['sort']
  update({ sort: k, order: query.value.sort === k && query.value.order === 'asc' ? 'desc' : 'asc' })
}
function toggleState(s: FindingState, on: boolean): void {
  const set = new Set(query.value.states)
  if (on) set.add(s)
  else set.delete(s)
  update({ states: [...set] })
}
const filtered = computed(
  () =>
    JSON.stringify(query.value) !==
      JSON.stringify({
        ...DEFAULT_QUERY,
        page: query.value.page,
        pageSize: query.value.pageSize,
      }) &&
    JSON.stringify({ ...query.value, page: 1, pageSize: 50 }) !== JSON.stringify(DEFAULT_QUERY),
)

const SEVERITIES = ['CRITICAL', 'HIGH', 'MODERATE', 'MEDIUM', 'LOW'] as const
const ECOSYSTEMS = ['PyPI', 'npm', 'Maven', 'Go']

// bulk triage
const selection = ref<Record<string, boolean>>({})
const selectedIds = computed(() => Object.keys(selection.value).filter((k) => selection.value[k]))
const bulkOpen = ref(false)
const bulkBusy = ref(false)
const bulkErrors = ref<Record<string, string>>({})
const bulkMessage = ref<string | null>(null)

async function bulk(draft: Draft): Promise<void> {
  bulkBusy.value = true
  bulkErrors.value = {}
  bulkMessage.value = null
  try {
    const out = await api.bulkTriage(selectedIds.value, draft)
    notify.success(id.bulk.done(out.created))
    bulkOpen.value = false
    selection.value = {}
    await Promise.all([findings.reload(), release.reload()])
  } catch (e) {
    bulkErrors.value = fieldErrorsOf(e)
    const failed = failedFindingId(e)
    const row = findings.data.value?.items.find((i) => i.id === failed)
    bulkMessage.value = failed
      ? `${messageFor(e)} ${id.bulk.failedFinding}${id.common.separator} ${row ? `${row.vulnerability_id} ${row.component_ref}` : failed}`
      : messageFor(e)
  } finally {
    bulkBusy.value = false
  }
}

const rel = computed(() => release.data.value)
// While matching runs the list is incomplete: keep checking so it fills in by itself.
const poll = setInterval(() => {
  if (rel.value?.status === 'MATCH_PENDING') void Promise.all([release.reload(), findings.reload()])
}, 5000)
onBeforeUnmount(() => clearInterval(poll))
const unmatchable = computed(() =>
  (rel.value?.sbom?.warnings ?? []).filter((w) =>
    ['no_purl', 'invalid_purl', 'unsupported_ecosystem'].includes(w.code),
  ),
)
const unmatchableTotal = computed(
  () => (rel.value?.sbom?.no_purl_count ?? 0) + (rel.value?.sbom?.unsupported_ecosystem_count ?? 0),
)
const rowLabel = (r: FindingItem): string => `${r.vulnerability_id} ${r.component_ref}`
const emptyText = computed(() => {
  const s = findings.data.value?.match_status
  if (s === 'MATCH_PENDING') return id.release.pendingNoFindings
  if (s === 'MATCH_FAILED') return id.release.failedNoFindings
  return filtered.value ? id.release.noFindings : id.release.noFindingsMatched
})
</script>

<template>
  <div>
    <AppBreadcrumbs
      :items="[
        { label: id.products.title, to: '/products' },
        { label: product.data.value?.name ?? slug, to: `/products/${slug}` },
        { label: version },
      ]"
    />
    <div class="row">
      <h1 class="grow">{{ slug }} {{ version }}</h1>
      <NuxtLink class="btn" :to="`/products/${slug}/releases/${version}/export`">{{
        id.release.exportLink
      }}</NuxtLink>
    </div>

    <AsyncBlock
      :loading="release.loading.value"
      :error="release.error.value"
      @retry="release.reload"
    >
      <section v-if="rel" class="card">
        <div class="row">
          <ReleaseStatusBadge :status="rel.status" />
          <span
            >{{ id.release.openCount }}{{ id.common.separator }}
            <strong>{{ rel.open_count }}</strong></span
          >
          <span
            >{{ id.investigating }}{{ id.common.separator }}
            <strong>{{ rel.investigating_count }}</strong></span
          >
          <span
            >{{ id.product.findingsTotal }}{{ id.common.separator }}
            <strong>{{ rel.finding_total }}</strong></span
          >
        </div>
        <ul class="row" style="list-style: none; padding: 0">
          <li v-for="s in FINDING_STATES" :key="s">
            <StateBadge :state="s" /> {{ rel.findings_by_state[s] ?? 0 }}
          </li>
        </ul>
        <p
          v-if="rel.status !== 'MATCHED'"
          class="notice"
          :class="rel.status === 'MATCH_FAILED' ? 'bad' : 'warn'"
          role="status"
        >
          {{ id.releaseStatusHelp[rel.status] }}
          <template v-if="rel.match_error">
            {{ id.product.matchError }}{{ id.common.separator }}
            <span class="mono">{{ rel.match_error }}</span></template
          >
        </p>
        <ul v-if="rel.match_notes.length">
          <li v-for="n in rel.match_notes" :key="n" class="plain-text">{{ n }}</li>
        </ul>
      </section>
    </AsyncBlock>

    <section class="card" :aria-label="id.release.filters">
      <h2 style="margin-top: 0">{{ id.release.filters }}</h2>
      <div class="row" style="align-items: start">
        <fieldset>
          <legend>{{ id.release.filterState }}</legend>
          <label
            v-for="s in FINDING_STATES"
            :key="s"
            style="display: inline-block; margin-right: 0.8rem"
          >
            <input
              type="checkbox"
              :checked="query.states.includes(s)"
              @change="toggleState(s, ($event.target as HTMLInputElement).checked)"
            />
            {{ id.state[s] }}
          </label>
        </fieldset>
        <FormField v-slot="f" :label="id.release.filterSeverity">
          <select
            :id="f.id"
            :value="query.severity"
            @change="update({ severity: ($event.target as HTMLSelectElement).value })"
          >
            <option value="">{{ id.common.all }}</option>
            <option v-for="s in SEVERITIES" :key="s" :value="s">{{ id.severity[s] }}</option>
          </select>
        </FormField>
        <FormField v-slot="f" :label="id.release.filterEcosystem">
          <select
            :id="f.id"
            :value="query.ecosystem"
            @change="update({ ecosystem: ($event.target as HTMLSelectElement).value })"
          >
            <option value="">{{ id.common.all }}</option>
            <option v-for="e in ECOSYSTEMS" :key="e" :value="e">{{ e }}</option>
          </select>
        </FormField>
        <FormField v-slot="f" :label="id.release.filterAssignee">
          <select
            :id="f.id"
            :value="query.assignee"
            @change="update({ assignee: ($event.target as HTMLSelectElement).value })"
          >
            <option value="">{{ id.common.all }}</option>
            <option v-for="o in assignees.options.value" :key="o.id" :value="o.id">
              {{ o.label }}
            </option>
          </select>
        </FormField>
        <button
          v-if="filtered"
          type="button"
          @click="update({ ...DEFAULT_QUERY, pageSize: query.pageSize })"
        >
          {{ id.release.clearFilters }}
        </button>
      </div>
    </section>

    <div v-if="selectedIds.length" class="notice info row" role="status">
      <strong class="grow">{{ id.release.selected(selectedIds.length) }}</strong>
      <button type="button" class="primary" @click="bulkOpen = true">
        {{ id.release.bulkTriage }}
      </button>
      <button type="button" @click="selection = {}">{{ id.release.clearSelection }}</button>
    </div>

    <AsyncBlock
      :loading="findings.loading.value"
      :error="findings.error.value"
      :empty="findings.data.value?.total === 0"
      :empty-text="emptyText"
      @retry="findings.reload"
    >
      <template v-if="findings.data.value">
        <DataTable
          v-model:selection="selection"
          :caption="id.release.findings"
          :selectable="session.can('analyst')"
          :row-label="rowLabel"
          :sort="{ key: query.sort, order: query.order }"
          :columns="[
            { id: 'vulnerability', header: id.release.vulnerability, sortable: true },
            { id: 'component', header: id.release.component, sortable: true },
            { id: 'severity', header: id.release.severityCol, sortable: true },
            { id: 'state', header: id.release.stateCol, sortable: true },
            { id: 'assignee', header: id.release.assignee },
          ]"
          :rows="findings.data.value.items"
          @sort="sortBy"
        >
          <template #cell-vulnerability="{ row }">
            <NuxtLink :to="`/findings/${row.id}`">{{ row.vulnerability_id }}</NuxtLink>
            <div v-if="row.aliases.length" class="muted mono">{{ row.aliases.join(', ') }}</div>
          </template>
          <template #cell-component="{ row }">
            <span class="mono">{{ row.component_ref }}</span>
            <div v-if="row.ecosystem" class="muted">{{ row.ecosystem }}</div>
          </template>
          <template #cell-severity="{ row }">
            {{
              row.severity_label
                ? (id.severity[row.severity_label.toUpperCase() as keyof typeof id.severity] ??
                  row.severity_label)
                : id.severity.unknown
            }}
          </template>
          <template #cell-state="{ row }"
            ><StateBadge :state="row.state" :investigating="row.investigating"
          /></template>
          <template #cell-assignee="{ row }">{{ assignees.label(row.assignee_id) }}</template>
        </DataTable>
        <p class="muted">{{ id.severity.note }}</p>
        <PagerBar
          :page="findings.data.value.page"
          :page-size="findings.data.value.page_size"
          :total="findings.data.value.total"
          @page="(p) => update({ page: p }, false)"
          @size="(n) => update({ pageSize: n })"
        />
      </template>
    </AsyncBlock>

    <section class="card">
      <h2 style="margin-top: 0">{{ id.release.unmatchable }} ({{ unmatchableTotal }})</h2>
      <p class="muted">{{ id.release.unmatchableHelp }}</p>
      <p v-if="!unmatchable.length">{{ id.release.unmatchableNone }}</p>
      <ul v-else>
        <li v-for="(w, i) in unmatchable" :key="i" class="plain-text">
          <span class="badge warn">{{
            w.code === 'unsupported_ecosystem'
              ? id.release.reasonUnsupported
              : id.release.reasonNoPurl
          }}</span>
          {{ w.message }}
        </li>
      </ul>
      <p v-if="unmatchable.length < unmatchableTotal" class="muted">
        {{ id.release.unmatchableTruncated }}
      </p>
    </section>

    <AppModal :open="bulkOpen" :title="id.bulk.title" @close="bulkOpen = false">
      <p>{{ id.bulk.intro(selectedIds.length) }}</p>
      <p v-if="bulkMessage" class="notice bad" role="alert">{{ bulkMessage }}</p>
      <TriageForm
        :product="product.data.value"
        :server-errors="bulkErrors"
        :busy="bulkBusy"
        :submit-label="id.release.bulkTriage"
        @submit="bulk"
      />
    </AppModal>
  </div>
</template>
