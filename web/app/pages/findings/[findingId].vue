<script setup lang="ts">
// Copyright (c) 2026 Vassel Goleyu. MIT License.
import { id } from '~/i18n/id'
import { ApiError, fieldErrorsOf, messageFor } from '~/lib/errors'
import { formatDateTime } from '~/lib/format'
import { emptyForm, type TriageForm } from '~/lib/triage-rules'
import type { Draft, FindingDetail, Product } from '~/lib/types'
import { useSessionStore } from '~/stores/session'

const route = useRoute()
const findingId = String(route.params.findingId)
const api = useApi()
const session = useSessionStore()
const notify = useNotify()
const assignees = useAssignees()

const loader = useLoad(() => api.finding(findingId))
const product = ref<Product | null>(null)
const f = computed<FindingDetail | null>(() => loader.data.value)
watch(
  () => f.value?.product_slug,
  (slug) => {
    if (slug && product.value?.slug !== slug) {
      void api.product(slug).then((p) => (product.value = p))
    }
  },
)
const canTriage = computed(() => session.can('analyst') && f.value?.state !== 'WITHDRAWN')

const busy = ref(false)
const errors = ref<Record<string, string>>({})
const conflict = ref(false)
const formKey = ref(0)

/** NEEDS_REVIEW: start from the old statement so the analyst only edits what changed. */
const initial = computed<TriageForm>(() => {
  const old = f.value?.review_context?.statement
  const form = emptyForm()
  if (!old) return form
  form.status = old.status
  form.justification = old.justification ?? ''
  form.impact = old.impact_statement ?? ''
  form.action = old.action_statement ?? ''
  form.notes = old.status_notes ?? ''
  form.evidence = old.evidence.flatMap((e) =>
    e.kind === 'FILE' || !e.value ? [] : [{ kind: e.kind, value: e.value }],
  )
  return form
})

async function refresh(): Promise<void> {
  conflict.value = false
  await loader.reload()
  formKey.value++
}

async function guarded(action: () => Promise<void>): Promise<void> {
  busy.value = true
  errors.value = {}
  try {
    await action()
  } catch (e) {
    errors.value = fieldErrorsOf(e)
    if (e instanceof ApiError && e.code === 'conflict') conflict.value = true
    notify.failure(e)
  } finally {
    busy.value = false
  }
}

const triage = (draft: Draft): Promise<void> =>
  guarded(async () => {
    await api.triage(findingId, draft, f.value?.head_id ?? null)
    notify.success(id.triage.saved)
    await refresh()
  })
const confirmInherited = (): Promise<void> =>
  guarded(async () => {
    await api.confirm(findingId, f.value?.head_id ?? null)
    notify.success(id.finding.confirmed)
    await refresh()
  })
const assign = (value: string): Promise<void> =>
  guarded(async () => {
    await api.assign(findingId, value || null)
    notify.success(id.triage.assigned)
    await loader.reload()
  })
const addFile = (ev: Event): Promise<void> => {
  const input = ev.target as HTMLInputElement
  const file = input.files?.[0]
  input.value = ''
  if (!file) return Promise.resolve()
  return guarded(async () => {
    await api.addEvidenceFile(findingId, file, f.value?.head_id ?? null)
    notify.success(id.triage.evidenceAdded)
    await refresh()
  })
}
const fileId = useId()
</script>

<template>
  <div>
    <AppBreadcrumbs
      :items="[
        { label: id.products.title, to: '/products' },
        ...(f
          ? [
              { label: f.product_slug, to: `/products/${f.product_slug}` },
              {
                label: f.release_version,
                to: `/products/${f.product_slug}/releases/${f.release_version}`,
              },
            ]
          : []),
        { label: f?.vulnerability_id ?? findingId },
      ]"
    />
    <AsyncBlock :loading="loader.loading.value" :error="loader.error.value" @retry="loader.reload">
      <template v-if="f">
        <div class="row">
          <h1 class="grow">{{ f.vulnerability_id }}</h1>
          <StateBadge :state="f.state" :investigating="f.investigating" />
        </div>
        <p class="mono">{{ f.component_ref }}</p>
        <p v-if="f.state === 'WITHDRAWN'" class="notice info">{{ id.finding.withdrawnNote }}</p>

        <div class="cols two">
          <div>
            <section class="card">
              <h2 style="margin-top: 0">{{ id.finding.summary }}</h2>
              <dl class="kv">
                <dt>{{ id.finding.aliases }}</dt>
                <dd class="mono">{{ f.aliases.length ? f.aliases.join(', ') : id.common.none }}</dd>
                <dt>{{ id.finding.severity }}</dt>
                <dd>{{ f.severity_label ?? id.severity.unknown }}</dd>
              </dl>
              <p class="muted">{{ id.severity.note }}</p>
              <p v-if="!f.osv.length" class="muted">{{ id.finding.noSummary }}</p>
              <article v-for="o in f.osv" :key="o.id" class="stack" style="margin-top: 1rem">
                <h3 class="mono">{{ o.id }}</h3>
                <p class="plain-text">{{ o.summary ?? id.finding.noSummary }}</p>
                <p v-if="o.severity.length" class="mono">
                  <span v-for="(s, i) in o.severity" :key="i"
                    >{{ s.type }} {{ s.score }}{{ ' ' }}</span
                  >
                </p>
                <p class="muted">
                  {{ id.finding.published }}{{ id.common.separator }}
                  {{ o.published ? formatDateTime(o.published) : id.common.unknown }}.
                  {{ id.finding.modified }}{{ id.common.separator }}
                  {{ formatDateTime(o.modified) }}.
                  <template v-if="o.withdrawn"
                    >{{ id.finding.withdrawn }}{{ id.common.separator }}
                    {{ formatDateTime(o.withdrawn) }}.</template
                  >
                </p>
                <details v-if="o.details">
                  <summary>{{ id.finding.details }}</summary>
                  <p class="plain-text">{{ o.details }}</p>
                </details>
                <div v-if="o.references.length">
                  <strong>{{ id.finding.references }}</strong>
                  <ul>
                    <li v-for="(r, i) in o.references" :key="i"><SafeLink :href="r.url" /></li>
                  </ul>
                </div>
              </article>
              <div v-if="f.match_discrepancy" class="notice warn">
                <strong>{{ id.finding.discrepancy }}</strong>
                <p>{{ id.finding.discrepancyHelp }}</p>
              </div>
            </section>

            <section class="card">
              <h2 style="margin-top: 0">{{ id.finding.component }}</h2>
              <dl class="kv">
                <dt>{{ id.finding.purl }}</dt>
                <dd class="mono">{{ f.component.purl ?? id.common.none }}</dd>
                <dt>{{ id.finding.hash }}</dt>
                <dd class="mono">{{ f.component.component_hash ?? id.common.none }}</dd>
              </dl>
              <h3>{{ id.finding.dependencyPath }}</h3>
              <p v-if="!f.dependency_path.reachable" class="notice warn">
                {{ id.finding.unreachable }}
              </p>
              <template v-else>
                <p>
                  <span class="badge neutral">{{
                    f.dependency_path.direct ? id.finding.direct : id.finding.transitive
                  }}</span>
                </p>
                <ol>
                  <li v-for="n in f.dependency_path.path" :key="n.component_id" class="mono">
                    {{ n.name }} {{ n.version }}
                  </li>
                </ol>
              </template>
            </section>

            <section v-if="f.review_context" class="card">
              <h2 style="margin-top: 0">{{ id.finding.context }}</h2>
              <p class="notice warn">{{ id.finding.contextHelp }}</p>
              <p class="muted">
                {{ id.finding.release }}{{ id.common.separator }}
                {{ f.review_context.release_version }}
              </p>
              <StatementView :statement="f.review_context.statement" />
            </section>

            <section class="card">
              <h2 style="margin-top: 0">{{ id.finding.history }}</h2>
              <p v-if="!f.statements.length" class="muted">{{ id.finding.noHistory }}</p>
              <ol class="timeline">
                <li v-for="(s, i) in f.statements" :key="s.id" :class="{ head: i === 0 }">
                  <span v-if="i === 0" class="badge ok">{{ id.finding.head }}</span>
                  <StatementView :statement="s" />
                </li>
              </ol>
            </section>
          </div>

          <aside>
            <section class="card">
              <h2 style="margin-top: 0">{{ id.triage.title }}</h2>
              <p v-if="!session.can('analyst')" class="notice info">{{ id.triage.readOnly }}</p>
              <template v-else-if="canTriage">
                <p v-if="conflict" class="notice bad" role="alert">
                  {{ messageFor(new ApiError({ status: 409, code: 'conflict' })) }}
                  <button type="button" @click="refresh">{{ id.finding.reload }}</button>
                </p>
                <div v-if="f.state === 'INHERITED'" class="notice info">
                  <strong>{{ id.finding.confirmTitle }}</strong>
                  <p>{{ id.finding.confirmHelp }}</p>
                  <button type="button" class="primary" :disabled="busy" @click="confirmInherited">
                    {{ id.finding.confirmButton }}
                  </button>
                </div>
                <FormField v-slot="a" :label="id.triage.assignee">
                  <select
                    :id="a.id"
                    :value="f.assignee_id ?? ''"
                    :disabled="busy"
                    @change="assign(($event.target as HTMLSelectElement).value)"
                  >
                    <option value="">{{ id.common.unassigned }}</option>
                    <option v-for="o in assignees.options.value" :key="o.id" :value="o.id">
                      {{ o.label }}
                    </option>
                    <option
                      v-if="
                        f.assignee_id &&
                        !assignees.options.value.some((o) => o.id === f?.assignee_id)
                      "
                      :value="f.assignee_id"
                    >
                      {{ assignees.label(f.assignee_id) }}
                    </option>
                  </select>
                </FormField>
                <TriageForm
                  :key="formKey"
                  :product="product"
                  :initial="initial"
                  :server-errors="errors"
                  :busy="busy"
                  :submit-label="id.triage.submit"
                  @submit="triage"
                />
                <div v-if="f.head_id" class="field" style="margin-top: 1rem">
                  <label class="label" :for="fileId">{{ id.triage.evidenceFile }}</label>
                  <input :id="fileId" type="file" :disabled="busy" @change="addFile" />
                  <span class="hint">{{ id.triage.evidenceFileHelp }}</span>
                </div>
              </template>
            </section>
          </aside>
        </div>
      </template>
    </AsyncBlock>
  </div>
</template>
