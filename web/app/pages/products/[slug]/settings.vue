<script setup lang="ts">
// Copyright (c) 2026 Vassel Goleyu. MIT License.
import { id } from '~/i18n/id'
import { fieldErrorsOf } from '~/lib/errors'
import type { Product } from '~/lib/types'
import { useSessionStore } from '~/stores/session'

const route = useRoute()
const slug = String(route.params.slug)
const api = useApi()
const session = useSessionStore()
const notify = useNotify()
const loader = useLoad(() => api.product(slug))

type DaysKey =
  | 'validity_not_affected_days'
  | 'validity_under_investigation_days'
  | 'validity_affected_days'
  | 'validity_fixed_days'
const DAYS: { key: DaysKey; label: string }[] = [
  { key: 'validity_not_affected_days', label: id.status.not_affected },
  { key: 'validity_under_investigation_days', label: id.status.under_investigation },
  { key: 'validity_affected_days', label: id.status.affected },
  { key: 'validity_fixed_days', label: id.status.fixed },
]

const form = reactive({
  name: '',
  purl: '',
  vex_author: '',
  inherit_enabled: true,
  days: {} as Record<DaysKey, string>,
})
const errors = ref<Record<string, string>>({})
const busy = ref(false)
const canEdit = computed(() => session.can('admin'))

watch(
  () => loader.data.value,
  (p: Product | null) => {
    if (!p) return
    form.name = p.name
    form.purl = p.purl
    form.vex_author = p.vex_author
    form.inherit_enabled = p.inherit_enabled
    for (const { key } of DAYS) form.days[key] = p[key] === null ? '' : String(p[key])
  },
  { immediate: true },
)

function parseDays(text: string): number | null | undefined {
  if (text.trim() === '') return null
  const n = Number(text)
  return Number.isInteger(n) && n >= 1 && n <= 3650 ? n : undefined
}

async function save(): Promise<void> {
  errors.value = {}
  const body: Record<string, unknown> = {
    name: form.name,
    purl: form.purl,
    vex_author: form.vex_author,
    inherit_enabled: form.inherit_enabled,
  }
  for (const { key } of DAYS) {
    const v = parseDays(form.days[key])
    if (v === undefined) errors.value[key] = id.fieldErrors.days
    else body[key] = v
  }
  if (Object.keys(errors.value).length) return
  busy.value = true
  try {
    await api.patchProduct(slug, body)
    notify.success(id.settings.saved)
    await loader.reload()
  } catch (e) {
    errors.value = fieldErrorsOf(e)
    notify.failure(e)
  } finally {
    busy.value = false
  }
}
</script>

<template>
  <div>
    <AppBreadcrumbs
      :items="[
        { label: id.products.title, to: '/products' },
        { label: slug, to: `/products/${slug}` },
        { label: id.settings.title },
      ]"
    />
    <h1>{{ id.settings.title }}</h1>
    <AsyncBlock :loading="loader.loading.value" :error="loader.error.value" @retry="loader.reload">
      <form v-if="loader.data.value" class="card" @submit.prevent="save">
        <p v-if="!canEdit" class="notice info">{{ id.settings.adminOnly }}</p>
        <fieldset :disabled="!canEdit">
          <FormField v-slot="f" :label="id.common.name">
            <input :id="f.id" v-model="form.name" required />
          </FormField>
          <FormField v-slot="f" :label="id.products.purl" :error="errors.purl">
            <input :id="f.id" v-model="form.purl" required :aria-describedby="f.describedBy" />
          </FormField>
          <FormField v-slot="f" :label="id.products.author" :hint="id.products.authorHint">
            <input
              :id="f.id"
              v-model="form.vex_author"
              required
              :aria-describedby="f.describedBy"
            />
          </FormField>
          <label class="field">
            <input v-model="form.inherit_enabled" type="checkbox" />
            {{ id.settings.inherit }}
          </label>
          <p class="notice warn">{{ id.settings.inheritWarning }}</p>
          <fieldset>
            <legend>{{ id.settings.validityTitle }}</legend>
            <p class="muted">{{ id.settings.validityHint }}</p>
            <FormField
              v-for="d in DAYS"
              :key="d.key"
              v-slot="f"
              :label="d.label"
              :error="errors[d.key]"
            >
              <input
                :id="f.id"
                v-model="form.days[d.key]"
                inputmode="numeric"
                :aria-describedby="f.describedBy"
                :aria-invalid="f.invalid"
              />
            </FormField>
          </fieldset>
        </fieldset>
        <button v-if="canEdit" type="submit" class="primary" :disabled="busy">
          {{ id.common.save }}
        </button>
      </form>
    </AsyncBlock>
  </div>
</template>
