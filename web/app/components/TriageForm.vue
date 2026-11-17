<script setup lang="ts">
// Copyright (c) 2026 Vassel Goleyu. MIT License.
// One form for single and bulk triage. Rules mirror the domain (lib/triage-rules.ts); server
// errors come back by stable code and are shown on the same fields.
import { id } from '~/i18n/id'
import { messageForCode } from '~/lib/errors'
import { formatDateTime } from '~/lib/format'
import {
  defaultValidUntil,
  emptyForm,
  toDraft,
  validateForm,
  type TriageForm as Form,
} from '~/lib/triage-rules'
import { JUSTIFICATIONS, STATUSES, type Draft, type Product } from '~/lib/types'

const props = defineProps<{
  product: Product | null
  initial?: Form
  serverErrors?: Record<string, string>
  busy?: boolean
  submitLabel: string
}>()
const emit = defineEmits<{ submit: [draft: Draft] }>()

const form = reactive<Form>(structuredClone(toRaw(props.initial ?? emptyForm())))
const local = ref<Record<string, string>>({})
const base = useId()

const errors = computed(() => ({ ...props.serverErrors, ...local.value }))
const evidenceMissing = computed(() => form.evidence.length === 0)
const defaultText = computed(() => {
  if (form.status === '' || !props.product) return ''
  const when = defaultValidUntil(form.status, new Date(), props.product)
  return when
    ? id.triage.validUntilDefault(formatDateTime(when.toISOString()))
    : id.triage.validUntilNone
})

watch(
  () => form.status,
  (status) => {
    if (status !== 'not_affected') form.justification = ''
  },
)

function submit(): void {
  const found = validateForm(form, new Date())
  local.value = Object.fromEntries(
    found.map((e) => [
      e.field,
      e.field === 'status' ? id.fieldErrors.required : messageForCode(e.code),
    ]),
  )
  if (found.length === 0) emit('submit', toDraft(form))
}
const addEvidence = (kind: 'LINK' | 'NOTE'): void => {
  form.evidence.push({ kind, value: '' })
}
</script>

<template>
  <form novalidate @submit.prevent="submit">
    <fieldset :aria-describedby="errors.status ? `${base}-st` : undefined">
      <legend>{{ id.triage.status }}</legend>
      <label v-for="s in STATUSES" :key="s" style="display: block">
        <input v-model="form.status" type="radio" name="status" :value="s" />
        {{ id.status[s] }}
      </label>
      <span v-if="errors.status" :id="`${base}-st`" class="field"
        ><span class="error" role="alert">{{ errors.status }}</span></span
      >
      <p v-if="form.status === 'under_investigation'" class="muted">
        {{ id.triage.investigatingNote }}
      </p>
    </fieldset>

    <fieldset
      v-if="form.status === 'not_affected'"
      :class="{ field: true, invalid: !!errors.justification }"
    >
      <legend>{{ id.triage.justification }}</legend>
      <p class="muted">{{ id.triage.justificationHelp }}</p>
      <div v-for="j in JUSTIFICATIONS" :key="j" style="margin-bottom: 0.6rem">
        <label>
          <input v-model="form.justification" type="radio" name="justification" :value="j" />
          <strong>{{ id.justification[j].label }}</strong>
        </label>
        <div class="muted" style="margin-left: 1.5rem">
          {{ id.justification[j].help }} {{ id.justification[j].example }}
        </div>
      </div>
      <span v-if="errors.justification" class="error" role="alert">{{ errors.justification }}</span>
    </fieldset>

    <FormField
      v-if="form.status === 'not_affected'"
      v-slot="f"
      :label="id.triage.impact"
      :hint="id.triage.impactHint"
      :error="errors.impact_statement"
    >
      <textarea
        :id="f.id"
        v-model="form.impact"
        :aria-describedby="f.describedBy"
        :aria-invalid="f.invalid"
      ></textarea>
    </FormField>
    <FormField
      v-if="form.status === 'affected'"
      v-slot="f"
      :label="id.triage.action"
      :hint="id.triage.actionHint"
      :error="errors.action_statement"
    >
      <textarea
        :id="f.id"
        v-model="form.action"
        :aria-describedby="f.describedBy"
        :aria-invalid="f.invalid"
      ></textarea>
    </FormField>
    <FormField
      v-if="form.status !== ''"
      v-slot="f"
      :label="id.triage.notes"
      :hint="form.status === 'fixed' ? id.triage.notesHint : undefined"
      :error="errors.status_notes"
    >
      <textarea
        :id="f.id"
        v-model="form.notes"
        :aria-describedby="f.describedBy"
        :aria-invalid="f.invalid"
      ></textarea>
    </FormField>

    <fieldset v-if="form.status !== ''" :class="{ field: true, invalid: !!errors.evidence }">
      <legend>{{ id.triage.evidenceTitle }}</legend>
      <div v-for="(ev, i) in form.evidence" :key="i" class="row" style="margin-bottom: 0.4rem">
        <label class="grow">
          <span class="sr-only"
            >{{ ev.kind === 'LINK' ? id.triage.linkLabel : id.triage.noteLabel }} {{ i + 1 }}</span
          >
          <input
            v-if="ev.kind === 'LINK'"
            v-model="ev.value"
            style="width: 100%"
            :placeholder="id.triage.linkPlaceholder"
            :aria-label="`${id.triage.linkLabel} ${i + 1}`"
          />
          <textarea
            v-else
            v-model="ev.value"
            :aria-label="`${id.triage.noteLabel} ${i + 1}`"
          ></textarea>
        </label>
        <button type="button" @click="form.evidence.splice(i, 1)">{{ id.triage.remove }}</button>
      </div>
      <div class="row">
        <button type="button" @click="addEvidence('LINK')">{{ id.triage.addLink }}</button>
        <button type="button" @click="addEvidence('NOTE')">{{ id.triage.addNote }}</button>
      </div>
      <span v-if="errors.evidence" class="error" role="alert">{{ errors.evidence }}</span>
      <p v-if="evidenceMissing" class="notice warn">{{ id.triage.noEvidenceWarning }}</p>
    </fieldset>

    <FormField
      v-if="form.status !== ''"
      v-slot="f"
      :label="id.triage.validUntil"
      :hint="defaultText"
      :error="errors.valid_until"
    >
      <div class="row">
        <input
          :id="f.id"
          v-model="form.validUntil"
          type="datetime-local"
          :aria-describedby="f.describedBy"
          :aria-invalid="f.invalid"
        />
        <button v-if="form.validUntil" type="button" @click="form.validUntil = ''">
          {{ id.triage.useDefault }}
        </button>
      </div>
    </FormField>
    <FormField v-if="form.status !== ''" v-slot="f" :label="id.triage.reason">
      <input :id="f.id" v-model="form.reason" style="width: 100%" />
    </FormField>

    <p v-if="Object.keys(errors).length" class="notice bad" role="alert">
      {{ id.triage.fixErrors }}
    </p>
    <button type="submit" class="primary" :disabled="busy">
      {{ busy ? id.triage.submitting : submitLabel }}
    </button>
  </form>
</template>
