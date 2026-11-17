// Copyright (c) 2026 Vassel Goleyu. MIT License.
// Client-side mirror of the statement rules in src/vexledger/domain/statements.py.
// The server stays the authority; this only avoids a round trip. tests/unit/triage-rules.test.ts
// pins every rule and its boundary to the domain test cases.
import { safeHttpUrl } from './safe-url'
import type { Draft, EvidenceDraft, Justification, Product, Status } from './types'

export const MIN_IMPACT_CHARS = 20
export const MIN_STATUS_NOTES_CHARS = 10

export interface TriageForm {
  status: Status | ''
  justification: Justification | ''
  impact: string
  action: string
  notes: string
  evidence: EvidenceDraft[]
  /** Empty means: use the product default (the server computes it). */
  validUntil: string
  reason: string
}

export interface RuleError {
  field: string
  /** Stable API error code, so the message is the same one the server would produce. */
  code: string
}

type Policy = Pick<
  Product,
  | 'validity_not_affected_days'
  | 'validity_under_investigation_days'
  | 'validity_affected_days'
  | 'validity_fixed_days'
>

export function emptyForm(): TriageForm {
  return {
    status: '',
    justification: '',
    impact: '',
    action: '',
    notes: '',
    evidence: [],
    validUntil: '',
    reason: '',
  }
}

export function defaultDays(status: Status, policy: Policy): number | null {
  return {
    not_affected: policy.validity_not_affected_days,
    under_investigation: policy.validity_under_investigation_days,
    affected: policy.validity_affected_days,
    fixed: policy.validity_fixed_days,
  }[status]
}

/** Product default expiry for a status, or null for "never expires". */
export function defaultValidUntil(status: Status, now: Date, policy: Policy): Date | null {
  const days = defaultDays(status, policy)
  return days === null ? null : new Date(now.getTime() + days * 86_400_000)
}

const clean = (text: string): string => text.trim()

export function validateForm(form: TriageForm, now: Date): RuleError[] {
  const errors: RuleError[] = []
  const add = (field: string, code: string): void => {
    errors.push({ field, code })
  }
  if (form.status === '') {
    add('status', 'validation_error')
    return errors
  }
  if (form.status === 'not_affected') {
    if (form.justification === '') add('justification', 'justification_required')
    if (clean(form.impact).length < MIN_IMPACT_CHARS)
      add('impact_statement', 'impact_statement_required')
  } else if (form.justification !== '') {
    add('justification', 'justification_not_allowed')
  }
  if (form.status === 'affected' && clean(form.action) === '') {
    add('action_statement', 'action_statement_required')
  }
  if (form.status === 'fixed' && clean(form.notes).length < MIN_STATUS_NOTES_CHARS) {
    add('status_notes', 'status_notes_required')
  }
  for (const ev of form.evidence) {
    if (clean(ev.value) === '' || (ev.kind === 'LINK' && safeHttpUrl(ev.value) === null)) {
      add('evidence', 'evidence_invalid')
      break
    }
  }
  if (form.validUntil !== '') {
    const when = new Date(form.validUntil)
    if (Number.isNaN(when.getTime()) || when.getTime() <= now.getTime()) {
      add('valid_until', 'valid_until_not_in_future')
    }
  }
  return errors
}

const orNull = (text: string): string | null => clean(text) || null

/** Request body for triage, confirm-less paths and bulk triage. */
export function toDraft(form: TriageForm): Draft {
  if (form.status === '') throw new Error('status is required')
  return {
    status: form.status,
    justification: form.justification === '' ? null : form.justification,
    impact_statement: orNull(form.impact),
    action_statement: orNull(form.action),
    status_notes: orNull(form.notes),
    evidence: form.evidence.map((e) => ({ kind: e.kind, value: e.value.trim() })),
    valid_until: form.validUntil === '' ? null : new Date(form.validUntil).toISOString(),
    reason: orNull(form.reason),
  }
}
