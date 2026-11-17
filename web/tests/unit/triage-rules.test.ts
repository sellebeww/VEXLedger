// Copyright (c) 2026 Vassel Goleyu. MIT License.
// Same cases as tests/unit/domain/test_statements.py.
import { expect, test } from 'vitest'
import {
  defaultValidUntil,
  emptyForm,
  toDraft,
  validateForm,
  type TriageForm,
} from '../../app/lib/triage-rules'

const now = new Date('2026-11-16T12:00:00Z')
const form = (patch: Partial<TriageForm>): TriageForm => ({ ...emptyForm(), ...patch })
const codes = (f: TriageForm): string[] => validateForm(f, now).map((e) => e.code)

test('status is required', () => {
  expect(codes(form({}))).toEqual(['validation_error'])
})

test('not_affected needs a justification and an impact statement of 20 characters', () => {
  expect(codes(form({ status: 'not_affected' }))).toEqual([
    'justification_required',
    'impact_statement_required',
  ])
  const ok = form({
    status: 'not_affected',
    justification: 'component_not_present',
    impact: 'x'.repeat(20),
  })
  expect(codes(ok)).toEqual([])
  expect(codes({ ...ok, impact: 'x'.repeat(19) })).toEqual(['impact_statement_required'])
  // surrounding whitespace is trimmed before counting
  expect(codes({ ...ok, impact: `  ${'x'.repeat(19)}  ` })).toEqual(['impact_statement_required'])
})

test('a justification on any other status is refused', () => {
  for (const status of ['affected', 'fixed', 'under_investigation'] as const) {
    const f = form({
      status,
      justification: 'component_not_present',
      action: 'upgrade now',
      notes: 'n'.repeat(10),
    })
    expect(codes(f)).toEqual(['justification_not_allowed'])
  }
})

test('affected needs an action statement', () => {
  expect(codes(form({ status: 'affected' }))).toEqual(['action_statement_required'])
  expect(codes(form({ status: 'affected', action: '   ' }))).toEqual(['action_statement_required'])
  expect(codes(form({ status: 'affected', action: 'Upgrade to 2.0' }))).toEqual([])
})

test('fixed needs status notes of 10 characters', () => {
  expect(codes(form({ status: 'fixed', notes: 'n'.repeat(9) }))).toEqual(['status_notes_required'])
  expect(codes(form({ status: 'fixed', notes: 'n'.repeat(10) }))).toEqual([])
})

test('under_investigation has no mandatory text', () => {
  expect(codes(form({ status: 'under_investigation' }))).toEqual([])
})

test('link evidence must be a lowercase http(s) URL with a host and no spaces', () => {
  const base = form({ status: 'under_investigation' })
  const link = (value: string): string[] => codes({ ...base, evidence: [{ kind: 'LINK', value }] })
  expect(link('https://example.com/a')).toEqual([])
  expect(link('http://example.com')).toEqual([])
  for (const bad of [
    '',
    'ftp://x.test',
    'javascript:alert(1)',
    'http:/x',
    'HTTP://x.test',
    'https://a b.test',
    'https://',
  ]) {
    expect(link(bad)).toEqual(['evidence_invalid'])
  }
  expect(codes({ ...base, evidence: [{ kind: 'NOTE', value: '  ' }] })).toEqual([
    'evidence_invalid',
  ])
  expect(codes({ ...base, evidence: [{ kind: 'NOTE', value: 'checked by hand' }] })).toEqual([])
})

test('valid_until must be in the future (the boundary instant is expired)', () => {
  const base = form({ status: 'under_investigation' })
  const at = (d: Date): string[] => codes({ ...base, validUntil: d.toISOString() })
  expect(at(new Date(now.getTime() + 1000))).toEqual([])
  expect(at(now)).toEqual(['valid_until_not_in_future'])
  expect(codes({ ...base, validUntil: 'not a date' })).toEqual(['valid_until_not_in_future'])
})

test('default validity follows the product policy (null means never)', () => {
  const policy = {
    validity_not_affected_days: 180,
    validity_under_investigation_days: 14,
    validity_affected_days: null,
    validity_fixed_days: null,
  }
  expect(defaultValidUntil('not_affected', now, policy)?.toISOString()).toBe(
    '2027-05-15T12:00:00.000Z',
  )
  expect(defaultValidUntil('under_investigation', now, policy)?.toISOString()).toBe(
    '2026-11-30T12:00:00.000Z',
  )
  expect(defaultValidUntil('affected', now, policy)).toBeNull()
  expect(defaultValidUntil('fixed', now, policy)).toBeNull()
})

test('toDraft trims text, nulls empties and omits the date when the default is wanted', () => {
  const draft = toDraft(
    form({
      status: 'not_affected',
      justification: 'inline_mitigations_already_exist',
      impact: '  mitigated by an upstream proxy  ',
      notes: '   ',
      evidence: [{ kind: 'LINK', value: ' https://example.com ' }],
    }),
  )
  expect(draft).toEqual({
    status: 'not_affected',
    justification: 'inline_mitigations_already_exist',
    impact_statement: 'mitigated by an upstream proxy',
    action_statement: null,
    status_notes: null,
    evidence: [{ kind: 'LINK', value: 'https://example.com' }],
    valid_until: null,
    reason: null,
  })
  expect(() => toDraft(form({}))).toThrow()
})
