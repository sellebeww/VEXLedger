// Copyright (c) 2026 Vassel Goleyu. MIT License.
import { expect, test } from 'vitest'
import { id } from '../../app/i18n/id'
import {
  ApiError,
  failedFindingId,
  fieldErrorsOf,
  messageFor,
  messageForCode,
} from '../../app/lib/errors'

// Every stable code of docs/API.md ("Bentuk galat"). A new server code must get a message here.
const API_CODES = [
  'unauthorized',
  'invalid_credentials',
  'forbidden',
  'csrf_failed',
  'session_required',
  'rate_limited',
  'not_found',
  'conflict',
  'release_incomplete',
  'release_not_matched',
  'release_exists',
  'product_exists',
  'user_exists',
  'last_admin',
  'not_inherited',
  'no_statement',
  'payload_too_large',
  'sbom_too_large',
  'file_too_large',
  'validation_error',
  'justification_required',
  'justification_not_allowed',
  'impact_statement_required',
  'action_statement_required',
  'status_notes_required',
  'evidence_invalid',
  'valid_until_not_in_future',
  'no_op',
  'no_exportable_statements',
  'sbom_not_json',
  'sbom_unsupported_format',
  'sbom_schema_invalid',
  'sbom_limit_exceeded',
  'empty_file',
  'type_not_allowed',
  'content_does_not_match_type',
  'invalid_purl',
  'invalid_assignee',
  'password_too_short',
  'internal_error',
  'service_unavailable',
  'method_not_allowed',
  'bad_request',
]

test('every stable API code has an Indonesian message distinct from the fallback', () => {
  for (const code of API_CODES) {
    expect(id.errors[code], code).toBeTruthy()
    expect(messageForCode(code), code).not.toBe(id.errors.unknown)
  }
})

test('unknown codes and non-API errors fall back to the generic message', () => {
  expect(messageForCode('brand_new_code')).toBe(id.errors.unknown)
  expect(messageFor(new Error('boom'))).toBe(id.errors.unknown)
  expect(messageFor(new ApiError({ status: 0, code: 'network_error' }))).toBe(
    id.errors.network_error,
  )
})

test('server English text is never shown', () => {
  const e = new ApiError({
    status: 422,
    code: 'no_op',
    message: 'identical to the active statement',
  })
  expect(messageFor(e)).toBe(id.errors.no_op)
})

test('domain codes map to their form field', () => {
  const cases: Record<string, string> = {
    justification_required: 'justification',
    justification_not_allowed: 'justification',
    impact_statement_required: 'impact_statement',
    action_statement_required: 'action_statement',
    status_notes_required: 'status_notes',
    evidence_invalid: 'evidence',
    valid_until_not_in_future: 'valid_until',
  }
  for (const [code, field] of Object.entries(cases)) {
    expect(Object.keys(fieldErrorsOf(new ApiError({ status: 422, code })))).toEqual([field])
  }
  expect(fieldErrorsOf(new ApiError({ status: 409, code: 'conflict' }))).toEqual({})
  expect(fieldErrorsOf('nope')).toEqual({})
})

test('validation_error details point at the fields (body prefix dropped)', () => {
  const e = new ApiError({
    status: 422,
    code: 'validation_error',
    details: { errors: [{ loc: ['body', 'evidence', '0', 'value'], message: 'x', type: 'y' }] },
  })
  expect(Object.keys(fieldErrorsOf(e))).toEqual(['evidence.0.value'])
})

test('a failed bulk triage names the finding', () => {
  const e = new ApiError({ status: 422, code: 'no_op', details: { finding_id: 'abc' } })
  expect(failedFindingId(e)).toBe('abc')
  expect(failedFindingId(new ApiError({ status: 422, code: 'no_op' }))).toBeNull()
})
