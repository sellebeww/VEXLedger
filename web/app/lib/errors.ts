// Copyright (c) 2026 Vassel Goleyu. MIT License.
import { id } from '../i18n/id'

export interface ValidationItem {
  loc: string[]
  message: string
  type: string
}

export class ApiError extends Error {
  readonly status: number
  readonly code: string
  readonly field: string | null
  readonly details: Record<string, unknown> | null
  readonly requestId: string | null
  readonly retryAfter: number | null

  constructor(init: {
    status: number
    code: string
    message?: string
    field?: string | null
    details?: Record<string, unknown> | null
    requestId?: string | null
    retryAfter?: number | null
  }) {
    super(init.message ?? init.code)
    this.status = init.status
    this.code = init.code
    this.field = init.field ?? null
    this.details = init.details ?? null
    this.requestId = init.requestId ?? null
    this.retryAfter = init.retryAfter ?? null
  }
}

/** Indonesian message for a stable API error code (never the server's English text). */
export function messageForCode(code: string): string {
  return id.errors[code] ?? id.errors.unknown!
}

export function messageFor(error: unknown): string {
  return error instanceof ApiError ? messageForCode(error.code) : id.errors.unknown!
}

/** Maps a domain error code to the form field it belongs to. */
const FIELD_OF_CODE: Record<string, string> = {
  justification_required: 'justification',
  justification_not_allowed: 'justification',
  impact_statement_required: 'impact_statement',
  action_statement_required: 'action_statement',
  status_notes_required: 'status_notes',
  evidence_invalid: 'evidence',
  valid_until_not_in_future: 'valid_until',
}

/** Field errors to show inline; unknown or field-less errors return an empty map. */
export function fieldErrorsOf(error: unknown): Record<string, string> {
  if (!(error instanceof ApiError)) return {}
  const out: Record<string, string> = {}
  const field = error.field ?? FIELD_OF_CODE[error.code]
  if (field) out[field] = messageForCode(error.code)
  const items = error.details?.errors
  if (error.code === 'validation_error' && Array.isArray(items)) {
    for (const item of items as ValidationItem[]) {
      const name = item.loc.filter((p) => p !== 'body').join('.')
      if (name) out[name] = messageForCode('validation_error')
    }
  }
  return out
}

/** The finding that made an atomic bulk triage fail, when the API names it. */
export function failedFindingId(error: unknown): string | null {
  const value = error instanceof ApiError ? error.details?.finding_id : null
  return typeof value === 'string' ? value : null
}
