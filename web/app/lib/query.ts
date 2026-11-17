// Copyright (c) 2026 Vassel Goleyu. MIT License.
import { FINDING_STATES, type FindingState } from './types'

export type SortKey = 'state' | 'severity' | 'vulnerability' | 'component'
export const SORT_KEYS: readonly SortKey[] = ['state', 'severity', 'vulnerability', 'component']
export const PAGE_SIZES = [25, 50, 100, 200] as const

export interface FindingQuery {
  states: FindingState[]
  severity: string
  ecosystem: string
  assignee: string
  sort: SortKey
  order: 'asc' | 'desc'
  page: number
  pageSize: number
}

export const DEFAULT_QUERY: FindingQuery = {
  states: [],
  severity: '',
  ecosystem: '',
  assignee: '',
  sort: 'state',
  order: 'asc',
  page: 1,
  pageSize: 50,
}

type Params = Record<string, string | number | boolean | (string | number)[] | null | undefined>

/** Builds a query string; repeats array keys, skips empty values. */
export function buildQuery(params: Params): string {
  const sp = new URLSearchParams()
  for (const [key, value] of Object.entries(params)) {
    const values = Array.isArray(value) ? value : [value]
    for (const v of values) {
      if (v === null || v === undefined || v === '') continue
      sp.append(key, String(v))
    }
  }
  const text = sp.toString()
  return text ? `?${text}` : ''
}

/** Parameters of GET .../findings (only non-default values are sent). */
export function findingsParams(q: FindingQuery): Params {
  return {
    state: q.states,
    severity: q.severity,
    ecosystem: q.ecosystem,
    assignee_id: q.assignee,
    sort: q.sort,
    order: q.order,
    page: q.page,
    page_size: q.pageSize,
  }
}

type RouteQuery = Record<string, string | null | (string | null)[] | undefined>

const first = (v: RouteQuery[string]): string => (Array.isArray(v) ? (v[0] ?? '') : (v ?? ''))
const positiveInt = (text: string, fallback: number): number => {
  const n = Number(text)
  return Number.isInteger(n) && n >= 1 ? n : fallback
}

/** Reads the URL query into a valid FindingQuery; anything unrecognised falls back to defaults. */
export function parseFindingQuery(route: RouteQuery): FindingQuery {
  const raw = route.state
  const list = (Array.isArray(raw) ? raw : raw ? [raw] : []).filter(
    (s): s is FindingState => !!s && (FINDING_STATES as readonly string[]).includes(s),
  )
  const sort = first(route.sort)
  const size = positiveInt(first(route.page_size), DEFAULT_QUERY.pageSize)
  return {
    states: [...new Set(list)],
    severity: /^[A-Za-z]{1,20}$/.test(first(route.severity)) ? first(route.severity) : '',
    ecosystem: /^[A-Za-z0-9._-]{1,30}$/.test(first(route.ecosystem)) ? first(route.ecosystem) : '',
    assignee: /^[0-9a-f-]{36}$/i.test(first(route.assignee_id)) ? first(route.assignee_id) : '',
    sort: (SORT_KEYS as readonly string[]).includes(sort) ? (sort as SortKey) : 'state',
    order: first(route.order) === 'desc' ? 'desc' : 'asc',
    page: positiveInt(first(route.page), 1),
    pageSize: size <= 200 ? size : DEFAULT_QUERY.pageSize,
  }
}

/** Route query (URL) for a FindingQuery: defaults are omitted to keep URLs short. */
export function toRouteQuery(q: FindingQuery): Record<string, string | string[]> {
  const out: Record<string, string | string[]> = {}
  if (q.states.length) out.state = q.states
  if (q.severity) out.severity = q.severity
  if (q.ecosystem) out.ecosystem = q.ecosystem
  if (q.assignee) out.assignee_id = q.assignee
  if (q.sort !== DEFAULT_QUERY.sort) out.sort = q.sort
  if (q.order !== DEFAULT_QUERY.order) out.order = q.order
  if (q.page !== 1) out.page = String(q.page)
  if (q.pageSize !== DEFAULT_QUERY.pageSize) out.page_size = String(q.pageSize)
  return out
}
