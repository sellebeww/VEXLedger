// Copyright (c) 2026 Vassel Goleyu. MIT License.
import { expect, test } from 'vitest'
import {
  buildQuery,
  DEFAULT_QUERY,
  findingsParams,
  parseFindingQuery,
  toRouteQuery,
} from '../../app/lib/query'

test('buildQuery repeats arrays, skips empties and encodes values', () => {
  expect(buildQuery({ state: ['UNTRIAGED', 'EXPIRED'], severity: '', page: 2 })).toBe(
    '?state=UNTRIAGED&state=EXPIRED&page=2',
  )
  expect(buildQuery({ a: null, b: undefined })).toBe('')
  expect(buildQuery({ q: 'a b&c' })).toBe('?q=a+b%26c')
})

test('findings params carry filters, sort and pagination to the API names', () => {
  const q = {
    ...DEFAULT_QUERY,
    states: ['NEEDS_REVIEW' as const],
    severity: 'HIGH',
    sort: 'severity' as const,
    order: 'desc' as const,
    page: 3,
    pageSize: 25,
    assignee: 'a'.repeat(8),
  }
  const text = buildQuery(findingsParams(q))
  expect(text).toBe(
    '?state=NEEDS_REVIEW&severity=HIGH&assignee_id=aaaaaaaa&sort=severity&order=desc&page=3&page_size=25',
  )
})

test('route query round-trips and omits defaults', () => {
  expect(toRouteQuery(DEFAULT_QUERY)).toEqual({})
  const q = {
    ...DEFAULT_QUERY,
    states: ['UNTRIAGED' as const, 'EXPIRED' as const],
    ecosystem: 'npm',
    order: 'desc' as const,
    page: 4,
  }
  expect(parseFindingQuery(toRouteQuery(q))).toEqual(q)
})

test('hostile or malformed URL parameters fall back to defaults', () => {
  const parsed = parseFindingQuery({
    state: ['BOGUS', 'TRIAGED', 'TRIAGED'],
    severity: 'HI GH;drop',
    ecosystem: '../x',
    assignee_id: 'not-a-uuid',
    sort: 'password',
    order: 'sideways',
    page: '-3',
    page_size: '100000',
  })
  expect(parsed).toEqual({ ...DEFAULT_QUERY, states: ['TRIAGED'] })
})
