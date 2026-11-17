// Copyright (c) 2026 Vassel Goleyu. MIT License.
import { expect, test, vi } from 'vitest'
import { createApi } from '../../app/lib/api'
import { createClient } from '../../app/lib/client'
import { ApiError } from '../../app/lib/errors'

interface Call {
  url: string
  init: RequestInit
}
function setup(respond: (c: Call) => Response, csrf: string | null = 'tok') {
  const calls: Call[] = []
  const onUnauthorized = vi.fn()
  const fetchMock = ((url: string, init: RequestInit) => {
    const call = { url, init }
    calls.push(call)
    return Promise.resolve(respond(call))
  }) as unknown as typeof fetch
  const client = createClient({
    fetch: fetchMock,
    baseUrl: '',
    getCsrf: () => csrf,
    onUnauthorized,
  })
  return { calls, onUnauthorized, api: createApi({ client, getCsrf: () => csrf, onUnauthorized }) }
}
const json = (body: unknown, status = 200, headers: Record<string, string> = {}): Response =>
  new Response(JSON.stringify(body), {
    status,
    headers: { 'Content-Type': 'application/json', ...headers },
  })

test('mutations send the CSRF token and cookies, reads do not need it', async () => {
  const { api, calls } = setup(() => json({}))
  await api.product('web-app')
  await api.triage('f1', { status: 'under_investigation' }, 'head-1')
  expect((calls[0]!.init.headers as Record<string, string>)['X-CSRF-Token']).toBeUndefined()
  const post = calls[1]!
  expect((post.init.headers as Record<string, string>)['X-CSRF-Token']).toBe('tok')
  expect(post.init.credentials).toBe('same-origin')
  expect(JSON.parse(post.init.body as string)).toMatchObject({
    status: 'under_investigation',
    expected_head_id: 'head-1',
  })
})

test('paths are encoded and filters become the findings query string', async () => {
  const { api, calls } = setup(() => json({ items: [] }))
  await api.findings('web app', '1.0/x', {
    states: ['UNTRIAGED'],
    severity: 'HIGH',
    ecosystem: '',
    assignee: '',
    sort: 'component',
    order: 'desc',
    page: 2,
    pageSize: 25,
  })
  expect(calls[0]!.url).toBe(
    '/api/v1/products/web%20app/releases/1.0%2Fx/findings?state=UNTRIAGED&severity=HIGH&sort=component&order=desc&page=2&page_size=25',
  )
})

test('an API error keeps its stable code, field, details and request id', async () => {
  const { api } = setup(() =>
    json(
      {
        error: {
          code: 'release_incomplete',
          message: 'english',
          details: { open_count: 2 },
          request_id: 'r1',
        },
      },
      409,
    ),
  )
  const err = await api.exportRelease('p', '1', false).catch((e: unknown) => e)
  expect(err).toBeInstanceOf(ApiError)
  expect(err).toMatchObject({
    status: 409,
    code: 'release_incomplete',
    requestId: 'r1',
    details: { open_count: 2 },
  })
})

test('401 drops the session except for login itself', async () => {
  const { api, onUnauthorized } = setup(() =>
    json({ error: { code: 'unauthorized', message: 'x' } }, 401),
  )
  await api.products().catch(() => undefined)
  expect(onUnauthorized).toHaveBeenCalledTimes(1)
  const bad = await api.login('a', 'b').catch((e: unknown) => e)
  expect(bad).toMatchObject({ code: 'unauthorized' })
  expect(onUnauthorized).toHaveBeenCalledTimes(1)
})

test('rate limiting exposes Retry-After', async () => {
  const { api } = setup(() =>
    json({ error: { code: 'rate_limited', message: 'x' } }, 429, { 'Retry-After': '42' }),
  )
  const err = await api.login('a', 'b').catch((e: unknown) => e)
  expect(err).toMatchObject({ code: 'rate_limited', retryAfter: 42 })
})

test('network failures and non-JSON bodies become typed errors', async () => {
  const down = createClient({
    fetch: (() => Promise.reject(new TypeError('x'))) as unknown as typeof fetch,
    baseUrl: '',
    getCsrf: () => null,
    onUnauthorized: () => undefined,
  })
  await expect(down.json('GET', '/x')).rejects.toMatchObject({ code: 'network_error' })
  const { api } = setup(() => new Response('<html>', { status: 200 }))
  await expect(api.products()).rejects.toMatchObject({ code: 'bad_response' })
  const gateway = setup(() => new Response('<html>', { status: 502 }))
  await expect(gateway.api.products()).rejects.toMatchObject({ code: 'internal_error' })
})

test('export returns the document text and the version headers', async () => {
  const { api, calls } = setup(
    () =>
      new Response('{"@context":"x"}', {
        status: 200,
        headers: {
          'X-VEX-Version': '3',
          'X-VEX-Content-SHA256': 'ab',
          'X-VEX-New-Version': 'false',
        },
      }),
  )
  const out = await api.exportRelease('p', '1', true)
  expect(out).toEqual({ text: '{"@context":"x"}', version: 3, sha256: 'ab', isNew: false })
  expect(calls[0]!.url).toBe('/api/v1/products/p/releases/1/export?allow_incomplete=true')
})

test('diff uses the from and to parameter names of the API', async () => {
  const { api, calls } = setup(() => json({}))
  await api.diff('p', '1.0', '1.1')
  expect(calls[0]!.url).toBe('/api/v1/products/p/diff?from=1.0&to=1.1')
})
