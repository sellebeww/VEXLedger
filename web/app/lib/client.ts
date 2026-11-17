// Copyright (c) 2026 Vassel Goleyu. MIT License.
import { ApiError } from './errors'

export interface ClientDeps {
  fetch: typeof fetch
  baseUrl: string
  getCsrf: () => string | null
  /** Called on a 401 from any call other than login, so the app can drop the session. */
  onUnauthorized: () => void
}

export interface RequestOptions {
  query?: string
  json?: unknown
  form?: FormData
  /** Send an upload with progress (XMLHttpRequest) instead of fetch. */
  onProgress?: (fraction: number) => void
  allowUnauthorized?: boolean
}

const MUTATING = new Set(['POST', 'PUT', 'PATCH', 'DELETE'])

async function toError(res: Response): Promise<ApiError> {
  let body: unknown
  try {
    body = await res.json()
  } catch {
    body = null
  }
  const e = (body as { error?: Record<string, unknown> } | null)?.error
  const retry = Number(res.headers.get('Retry-After'))
  return new ApiError({
    status: res.status,
    code: typeof e?.code === 'string' ? e.code : res.status >= 500 ? 'internal_error' : 'unknown',
    field: typeof e?.field === 'string' ? e.field : null,
    details: (e?.details as Record<string, unknown> | undefined) ?? null,
    requestId: typeof e?.request_id === 'string' ? e.request_id : res.headers.get('X-Request-ID'),
    retryAfter: Number.isFinite(retry) && retry > 0 ? retry : null,
  })
}

export interface Client {
  request: (method: string, path: string, opts?: RequestOptions) => Promise<Response>
  json: <T>(method: string, path: string, opts?: RequestOptions) => Promise<T>
}

export function createClient(deps: ClientDeps): Client {
  async function request(
    method: string,
    path: string,
    opts: RequestOptions = {},
  ): Promise<Response> {
    const headers: Record<string, string> = { Accept: 'application/json' }
    if (opts.json !== undefined) headers['Content-Type'] = 'application/json'
    const body: BodyInit | undefined =
      opts.json !== undefined ? JSON.stringify(opts.json) : opts.form
    if (MUTATING.has(method)) {
      const csrf = deps.getCsrf()
      if (csrf) headers['X-CSRF-Token'] = csrf
    }
    let res: Response
    try {
      res = await deps.fetch(`${deps.baseUrl}${path}${opts.query ?? ''}`, {
        method,
        headers,
        body,
        credentials: 'same-origin',
      })
    } catch {
      throw new ApiError({ status: 0, code: 'network_error' })
    }
    if (!res.ok) {
      const err = await toError(res)
      if (res.status === 401 && !opts.allowUnauthorized) deps.onUnauthorized()
      throw err
    }
    return res
  }

  async function json<T>(method: string, path: string, opts?: RequestOptions): Promise<T> {
    const res = await request(method, path, opts)
    if (res.status === 204) return undefined as T
    try {
      return (await res.json()) as T
    } catch {
      throw new ApiError({ status: res.status, code: 'bad_response' })
    }
  }

  return { request, json }
}

/** Upload with progress: fetch has no upload progress events, XHR does. */
export function uploadWithProgress<T>(
  url: string,
  form: FormData,
  csrf: string | null,
  onProgress: (fraction: number) => void,
  onUnauthorized: () => void,
): Promise<T> {
  return new Promise((resolve, reject) => {
    const xhr = new XMLHttpRequest()
    xhr.open('POST', url)
    xhr.withCredentials = true
    xhr.setRequestHeader('Accept', 'application/json')
    if (csrf) xhr.setRequestHeader('X-CSRF-Token', csrf)
    xhr.upload.onprogress = (ev) => {
      if (ev.lengthComputable) onProgress(ev.loaded / ev.total)
    }
    xhr.onerror = () => reject(new ApiError({ status: 0, code: 'network_error' }))
    xhr.onload = () => {
      let parsed: unknown
      try {
        parsed = JSON.parse(xhr.responseText)
      } catch {
        parsed = null
      }
      if (xhr.status >= 200 && xhr.status < 300) {
        if (parsed === null) reject(new ApiError({ status: xhr.status, code: 'bad_response' }))
        else resolve(parsed as T)
        return
      }
      if (xhr.status === 401) onUnauthorized()
      const e = (parsed as { error?: Record<string, unknown> } | null)?.error
      reject(
        new ApiError({
          status: xhr.status,
          code: typeof e?.code === 'string' ? e.code : 'unknown',
          field: typeof e?.field === 'string' ? e.field : null,
          details: (e?.details as Record<string, unknown> | undefined) ?? null,
          requestId: typeof e?.request_id === 'string' ? e.request_id : null,
        }),
      )
    }
    xhr.send(form)
  })
}
