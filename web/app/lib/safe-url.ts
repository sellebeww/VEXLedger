// Copyright (c) 2026 Vassel Goleyu. MIT License.
/** Only absolute http(s) URLs with a host may become links. Everything else renders as text. */
export function safeHttpUrl(value: string | null | undefined): string | null {
  if (!value || /\s/.test(value) || !/^https?:\/\//.test(value)) return null
  try {
    const url = new URL(value)
    return (url.protocol === 'http:' || url.protocol === 'https:') && url.hostname ? value : null
  } catch {
    return null
  }
}

/** Evidence downloads are same-origin API paths only. */
export function safeDownloadPath(value: string | null | undefined): string | null {
  return value && /^\/api\/v1\/evidence-files\/[0-9a-f-]{36}\/download$/.test(value) ? value : null
}
