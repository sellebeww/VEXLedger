// Copyright (c) 2026 Vassel Goleyu. MIT License.
import { id } from '../i18n/id'

/** UTC timestamps from the API shown in the viewer's locale and time zone. */
export function formatDateTime(value: string | null | undefined): string {
  if (!value) return id.common.never
  const d = new Date(value)
  if (Number.isNaN(d.getTime())) return id.common.unknown
  return new Intl.DateTimeFormat('id-ID', { dateStyle: 'medium', timeStyle: 'short' }).format(d)
}

/** Value for <input type="datetime-local"> (local time, minute precision). */
export function toLocalInput(d: Date): string {
  const pad = (n: number): string => String(n).padStart(2, '0')
  return `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())}T${pad(d.getHours())}:${pad(d.getMinutes())}`
}

export function shortHash(hash: string): string {
  return hash.slice(0, 12)
}
