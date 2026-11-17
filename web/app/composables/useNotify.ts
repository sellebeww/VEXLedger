// Copyright (c) 2026 Vassel Goleyu. MIT License.
import { messageFor } from '../lib/errors'
import { useToastStore } from '../stores/toasts'

export function useNotify(): {
  success: (text: string) => void
  info: (text: string) => void
  failure: (error: unknown) => void
} {
  const toasts = useToastStore()
  return {
    success: (text) => toasts.push('success', text),
    info: (text) => toasts.push('info', text),
    failure: (error) => toasts.push('error', messageFor(error)),
  }
}
