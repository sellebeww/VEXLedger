// Copyright (c) 2026 Vassel Goleyu. MIT License.
import { defineStore } from 'pinia'
import { ref } from 'vue'

export interface Toast {
  key: number
  kind: 'success' | 'error' | 'info'
  text: string
}

export const useToastStore = defineStore('toasts', () => {
  const items = ref<Toast[]>([])
  let next = 1
  function push(kind: Toast['kind'], text: string): void {
    const key = next++
    items.value.push({ key, kind, text })
    // Errors stay until dismissed; the rest disappear on their own.
    if (kind !== 'error') setTimeout(() => dismiss(key), 6000)
  }
  function dismiss(key: number): void {
    items.value = items.value.filter((t) => t.key !== key)
  }
  return { items, push, dismiss }
})
