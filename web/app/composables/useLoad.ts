// Copyright (c) 2026 Vassel Goleyu. MIT License.
import { ref, type Ref } from 'vue'
import { ApiError } from '../lib/errors'

export interface Loader<T> {
  data: Ref<T | null>
  loading: Ref<boolean>
  error: Ref<ApiError | null>
  reload: () => Promise<void>
}

/** Runs `fn` now and on reload; keeps the previous data while reloading. */
export function useLoad<T>(fn: () => Promise<T>): Loader<T> {
  const data = ref<T | null>(null) as Ref<T | null>
  const loading = ref(true)
  const error = ref<ApiError | null>(null)
  let seq = 0
  async function reload(): Promise<void> {
    const mine = ++seq
    loading.value = true
    try {
      const value = await fn()
      if (mine !== seq) return
      data.value = value
      error.value = null
    } catch (e) {
      if (mine !== seq) return
      error.value = e instanceof ApiError ? e : new ApiError({ status: 0, code: 'unknown' })
    } finally {
      if (mine === seq) loading.value = false
    }
  }
  void reload()
  return { data, loading, error, reload }
}
