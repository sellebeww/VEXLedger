// Copyright (c) 2026 Vassel Goleyu. MIT License.
import { defineStore } from 'pinia'
import { computed, ref } from 'vue'
import { atLeast } from '../lib/roles'
import type { Role, Session, User } from '../lib/types'

/** Session state lives in memory only. The cookie is httpOnly; the CSRF token is re-read via /auth/me. */
export const useSessionStore = defineStore('session', () => {
  const user = ref<User | null>(null)
  const csrf = ref<string | null>(null)
  const loaded = ref(false)
  const demoData = ref(false)

  const role = computed<Role | null>(() => user.value?.role ?? null)
  const can = (needed: Role): boolean => atLeast(role.value, needed)

  function set(session: Session): void {
    user.value = session.user
    csrf.value = session.csrf_token
    demoData.value = session.demo_data
    loaded.value = true
  }
  function clear(): void {
    user.value = null
    csrf.value = null
    loaded.value = true
  }
  return { user, csrf, loaded, demoData, role, can, set, clear }
})
