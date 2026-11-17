// Copyright (c) 2026 Vassel Goleyu. MIT License.
import { ApiError } from '../lib/errors'
import { atLeast, requiredRole } from '../lib/roles'
import { useSessionStore } from '../stores/session'

/** Route guard per role. The server enforces the same rules; this removes dead ends from the UI. */
export default defineNuxtRouteMiddleware(async (to) => {
  const session = useSessionStore()
  const needed = requiredRole(to.path)
  if (!session.loaded) {
    try {
      session.set(await useApi().me())
    } catch (error) {
      // 401 or an unreachable server: show the login page (its submit reports the real problem).
      if (!(error instanceof ApiError)) throw error
      session.clear()
    }
  }
  if (needed === 'public') {
    return session.user && to.path === '/login' ? navigateTo('/products') : undefined
  }
  if (!session.user) return navigateTo({ path: '/login', query: { next: to.fullPath } })
  if (!atLeast(session.role, needed)) return navigateTo('/products')
})
