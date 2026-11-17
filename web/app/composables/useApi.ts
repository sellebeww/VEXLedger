// Copyright (c) 2026 Vassel Goleyu. MIT License.
import { createApi, type Api } from '../lib/api'
import { createClient } from '../lib/client'
import { useSessionStore } from '../stores/session'

let cached: Api | null = null

/** One typed API instance per page load; CSRF and 401 handling go through the session store. */
export function useApi(): Api {
  if (cached) return cached
  const session = useSessionStore()
  const router = useRouter()
  const onUnauthorized = (): void => {
    session.clear()
    const route = router.currentRoute.value
    if (route.path !== '/login') {
      void router.push({ path: '/login', query: { next: route.fullPath, expired: '1' } })
    }
  }
  const getCsrf = (): string | null => session.csrf
  const client = createClient({
    fetch: (...a) => fetch(...a),
    baseUrl: '',
    getCsrf,
    onUnauthorized,
  })
  cached = createApi({ client, getCsrf, onUnauthorized })
  return cached
}
