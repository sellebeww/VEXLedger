// Copyright (c) 2026 Vassel Goleyu. MIT License.
import type { Role } from './types'

const RANK: Record<Role, number> = { viewer: 0, analyst: 1, admin: 2 }

export function atLeast(role: Role | null | undefined, needed: Role): boolean {
  return role != null && RANK[role] >= RANK[needed]
}

/** Minimum role per route path (the server enforces the same; this only hides dead ends). */
export function requiredRole(path: string): Role | 'public' {
  if (path === '/login') return 'public'
  if (path === '/admin' || path.startsWith('/admin/')) return 'admin'
  return 'viewer'
}
