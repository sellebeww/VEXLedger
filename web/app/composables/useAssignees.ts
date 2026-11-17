// Copyright (c) 2026 Vassel Goleyu. MIT License.
import { id } from '../i18n/id'
import { useSessionStore } from '../stores/session'

export interface AssigneeOption {
  id: string
  label: string
}

/**
 * Who can be assigned. Only admins may list users (GET /admin/users); everyone else can assign
 * to themselves, and other people's assignments show as a generic label.
 */
export function useAssignees(): {
  options: Ref<AssigneeOption[]>
  label: (assigneeId: string | null) => string
} {
  const session = useSessionStore()
  const api = useApi()
  const options = ref<AssigneeOption[]>([])
  const known = new Map<string, string>()

  function setOptions(list: AssigneeOption[]): void {
    options.value = list
    for (const o of list) known.set(o.id, o.label)
  }
  const me = session.user
  if (me && me.role !== 'viewer') setOptions([{ id: me.id, label: id.common.me }])
  if (session.can('admin')) {
    void api
      .users()
      .then((users) =>
        setOptions(
          users
            .filter((u) => u.is_active && u.role !== 'viewer')
            .map((u) => ({
              id: u.id,
              label: u.id === me?.id ? `${u.username} (${id.common.me})` : u.username,
            })),
        ),
      )
      .catch(() => undefined)
  }
  const label = (assigneeId: string | null): string =>
    assigneeId === null
      ? id.common.unassigned
      : assigneeId === me?.id
        ? id.common.me
        : (known.get(assigneeId) ?? id.common.assigned)
  return { options, label }
}
