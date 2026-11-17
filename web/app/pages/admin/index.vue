<script setup lang="ts">
// Copyright (c) 2026 Vassel Goleyu. MIT License.
import { id } from '~/i18n/id'
import { ApiError, fieldErrorsOf } from '~/lib/errors'
import { formatDateTime } from '~/lib/format'
import type { ApiTokenCreated, AuditEntry, Role } from '~/lib/types'

const api = useApi()
const notify = useNotify()
const route = useRoute()
const router = useRouter()

const TABS = ['users', 'tokens', 'audit'] as const
type Tab = (typeof TABS)[number]
const tab = computed<Tab>(() =>
  (TABS as readonly string[]).includes(String(route.query.tab))
    ? (route.query.tab as Tab)
    : 'users',
)
const setTab = (t: Tab): void => void router.replace({ query: { tab: t } })
const onTabKey = (ev: KeyboardEvent): void => {
  const i = TABS.indexOf(tab.value)
  if (ev.key === 'ArrowRight') setTab(TABS[(i + 1) % TABS.length]!)
  else if (ev.key === 'ArrowLeft') setTab(TABS[(i + TABS.length - 1) % TABS.length]!)
  else return
  ev.preventDefault()
}

// ---- users
const users = useLoad(() => api.users())
const userForm = reactive({ username: '', password: '', role: 'analyst' as Role })
const userErrors = ref<Record<string, string>>({})
const newPassword = reactive<Record<string, string>>({})
async function createUser(): Promise<void> {
  userErrors.value = {}
  if (userForm.password.length < 12) userErrors.value.password = id.fieldErrors.password
  if (!userForm.username) userErrors.value.username = id.fieldErrors.required
  if (Object.keys(userErrors.value).length) return
  try {
    await api.createUser(userForm.username, userForm.password, userForm.role)
    notify.success(id.admin.userCreated)
    userForm.username = ''
    userForm.password = ''
    await users.reload()
  } catch (e) {
    userErrors.value = fieldErrorsOf(e)
    notify.failure(e)
  }
}
async function patchUser(
  userId: string,
  body: { role?: Role; is_active?: boolean; password?: string },
): Promise<void> {
  try {
    await api.patchUser(userId, body)
    notify.success(id.admin.userUpdated)
    newPassword[userId] = ''
    await users.reload()
  } catch (e) {
    notify.failure(e)
    await users.reload()
  }
}

// ---- tokens
const all = useLoad(() => api.allTokens())
const tokenName = ref('')
const created = ref<ApiTokenCreated | null>(null)
const nameOf = (userId: string): string =>
  users.data.value?.find((u) => u.id === userId)?.username ?? userId
async function createToken(): Promise<void> {
  if (!tokenName.value.trim()) return
  try {
    created.value = await api.createToken(tokenName.value.trim())
    tokenName.value = ''
    await all.reload()
  } catch (e) {
    notify.failure(e)
  }
}
async function copyToken(): Promise<void> {
  if (!created.value) return
  await navigator.clipboard.writeText(created.value.token)
  notify.success(id.admin.tokenCopied)
}
async function revoke(tokenId: string): Promise<void> {
  if (!window.confirm(id.admin.confirmRevoke)) return
  try {
    await api.revokeToken(tokenId)
    notify.success(id.admin.tokenRevoked)
    await all.reload()
  } catch (e) {
    notify.failure(e)
  }
}

// ---- audit
const entityType = ref('')
const action = ref('')
const entries = ref<AuditEntry[]>([])
const nextBefore = ref<number | null>(null)
const auditBusy = ref(false)
const auditError = ref<ApiError | null>(null)
async function loadAudit(more: boolean): Promise<void> {
  auditBusy.value = true
  auditError.value = null
  try {
    const page = await api.audit({
      entity_type: entityType.value || undefined,
      action: action.value || undefined,
      before_id: more ? nextBefore.value : null,
    })
    entries.value = more ? [...entries.value, ...page.items] : page.items
    nextBefore.value = page.next_before_id
  } catch (e) {
    auditError.value = e instanceof ApiError ? e : null
    notify.failure(e)
  } finally {
    auditBusy.value = false
  }
}
onMounted(() => void loadAudit(false))
const actorName = (a: string | null): string => (a ? nameOf(a) : id.admin.system)
const json = (v: unknown): string => (v ? JSON.stringify(v) : '')
const ROLES: Role[] = ['admin', 'analyst', 'viewer']
</script>

<template>
  <div>
    <h1>{{ id.admin.title }}</h1>
    <div role="tablist" :aria-label="id.admin.tabs" class="row" @keydown="onTabKey">
      <button
        v-for="t in TABS"
        :id="`tab-${t}`"
        :key="t"
        type="button"
        role="tab"
        :aria-selected="tab === t"
        :aria-controls="`panel-${t}`"
        :tabindex="tab === t ? 0 : -1"
        :class="{ primary: tab === t }"
        @click="setTab(t)"
      >
        {{ id.admin[t] }}
      </button>
    </div>

    <section
      v-show="tab === 'users'"
      id="panel-users"
      role="tabpanel"
      aria-labelledby="tab-users"
      class="stack"
    >
      <form class="card row" style="align-items: start" @submit.prevent="createUser">
        <FormField v-slot="f" :label="id.admin.username" :error="userErrors.username">
          <input
            :id="f.id"
            v-model="userForm.username"
            autocomplete="off"
            :aria-describedby="f.describedBy"
            :aria-invalid="f.invalid"
          />
        </FormField>
        <FormField v-slot="f" :label="id.admin.password" :error="userErrors.password">
          <input
            :id="f.id"
            v-model="userForm.password"
            type="password"
            autocomplete="new-password"
            :aria-describedby="f.describedBy"
            :aria-invalid="f.invalid"
          />
        </FormField>
        <FormField v-slot="f" :label="id.admin.role">
          <select :id="f.id" v-model="userForm.role">
            <option v-for="r in ROLES" :key="r" :value="r">{{ id.roles[r] }}</option>
          </select>
        </FormField>
        <button type="submit" class="primary">{{ id.admin.newUser }}</button>
      </form>
      <AsyncBlock :loading="users.loading.value" :error="users.error.value" @retry="users.reload">
        <DataTable
          v-if="users.data.value"
          :caption="id.admin.users"
          :columns="[
            { id: 'username', header: id.admin.username },
            { id: 'role', header: id.admin.role },
            { id: 'is_active', header: id.triage.status },
            { id: 'actions', header: id.common.actions },
          ]"
          :rows="users.data.value"
        >
          <template #cell-role="{ row }">
            <select
              :aria-label="`${id.admin.role} ${row.username}`"
              :value="row.role"
              @change="
                patchUser(row.id, { role: ($event.target as HTMLSelectElement).value as Role })
              "
            >
              <option v-for="r in ROLES" :key="r" :value="r">{{ id.roles[r] }}</option>
            </select>
          </template>
          <template #cell-is_active="{ row }">
            <span class="badge" :class="row.is_active ? 'ok' : 'neutral'">{{
              row.is_active ? id.admin.active : id.admin.inactive
            }}</span>
          </template>
          <template #cell-actions="{ row }">
            <div class="row">
              <button type="button" @click="patchUser(row.id, { is_active: !row.is_active })">
                {{ row.is_active ? id.admin.deactivate : id.admin.activate }}
              </button>
              <input
                v-model="newPassword[row.id]"
                type="password"
                autocomplete="new-password"
                :aria-label="`${id.admin.newPassword} ${row.username}`"
              />
              <button
                type="button"
                :disabled="!newPassword[row.id] || newPassword[row.id]!.length < 12"
                @click="patchUser(row.id, { password: newPassword[row.id] })"
              >
                {{ id.admin.setPassword }}
              </button>
            </div>
          </template>
        </DataTable>
      </AsyncBlock>
    </section>

    <section
      v-show="tab === 'tokens'"
      id="panel-tokens"
      role="tabpanel"
      aria-labelledby="tab-tokens"
      class="stack"
    >
      <h2>{{ id.admin.myTokens }}</h2>
      <form class="row" style="align-items: end" @submit.prevent="createToken">
        <FormField v-slot="f" :label="id.admin.tokenName">
          <input :id="f.id" v-model="tokenName" maxlength="100" />
        </FormField>
        <button type="submit" class="primary" style="margin-bottom: 0.9rem">
          {{ id.admin.createToken }}
        </button>
      </form>
      <div v-if="created" class="notice ok" role="status">
        <strong>{{ id.admin.tokenCreatedTitle }}</strong>
        <p>{{ id.admin.tokenShownOnce }}</p>
        <p class="mono">{{ created.token }}</p>
        <button type="button" @click="copyToken">{{ id.common.copy }}</button>
        <button type="button" @click="created = null">{{ id.common.close }}</button>
      </div>
      <h2>{{ id.admin.allTokens }}</h2>
      <AsyncBlock
        :loading="all.loading.value"
        :error="all.error.value"
        :empty="all.data.value?.length === 0"
        :empty-text="id.admin.noTokens"
        @retry="all.reload"
      >
        <DataTable
          v-if="all.data.value"
          :caption="id.admin.allTokens"
          :columns="[
            { id: 'name', header: id.common.name },
            { id: 'user_id', header: id.admin.owner },
            { id: 'last_used_at', header: id.admin.lastUsed },
            { id: 'revoked_at', header: id.admin.revokedAt },
            { id: 'actions', header: id.common.actions },
          ]"
          :rows="all.data.value"
        >
          <template #cell-user_id="{ row }">{{ nameOf(row.user_id) }}</template>
          <template #cell-last_used_at="{ row }">{{ formatDateTime(row.last_used_at) }}</template>
          <template #cell-revoked_at="{ row }">{{
            row.revoked_at ? formatDateTime(row.revoked_at) : id.common.none
          }}</template>
          <template #cell-actions="{ row }">
            <button v-if="!row.revoked_at" type="button" class="danger" @click="revoke(row.id)">
              {{ id.admin.revoke }}
            </button>
          </template>
        </DataTable>
      </AsyncBlock>
    </section>

    <section
      v-show="tab === 'audit'"
      id="panel-audit"
      role="tabpanel"
      aria-labelledby="tab-audit"
      class="stack"
    >
      <form class="card row" style="align-items: end" @submit.prevent="loadAudit(false)">
        <FormField v-slot="f" :label="id.admin.auditFilterType"
          ><input :id="f.id" v-model="entityType"
        /></FormField>
        <FormField v-slot="f" :label="id.admin.auditFilterAction"
          ><input :id="f.id" v-model="action"
        /></FormField>
        <button type="submit" style="margin-bottom: 0.9rem">{{ id.admin.auditApply }}</button>
      </form>
      <AsyncBlock
        :loading="auditBusy"
        :error="auditError"
        :empty="!auditBusy && entries.length === 0"
        :empty-text="id.admin.auditEmpty"
        @retry="loadAudit(false)"
      >
        <DataTable
          :caption="id.admin.audit"
          :columns="[
            { id: 'at', header: id.admin.colAt },
            { id: 'actor_id', header: id.admin.colActor },
            { id: 'action', header: id.admin.colAction },
            { id: 'entity', header: id.admin.colEntity },
            { id: 'change', header: id.admin.colChange },
            { id: 'reason', header: id.admin.colReason },
          ]"
          :rows="entries.map((e) => ({ ...e, id: String(e.id) }))"
        >
          <template #cell-at="{ row }">{{ formatDateTime(row.at) }}</template>
          <template #cell-actor_id="{ row }">{{ actorName(row.actor_id) }}</template>
          <template #cell-entity="{ row }"
            ><span class="mono">{{ row.entity_type }} {{ row.entity_id }}</span></template
          >
          <template #cell-change="{ row }"
            ><span class="mono plain-text"
              >{{ json(row.before) }} {{ id.diff.arrow }} {{ json(row.after) }}</span
            ></template
          >
        </DataTable>
        <button v-if="nextBefore" type="button" :disabled="auditBusy" @click="loadAudit(true)">
          {{ id.admin.auditMore }}
        </button>
      </AsyncBlock>
    </section>
  </div>
</template>
