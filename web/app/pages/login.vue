<script setup lang="ts">
// Copyright (c) 2026 Vassel Goleyu. MIT License.
import { id } from '~/i18n/id'
import { ApiError, messageFor } from '~/lib/errors'
import { useSessionStore } from '~/stores/session'

const api = useApi()
const session = useSessionStore()
const route = useRoute()

const username = ref('')
const password = ref('')
const busy = ref(false)
const error = ref<string | null>(null)

/** Only same-app paths are accepted as the post-login target (no open redirect). */
function target(): string {
  const next = typeof route.query.next === 'string' ? route.query.next : ''
  return /^\/(?![/\\])/.test(next) ? next : '/products'
}

async function submit(): Promise<void> {
  busy.value = true
  error.value = null
  try {
    session.set(await api.login(username.value, password.value))
    password.value = ''
    await navigateTo(target())
  } catch (e) {
    error.value =
      e instanceof ApiError && e.retryAfter
        ? `${messageFor(e)} ${id.login.retryAfter(e.retryAfter)}`
        : messageFor(e)
  } finally {
    busy.value = false
  }
}
</script>

<template>
  <div class="card" style="max-width: 26rem; margin: 2rem auto">
    <h1>{{ id.login.title }}</h1>
    <p class="muted">{{ id.tagline }}</p>
    <p v-if="route.query.expired" class="notice info" role="status">
      {{ id.login.sessionExpired }}
    </p>
    <form @submit.prevent="submit">
      <FormField v-slot="f" :label="id.login.username">
        <input
          :id="f.id"
          v-model="username"
          name="username"
          autocomplete="username"
          required
          :aria-describedby="f.describedBy"
        />
      </FormField>
      <FormField v-slot="f" :label="id.login.password">
        <input
          :id="f.id"
          v-model="password"
          name="password"
          type="password"
          autocomplete="current-password"
          required
          :aria-describedby="f.describedBy"
        />
      </FormField>
      <p v-if="error" class="notice bad" role="alert">{{ error }}</p>
      <button type="submit" class="primary" :disabled="busy">
        {{ busy ? id.login.submitting : id.login.submit }}
      </button>
    </form>
    <h2>{{ id.honestTitle }}</h2>
    <ul>
      <li v-for="line in id.honest" :key="line">{{ line }}</li>
    </ul>
  </div>
</template>
