<script setup lang="ts">
// Copyright (c) 2026 Vassel Goleyu. MIT License.
import { id } from '~/i18n/id'
import { ApiError } from '~/lib/errors'
import { useSessionStore } from '~/stores/session'

const session = useSessionStore()
const api = useApi()
const router = useRouter()
const notify = useNotify()

async function logout(): Promise<void> {
  try {
    await api.logout()
  } catch (error) {
    // Stay signed in on screen when the server could not end the session (401 means it is gone).
    if (!(error instanceof ApiError)) throw error
    if (error.status !== 401) {
      notify.failure(error)
      return
    }
  }
  session.clear()
  await router.push('/login')
}
</script>

<template>
  <div v-if="session.demoData" class="demo-banner" role="status">{{ id.demoBanner }}</div>
  <a href="#main" class="skip-link">{{ id.common.skipToContent }}</a>
  <header class="shell-header">
    <NuxtLink to="/products" class="brand">{{ id.appName }}</NuxtLink>
    <nav v-if="session.user" :aria-label="id.common.mainNav">
      <NuxtLink to="/products">{{ id.nav.products }}</NuxtLink>
      <NuxtLink v-if="session.can('admin')" to="/admin">{{ id.nav.admin }}</NuxtLink>
    </nav>
    <span v-else class="grow"></span>
    <span v-if="session.user" class="muted">
      {{ id.nav.signedInAs }} {{ session.user.username }} ({{ id.roles[session.user.role] }})
    </span>
    <button v-if="session.user" type="button" @click="logout">{{ id.nav.logout }}</button>
  </header>
  <main id="main" tabindex="-1">
    <NuxtPage />
  </main>
  <ToastHost />
</template>
