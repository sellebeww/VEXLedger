<script setup lang="ts">
// Copyright (c) 2026 Vassel Goleyu. MIT License.
import { id } from '~/i18n/id'
import { useToastStore } from '~/stores/toasts'

const toasts = useToastStore()
const cls = { success: 'ok', error: 'bad', info: 'info' } as const
</script>

<template>
  <div class="toasts" role="region" :aria-label="id.a11y.toasts">
    <div
      v-for="t in toasts.items"
      :key="t.key"
      class="notice toast"
      :class="cls[t.kind]"
      :role="t.kind === 'error' ? 'alert' : 'status'"
    >
      <span class="plain-text">{{ t.text }}</span>
      <button type="button" :aria-label="id.common.close" @click="toasts.dismiss(t.key)">
        {{ id.common.close }}
      </button>
    </div>
  </div>
</template>
