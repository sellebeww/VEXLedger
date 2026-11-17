<script setup lang="ts">
// Copyright (c) 2026 Vassel Goleyu. MIT License.
// Consistent loading, error and empty states for every page.
import { id } from '~/i18n/id'
import { type ApiError, messageForCode } from '~/lib/errors'

defineProps<{
  loading: boolean
  error: ApiError | null
  empty?: boolean
  emptyText?: string
  emptyHint?: string
}>()
const emit = defineEmits<{ retry: [] }>()
</script>

<template>
  <div v-if="error" class="notice bad" role="alert">
    <p>
      <strong>{{ id.common.errorTitle }}{{ id.common.separator }}</strong>
      {{ messageForCode(error.code) }}
    </p>
    <p v-if="error.requestId" class="muted">
      {{ id.common.requestId }}{{ id.common.separator }}
      <span class="mono">{{ error.requestId }}</span>
    </p>
    <button type="button" @click="emit('retry')">{{ id.common.retry }}</button>
  </div>
  <p v-else-if="loading && !$slots.default" role="status">{{ id.common.loading }}</p>
  <template v-else>
    <p v-if="loading" role="status" class="muted">{{ id.common.loading }}</p>
    <div v-if="empty && !loading" class="notice info">
      <p>
        <strong>{{ emptyText ?? id.common.emptyTitle }}</strong>
      </p>
      <p v-if="emptyHint">{{ emptyHint }}</p>
    </div>
    <slot v-else />
  </template>
</template>
