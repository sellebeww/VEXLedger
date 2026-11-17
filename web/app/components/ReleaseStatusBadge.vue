<script setup lang="ts">
// Copyright (c) 2026 Vassel Goleyu. MIT License.
import { id } from '~/i18n/id'
import type { MatchStatus } from '~/lib/types'

defineProps<{ status: MatchStatus }>()
const tone: Record<MatchStatus, string> = {
  MATCH_PENDING: 'warn',
  MATCHED: 'ok',
  MATCH_FAILED: 'bad',
}
const icon: Record<MatchStatus, string> = { MATCH_PENDING: '⌛', MATCHED: '✓', MATCH_FAILED: '✕' }
</script>

<template>
  <span class="badge" :class="tone[status]">
    <span aria-hidden="true">{{ icon[status] }}</span>
    <span>{{ id.releaseStatus[status] }}</span>
  </span>
</template>
