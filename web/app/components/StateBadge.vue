<script setup lang="ts">
// Copyright (c) 2026 Vassel Goleyu. MIT License.
// State is conveyed by a glyph and a text label, never by colour alone.
import { id } from '~/i18n/id'
import type { FindingState } from '~/lib/types'

defineProps<{ state: FindingState; investigating?: boolean }>()
const tone: Record<FindingState, string> = {
  UNTRIAGED: 'bad',
  NEEDS_REVIEW: 'warn',
  EXPIRED: 'bad',
  INHERITED: 'info',
  TRIAGED: 'ok',
  WITHDRAWN: 'neutral',
}
</script>

<template>
  <span class="badge" :class="tone[state]" :title="id.stateHelp[state]">
    <span aria-hidden="true">{{ id.a11y.stateIcons[state] }}</span>
    <span>{{ id.state[state] }}</span>
    <span v-if="investigating">({{ id.investigating }})</span>
  </span>
</template>
