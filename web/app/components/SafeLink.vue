<script setup lang="ts">
// Copyright (c) 2026 Vassel Goleyu. MIT License.
// User-supplied URLs become links only when they are http(s); otherwise they stay plain text.
import { id } from '~/i18n/id'
import { safeHttpUrl } from '~/lib/safe-url'

const props = defineProps<{ href: string | null | undefined; text?: string }>()
const url = computed(() => safeHttpUrl(props.href))
</script>

<template>
  <a v-if="url" :href="url" target="_blank" rel="noopener noreferrer" class="plain-text">
    {{ text ?? url }}
    <span class="sr-only">({{ id.common.opensInNewTab }})</span>
  </a>
  <span v-else class="plain-text">{{ text ?? href }}</span>
</template>
