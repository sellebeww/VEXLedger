<script setup lang="ts">
// Copyright (c) 2026 Vassel Goleyu. MIT License.
import { id } from '~/i18n/id'

defineProps<{ items: { label: string; to?: string }[] }>()
</script>

<template>
  <nav :aria-label="id.common.breadcrumb">
    <ol class="crumbs">
      <li v-for="(item, i) in items" :key="i">
        <span v-if="i > 0" aria-hidden="true">{{ id.a11y.breadcrumbSep }}</span>
        <NuxtLink v-if="item.to" :to="item.to">{{ item.label }}</NuxtLink>
        <span v-else aria-current="page">{{ item.label }}</span>
      </li>
    </ol>
  </nav>
</template>
