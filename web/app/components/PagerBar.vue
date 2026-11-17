<script setup lang="ts">
// Copyright (c) 2026 Vassel Goleyu. MIT License.
import { id } from '~/i18n/id'
import { PAGE_SIZES } from '~/lib/query'

const props = defineProps<{ page: number; pageSize: number; total: number }>()
const emit = defineEmits<{ page: [value: number]; size: [value: number] }>()
const pages = computed(() => Math.max(1, Math.ceil(props.total / props.pageSize)))
const sizeId = useId()
</script>

<template>
  <nav class="pager" :aria-label="id.common.page">
    <button type="button" :disabled="page <= 1" @click="emit('page', page - 1)">
      {{ id.common.previous }}
    </button>
    <span aria-live="polite">
      {{ id.common.page }} {{ page }} {{ id.common.of }} {{ pages }} ({{ id.common.total }}:
      {{ total }})
    </span>
    <button type="button" :disabled="page >= pages" @click="emit('page', page + 1)">
      {{ id.common.next }}
    </button>
    <label :for="sizeId">{{ id.common.perPage }}</label>
    <select
      :id="sizeId"
      :value="pageSize"
      @change="emit('size', Number(($event.target as HTMLSelectElement).value))"
    >
      <option v-for="n in PAGE_SIZES" :key="n" :value="n">{{ n }}</option>
    </select>
  </nav>
</template>
