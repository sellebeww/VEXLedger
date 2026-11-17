<script setup lang="ts">
// Copyright (c) 2026 Vassel Goleyu. MIT License.
// Label + hint + error wired to the control through aria-describedby (the control gets the ids).
// Hint and error elements exist only while they have text, so screen readers hear no empty alerts.
const props = defineProps<{ label: string; error?: string | null; hint?: string }>()
const base = useId()
const describedBy = computed(
  () =>
    [props.hint ? `${base}-h` : '', props.error ? `${base}-e` : ''].filter(Boolean).join(' ') ||
    undefined,
)
</script>

<template>
  <div class="field" :class="{ invalid: !!error }">
    <label class="label" :for="`${base}-c`">{{ label }}</label>
    <slot :id="`${base}-c`" :described-by="describedBy" :invalid="!!error" />
    <span v-if="hint" :id="`${base}-h`" class="hint">{{ hint }}</span>
    <span v-if="error" :id="`${base}-e`" class="error" role="alert">{{ error }}</span>
  </div>
</template>
