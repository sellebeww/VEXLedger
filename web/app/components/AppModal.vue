<script setup lang="ts">
// Copyright (c) 2026 Vassel Goleyu. MIT License.
// Native <dialog>: focus is trapped, Escape closes, focus returns to the opener.
import { id } from '~/i18n/id'

const props = defineProps<{ open: boolean; title: string }>()
const emit = defineEmits<{ close: [] }>()
const dialog = ref<HTMLDialogElement | null>(null)
const titleId = useId()

function sync(): void {
  const el = dialog.value
  if (!el) return
  if (props.open && !el.open) el.showModal()
  else if (!props.open && el.open) el.close()
}
watch(() => props.open, sync, { flush: 'post' })
onMounted(sync)
</script>

<template>
  <dialog
    ref="dialog"
    :aria-labelledby="titleId"
    @close="emit('close')"
    @cancel.prevent="emit('close')"
  >
    <div v-if="open" class="stack">
      <div class="row">
        <h2 :id="titleId" class="grow">{{ title }}</h2>
        <button type="button" :aria-label="id.a11y.dialogClose" @click="emit('close')">
          {{ id.common.close }}
        </button>
      </div>
      <slot />
    </div>
  </dialog>
</template>
