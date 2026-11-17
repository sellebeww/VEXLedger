<script setup lang="ts">
// Copyright (c) 2026 Vassel Goleyu. MIT License.
import { id } from '~/i18n/id'
import { fieldErrorsOf, messageFor } from '~/lib/errors'
import { useSessionStore } from '~/stores/session'

const api = useApi()
const session = useSessionStore()
const notify = useNotify()
const list = useLoad(() => api.products())

const open = ref(false)
const form = reactive({ slug: '', name: '', purl: '', vex_author: '' })
const errors = ref<Record<string, string>>({})
const formError = ref<string | null>(null)
const busy = ref(false)

const SLUG = /^[a-z0-9][a-z0-9-]{0,62}$/
function localErrors(): Record<string, string> {
  const out: Record<string, string> = {}
  if (!SLUG.test(form.slug)) out.slug = id.fieldErrors.slug
  if (!form.name.trim()) out.name = id.fieldErrors.required
  if (!form.purl.trim()) out.purl = id.fieldErrors.required
  if (!form.vex_author.trim()) out.vex_author = id.fieldErrors.required
  return out
}

async function create(): Promise<void> {
  formError.value = null
  errors.value = localErrors()
  if (Object.keys(errors.value).length) return
  busy.value = true
  try {
    const product = await api.createProduct({ ...form })
    open.value = false
    await navigateTo(`/products/${product.slug}`)
  } catch (e) {
    errors.value = fieldErrorsOf(e)
    formError.value = messageFor(e)
    notify.failure(e)
  } finally {
    busy.value = false
  }
}
</script>

<template>
  <div>
    <div class="row">
      <h1 class="grow">{{ id.products.title }}</h1>
      <button v-if="session.can('admin')" type="button" class="primary" @click="open = true">
        {{ id.products.create }}
      </button>
    </div>
    <AsyncBlock
      :loading="list.loading.value"
      :error="list.error.value"
      :empty="list.data.value?.length === 0"
      :empty-text="id.products.empty"
      :empty-hint="id.products.emptyHint"
      @retry="list.reload"
    >
      <DataTable
        v-if="list.data.value"
        :caption="id.products.title"
        :columns="[
          { id: 'name', header: id.common.name },
          { id: 'purl', header: id.products.purl },
          { id: 'vex_author', header: id.products.author },
          { id: 'actions', header: id.common.actions },
        ]"
        :rows="list.data.value"
      >
        <template #cell-name="{ row }">
          <NuxtLink :to="`/products/${row.slug}`">{{ row.name }}</NuxtLink>
          <div class="muted mono">{{ row.slug }}</div>
        </template>
        <template #cell-purl="{ row }"
          ><span class="mono">{{ row.purl }}</span></template
        >
        <template #cell-actions="{ row }">
          <NuxtLink :to="`/products/${row.slug}/settings`">{{ id.products.settings }}</NuxtLink>
        </template>
      </DataTable>
    </AsyncBlock>

    <AppModal :open="open" :title="id.products.createTitle" @close="open = false">
      <form @submit.prevent="create">
        <FormField
          v-slot="f"
          :label="id.products.slug"
          :hint="id.products.slugHint"
          :error="errors.slug"
        >
          <input
            :id="f.id"
            v-model="form.slug"
            :aria-describedby="f.describedBy"
            :aria-invalid="f.invalid"
            autocomplete="off"
          />
        </FormField>
        <FormField v-slot="f" :label="id.common.name" :error="errors.name">
          <input
            :id="f.id"
            v-model="form.name"
            :aria-describedby="f.describedBy"
            :aria-invalid="f.invalid"
          />
        </FormField>
        <FormField
          v-slot="f"
          :label="id.products.purl"
          :hint="id.products.purlHint"
          :error="errors.purl"
        >
          <input
            :id="f.id"
            v-model="form.purl"
            :aria-describedby="f.describedBy"
            :aria-invalid="f.invalid"
            autocomplete="off"
          />
        </FormField>
        <FormField
          v-slot="f"
          :label="id.products.author"
          :hint="id.products.authorHint"
          :error="errors.vex_author"
        >
          <input
            :id="f.id"
            v-model="form.vex_author"
            :aria-describedby="f.describedBy"
            :aria-invalid="f.invalid"
          />
        </FormField>
        <p v-if="formError" class="notice bad" role="alert">{{ formError }}</p>
        <div class="row end">
          <button type="button" @click="open = false">{{ id.common.cancel }}</button>
          <button type="submit" class="primary" :disabled="busy">{{ id.common.create }}</button>
        </div>
      </form>
    </AppModal>
  </div>
</template>
