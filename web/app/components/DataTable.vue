<script setup lang="ts" generic="T extends { id: string }">
// Copyright (c) 2026 Vassel Goleyu. MIT License.
// Server-side table on TanStack Table v9: the server sorts and paginates (manual*), the table
// renders rows, headers and row selection. Cells are rendered through `cell-<column id>` slots.
import {
  FlexRender,
  rowSelectionFeature,
  rowSortingFeature,
  tableFeatures,
  useTable,
  type RowSelectionState,
  type Updater,
} from '@tanstack/vue-table'
import { id } from '~/i18n/id'

interface Col {
  id: string
  header: string
  sortable?: boolean
}
interface Sort {
  key: string
  order: 'asc' | 'desc'
}

const props = defineProps<{
  caption: string
  columns: Col[]
  rows: T[]
  sort?: Sort
  selectable?: boolean
  selection?: Record<string, boolean>
  rowLabel?: (row: T) => string
}>()
const emit = defineEmits<{
  sort: [key: string]
  'update:selection': [value: Record<string, boolean>]
}>()

const features = tableFeatures({ rowSortingFeature, rowSelectionFeature })
const resolve = <V,>(updater: Updater<V>, previous: V): V =>
  typeof updater === 'function' ? (updater as (old: V) => V)(previous) : updater

const table = useTable({
  features,
  columns: computed(() =>
    props.columns.map((c) => ({
      id: c.id,
      header: c.header,
      accessorFn: (row: T): unknown => (row as Record<string, unknown>)[c.id],
    })),
  ),
  data: computed(() => props.rows),
  manualSorting: true,
  getRowId: (row: T) => row.id,
  enableRowSelection: computed(() => !!props.selectable),
  state: computed(() => ({ rowSelection: (props.selection ?? {}) as RowSelectionState })),
  onRowSelectionChange: (updater: Updater<RowSelectionState>) =>
    emit('update:selection', resolve(updater, (props.selection ?? {}) as RowSelectionState)),
})

function ariaSort(col: Col): 'ascending' | 'descending' | 'none' | undefined {
  if (!col.sortable) return undefined
  if (props.sort?.key !== col.id) return 'none'
  return props.sort.order === 'asc' ? 'ascending' : 'descending'
}
function sortHint(col: Col): string {
  if (props.sort?.key !== col.id) return id.a11y.notSorted
  return props.sort.order === 'asc' ? id.a11y.sortedAsc : id.a11y.sortedDesc
}
</script>

<template>
  <div class="table-wrap">
    <table>
      <caption class="sr-only">
        {{
          caption
        }}
      </caption>
      <thead>
        <tr>
          <th v-if="selectable" scope="col">
            <input
              type="checkbox"
              :aria-label="id.release.selectAll"
              :checked="table.getIsAllRowsSelected()"
              :indeterminate="table.getIsSomeRowsSelected() && !table.getIsAllRowsSelected()"
              @change="table.toggleAllRowsSelected(($event.target as HTMLInputElement).checked)"
            />
          </th>
          <th v-for="col in columns" :key="col.id" scope="col" :aria-sort="ariaSort(col)">
            <button v-if="col.sortable" type="button" @click="emit('sort', col.id)">
              {{ col.header }}
              <span aria-hidden="true">{{
                sort?.key === col.id ? (sort.order === 'asc' ? '▲' : '▼') : '↕'
              }}</span>
              <span class="sr-only">({{ sortHint(col) }})</span>
            </button>
            <template v-else>{{ col.header }}</template>
          </th>
        </tr>
      </thead>
      <tbody>
        <tr
          v-for="row in table.getRowModel().rows"
          :key="row.id"
          :aria-selected="selectable ? row.getIsSelected() : undefined"
        >
          <td v-if="selectable">
            <input
              type="checkbox"
              :aria-label="id.release.selectRow(rowLabel ? rowLabel(row.original) : row.id)"
              :checked="row.getIsSelected()"
              @change="row.toggleSelected(($event.target as HTMLInputElement).checked)"
            />
          </td>
          <td v-for="cell in row.getAllCells()" :key="cell.id">
            <slot :name="`cell-${cell.column.id}`" :row="row.original">
              <FlexRender :cell="cell" />
            </slot>
          </td>
        </tr>
      </tbody>
    </table>
  </div>
</template>
