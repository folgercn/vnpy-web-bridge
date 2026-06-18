<template>
  <n-card :title="title" size="small">
    <template #header-extra>
      <slot name="actions" />
    </template>
    <n-data-table size="small" :columns="columns" :data="rows" :pagination="{ pageSize }" :scroll-x="scrollX" />
  </n-card>
</template>

<script setup lang="ts">
import type { DataTableColumns } from 'naive-ui'

withDefaults(defineProps<{
  title: string
  columns: DataTableColumns<Record<string, unknown>>
  rows: Record<string, unknown>[]
  scrollX?: number
  pageSize?: number
}>(), {
  scrollX: 900,
  pageSize: 12
})
</script>
