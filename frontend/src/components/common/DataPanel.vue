<template>
  <n-card :title="title" size="small">
    <template #header-extra>
      <slot name="actions" />
    </template>
    <n-data-table size="small" :columns="columns" :data="rows" :pagination="{ pageSize: 12 }" />
  </n-card>
</template>

<script setup lang="ts">
import type { DataTableColumns } from 'naive-ui'

defineProps<{
  title: string
  columns: DataTableColumns<Record<string, unknown>>
  rows: Record<string, unknown>[]
}>()
</script>
