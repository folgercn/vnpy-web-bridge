<template><responsive-data-table :columns="columns" :data="events" :pagination="pagination" :scroll-x="980" /></template>

<script setup lang="ts">
import type { DataTableColumns, PaginationProps } from 'naive-ui'
import ResponsiveDataTable from './ResponsiveDataTable.vue'

interface AuditEvent extends Record<string, unknown> {
  id: string
  timestamp: string
  actor: string
  action: string
  result: string
}

withDefaults(defineProps<{
  events: AuditEvent[]
  pagination?: false | PaginationProps
}>(), { pagination: false })
const columns: DataTableColumns<AuditEvent> = [
  { title: '时间', key: 'timestamp', width: 180 },
  { title: '操作人', key: 'actor', width: 140 },
  { title: '动作', key: 'action', width: 180 },
  { title: '结果', key: 'result' }
]
</script>
