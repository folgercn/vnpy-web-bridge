<template>
  <responsive-data-table :columns="columns" :data="rows" :pagination="false" :scroll-x="640" />
</template>

<script setup lang="ts">
import type { DataTableColumns } from 'naive-ui'
import ResponsiveDataTable from './ResponsiveDataTable.vue'

interface ConfigDiffRow extends Record<string, unknown> {
  key: string
  label: string
  before: string
  after: string
}

defineProps<{ rows: ConfigDiffRow[] }>()
const columns: DataTableColumns<ConfigDiffRow> = [
  { title: '配置项', key: 'label' },
  { title: '变更前', key: 'before' },
  { title: '变更后', key: 'after' }
]
</script>
