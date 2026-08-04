<template>
  <n-data-table
    :columns="columns"
    :data="data"
    :pagination="pagination"
    :scroll-x="scrollX"
    :size="isMobile ? 'small' : size"
  />
</template>

<script setup lang="ts" generic="T extends Record<string, unknown>">
import { NDataTable, type DataTableColumns, type PaginationProps } from 'naive-ui'
import { useMediaQuery } from '../../composables/useMediaQuery'

withDefaults(defineProps<{
  columns: DataTableColumns<T>
  data: T[]
  pagination?: false | PaginationProps
  scrollX?: number
  size?: 'small' | 'medium' | 'large'
}>(), {
  pagination: false,
  scrollX: 900,
  size: 'small'
})
const isMobile = useMediaQuery('(max-width: 640px)')
</script>
