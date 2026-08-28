<template>
  <n-card class="lab-card" size="small" title="十品种持仓">
    <ResponsiveDataTable :columns="columns" :data="rows" :scroll-x="980" />
  </n-card>
</template>

<script setup lang="ts">
import { h } from 'vue'
import { NCard, type DataTableColumns } from 'naive-ui'
import ResponsiveDataTable from '../../../components/common/ResponsiveDataTable.vue'
import { formatMoney, formatNumber } from '../formatters'
import type { LabPortfolioRow } from '../types'
import LabStatusTag from './LabStatusTag.vue'

defineProps<{ rows: LabPortfolioRow[] }>()
const numeric = (value: number) => h('span', { class: 'number-cell' }, formatNumber(value))
const columns: DataTableColumns<LabPortfolioRow> = [
  { title: '品种', key: 'product' }, { title: '合约', key: 'vt_symbol' },
  { title: '目标', key: 'target_quantity', align: 'right', render: (row) => numeric(row.target_quantity) },
  { title: '当前', key: 'current_quantity', align: 'right', render: (row) => numeric(row.current_quantity) },
  { title: '差额', key: 'delta', align: 'right', render: (row) => numeric(row.delta) },
  { title: '浮动盈亏', key: 'unrealized_pnl', align: 'right', render: (row) => h('span', { class: ['number-cell', row.unrealized_pnl >= 0 ? 'positive' : 'negative'] }, formatMoney(row.unrealized_pnl)) },
  { title: '状态', key: 'status', render: (row) => h(LabStatusTag, { status: row.status }) }
]
</script>

<style scoped>
.lab-card { border-radius: var(--card-radius); }
:deep(.number-cell) { font-variant-numeric: tabular-nums; }
:deep(.positive) { color: var(--color-success); }
:deep(.negative) { color: var(--color-error); }
</style>
