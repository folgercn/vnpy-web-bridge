<template>
  <n-card class="lab-card" size="small">
    <n-tabs type="line" animated>
      <n-tab-pane name="orders" tab="委托">
        <ResponsiveDataTable :columns="orderColumns" :data="orders" :pagination="pagination" :scroll-x="1200" />
      </n-tab-pane>
      <n-tab-pane name="trades" tab="成交">
        <ResponsiveDataTable :columns="tradeColumns" :data="trades" :pagination="pagination" :scroll-x="1100" />
      </n-tab-pane>
      <n-tab-pane name="incidents" tab="异常">
        <ResponsiveDataTable :columns="incidentColumns" :data="incidents" :pagination="pagination" :scroll-x="900" />
      </n-tab-pane>
    </n-tabs>
  </n-card>
</template>

<script setup lang="ts">
import { h } from 'vue'
import { NCard, NTabs, NTabPane, type DataTableColumns } from 'naive-ui'
import ResponsiveDataTable from '../../../components/common/ResponsiveDataTable.vue'
import { formatMoney, formatNumber, formatTime, shortId } from '../formatters'
import type { LabIncident, LabOrder, LabTrade } from '../types'
import LabStatusTag from './LabStatusTag.vue'

defineProps<{ orders: LabOrder[]; trades: LabTrade[]; incidents: LabIncident[] }>()
const pagination = { pageSize: 20, pageSizes: [20, 50, 100], showSizePicker: true }
const mono = (value: string | null) => h('span', { class: 'mono', title: value || '' }, shortId(value))
const orderColumns: DataTableColumns<LabOrder> = [
  { title: '订单 ID', key: 'client_order_id', render: (row) => mono(row.client_order_id) },
  { title: '合约', key: 'symbol' }, { title: '方向', key: 'direction' }, { title: '开平', key: 'offset' },
  { title: '数量', key: 'quantity', align: 'right', render: (row) => formatNumber(row.quantity) },
  { title: '成交', key: 'traded', align: 'right', render: (row) => formatNumber(row.traded) },
  { title: '限价', key: 'limit_price', align: 'right', render: (row) => formatNumber(row.limit_price) },
  { title: '状态', key: 'status', render: (row) => h(LabStatusTag, { status: row.status }) },
  { title: '更新时间', key: 'updated_at', render: (row) => formatTime(row.updated_at) }
]
const tradeColumns: DataTableColumns<LabTrade> = [
  { title: '成交 ID', key: 'trade_key', render: (row) => mono(row.trade_key) },
  { title: '合约', key: 'symbol' }, { title: '方向', key: 'direction' }, { title: '开平', key: 'offset' },
  { title: '价格', key: 'price', align: 'right', render: (row) => formatMoney(row.price) },
  { title: '数量', key: 'volume', align: 'right', render: (row) => formatNumber(row.volume) },
  { title: '滑点', key: 'slippage', align: 'right', render: (row) => formatNumber(row.slippage) },
  { title: '时间', key: 'trade_time', render: (row) => formatTime(row.trade_time) }
]
const incidentColumns: DataTableColumns<LabIncident> = [
  { title: 'Run ID', key: 'run_id', render: (row) => mono(row.run_id) },
  { title: '时间', key: 'observed_at', render: (row) => formatTime(row.observed_at) },
  { title: '异常代码', key: 'code' }, { title: '说明', key: 'message' }
]
</script>

<style scoped>
.lab-card { border-radius: var(--card-radius); }
:deep(.mono) { font-family: SFMono-Regular, Consolas, monospace; }
</style>
