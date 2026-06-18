<template>
  <div class="page data-page">
    <n-card title="历史数据管理" size="small">
      <div class="toolbar">
        <n-input v-model:value="filters.symbol" placeholder="合约代码" class="short-control" clearable />
        <n-select v-model:value="filters.exchange" :options="exchangeOptions" placeholder="交易所" class="short-control" clearable />
        <n-input v-model:value="filters.vt_symbol" placeholder="vt_symbol" class="symbol-control" clearable />
        <n-input v-model:value="filters.start" type="datetime-local" class="time-control" clearable />
        <n-input v-model:value="filters.end" type="datetime-local" class="time-control" clearable />
        <n-input-number v-model:value="filters.limit" :min="1" :max="5000" class="limit-control" />
        <n-button type="primary" @click="loadTicks">查询</n-button>
        <n-button @click="downloadCsv">导出CSV</n-button>
        <n-button @click="fileInput?.click()">导入CSV</n-button>
        <input ref="fileInput" class="file-input" type="file" accept=".csv,text/csv" @change="uploadCsv" />
      </div>
    </n-card>

    <data-panel title="数据覆盖范围" :columns="overviewColumns" :rows="overviewRows" :scroll-x="900">
      <template #actions>
        <n-button size="small" @click="loadOverview">刷新</n-button>
      </template>
    </data-panel>

    <data-panel title="Tick 数据" :columns="tickColumns" :rows="tickRows" :scroll-x="1200" />
  </div>
</template>

<script setup lang="ts">
import { onMounted, reactive, ref } from 'vue'
import { useMessage } from 'naive-ui'
import DataPanel from '../components/common/DataPanel.vue'
import { exchangeOptions } from '../constants/exchanges'
import { exportMarketDataCsv, getMarketDataOverview, getMarketDataTicks, importMarketDataCsv } from '../api/market'

const message = useMessage()
const overviewRows = ref<Record<string, unknown>[]>([])
const tickRows = ref<Record<string, unknown>[]>([])
const fileInput = ref<HTMLInputElement | null>(null)
const filters = reactive({
  symbol: '',
  exchange: null as string | null,
  vt_symbol: '',
  start: '',
  end: '',
  limit: 200
})

const overviewColumns = [
  { title: 'vt_symbol', key: 'vt_symbol' },
  { title: 'symbol', key: 'symbol' },
  { title: 'exchange', key: 'exchange' },
  { title: 'rows', key: 'row_count' },
  { title: 'start_time', key: 'start_time' },
  { title: 'end_time', key: 'end_time' }
]
const tickColumns = [
  { title: 'datetime', key: 'datetime' },
  { title: 'vt_symbol', key: 'vt_symbol' },
  { title: 'last_price', key: 'last_price' },
  { title: 'bid_price_1', key: 'bid_price_1' },
  { title: 'ask_price_1', key: 'ask_price_1' },
  { title: 'volume', key: 'volume' },
  { title: 'open_interest', key: 'open_interest' },
  { title: 'gateway_name', key: 'gateway_name' }
]

onMounted(async () => {
  await loadOverview()
  await loadTicks()
})

async function loadOverview() {
  overviewRows.value = await getMarketDataOverview().catch((exc) => {
    message.error(errorText(exc, '数据范围查询失败'))
    return []
  })
}

async function loadTicks() {
  tickRows.value = await getMarketDataTicks(toQuery()).catch((exc) => {
    message.error(errorText(exc, 'Tick 查询失败'))
    return []
  })
}

async function downloadCsv() {
  try {
    const blob = await exportMarketDataCsv(toQuery())
    const url = URL.createObjectURL(blob)
    const link = document.createElement('a')
    link.href = url
    link.download = 'market_ticks.csv'
    link.click()
    URL.revokeObjectURL(url)
  } catch (exc) {
    message.error(errorText(exc, '导出失败'))
  }
}

async function uploadCsv(event: Event) {
  const input = event.target as HTMLInputElement
  const file = input.files?.[0]
  if (!file) return
  try {
    const result = await importMarketDataCsv(file)
    message.success(`导入完成：${result.imported || 0} 条`)
    await loadOverview()
    await loadTicks()
  } catch (exc) {
    message.error(errorText(exc, '导入失败'))
  } finally {
    input.value = ''
  }
}

function toQuery() {
  return {
    symbol: filters.symbol,
    exchange: filters.exchange || undefined,
    vt_symbol: filters.vt_symbol,
    start: filters.start,
    end: filters.end,
    limit: filters.limit
  }
}

function errorText(exc: unknown, fallback: string) {
  return exc instanceof Error ? exc.message : fallback
}
</script>

<style scoped>
.data-page {
  gap: 16px;
}

.short-control {
  width: 150px;
}

.symbol-control {
  width: 190px;
}

.time-control {
  width: 210px;
}

.limit-control {
  width: 120px;
}

.file-input {
  display: none;
}

@media (max-width: 760px) {
  .short-control,
  .symbol-control,
  .time-control,
  .limit-control {
    width: 100%;
  }
}
</style>
