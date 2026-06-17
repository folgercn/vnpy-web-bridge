<template>
  <div class="page">
    <n-card title="行情订阅" size="small">
      <div class="toolbar">
        <n-input v-model:value="symbol" placeholder="rb2610" style="max-width: 180px" />
        <n-select v-model:value="exchange" :options="exchangeOptions" style="max-width: 160px" />
        <n-button type="primary" @click="subscribe">订阅</n-button>
        <n-button @click="terminal.refreshContracts">刷新合约</n-button>
      </div>
    </n-card>
    <n-card :title="`${vtSymbol} 1分钟K线`" size="small">
      <div ref="chartEl" class="chart"></div>
      <div v-if="!currentTick" class="muted chart-empty">订阅后等待 tick，K线会自动更新。</div>
    </n-card>
    <div class="grid-2">
      <data-panel title="合约" :columns="contractColumns" :rows="filteredContracts.slice(0, 200)" />
      <data-panel title="最新 Tick" :columns="tickColumns" :rows="Object.values(terminal.ticks)" />
    </div>
  </div>
</template>

<script setup lang="ts">
import { computed, onBeforeUnmount, onMounted, ref, watch } from 'vue'
import { useMessage } from 'naive-ui'
import {
  CandlestickSeries,
  createChart,
  type CandlestickData,
  type IChartApi,
  type ISeriesApi,
  type UTCTimestamp
} from 'lightweight-charts'
import DataPanel from '../components/common/DataPanel.vue'
import { useTerminalStore } from '../stores/terminal'

const message = useMessage()
const terminal = useTerminalStore()
const symbol = ref('rb2610')
const exchange = ref('SHFE')
const chartEl = ref<HTMLElement | null>(null)
let chart: IChartApi | null = null
let candleSeries: ISeriesApi<'Candlestick'> | null = null
const candleData: CandlestickData[] = []
const exchangeOptions = ['SHFE', 'DCE', 'CZCE', 'CFFEX', 'INE', 'GFEX'].map((value) => ({ label: value, value }))
const contractColumns = cols(['vt_symbol', 'name', 'exchange', 'product', 'gateway_name'])
const tickColumns = cols(['vt_symbol', 'last_price', 'bid_price_1', 'ask_price_1', 'volume', 'open_interest', 'limit_up', 'limit_down'])
const vtSymbol = computed(() => `${symbol.value}.${exchange.value}`)
const currentTick = computed(() => terminal.ticks[vtSymbol.value])
const filteredContracts = computed(() => {
  const keyword = symbol.value.trim().toLowerCase()
  if (!keyword) return terminal.contracts
  return terminal.contracts.filter((row) => String(row.vt_symbol || row.symbol || '').toLowerCase().includes(keyword))
})

onMounted(async () => {
  setupChart()
  if (!terminal.contracts.length) await terminal.refreshContracts().catch(() => undefined)
})

onBeforeUnmount(() => {
  chart?.remove()
})

watch(currentTick, (tick) => {
  if (!tick) return
  const price = Number(tick.last_price || 0)
  if (!price || !candleSeries) return
  const time = toMinuteTimestamp(tick.datetime)
  const last = candleData[candleData.length - 1]
  if (last?.time === time) {
    last.high = Math.max(last.high, price)
    last.low = Math.min(last.low, price)
    last.close = price
  } else {
    candleData.push({ time, open: price, high: price, low: price, close: price })
  }
  candleSeries.setData(candleData)
  chart?.timeScale().fitContent()
})

async function subscribe() {
  try {
    candleData.length = 0
    candleSeries?.setData([])
    await terminal.subscribe(symbol.value, exchange.value)
    message.success('订阅请求已发送')
  } catch (exc) {
    message.error(exc instanceof Error ? exc.message : '订阅失败')
  }
}

function cols(keys: string[]) {
  return keys.map((key) => ({ title: key, key }))
}

function setupChart() {
  if (!chartEl.value) return
  chart = createChart(chartEl.value, {
    height: 280,
    layout: { background: { color: '#11141c' }, textColor: '#d7dde5' },
    grid: { vertLines: { color: '#222631' }, horzLines: { color: '#222631' } },
    rightPriceScale: { borderColor: '#303642' },
    timeScale: { borderColor: '#303642' }
  })
  candleSeries = chart.addSeries(CandlestickSeries, {
    upColor: '#12d7b0',
    downColor: '#ff4d6d',
    borderUpColor: '#12d7b0',
    borderDownColor: '#ff4d6d',
    wickUpColor: '#12d7b0',
    wickDownColor: '#ff4d6d'
  })
}

function toMinuteTimestamp(value: unknown): UTCTimestamp {
  const parsed = value ? new Date(String(value)).getTime() : Date.now()
  const fallback = Number.isFinite(parsed) ? parsed : Date.now()
  return (Math.floor(fallback / 60000) * 60) as UTCTimestamp
}
</script>

<style scoped>
.chart {
  width: 100%;
  height: 280px;
}

.chart-empty {
  margin-top: -160px;
  height: 160px;
  display: grid;
  place-items: center;
  pointer-events: none;
}
</style>
