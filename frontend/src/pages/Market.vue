<template>
  <div class="page">
    <n-card title="行情订阅" size="small">
      <div class="product-tabs">
        <n-button
          v-for="item in watchedProductItems"
          :key="item.watch_key"
          :type="activeWatchKey === item.watch_key ? 'primary' : 'default'"
          @click="selectProduct(item)"
        >
          {{ item.display_name }}
        </n-button>
      </div>
      <div class="toolbar market-subscribe-toolbar">
        <n-select
          v-model:value="selectedVtSymbol"
          :options="activeProductContractOptions"
          filterable
          clearable
          placeholder="选择合约"
          class="market-contract-select"
          @update:value="selectContract"
        />
        <n-button type="primary" @click="subscribe">订阅</n-button>
        <n-button :disabled="!isCurrentSubscribed" @click="unsubscribe">取消订阅</n-button>
        <n-button @click="resetChartView">重置视图</n-button>
        <n-button @click="showWatchManager = !showWatchManager">管理</n-button>
        <n-button @click="terminal.refreshContracts">刷新</n-button>
      </div>
      <div class="market-session">
        <trading-session-badge :exchange="exchange" :symbol="symbol" compact />
        <span class="muted">交易时段按品种优先，交易所兜底</span>
      </div>
      <div v-if="showWatchManager" class="watch-manager">
        <div class="toolbar watch-manager-toolbar">
          <n-select
            v-model:value="candidateVtSymbol"
            :options="contractOptions"
            filterable
            remote
            clearable
            placeholder="搜索期货合约"
            class="market-contract-select"
            @search="searchKeyword = $event"
          />
          <n-button type="primary" @click="addWatchedContract">添加关注</n-button>
        </div>
        <div class="watch-tags">
          <n-tag
            v-for="item in watchedItems"
            :key="item.key"
            :closable="item.removable"
            @close="removeWatched(item.key)"
          >
            {{ item.label }}
          </n-tag>
        </div>
      </div>
    </n-card>
    <n-card :title="`${selectedContractLabel} 1分钟K线`" size="small">
      <div ref="chartEl" class="chart"></div>
      <div v-if="!candleCount" class="muted chart-empty">
        {{ historyError || '订阅后等待 tick，K线会自动更新。' }}
      </div>
    </n-card>
    <div class="grid-2">
      <data-panel title="关注品种" :columns="marketColumns" :rows="watchedMarketRows" :scroll-x="760" />
      <data-panel title="最新 Tick" :columns="tickColumns" :rows="visibleTickRows" />
    </div>
  </div>
</template>

<script setup lang="ts">
import { computed, h, onBeforeUnmount, onMounted, ref, watch } from 'vue'
import { NTag, useMessage } from 'naive-ui'
import {
  CandlestickSeries,
  createChart,
  type CandlestickData,
  type IChartApi,
  type ISeriesApi,
  type UTCTimestamp
} from 'lightweight-charts'
import DataPanel from '../components/common/DataPanel.vue'
import {
  compareContractMonths,
  contractSearchText,
  formatContractTitle,
  isMainContract,
  mainContracts,
  normalizeKeyword,
  preferredMainContract,
  productNameForRow,
  symbolRoot,
  vtSymbolOf,
  type ContractRow
} from '../utils/marketContracts'
import { useMediaQuery } from '../composables/useMediaQuery'
import { addMarketWatchlistItem, getMarketWatchlist, removeMarketWatchlistItem, type MarketWatchlistItem } from '../api/market'
import { useTerminalStore } from '../stores/terminal'
import { useThemeStore } from '../stores/theme'

const message = useMessage()
const terminal = useTerminalStore()
const theme = useThemeStore()
const symbol = ref('ru2609')
const exchange = ref('SHFE')
const selectedVtSymbol = ref('ru2609.SHFE')
const candidateVtSymbol = ref<string | null>(null)
const searchKeyword = ref('')
const showWatchManager = ref(false)
const watchlistItems = ref<MarketWatchlistItem[]>([])
const activeWatchKey = ref('')
const chartEl = ref<HTMLElement | null>(null)
const isMobile = useMediaQuery('(max-width: 640px)')
const historyError = ref('')
const candleCount = ref(0)
const chartVtSymbol = ref('')
let chart: IChartApi | null = null
let candleSeries: ISeriesApi<'Candlestick'> | null = null
const candleData: CandlestickData[] = []
const marketColumns = [
  { title: '品种', key: 'product_name' },
  { title: '默认合约', key: 'contract_label' },
  {
    title: '标识',
    key: 'contract_role',
    render: (row: ContractRow) =>
      row.contract_role === '主力' ? h(NTag, { type: 'success', round: true }, { default: () => '主力' }) : '-'
  },
  { title: '最新', key: 'last_price', render: (row: ContractRow) => formatMarketValue(row.last_price) },
  { title: '买一', key: 'bid_price_1', render: (row: ContractRow) => formatMarketValue(row.bid_price_1) },
  { title: '卖一', key: 'ask_price_1', render: (row: ContractRow) => formatMarketValue(row.ask_price_1) },
  { title: '成交量', key: 'volume', render: (row: ContractRow) => formatMarketValue(row.volume) },
  { title: '持仓', key: 'open_interest', render: (row: ContractRow) => formatMarketValue(row.open_interest) }
]
const tickColumns = [
  { title: '合约', key: 'vt_symbol', render: (row: ContractRow) => displayContractForVtSymbol(row.vt_symbol) },
  { title: '最新', key: 'last_price', render: (row: ContractRow) => formatMarketValue(row.last_price) },
  { title: '买一', key: 'bid_price_1', render: (row: ContractRow) => formatMarketValue(row.bid_price_1) },
  { title: '卖一', key: 'ask_price_1', render: (row: ContractRow) => formatMarketValue(row.ask_price_1) },
  { title: '成交量', key: 'volume', render: (row: ContractRow) => formatMarketValue(row.volume) },
  { title: '持仓', key: 'open_interest', render: (row: ContractRow) => formatMarketValue(row.open_interest) }
]
const vtSymbol = computed(() => `${symbol.value}.${exchange.value}`)
const currentTick = computed(() => terminal.ticks[vtSymbol.value])
const isCurrentSubscribed = computed(() => Boolean(terminal.subscribedVtSymbols[vtSymbol.value]))
const selectedContract = computed(() => terminal.contracts.find((row) => vtSymbolOf(row) === vtSymbol.value))
const selectedContractLabel = computed(() => (selectedContract.value ? formatContractTitle(selectedContract.value) : vtSymbol.value))
const contractOptions = computed(() => {
  const keyword = normalizeKeyword(searchKeyword.value)
  if (!keyword) return []
  return mainContracts(terminal.contracts)
    .filter(isFuturesContract)
    .filter((row) => contractMatchesKeyword(row, keyword))
    .slice(0, 80)
    .map(contractOption)
})
const watchedProductItems = computed(() => watchlistItems.value.filter((item) => item.watch_type === 'product'))
const activeProduct = computed(() => watchlistItems.value.find((item) => item.watch_key === activeWatchKey.value) || watchedProductItems.value[0])
const activeProductContracts = computed(() => {
  if (!activeProduct.value) return []
  return mainContracts(contractsForWatchItem(activeProduct.value).filter(isFuturesContract)).sort(compareContractMonths)
})
const explicitWatchedContracts = computed(() =>
  watchlistItems.value
    .filter((item) => item.watch_type === 'contract' && item.vt_symbol)
    .flatMap((item) => terminal.contracts.filter((row) => vtSymbolOf(row) === item.vt_symbol && isFuturesContract(row) && isMainContract(row)))
)
const selectableContracts = computed(() => uniqueContracts([...activeProductContracts.value, ...explicitWatchedContracts.value]))
const activeProductContractOptions = computed(() => selectableContracts.value.map(contractOption))
const focusedContracts = computed(() => {
  const rows = new Map<string, ContractRow>()
  for (const item of watchlistItems.value) {
    const row = preferredContractForWatchItem(item)
    if (row) rows.set(vtSymbolOf(row), row)
  }
  return Array.from(rows.values()).sort(compareContractMonths)
})
const watchedItems = computed(() =>
  watchlistItems.value.map((item) => ({
    key: item.watch_key,
    removable: item.watch_type === 'contract',
    label: watchedLabel(item)
  }))
)
const watchedMarketRows = computed(() =>
  watchedProductItems.value.map((item) => {
    const contract = preferredContractForWatchItem(item)
    const vtSymbol = contract ? vtSymbolOf(contract) : ''
    const tick = vtSymbol ? terminal.ticks[vtSymbol] || {} : {}
    return {
      product_name: item.display_name,
      contract_label: contract ? formatContractTitle(contract, item.display_name, { main: true }) : '暂无主力合约',
      contract_role: contract ? '主力' : '-',
      ...tick
    }
  })
)
const visibleTickRows = computed(() =>
  Object.values(terminal.ticks).filter((row) => {
    const contract = terminal.contracts.find((item) => vtSymbolOf(item) === row.vt_symbol)
    return !contract || isFuturesContract(contract)
  })
)

onMounted(async () => {
  setupChart()
  await loadWatchlist()
  if (!terminal.contracts.length) await terminal.refreshContracts().catch(() => undefined)
  selectFirstFocusedContract()
  await loadSelectedMarket()
})

onBeforeUnmount(() => {
  chart?.remove()
})

watch(currentTick, (tick) => {
  if (!tick) return
  appendTickToCandle(tick)
}, { immediate: true })

async function subscribe() {
  try {
    await loadSelectedMarket()
    await terminal.subscribe(symbol.value, exchange.value)
    await loadTickSnapshot()
    message.success('订阅请求已发送')
  } catch (exc) {
    message.error(exc instanceof Error ? exc.message : '订阅失败')
  }
}

async function unsubscribe() {
  try {
    await terminal.unsubscribe(symbol.value, exchange.value)
    if (chartVtSymbol.value === vtSymbol.value) clearCandles()
    historyError.value = '已取消订阅'
    message.success('订阅已取消')
  } catch (exc) {
    message.error(exc instanceof Error ? exc.message : '取消订阅失败')
  }
}

async function selectContract(value: string | null) {
  if (!value) return
  const changed = value !== vtSymbol.value
  applyVtSymbol(value)
  selectedVtSymbol.value = value
  if (changed) {
    historyError.value = ''
    if (chartVtSymbol.value !== value) clearCandles()
  }
  await loadSelectedMarket()
}

async function selectProduct(item: MarketWatchlistItem) {
  activeWatchKey.value = item.watch_key
  const contract = preferredContractForWatchItem(item)
  if (!contract) {
    message.warning(`${item.display_name} 暂无可用期货合约`)
    return
  }
  await selectContract(vtSymbolOf(contract))
}

async function addWatchedContract() {
  if (!candidateVtSymbol.value) return
  const row = terminal.contracts.find((item) => vtSymbolOf(item) === candidateVtSymbol.value)
  if (!row) return
  await addMarketWatchlistItem({
    vt_symbol: vtSymbolOf(row),
    symbol: String(row.symbol || ''),
    exchange: String(row.exchange || ''),
    display_name: formatContractTitle(row)
  })
  await loadWatchlist()
  applyVtSymbol(candidateVtSymbol.value)
  selectedVtSymbol.value = candidateVtSymbol.value
  candidateVtSymbol.value = null
  searchKeyword.value = ''
}

async function removeWatched(key: string) {
  await removeMarketWatchlistItem(key)
  await loadWatchlist()
  selectFirstFocusedContract()
}

async function loadSelectedMarket() {
  historyError.value = ''
  await loadHistory().catch((exc) => setHistoryError(exc))
  await loadTickSnapshot()
}

async function loadHistory() {
  const targetVtSymbol = vtSymbol.value
  const rows = await terminal.loadBars(symbol.value, exchange.value, '1m', 300)
  const nextData: CandlestickData[] = []
  for (const row of rows) {
    const time = toMinuteTimestamp(row.datetime)
    const open = Number(row.open_price || row.open || 0)
    const high = Number(row.high_price || row.high || open)
    const low = Number(row.low_price || row.low || open)
    const close = Number(row.close_price || row.close || open)
    if (open > 0 && high > 0 && low > 0 && close > 0) {
      nextData.push({ time, open, high, low, close })
    }
  }
  if (nextData.length) {
    candleData.length = 0
    candleData.push(...nextData)
    chartVtSymbol.value = targetVtSymbol
    candleSeries?.setData(candleData)
    chart?.timeScale().fitContent()
  } else if (chartVtSymbol.value !== targetVtSymbol) {
    clearCandles()
  }
  historyError.value = candleData.length ? '' : '历史K线暂无数据，订阅后将用实时 tick 生成。'
  candleCount.value = candleData.length
  return candleData.length
}

async function loadTickSnapshot() {
  const tick = await terminal.refreshTick(vtSymbol.value).catch(() => null)
  if (tick) appendTickToCandle(tick)
}

function appendTickToCandle(tick: Record<string, unknown>) {
  const tickVtSymbol = String(tick.vt_symbol || '')
  if (tickVtSymbol && tickVtSymbol !== vtSymbol.value) return
  const price = Number(tick.last_price || 0)
  if (!price || !candleSeries) return
  const time = toMinuteTimestamp(tick.datetime)
  const last = candleData[candleData.length - 1]
  const wasEmpty = candleData.length === 0
  let candle: CandlestickData
  if (last?.time === time) {
    last.high = Math.max(last.high, price)
    last.low = Math.min(last.low, price)
    last.close = price
    candle = last
  } else {
    candle = { time, open: price, high: price, low: price, close: price }
    candleData.push(candle)
  }
  chartVtSymbol.value = vtSymbol.value
  historyError.value = ''
  candleCount.value = candleData.length
  candleSeries.update(candle)
  if (wasEmpty) resetChartView()
}

function clearCandles() {
  candleData.length = 0
  candleCount.value = 0
  chartVtSymbol.value = ''
  candleSeries?.setData([])
}

async function loadWatchlist() {
  try {
    watchlistItems.value = await getMarketWatchlist()
    if (!activeWatchKey.value) activeWatchKey.value = watchedProductItems.value[0]?.watch_key || ''
  } catch {
    message.error('关注合约加载失败，请检查 PostgreSQL 配置')
  }
}

function applyVtSymbol(value: string) {
  const [nextSymbol, nextExchange] = value.split('.')
  if (!nextSymbol || !nextExchange) return
  symbol.value = nextSymbol
  exchange.value = nextExchange
}

function selectFirstFocusedContract() {
  if (focusedContracts.value.some((row) => vtSymbolOf(row) === vtSymbol.value)) return
  const first = activeProduct.value ? preferredContractForWatchItem(activeProduct.value) : focusedContracts.value[0]
  if (!first) return
  const next = vtSymbolOf(first)
  applyVtSymbol(next)
  selectedVtSymbol.value = next
}

function contractsForWatchItem(item: MarketWatchlistItem) {
  if (item.watch_type === 'contract' && item.vt_symbol) {
    const vtSymbol = item.vt_symbol
    return terminal.contracts.filter((row) => vtSymbolOf(row) === vtSymbol)
  }
  return terminal.contracts.filter((row) => productMatches(row, item))
}

function preferredContractForWatchItem(item: MarketWatchlistItem) {
  const rows = contractsForWatchItem(item).filter(isFuturesContract).sort(compareContractMonths)
  return preferredMainContract(rows)
}

function productMatches(row: ContractRow, product: MarketWatchlistItem) {
  const symbolCode = symbolRoot(row)
  const exchangeCode = String(row.exchange || '').toUpperCase()
  const name = String(row.name || '')
  return (
    ((product.product_codes || []).includes(symbolCode) || name.includes(product.display_name)) &&
    (!(product.exchange_codes || []).length || product.exchange_codes.includes(exchangeCode))
  )
}

function watchedLabel(item: MarketWatchlistItem) {
  if (item.watch_type === 'contract' && item.vt_symbol) {
    const vtSymbol = item.vt_symbol
    const row = terminal.contracts.find((item) => vtSymbolOf(item) === vtSymbol)
    return row ? formatContractTitle(row) : vtSymbol
  }
  return item.display_name
}

function contractOption(row: ContractRow) {
  const value = vtSymbolOf(row)
  return { label: formatContractTitle(row, productLabelForRow(row) || productNameForRow(row), { main: isMainContract(row) }), value }
}

function contractMatchesKeyword(row: ContractRow, keyword: string) {
  return contractSearchText(row).includes(keyword)
}

function displayContractForVtSymbol(value: unknown) {
  const vtSymbol = String(value || '')
  const row = terminal.contracts.find((item) => vtSymbolOf(item) === vtSymbol)
  return row ? formatContractTitle(row, productLabelForRow(row) || productNameForRow(row), { main: isMainContract(row) }) : vtSymbol
}

function uniqueContracts(rows: ContractRow[]) {
  const values = new Map<string, ContractRow>()
  for (const row of rows) values.set(vtSymbolOf(row), row)
  return Array.from(values.values()).sort(compareContractMonths)
}

function isFuturesContract(row: ContractRow) {
  const product = String(row.product || '').toLowerCase()
  const symbol = String(row.symbol || '')
  const isOptionProduct = product === '期权' || product === 'option'
  const hasOptionStrike = /\d+[CP]\d+$/i.test(symbol)
  return !isOptionProduct && !hasOptionStrike
}

function productLabelForRow(row: ContractRow) {
  return watchedProductItems.value.find((item) => productMatches(row, item))?.display_name || ''
}

function formatMarketValue(value: unknown) {
  if (value === undefined || value === null || value === '') return '-'
  return String(value)
}

function setupChart() {
  if (!chartEl.value) return
  const colors = chartColors()
  chart = createChart(chartEl.value, {
    height: isMobile.value ? 220 : 280,
    layout: { background: { color: colors.background }, textColor: colors.text },
    grid: { vertLines: { color: colors.grid }, horzLines: { color: colors.grid } },
    rightPriceScale: { borderColor: colors.border },
    timeScale: { borderColor: colors.border }
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

function applyChartTheme() {
  if (!chart) return
  const colors = chartColors()
  chart.applyOptions({
    layout: { background: { color: colors.background }, textColor: colors.text },
    grid: { vertLines: { color: colors.grid }, horzLines: { color: colors.grid } },
    rightPriceScale: { borderColor: colors.border },
    timeScale: { borderColor: colors.border }
  })
}

function chartColors() {
  if (theme.effectiveTheme === 'dark') {
    return {
      background: '#11141c',
      text: '#d7dde5',
      grid: '#222631',
      border: '#303642'
    }
  }
  return {
    background: '#ffffff',
    text: '#334155',
    grid: '#e5e7eb',
    border: '#d7dde5'
  }
}

function resetChartView() {
  chart?.timeScale().fitContent()
}

function setHistoryError(exc: unknown) {
  if (chartVtSymbol.value !== vtSymbol.value) clearCandles()
  historyError.value = exc instanceof Error ? `历史K线取不到：${exc.message}` : '历史K线取不到'
}

watch(isMobile, (mobile) => {
  chart?.applyOptions({ height: mobile ? 220 : 280 })
  chart?.timeScale().fitContent()
})

watch(() => theme.effectiveTheme, applyChartTheme)

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

.page :deep(.n-card) {
  min-width: 0;
}

.product-tabs {
  display: flex;
  flex-wrap: wrap;
  gap: 8px;
  margin-bottom: 12px;
}

.market-contract-select {
  flex: 0 1 420px;
  width: 420px;
  min-width: 260px;
  max-width: 420px;
}

.market-short-control {
  flex: 0 0 160px;
  width: 160px;
  max-width: 160px;
}

.market-subscribe-toolbar {
  flex-wrap: nowrap;
  width: 100%;
}

.market-subscribe-toolbar :deep(.n-button) {
  flex: 0 0 auto;
}

.watch-manager {
  margin-top: 12px;
  display: grid;
  gap: 10px;
}

.market-session {
  display: flex;
  flex-wrap: wrap;
  align-items: center;
  gap: 10px 16px;
  margin-top: 12px;
}

.watch-manager-toolbar {
  flex-wrap: nowrap;
}

.watch-tags {
  display: flex;
  flex-wrap: wrap;
  gap: 8px;
}

.chart-empty {
  margin-top: -160px;
  height: 160px;
  display: grid;
  place-items: center;
  pointer-events: none;
}

@media (max-width: 640px) {
  .chart {
    height: 220px;
  }

  .chart-empty {
    margin-top: -130px;
    height: 130px;
    padding: 0 16px;
    text-align: center;
  }

  .market-subscribe-toolbar {
    flex-wrap: wrap;
  }

  .watch-manager-toolbar {
    flex-wrap: wrap;
  }

  .market-session {
    align-items: flex-start;
  }

  .market-contract-select,
  .market-short-control {
    flex: 1 1 100%;
    width: 100%;
    max-width: none;
    min-width: 0;
  }

  .market-subscribe-toolbar :deep(.n-button) {
    flex: 1 1 100%;
  }

  .watch-manager-toolbar :deep(.n-button) {
    flex: 1 1 100%;
  }
}
</style>
