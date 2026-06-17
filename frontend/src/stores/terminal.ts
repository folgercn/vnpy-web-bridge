import { defineStore } from 'pinia'
import { computed, ref } from 'vue'
import { getAccount, getPositions } from '../api/account'
import { getContracts, getMarketBars, subscribeMarket } from '../api/market'
import { getRiskStatus } from '../api/risk'
import { getGatewayStatus, getRpcStatus, getStatus, getTradeConfig } from '../api/status'
import { getOrders, getTrades } from '../api/trade'

export const useTerminalStore = defineStore('terminal', () => {
  const backendStatus = ref<Record<string, unknown>>({})
  const rpcStatus = ref<Record<string, unknown>>({})
  const gatewayStatus = ref<Record<string, unknown>>({})
  const tradeConfig = ref<Record<string, unknown>>({})
  const riskStatus = ref<Record<string, unknown>>({})
  const contracts = ref<Record<string, unknown>[]>([])
  const ticks = ref<Record<string, Record<string, unknown>>>({})
  const accounts = ref<Record<string, unknown>[]>([])
  const positions = ref<Record<string, unknown>[]>([])
  const orders = ref<Record<string, unknown>[]>([])
  const trades = ref<Record<string, unknown>[]>([])
  const logs = ref<Record<string, unknown>[]>([])

  const webTradeEnabled = computed(() => Boolean(tradeConfig.value.web_trade_enabled || riskStatus.value.web_trade_enabled))

  async function refreshStatus() {
    const [backend, rpc, gateway, trade, risk] = await Promise.all([
      getStatus(),
      getRpcStatus(),
      getGatewayStatus(),
      getTradeConfig(),
      getRiskStatus()
    ])
    backendStatus.value = backend
    rpcStatus.value = rpc
    gatewayStatus.value = gateway
    tradeConfig.value = trade
    riskStatus.value = risk
  }

  async function refreshSnapshots() {
    const [accountRows, positionRows, orderRows, tradeRows] = await Promise.all([
      getAccount(),
      getPositions(),
      getOrders(),
      getTrades()
    ])
    accounts.value = accountRows
    positions.value = positionRows
    orders.value = orderRows
    trades.value = tradeRows
  }

  async function refreshContracts() {
    contracts.value = await getContracts()
  }

  async function subscribe(symbol: string, exchange: string) {
    return subscribeMarket(symbol, exchange)
  }

  async function loadBars(symbol: string, exchange: string, interval = '1m', limit = 300) {
    return getMarketBars(symbol, exchange, interval, limit)
  }

  function applyEvent(type: string, data: Record<string, unknown>) {
    if (type === 'tick' && data.vt_symbol) ticks.value[String(data.vt_symbol)] = data
    if (type === 'order') upsert(orders.value, data, 'vt_orderid')
    if (type === 'trade') upsert(trades.value, data, 'vt_tradeid')
    if (type === 'position') upsert(positions.value, data, 'vt_symbol')
    if (type === 'account') upsert(accounts.value, data, 'accountid')
    if (type === 'risk_alert') {
      riskStatus.value = (data.status as Record<string, unknown>) || riskStatus.value
      logs.value.unshift({ type, ...data })
    }
    if (type.endsWith('log') || type === 'log') logs.value.unshift({ type, ...data })
    logs.value = logs.value.slice(0, 500)
  }

  function clearLogs() {
    logs.value = []
  }

  return {
    backendStatus,
    rpcStatus,
    gatewayStatus,
    tradeConfig,
    riskStatus,
    contracts,
    ticks,
    accounts,
    positions,
    orders,
    trades,
    logs,
    webTradeEnabled,
    refreshStatus,
    refreshSnapshots,
    refreshContracts,
    subscribe,
    loadBars,
    applyEvent,
    clearLogs
  }
})

function upsert(rows: Record<string, unknown>[], data: Record<string, unknown>, key: string) {
  const value = data[key]
  const index = rows.findIndex((row) => row[key] === value)
  if (index >= 0) rows[index] = data
  else rows.unshift(data)
}
