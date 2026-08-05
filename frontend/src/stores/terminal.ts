import { defineStore } from 'pinia'
import { computed, ref } from 'vue'
import { ApiClientError } from '../api/client'
import { getStatus, getExecutionStatus, type ExecutionStatusProjection } from '../api/status'

type Row = Record<string, unknown>

/**
 * Phase A only exposes the typed Execution projection.  The old account,
 * market, order and risk endpoints remain visible as explicit unavailable
 * surfaces; they are deliberately not called from this store.
 */
export const useTerminalStore = defineStore('terminal', () => {
  const backendStatus = ref<Row>({})
  const rpcStatus = ref<Row>({})
  const gatewayStatus = ref<Row>({})
  const tradeConfig = ref<Row>({})
  const riskStatus = ref<Row>({})
  const executionProjection = ref<ExecutionStatusProjection | null>(null)
  const executionUnavailable = ref(true)
  const executionError = ref('Execution status projection unavailable')
  const phaseBUnavailable = ref(true)
  const contracts = ref<Row[]>([])
  const ticks = ref<Record<string, Row>>({})
  const subscribedVtSymbols = ref<Record<string, boolean>>({})
  const accounts = ref<Row[]>([])
  const positions = ref<Row[]>([])
  const orders = ref<Row[]>([])
  const trades = ref<Row[]>([])
  const logs = ref<Row[]>([])

  // Phase A does not expose a browser-side trading mutation path.  Keep this
  // false even if a future projection reports authority ENABLED, so legacy
  // order buttons can never submit directly to a removed endpoint.
  const webTradeEnabled = computed(() => false)

  async function refreshStatus() {
    try {
      backendStatus.value = await getStatus()
    } catch (exc) {
      backendStatus.value = { status: 'unavailable', error: errorMessage(exc) }
    }
    await refreshExecutionProjection()
  }

  async function refreshExecutionProjection() {
    try {
      const projection = await getExecutionStatus()
      applyExecutionProjection(projection)
      return projection
    } catch (exc) {
      markExecutionUnavailable(errorMessage(exc))
      throw exc
    }
  }

  async function refreshSnapshots() {
    await refreshExecutionProjection()
  }

  async function refreshContracts(): Promise<Row[]> {
    markPhaseBUnavailable()
    throw unavailable('market contracts')
  }

  async function subscribe(symbol: string, exchange: string): Promise<Row> {
    void symbol
    void exchange
    throw unavailable('market subscriptions')
  }

  async function unsubscribe(symbol: string, exchange: string): Promise<Row> {
    void symbol
    void exchange
    throw unavailable('market subscriptions')
  }

  async function loadBars(symbol: string, exchange: string, interval = '1m', limit = 300): Promise<Row[]> {
    void symbol
    void exchange
    void interval
    void limit
    throw unavailable('market bars')
  }

  async function refreshTick(vtSymbol: string): Promise<Row> {
    void vtSymbol
    throw unavailable('market ticks')
  }

  function applyEvent(type: string, data: Row) {
    if (type === 'execution_status') {
      if (isExecutionProjection(data)) applyExecutionProjection(data)
      return
    }
    if (type === 'tick' && data.vt_symbol) ticks.value[String(data.vt_symbol)] = data
    if (type === 'order') upsert(orders.value, data, 'vt_orderid')
    if (type === 'trade') upsert(trades.value, data, 'vt_tradeid')
    if (type === 'position') upsert(positions.value, data, 'vt_symbol')
    if (type === 'account') upsert(accounts.value, data, 'accountid')
    if (type === 'risk_alert') {
      riskStatus.value = (data.status as Row) || riskStatus.value
      logs.value.unshift({ type, ...data })
    }
    if (type.endsWith('log') || type === 'log') logs.value.unshift({ type, ...data })
    logs.value = logs.value.slice(0, 500)
  }

  function clearLogs() {
    logs.value = []
  }

  function applyExecutionProjection(projection: ExecutionStatusProjection | Row) {
    if (!isExecutionProjection(projection)) {
      markExecutionUnavailable('Invalid execution status projection')
      return
    }
    executionProjection.value = projection as ExecutionStatusProjection
    executionUnavailable.value = false
    executionError.value = ''
    markPhaseBUnavailable()

    const broker = asRow(projection.broker)
    const authority = asRow(projection.authority)
    const reconciliation = asRow(projection.reconciliation)
    const lifecycle = String(projection.lifecycle)
    const connected = Boolean(broker.connected)
    rpcStatus.value = {
      connected,
      lifecycle,
      state_version: projection.state_version,
      safe_to_restart: projection.safe_to_restart
    }
    gatewayStatus.value = {
      gateway_name: 'execution-orchestrator',
      connected,
      generation: broker.generation,
      active_order_count: broker.active_order_count
    }
    tradeConfig.value = {
      web_trade_enabled: false,
      phase_a_control_only: true,
      authority_state: authority.state,
      lifecycle
    }
    riskStatus.value = {
      lifecycle,
      reconciliation_state: reconciliation.state,
      unknown_outcomes: reconciliation.unknown_outcomes,
      safe_to_restart: projection.safe_to_restart,
      web_trade_enabled: false
    }
    orders.value = projection.send_intents.map((intent) => intentRow(intent))
    // Account, position and trade projections belong to the Phase B worker
    // surfaces.  Do not manufacture rows when those endpoints are unavailable.
    accounts.value = []
    positions.value = []
    trades.value = []
  }

  function markExecutionUnavailable(message: string) {
    executionProjection.value = null
    executionUnavailable.value = true
    executionError.value = message || 'Execution status projection unavailable'
    rpcStatus.value = { connected: false, status: 'unavailable' }
    gatewayStatus.value = { connected: false, status: 'unavailable' }
    tradeConfig.value = { web_trade_enabled: false, status: 'unavailable' }
    riskStatus.value = { status: 'unavailable', web_trade_enabled: false }
    contracts.value = []
    ticks.value = {}
    subscribedVtSymbols.value = {}
    accounts.value = []
    positions.value = []
    orders.value = []
    trades.value = []
  }

  function markPhaseBUnavailable() {
    phaseBUnavailable.value = true
  }

  return {
    backendStatus,
    rpcStatus,
    gatewayStatus,
    tradeConfig,
    riskStatus,
    executionProjection,
    executionUnavailable,
    executionError,
    phaseBUnavailable,
    contracts,
    ticks,
    subscribedVtSymbols,
    accounts,
    positions,
    orders,
    trades,
    logs,
    webTradeEnabled,
    refreshStatus,
    refreshExecutionProjection,
    refreshSnapshots,
    refreshContracts,
    subscribe,
    unsubscribe,
    loadBars,
    refreshTick,
    applyEvent,
    clearLogs
  }
})

function asRow(value: unknown): Row {
  return value && typeof value === 'object' && !Array.isArray(value) ? (value as Row) : {}
}

function isExecutionProjection(value: unknown): value is ExecutionStatusProjection {
  const candidate = asRow(value)
  return (
    candidate.schema_version === 'web_bridge_execution_status_v1' &&
    candidate.service === 'execution-orchestrator' &&
    typeof candidate.lifecycle === 'string' &&
    typeof candidate.state_version === 'number' &&
    Array.isArray(candidate.send_intents) &&
    typeof candidate.safe_to_restart === 'boolean'
  )
}

function intentRow(value: Row): Row {
  const intentId = String(value.intent_id || '')
  const state = String(value.state || 'UNKNOWN')
  return {
    ...value,
    vt_orderid: String(value.broker_order_id || intentId || value.idempotency_key || '-'),
    vt_symbol: String(value.plan_id || '-'),
    status: state.toLowerCase(),
    traded: 0,
    volume: 0
  }
}

function unavailable(surface: string) {
  return new ApiClientError({
    code: 'CONTROL_SURFACE_UNAVAILABLE',
    message: `${surface}在 Phase A 不可用`,
    detail: { surface, phase: 'A', status_code: 503 }
  })
}

function errorMessage(value: unknown) {
  return value instanceof Error ? value.message : 'Execution status projection unavailable'
}

function upsert(rows: Row[], data: Row, key: string) {
  const value = data[key]
  const index = rows.findIndex((row) => row[key] === value)
  if (index >= 0) rows[index] = data
  else rows.unshift(data)
}
