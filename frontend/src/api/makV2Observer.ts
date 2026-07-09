import { request } from './client'

export interface MakV2EnablePayload {
  manual_approval: boolean
  testnet_mode: boolean
  reason: string
  confirm_testnet_only: boolean
  confirm_no_production: boolean
  confirm_max_one_lot: boolean
  confirm_no_auto_promotion: boolean
}

export interface MakV2DisablePayload {
  reason: string
}

export interface MakV2DryRunSignalPayload {
  instrument: 'lc' | 'ps'
  exact_contract: string
  side: 'long' | 'short'
  z_score: number
  rolling_mean?: number | null
  rolling_std?: number | null
  last_price: number
  bid_price_1: number
  ask_price_1: number
  bid_volume_1: number
  ask_volume_1: number
  quote_age_ms: number
  cluster_id: string
  active_overlap_900s: number
  cooldown_state: string
  data_quality_status: 'pass' | 'degraded' | 'blocked'
}

export interface MakV2ObserverStatus {
  mode: string
  candidate_id: string
  profile_id: string
  capacity_status: string
  enabled: boolean
  manual_approval: boolean
  testnet_mode: boolean
  dry_run_only: boolean
  production_allowed: boolean
  max_order_lots: number
  max_testnet_orders_per_day: number
  signals_total: number
  dry_run_intents_total: number
  blocked_signals_total: number
  guardrail_events_total: number
  order_endpoint_touched: boolean
  enable_rejected?: boolean
}

export interface MakV2SafetyAuditPayload {
  probe_rpc: boolean
  collect_rpc_snapshot: boolean
  require_rpc_connected: boolean
  expected_exact_contracts: string[]
}

export interface MakV2SafetyAuditCheck {
  name: string
  status: 'PASS' | 'WATCH' | 'FAIL'
  observed: unknown
}

export interface MakV2SafetyAuditResult {
  audit_time_utc: string
  mode: string
  overall: 'PASS' | 'WATCH' | 'FAIL'
  single_order_smoke_allowed: boolean
  checks: MakV2SafetyAuditCheck[]
  observer: Record<string, unknown>
  risk: Record<string, unknown>
  trade_config: Record<string, unknown>
  rpc: Record<string, unknown>
  snapshot: {
    accounts: Record<string, unknown>[]
    mak_positions: Record<string, unknown>[]
    gfex_contracts: Record<string, unknown>[]
    errors: Record<string, unknown>
  }
  next_actions: string[]
}

export type MakV2SafetyAuditLatest = Partial<MakV2SafetyAuditResult>

export const getMakV2Status = () => request<MakV2ObserverStatus>('/api/mak-v2/testnet-observer/status')
export const getMakV2Signals = () => request<Record<string, unknown>[]>('/api/mak-v2/testnet-observer/signals')
export const getMakV2Orders = () => request<Record<string, unknown>[]>('/api/mak-v2/testnet-observer/orders')
export const getMakV2Fills = () => request<Record<string, unknown>[]>('/api/mak-v2/testnet-observer/fills')
export const getMakV2DailySummary = () => request<Record<string, unknown>[]>('/api/mak-v2/testnet-observer/daily-summary')
export const getMakV2Guardrails = () => request<Record<string, unknown>[]>('/api/mak-v2/testnet-observer/guardrails')
export const getMakV2SafetyAuditLatest = () =>
  request<MakV2SafetyAuditLatest>('/api/mak-v2/testnet-observer/safety-audit/latest')
export const listMakV2SafetyAudits = (limit = 50) =>
  request<MakV2SafetyAuditResult[]>(`/api/mak-v2/testnet-observer/safety-audits?limit=${encodeURIComponent(String(limit))}`)

export const enableMakV2Observer = (payload: MakV2EnablePayload) =>
  request<MakV2ObserverStatus>('/api/mak-v2/testnet-observer/enable', { method: 'POST', body: JSON.stringify(payload) })

export const disableMakV2Observer = (payload: MakV2DisablePayload) =>
  request<MakV2ObserverStatus>('/api/mak-v2/testnet-observer/disable', { method: 'POST', body: JSON.stringify(payload) })

export const flattenMakV2Testnet = () =>
  request<Record<string, unknown>>('/api/mak-v2/testnet-observer/flatten-testnet', { method: 'POST' })

export const dryRunMakV2Signal = (payload: MakV2DryRunSignalPayload) =>
  request<Record<string, unknown>>('/api/mak-v2/testnet-observer/dry-run/signal', { method: 'POST', body: JSON.stringify(payload) })

export const runMakV2SafetyAudit = (payload: MakV2SafetyAuditPayload) =>
  request<MakV2SafetyAuditResult>('/api/mak-v2/testnet-observer/safety-audit', { method: 'POST', body: JSON.stringify(payload) })
