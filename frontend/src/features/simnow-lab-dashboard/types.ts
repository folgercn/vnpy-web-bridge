export type LabStatus = 'RUNNING' | 'DONE' | 'NOOP' | 'ALIGNED' | 'PARTIAL' | 'STALE' | 'DEGRADED' | 'FAILED' | 'OFFLINE' | 'UNKNOWN' | 'IDLE' | 'NO_DATA'

export interface LabPoint { time: string; value: number }
export interface LabSummary {
  status: LabStatus
  blocker: string | null
  last_run_id: string | null
  target_id: string | null
  started_at: string | null
  ended_at: string | null
  active_order_count: number
  unknown_order_count: number
  aligned_products: number
  total_products: number
}
export interface LabMetrics {
  equity: number | null
  available: number | null
  margin: number | null
  unrealized_pnl: number
  realized_pnl: number
  cumulative_pnl: number
  daily_pnl: number
  max_drawdown: number
  slippage: number
  trade_count: number
}
export interface LabPortfolioRow {
  product: string
  vt_symbol: string
  target_quantity: number
  current_quantity: number
  delta: number
  unrealized_pnl: number
  status: LabStatus
}
export interface LabRun {
  run_id: string
  target_id: string
  started_at: string
  ended_at: string | null
  status: LabStatus
  error: string | null
}
export interface LabOrder {
  client_order_id: string
  run_id: string
  symbol: string
  direction: string
  offset: string
  quantity: number
  limit_price: number
  broker_order_id: string | null
  status: string
  traded: number
  created_at: string
  updated_at: string
}
export interface LabTrade {
  trade_key: string
  run_id: string
  client_order_id: string | null
  symbol: string
  direction: string
  offset: string
  price: number
  volume: number
  trade_time: string | null
  slippage: number | null
}
export interface LabIncident { run_id: string | null; observed_at: string | null; code: string; message: string }
export interface LabSeries { equity: LabPoint[]; cumulative_pnl: LabPoint[]; drawdown: LabPoint[]; daily_pnl: LabPoint[] }
export interface LabDashboard {
  schema_version: string
  generated_at: string
  runtime_version: string
  summary: LabSummary
  metrics: LabMetrics
  series: LabSeries
  portfolio: LabPortfolioRow[]
  runs: LabRun[]
  orders: LabOrder[]
  trades: LabTrade[]
  snapshots: LabSnapshot[]
  incidents: LabIncident[]
}
export interface LabSnapshot { snapshot_id: string; run_id: string; phase: string; observed_at: string; equity: number | null; available: number | null; margin: number | null; unrealized_pnl: number | null }
export interface LabRunDetail { run: LabRun; orders: LabOrder[]; trades: LabTrade[]; snapshots: LabSnapshot[] }
export interface DashboardResponse { stale: boolean; last_success_at: string | null; web_version: string; dashboard: LabDashboard }
export interface RunsResponse { stale: boolean; last_success_at: string | null; runs: LabRun[] }
export interface RunResponse { stale: boolean; last_success_at: string | null; run: LabRunDetail }
