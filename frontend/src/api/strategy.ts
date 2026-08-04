import { request } from './client'

export interface StrategySummary {
  strategy_name: string
  class_name?: string
  vt_symbol?: string
  status?: string
  inited?: boolean
  trading?: boolean
  [key: string]: unknown
}

export interface StrategyLogEntry {
  timestamp?: string
  level?: string
  message?: string
  strategy_name?: string
  [key: string]: unknown
}

export const getStrategies = () => request<StrategySummary[]>('/api/strategies')
export const initStrategy = (name: string) => request(`/api/strategies/${name}/init`, { method: 'POST' })
export const startStrategy = (name: string) => request(`/api/strategies/${name}/start`, { method: 'POST' })
export const stopStrategy = (name: string) => request(`/api/strategies/${name}/stop`, { method: 'POST' })
export const getStrategyLogs = (name: string) => request<StrategyLogEntry[]>(`/api/strategies/${name}/logs`)
