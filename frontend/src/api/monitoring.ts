import { request } from './client'

export interface MonitorSummary {
  enabled?: boolean
  active_count?: number
  highest_severity?: string
  last_updated_at?: string | null
  silence_count?: number
  telegram?: Record<string, unknown>
  last_check?: Record<string, unknown>
}

export interface MonitorIncident {
  incident_id: string
  rule_id: string
  scope_id: string
  status: string
  severity: string
  summary?: string
  first_seen?: string
  last_seen?: string
  acknowledged_by?: string
}

export const getMonitorSummary = () => request<MonitorSummary>('/api/monitor/summary')
export const getMonitorIncidents = (includeResolved = false) =>
  request<MonitorIncident[]>(`/api/monitor/incidents?include_resolved=${includeResolved ? 'true' : 'false'}`)
export const getTelegramConfig = () => request<Record<string, unknown>>('/api/monitor/telegram/config')
