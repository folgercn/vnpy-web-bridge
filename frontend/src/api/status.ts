import { request } from './client'

export interface ExecutionStatusProjection {
  schema_version: 'web_bridge_execution_status_v1'
  service: 'execution-orchestrator'
  service_version: string
  observed_at: string
  lifecycle: string
  state_version: number
  leader: Record<string, unknown>
  authority: Record<string, unknown>
  plan: Record<string, unknown>
  send_intents: Record<string, unknown>[]
  reconciliation: Record<string, unknown>
  safe_to_restart: boolean
  broker: Record<string, unknown>
}

export const getStatus = () => request<Record<string, unknown>>('/api/status')
export const getExecutionStatus = () => request<ExecutionStatusProjection>('/api/execution/status')
