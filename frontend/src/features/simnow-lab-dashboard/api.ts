import { request } from '../../api/client'
import type { DashboardResponse, RunResponse, RunsResponse } from './types'

const root = '/api/v1/simnow-lab'

export function getLabDashboard(): Promise<DashboardResponse> {
  return request<DashboardResponse>(`${root}/dashboard`)
}

export function getLabRuns(): Promise<RunsResponse> {
  return request<RunsResponse>(`${root}/runs`)
}

export function getLabRun(runId: string): Promise<RunResponse> {
  return request<RunResponse>(`${root}/runs/${encodeURIComponent(runId)}`)
}
