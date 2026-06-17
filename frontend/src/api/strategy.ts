import { request } from './client'

export const getStrategies = () => request<Record<string, unknown>[]>('/api/strategies')
export const initStrategy = (name: string) => request(`/api/strategies/${name}/init`, { method: 'POST' })
export const startStrategy = (name: string) => request(`/api/strategies/${name}/start`, { method: 'POST' })
export const stopStrategy = (name: string) => request(`/api/strategies/${name}/stop`, { method: 'POST' })
export const getStrategyLogs = (name: string) => request<Record<string, unknown>[]>(`/api/strategies/${name}/logs`)
