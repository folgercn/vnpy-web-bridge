import { request } from './client'

export const getAccount = () => request<Record<string, unknown>[]>('/api/account')
export const getPositions = () => request<Record<string, unknown>[]>('/api/positions')
