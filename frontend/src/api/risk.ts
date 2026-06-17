import { request } from './client'

export const getRiskStatus = () => request<Record<string, unknown>>('/api/risk/status')
export const getRiskRules = () => request<Record<string, unknown>>('/api/risk/rules')
export const enableTrade = () => request<Record<string, unknown>>('/api/risk/trade/enable', { method: 'POST' })
export const disableTrade = () => request<Record<string, unknown>>('/api/risk/trade/disable', { method: 'POST' })
