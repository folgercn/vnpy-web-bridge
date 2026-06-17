import { request } from './client'

export const getStatus = () => request<Record<string, unknown>>('/api/status')
export const getRpcStatus = () => request<Record<string, unknown>>('/api/rpc/status')
export const getGatewayStatus = () => request<Record<string, unknown>>('/api/gateway/status')
export const getTradeConfig = () => request<Record<string, unknown>>('/api/trade/config')
