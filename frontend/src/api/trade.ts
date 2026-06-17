import { request } from './client'

export interface OrderPayload {
  symbol: string
  exchange: string
  direction: 'long' | 'short'
  offset: 'open' | 'close' | 'closetoday' | 'closeyesterday'
  type: 'limit'
  price: number
  volume: number
  gateway_name?: string
  confirm: boolean
}

export const getOrders = () => request<Record<string, unknown>[]>('/api/orders')
export const getTrades = () => request<Record<string, unknown>[]>('/api/trades')
export const sendOrder = (payload: OrderPayload) =>
  request<Record<string, unknown>>('/api/orders', { method: 'POST', body: JSON.stringify(payload) })
export const cancelOrder = (vtOrderid: string) =>
  request<Record<string, unknown>>(`/api/orders/${encodeURIComponent(vtOrderid)}/cancel`, {
    method: 'POST',
    body: JSON.stringify({})
  })
export const cancelAll = (payload: Record<string, unknown> = {}) =>
  request<Record<string, unknown>>('/api/orders/cancel-all', { method: 'POST', body: JSON.stringify(payload) })
