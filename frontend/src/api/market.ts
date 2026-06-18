import { request } from './client'

export const getContracts = () => request<Record<string, unknown>[]>('/api/contracts')
export const subscribeMarket = (symbol: string, exchange: string) =>
  request<Record<string, unknown>>('/api/market/subscribe', {
    method: 'POST',
    body: JSON.stringify({ symbol, exchange })
  })
export const unsubscribeMarket = (symbol: string, exchange: string) =>
  request<Record<string, unknown>>('/api/market/unsubscribe', {
    method: 'POST',
    body: JSON.stringify({ symbol, exchange })
  })
export const getTick = (vtSymbol: string) => request<Record<string, unknown>>(`/api/market/tick/${vtSymbol}`)
export const getMarketBars = (symbol: string, exchange: string, interval = '1m', limit = 300) =>
  request<Record<string, unknown>[]>(
    `/api/market/bars?symbol=${encodeURIComponent(symbol)}&exchange=${encodeURIComponent(exchange)}&interval=${encodeURIComponent(interval)}&limit=${limit}`
  )
