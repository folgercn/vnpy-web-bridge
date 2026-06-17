import { request } from './client'

export const getContracts = () => request<Record<string, unknown>[]>('/api/contracts')
export const subscribeMarket = (symbol: string, exchange: string) =>
  request<Record<string, unknown>>('/api/market/subscribe', {
    method: 'POST',
    body: JSON.stringify({ symbol, exchange })
  })
export const getTick = (vtSymbol: string) => request<Record<string, unknown>>(`/api/market/tick/${vtSymbol}`)
