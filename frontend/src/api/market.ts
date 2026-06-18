import { request } from './client'

export interface MarketWatchlistItem {
  watch_type: 'product' | 'contract'
  watch_key: string
  vt_symbol?: string
  symbol?: string
  exchange?: string
  display_name: string
  product_codes: string[]
  exchange_codes: string[]
}

export const getContracts = () => request<Record<string, unknown>[]>('/api/contracts')
export const getMarketWatchlist = () => request<MarketWatchlistItem[]>('/api/market/watchlist')
export const addMarketWatchlistItem = (item: { vt_symbol: string; symbol: string; exchange: string; display_name: string }) =>
  request<MarketWatchlistItem>('/api/market/watchlist', {
    method: 'POST',
    body: JSON.stringify(item)
  })
export const removeMarketWatchlistItem = (watchKey: string) =>
  request<{ removed: boolean; watch_key: string }>(`/api/market/watchlist/${encodeURIComponent(watchKey)}`, {
    method: 'DELETE'
  })
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
