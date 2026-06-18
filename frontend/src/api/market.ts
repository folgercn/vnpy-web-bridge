import { apiBaseUrl, request } from './client'

export interface MarketDataQuery {
  symbol?: string
  exchange?: string
  vt_symbol?: string
  start?: string
  end?: string
  limit?: number
}

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
export const getMarketDataOverview = (limit = 500) =>
  request<Record<string, unknown>[]>(`/api/market/data/overview?limit=${limit}`)
export const getMarketDataTicks = (query: MarketDataQuery) =>
  request<Record<string, unknown>[]>(`/api/market/data/ticks?${toQueryString(query)}`)
export const importMarketDataCsv = async (file: File) => {
  const token = localStorage.getItem('access_token')
  const body = new FormData()
  body.append('file', file)
  const headers = new Headers()
  if (token) headers.set('Authorization', `Bearer ${token}`)
  const response = await fetch(`${apiBaseUrl}/api/market/data/import`, { method: 'POST', headers, body })
  const payload = await response.json()
  if (!payload.ok || !response.ok) throw new Error(payload.error?.message || response.statusText)
  return payload.data as Record<string, unknown>
}
export const exportMarketDataCsv = async (query: MarketDataQuery) => {
  const token = localStorage.getItem('access_token')
  const headers = new Headers()
  if (token) headers.set('Authorization', `Bearer ${token}`)
  const response = await fetch(`${apiBaseUrl}/api/market/data/export?${toQueryString(query)}`, { headers })
  if (!response.ok) throw new Error(response.statusText)
  return response.blob()
}

function toQueryString(query: MarketDataQuery) {
  const params = new URLSearchParams()
  for (const [key, value] of Object.entries(query)) {
    if (value !== undefined && value !== null && value !== '') params.set(key, String(value))
  }
  return params.toString()
}
