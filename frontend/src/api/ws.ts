import { request } from './client'

export interface WebSocketTicket {
  ticket: string
  expires_at: string
  ttl_seconds: number
}

/** Obtain a one-time ticket; bearer credentials stay in the HTTPS header. */
export const getWebSocketTicket = () =>
  request<WebSocketTicket>('/api/ws/ticket', { method: 'POST' })
