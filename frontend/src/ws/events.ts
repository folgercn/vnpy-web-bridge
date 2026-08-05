import { useTerminalStore } from '../stores/terminal'
import { useAuthStore } from '../stores/auth'
import { getWebSocketTicket } from '../api/ws'
import { ref } from 'vue'

export const wsUrl =
  import.meta.env.VITE_WS_URL ||
  `${window.location.protocol === 'https:' ? 'wss' : 'ws'}://${window.location.host}/ws/events`

export interface WsEvent {
  type: string
  ts: string
  data: Record<string, unknown>
}

export class EventSocket {
  status = ref<'disconnected' | 'connecting' | 'connected' | 'reconnecting'>('disconnected')
  private socket: WebSocket | null = null
  private reconnectTimer = 0

  async connect() {
    if (this.socket && (this.socket.readyState === WebSocket.CONNECTING || this.socket.readyState === WebSocket.OPEN)) return
    this.status.value = this.socket ? 'reconnecting' : 'connecting'
    let ticket: string
    try {
      const issued = await getWebSocketTicket()
      ticket = issued.ticket
    } catch {
      this.scheduleReconnect()
      return
    }
    // ``connect`` awaits a ticket request; ``close`` may run during that
    // await and mark the socket disconnected.  Keep the runtime guard while
    // avoiding an over-narrowed literal-union comparison in TypeScript.
    if ((this.status.value as string) === 'disconnected') return
    const url = `${wsUrl}${wsUrl.includes('?') ? '&' : '?'}ticket=${encodeURIComponent(ticket)}`
    this.socket = new WebSocket(url)
    this.socket.onopen = () => {
      this.status.value = 'connected'
      window.clearTimeout(this.reconnectTimer)
      void useTerminalStore().refreshStatus()
      void useTerminalStore().refreshSnapshots()
    }
    this.socket.onmessage = (message) => this.handleMessage(message.data)
    this.socket.onclose = (event) => this.scheduleReconnect(event)
    this.socket.onerror = () => this.scheduleReconnect()
  }

  close() {
    window.clearTimeout(this.reconnectTimer)
    this.socket?.close()
    this.socket = null
    this.status.value = 'disconnected'
  }

  handleMessage(raw: string) {
    try {
      const event = JSON.parse(raw) as WsEvent
      if (!event || typeof event.type !== 'string' || !event.data || typeof event.data !== 'object' || Array.isArray(event.data)) return
      useTerminalStore().applyEvent(event.type, event.data)
    } catch {
      useTerminalStore().applyEvent('log', { level: 'warn', message: 'invalid websocket message' })
    }
  }

  private scheduleReconnect(event?: CloseEvent) {
    this.socket = null
    if (event?.code === 1008) {
      useAuthStore().logout()
      this.status.value = 'disconnected'
      window.clearTimeout(this.reconnectTimer)
      if (window.location.pathname !== '/login') window.location.assign('/login')
      return
    }
    if (this.status.value === 'disconnected') return
    this.status.value = 'reconnecting'
    window.clearTimeout(this.reconnectTimer)
    this.reconnectTimer = window.setTimeout(() => this.connect(), 2000)
  }
}

export const eventSocket = new EventSocket()
