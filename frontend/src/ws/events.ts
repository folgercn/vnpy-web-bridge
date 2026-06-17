import { useTerminalStore } from '../stores/terminal'

export const wsUrl = import.meta.env.VITE_WS_URL || 'ws://127.0.0.1:8000/ws/events'

export interface WsEvent {
  type: string
  ts: string
  data: Record<string, unknown>
}

export class EventSocket {
  status: 'disconnected' | 'connecting' | 'connected' | 'reconnecting' = 'disconnected'
  private socket: WebSocket | null = null
  private reconnectTimer = 0

  connect() {
    this.status = this.socket ? 'reconnecting' : 'connecting'
    this.socket = new WebSocket(wsUrl)
    this.socket.onopen = () => {
      this.status = 'connected'
      window.clearTimeout(this.reconnectTimer)
    }
    this.socket.onmessage = (message) => this.handleMessage(message.data)
    this.socket.onclose = () => this.scheduleReconnect()
    this.socket.onerror = () => this.scheduleReconnect()
  }

  close() {
    window.clearTimeout(this.reconnectTimer)
    this.socket?.close()
    this.socket = null
    this.status = 'disconnected'
  }

  handleMessage(raw: string) {
    const event = JSON.parse(raw) as WsEvent
    useTerminalStore().applyEvent(event.type, event.data)
  }

  private scheduleReconnect() {
    if (this.status === 'disconnected') return
    this.status = 'reconnecting'
    window.clearTimeout(this.reconnectTimer)
    this.reconnectTimer = window.setTimeout(() => this.connect(), 2000)
  }
}

export const eventSocket = new EventSocket()
