import { createPinia, setActivePinia } from 'pinia'
import { beforeEach, describe, expect, it } from 'vitest'
import { useTerminalStore } from '../stores/terminal'
import { EventSocket } from '../ws/events'

describe('terminal websocket event handler', () => {
  beforeEach(() => setActivePinia(createPinia()))

  it('updates tick snapshot', () => {
    const store = useTerminalStore()
    store.applyEvent('tick', { vt_symbol: 'rb2610.SHFE', last_price: 3000 })

    expect(store.ticks['rb2610.SHFE'].last_price).toBe(3000)
  })

  it('keeps bounded logs', () => {
    const store = useTerminalStore()
    store.applyEvent('risk_alert', { action: 'trade_disable', status: { web_trade_enabled: false } })

    expect(store.logs[0].action).toBe('trade_disable')
    expect(store.riskStatus.web_trade_enabled).toBe(false)
  })

  it('ignores malformed websocket envelopes without crashing', () => {
    const socket = new EventSocket()
    const store = useTerminalStore()

    expect(() => socket.handleMessage(JSON.stringify({ type: 'tick', data: null }))).not.toThrow()
    expect(() => socket.handleMessage(JSON.stringify({ type: 'tick', data: [] }))).not.toThrow()

    expect(Object.keys(store.ticks)).toHaveLength(0)
  })
})
