import { createPinia, setActivePinia } from 'pinia'
import { beforeEach, describe, expect, it } from 'vitest'
import { useTerminalStore } from '../stores/terminal'

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
})
