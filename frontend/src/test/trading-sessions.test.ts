import { describe, expect, it } from 'vitest'
import { getTradingSessionStatus } from '../utils/tradingSessions'

describe('trading session status', () => {
  it('detects commodity day session', () => {
    const status = getTradingSessionStatus('SHFE', 'ru2609', new Date(2026, 5, 18, 9, 30))

    expect(status.isOpen).toBe(true)
    expect(status.statusText).toBe('上午盘进行中')
  })

  it('detects product night session', () => {
    const status = getTradingSessionStatus('CZCE', 'ma609', new Date(2026, 5, 18, 21, 30))

    expect(status.isOpen).toBe(true)
    expect(status.statusText).toBe('夜盘进行中')
  })

  it('shows next open countdown during closed hours', () => {
    const status = getTradingSessionStatus('GFEX', 'ps2609', new Date(2026, 5, 18, 16, 0))

    expect(status.isOpen).toBe(false)
    expect(status.nextOpenText).toBe('今天 21:00')
    expect(status.countdownText).toBe('5小时')
  })

  it('uses the provided clock when formatting tomorrow', () => {
    const status = getTradingSessionStatus('SHFE', 'ru2609', new Date(2026, 5, 18, 23, 30))

    expect(status.nextOpenText).toBe('明天 09:00')
  })
})
