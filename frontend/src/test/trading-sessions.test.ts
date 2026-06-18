import { describe, expect, it } from 'vitest'
import { getTradingSessionStatus } from '../utils/tradingSessions'

describe('trading session status', () => {
  const chinaTime = (value: string) => new Date(`${value}+08:00`)

  it('detects commodity day session', () => {
    const status = getTradingSessionStatus('SHFE', 'ru2609', chinaTime('2026-06-18T09:30:00'))

    expect(status.isOpen).toBe(true)
    expect(status.statusText).toBe('上午盘进行中')
  })

  it('uses the shared CFFEX day session profile', () => {
    const beforeOpen = getTradingSessionStatus('CFFEX', 'IF2606', chinaTime('2026-06-18T09:15:00'))
    const afterOpen = getTradingSessionStatus('CFFEX', 'IF2606', chinaTime('2026-06-18T09:45:00'))

    expect(beforeOpen.isOpen).toBe(false)
    expect(afterOpen.isOpen).toBe(true)
  })

  it('detects product night session', () => {
    const status = getTradingSessionStatus('CZCE', 'ma609', chinaTime('2026-06-18T21:30:00'))

    expect(status.isOpen).toBe(true)
    expect(status.statusText).toBe('夜盘进行中')
  })

  it('shows next open countdown during closed hours', () => {
    const status = getTradingSessionStatus('SHFE', 'ru2609', chinaTime('2026-06-18T16:00:00'))

    expect(status.isOpen).toBe(false)
    expect(status.nextOpenText).toBe('今天 21:00')
    expect(status.countdownText).toBe('5小时')
  })

  it('uses the provided clock when formatting tomorrow', () => {
    const status = getTradingSessionStatus('SHFE', 'ru2609', chinaTime('2026-06-18T23:30:00'))

    expect(status.nextOpenText).toBe('明天 09:00')
  })

  it('uses China time instead of browser local time', () => {
    const status = getTradingSessionStatus('SHFE', 'rb2607', new Date('2026-06-18T13:30:00.000Z'))

    expect(status.isOpen).toBe(true)
    expect(status.currentSessionText).toBe('21:00-23:00')
  })

  it('detects steel night sessions by product and exchange', () => {
    const rb = getTradingSessionStatus('SHFE', 'rb2607', chinaTime('2026-06-18T21:30:00'))
    const hc = getTradingSessionStatus('SHFE', 'hc2607', chinaTime('2026-06-18T21:30:00'))
    const wr = getTradingSessionStatus('SHFE', 'wr2607', chinaTime('2026-06-18T21:30:00'))
    const ss = getTradingSessionStatus('SHFE', 'ss2607', chinaTime('2026-06-19T00:30:00'))

    expect(rb.isOpen).toBe(true)
    expect(hc.isOpen).toBe(true)
    expect(wr.isOpen).toBe(true)
    expect(ss.isOpen).toBe(true)
    expect(ss.currentSessionText).toBe('21:00-01:00')
  })

  it('uses shared night product allowlist without defaulting unknown products', () => {
    const ad = getTradingSessionStatus('SHFE', 'ad2607', chinaTime('2026-06-19T00:30:00'))
    const unknown = getTradingSessionStatus('SHFE', 'zz2607', chinaTime('2026-06-18T21:30:00'))

    expect(ad.isOpen).toBe(true)
    expect(ad.currentSessionText).toBe('21:00-01:00')
    expect(unknown.isOpen).toBe(false)
  })

  it('does not add night sessions for GFEX products by default', () => {
    const status = getTradingSessionStatus('GFEX', 'ps2609', chinaTime('2026-06-18T21:30:00'))

    expect(status.isOpen).toBe(false)
    expect(status.nextOpenText).toBe('明天 09:00')
  })
})
