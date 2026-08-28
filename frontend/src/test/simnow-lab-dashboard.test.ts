import { describe, expect, it } from 'vitest'
import { readFileSync } from 'node:fs'
import { resolve } from 'node:path'
import { calculateReturnRatio, formatChartTime, formatNumber, shortId, statusTagType } from '../features/simnow-lab-dashboard/formatters'

describe('SIMNOW_LAB dashboard presentation', () => {
  it.each([
    ['RUNNING', 'info'], ['DONE', 'success'], ['NOOP', 'success'],
    ['PARTIAL', 'warning'], ['STALE', 'warning'], ['FAILED', 'error'], ['UNKNOWN', 'error'], ['IDLE', 'default']
  ] as const)('maps %s to the fixed semantic tag %s', (status, type) => {
    expect(statusTagType(status)).toBe(type)
  })

  it('formats metrics and identifiers consistently', () => {
    expect(formatNumber(1234.5)).toContain('1,234.5')
    expect(shortId('1234567890abcdef')).toBe('12345678…abcdef')
  })

  it('formats chart timestamps in Shanghai time', () => {
    expect(formatChartTime(Date.parse('2026-08-28T06:09:00Z') / 1000)).toContain('14:09')
  })

  it('calculates the visible period return from starting equity', () => {
    expect(calculateReturnRatio(19_948_712.81, 19_942_777.86)).toBeCloseTo(0.0002976, 7)
    expect(calculateReturnRatio(100, 0)).toBeNull()
  })

  it('keeps the dashboard-only shell off legacy Execution and WS startup', () => {
    const source = readFileSync(resolve('src/components/AppLayout.vue'), 'utf8')
    expect(source).toContain('if (dashboardOnly) return')
    expect(source).toContain('const menuOptions = dashboardOnly ?')
  })

  it('keeps intraday snapshots at unique timestamp precision', () => {
    const source = readFileSync(resolve('src/features/simnow-lab-dashboard/components/LabPerformanceChart.vue'), 'utf8')
    expect(source).toContain('Date.parse(point.time) / 1000')
    expect(source).toContain('tickMarkFormatter')
    expect(source).toContain('timeFormatter')
    expect(source).toContain('区间收益率')
    expect(source).toContain('margin-top: var(--section-gap)')
    expect(source).not.toContain("point.time.slice(0, 10)")
  })
})
