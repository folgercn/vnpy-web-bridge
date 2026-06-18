import { describe, expect, it } from 'vitest'
import { contractYearMonth, isMainContract, mainContracts, nextMainContractYearMonth, preferredMainContract } from '../utils/marketContracts'

const now = new Date('2026-06-18T12:00:00+08:00')

describe('main contract helpers', () => {
  it('uses the next 1/5/9 main month', () => {
    expect(nextMainContractYearMonth(now)).toBe(2609)
  })

  it('marks 2609 as the current main contract in June 2026', () => {
    expect(isMainContract({ symbol: 'bu2609', exchange: 'SHFE' }, now)).toBe(true)
    expect(isMainContract({ symbol: 'bu2607', exchange: 'SHFE' }, now)).toBe(false)
  })

  it('normalizes CZCE three-digit contract months to the same main month', () => {
    expect(contractYearMonth({ symbol: 'ma609', exchange: 'CZCE' }, now)).toBe(2609)
    expect(isMainContract({ symbol: 'ma609', exchange: 'CZCE' }, now)).toBe(true)
  })

  it('keeps only main contracts from a contract list', () => {
    const rows = [
      { symbol: 'bu2607', exchange: 'SHFE' },
      { symbol: 'bu2609', exchange: 'SHFE' },
      { symbol: 'bu2612', exchange: 'SHFE' }
    ]

    expect(mainContracts(rows, now).map((row) => row.symbol)).toEqual(['bu2609'])
    expect(preferredMainContract(rows, now)?.symbol).toBe('bu2609')
  })
})
