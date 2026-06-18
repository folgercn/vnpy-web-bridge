import { describe, expect, it } from 'vitest'
import { contractSearchText, formatContractTitle, normalizeKeyword } from '../utils/marketContracts'

describe('market contract search', () => {
  it('matches steel aliases when contract name does not contain steel', async () => {
    const row = { symbol: 'rb2607', exchange: 'SHFE', vt_symbol: 'rb2607.SHFE', name: '螺纹2607' }

    expect(contractSearchText(row)).toContain(normalizeKeyword('钢'))
    expect(formatContractTitle(row, '螺纹钢')).toBe('螺纹钢2607 / RB2607 · 上期所')
  })
})
