import { readFileSync } from 'node:fs'
import { resolve } from 'node:path'
import { describe, expect, it } from 'vitest'

const pages = [
  'Dashboard.vue',
  'DataManagement.vue',
  'Strategies.vue',
  'Market.vue',
  'Trading.vue',
  'Orders.vue',
  'Positions.vue',
  'Account.vue',
  'Trades.vue'
]

describe('Phase A unavailable surfaces', () => {
  it.each(pages)('%s does not import or call a removed worker API', (page) => {
    const source = readFileSync(resolve(process.cwd(), 'src/pages', page), 'utf8')

    expect(source).toMatch(/PhaseBUnavailable|PHASE_B_UNAVAILABLE/)
    expect(source).not.toMatch(/api\/(monitoring|market|strategy|trade|account|risk)/)
    expect(source).not.toMatch(
      /getMonitor|refreshMonitoring|getMarketData|useStrategiesStore|sendOrder|cancelOrder|getAccount|getPositions|getOrders|getTrades|refreshSnapshots|refreshContracts|refreshTick|subscribeMarket|unsubscribeMarket/
    )
  })

  it('does not mount the legacy Commodity SimNow page', () => {
    const source = readFileSync(resolve(process.cwd(), 'src/router/index.ts'), 'utf8')

    expect(source).not.toContain('CommoditySimNowPage')
    expect(source).toContain("component: PhaseBUnavailable")
    expect(source).toContain("surface: '商品 SimNow'")
  })
})
