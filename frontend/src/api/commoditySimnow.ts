import { request } from './client'

export interface CommodityStrategyTemplateStatus {
  template_id?: string
  configured?: boolean
  authorized?: boolean
  products?: string[]
  rebalance_cycle?: string
  contract_selection?: string
  target_source?: string
  roll_policy?: string
  delivery_month_cutoff_day?: number
  sc_pre_delivery_cutoff_day?: number
  manual_product_selection?: boolean
  manual_cycle_selection?: boolean
  manual_contract_selection?: boolean
}

export interface CommoditySimNowStatus {
  configured?: boolean
  enabled?: boolean
  production_allowed?: boolean
  auto_dispatch_allowed?: boolean
  auto_dispatch_active?: boolean
  plan_status?: string
  plan_hash?: string | null
  strategy_template?: CommodityStrategyTemplateStatus
}

export const getCommoditySimNowStatus = () =>
  request<CommoditySimNowStatus>('/api/commodity-simnow/status')

export const startCommodityStrategyTemplate = () =>
  request<Record<string, unknown>>('/api/commodity-simnow/template/start', {
    method: 'POST',
    body: JSON.stringify({
      reason: 'one-click STATIC_CORE_EQUAL SimNow strategy start',
      confirm_strategy_template: true,
      confirm_simnow_only: true,
      confirm_auto_dispatch: true,
      confirm_no_production: true
    })
  })

export const stopCommodityStrategyTemplate = () =>
  request<Record<string, unknown>>('/api/commodity-simnow/disable', {
    method: 'POST',
    body: JSON.stringify({ reason: 'one-click strategy stop' })
  })
