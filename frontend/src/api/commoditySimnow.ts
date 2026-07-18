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
  position_manager_shadow?: CommodityPositionManagerShadowStatus
}

export interface CommodityPositionManagerShadowTarget {
  product: string
  exact_contract: string
  baseline_target_quantity: number
  shadow_target_quantity: number
  baseline_source_target_weight: number
  shadow_source_target_weight: number
  baseline_buffered_target_weight: number
  shadow_buffered_target_weight: number
}

export interface CommodityPositionManagerShadowStatus {
  configured?: boolean
  valid?: boolean
  snapshot_hash?: string
  snapshot_id?: string
  position_manager_id?: string
  sector_map_id?: string
  mode?: string
  baseline_scheduler_id?: string
  baseline_batch_hash?: string
  baseline_link_state?: 'active' | 'completed' | 'unlinked'
  source_month?: string
  execution_day?: string
  input_cutoff_day?: string
  fast_lookback_days?: number
  slow_lookback_days?: number
  fast_annual_vol?: number
  slow_annual_vol?: number
  raw_scale?: number
  continuity_mode?: 'genesis' | 'linked'
  previous_snapshot_hash?: string | null
  continuity_state?: 'genesis' | 'verified' | 'unlinked'
  continuity_verified?: boolean
  previous_smoothed_scale?: number
  smoothed_scale?: number
  target_change_count?: number
  maximum_abs_target_quantity_delta?: number
  authority_granted?: boolean
  dispatch_allowed?: boolean
  error_type?: string
  targets?: CommodityPositionManagerShadowTarget[]
}

export const getCommoditySimNowStatus = () =>
  request<CommoditySimNowStatus>('/api/commodity-simnow/status')

export const getCommodityPositionManagerShadow = () =>
  request<CommodityPositionManagerShadowStatus>('/api/commodity-simnow/position-manager-shadow')

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
