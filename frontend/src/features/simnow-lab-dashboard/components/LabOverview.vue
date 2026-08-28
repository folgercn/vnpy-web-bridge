<template>
  <n-card class="lab-card" size="small">
    <div class="status-strip">
      <div><span class="label">Lab</span><LabStatusTag :status="summary.status" /></div>
      <div><span class="label">目标一致</span><strong>{{ summary.aligned_products }}/{{ summary.total_products }}</strong></div>
      <div><span class="label">Active</span><strong :class="{ danger: summary.active_order_count > 0 }">{{ summary.active_order_count }}</strong></div>
      <div><span class="label">UNKNOWN</span><strong :class="{ danger: summary.unknown_order_count > 0 }">{{ summary.unknown_order_count }}</strong></div>
      <div><span class="label">最近运行</span><span class="mono" :title="summary.last_run_id || ''">{{ shortId(summary.last_run_id) }}</span></div>
    </div>
  </n-card>
  <section class="metric-grid" aria-label="核心指标">
    <n-card v-for="item in items" :key="item.label" class="lab-card" size="small">
      <span class="label">{{ item.label }}</span>
      <strong class="metric" :class="item.tone">{{ item.value }}</strong>
    </n-card>
  </section>
</template>

<script setup lang="ts">
import { computed } from 'vue'
import { NCard } from 'naive-ui'
import { formatMoney, formatNumber, shortId } from '../formatters'
import type { LabMetrics, LabSummary } from '../types'
import LabStatusTag from './LabStatusTag.vue'

const props = defineProps<{ summary: LabSummary; metrics: LabMetrics }>()
const items = computed(() => [
  { label: '当前权益', value: formatMoney(props.metrics.equity), tone: '' },
  { label: '今日 PnL', value: formatMoney(props.metrics.daily_pnl), tone: props.metrics.daily_pnl >= 0 ? 'positive' : 'negative' },
  { label: '累计 PnL', value: formatMoney(props.metrics.cumulative_pnl), tone: props.metrics.cumulative_pnl >= 0 ? 'positive' : 'negative' },
  { label: '最大回撤', value: formatMoney(props.metrics.max_drawdown), tone: 'negative' },
  { label: '可用资金', value: formatMoney(props.metrics.available), tone: '' },
  { label: '保证金', value: formatMoney(props.metrics.margin), tone: '' },
  { label: '累计滑点', value: formatNumber(props.metrics.slippage), tone: props.metrics.slippage <= 0 ? 'positive' : 'negative' },
  { label: '成交笔数', value: formatNumber(props.metrics.trade_count), tone: '' }
])
</script>

<style scoped>
.lab-card { border-radius: var(--card-radius); }
.status-strip { display: grid; grid-template-columns: repeat(5, minmax(0, 1fr)); gap: var(--space-4); align-items: center; }
.status-strip > div { display: flex; flex-direction: column; gap: var(--space-1); min-width: 0; }
.metric-grid { display: grid; grid-template-columns: repeat(4, minmax(0, 1fr)); gap: var(--space-4); }
.label { color: var(--text-muted); font-size: var(--font-caption-size); line-height: var(--font-caption-line); }
.metric { display: block; margin-top: var(--space-1); font-size: var(--font-metric-size); line-height: var(--font-metric-line); font-variant-numeric: tabular-nums; }
.positive { color: var(--color-success); }
.negative, .danger { color: var(--color-error); }
.mono { overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
@media (width <= 980px) { .status-strip { grid-template-columns: repeat(2, minmax(0, 1fr)); } .metric-grid { grid-template-columns: repeat(2, minmax(0, 1fr)); } }
@media (width <= 640px) { .status-strip, .metric-grid { grid-template-columns: 1fr; } }
</style>
