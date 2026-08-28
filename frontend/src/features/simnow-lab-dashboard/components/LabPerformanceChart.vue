<template>
  <section class="charts" aria-label="收益图表">
    <n-card v-for="chart in charts" :key="chart.key" class="lab-card" size="small" :title="chartTitle(chart)">
      <n-empty v-if="!series[chart.key].length" description="暂无数据" />
      <div v-else :ref="(element) => setHost(chart.key, element)" class="chart-host" />
    </n-card>
  </section>
</template>

<script setup lang="ts">
import { nextTick, onBeforeUnmount, onMounted, watch } from 'vue'
import { AreaSeries, ColorType, HistogramSeries, LineSeries, createChart, type IChartApi, type Time, type UTCTimestamp } from 'lightweight-charts'
import { NCard, NEmpty } from 'naive-ui'
import { calculateReturnRatio, formatChartTime, formatPercent } from '../formatters'
import type { LabSeries } from '../types'

type SeriesKey = keyof LabSeries
const props = defineProps<{ series: LabSeries }>()
const charts: { key: SeriesKey; title: string }[] = [
  { key: 'equity', title: '权益' }, { key: 'cumulative_pnl', title: '累计 PnL' },
  { key: 'drawdown', title: '回撤' }, { key: 'daily_pnl', title: '每日 PnL' }
]
function chartTitle(chart: { key: SeriesKey; title: string }) {
  if (chart.key !== 'cumulative_pnl') return chart.title
  const equity = props.series.equity
  const ratio = calculateReturnRatio(equity.at(-1)?.value, equity[0]?.value)
  return `${chart.title} · 区间收益率 ${formatPercent(ratio)}`
}
const hosts = new Map<SeriesKey, HTMLElement>()
const instances = new Map<SeriesKey, IChartApi>()
function setHost(key: SeriesKey, element: unknown) { if (element instanceof HTMLElement) hosts.set(key, element) }
function css(name: string) { return getComputedStyle(document.documentElement).getPropertyValue(name).trim() }
function render() {
  instances.forEach((chart) => chart.remove()); instances.clear()
  for (const item of charts) {
    const host = hosts.get(item.key); if (!host || !props.series[item.key].length) continue
    const chart = createChart(host, { autoSize: true, layout: { background: { type: ColorType.Solid, color: css('--surface-card') }, textColor: css('--text-muted') }, grid: { vertLines: { color: css('--surface-border') }, horzLines: { color: css('--surface-border') } }, localization: { timeFormatter: (time: Time) => formatChartTime(Number(time)) }, timeScale: { timeVisible: true, secondsVisible: false, tickMarkFormatter: (time: Time) => formatChartTime(Number(time)) } })
    const color = item.key === 'equity' ? css('--color-primary') : item.key === 'drawdown' ? css('--color-error') : css('--color-success')
    const data = props.series[item.key]
      .map((point) => ({ time: Math.floor(Date.parse(point.time) / 1000) as UTCTimestamp, value: point.value }))
      .sort((left, right) => Number(left.time) - Number(right.time))
      .filter((point, index, values) => index === 0 || point.time !== values[index - 1].time)
    if (item.key === 'daily_pnl') chart.addSeries(HistogramSeries, { color }).setData(data.map((point) => ({ ...point, color: point.value >= 0 ? css('--color-success') : css('--color-error') })))
    else if (item.key === 'drawdown') chart.addSeries(AreaSeries, { lineColor: color, topColor: color, bottomColor: css('--surface-card') }).setData(data)
    else chart.addSeries(LineSeries, { color, lineWidth: 2 }).setData(data)
    chart.timeScale().fitContent(); instances.set(item.key, chart)
  }
}
onMounted(() => nextTick(render)); watch(() => props.series, () => nextTick(render), { deep: true })
onBeforeUnmount(() => instances.forEach((chart) => chart.remove()))
</script>

<style scoped>
.charts { display: grid; grid-template-columns: repeat(2, minmax(0, 1fr)); gap: var(--space-4); margin-top: var(--section-gap); }
.lab-card { border-radius: var(--card-radius); }
.chart-host { width: 100%; height: var(--chart-height); }
@media (width <= 980px) { .charts { grid-template-columns: 1fr; } }
</style>
