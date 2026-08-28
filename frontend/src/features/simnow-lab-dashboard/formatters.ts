const shanghai = new Intl.DateTimeFormat('zh-CN', {
  timeZone: 'Asia/Shanghai', year: 'numeric', month: '2-digit', day: '2-digit',
  hour: '2-digit', minute: '2-digit', second: '2-digit', hour12: false
})
const number = new Intl.NumberFormat('zh-CN', { maximumFractionDigits: 2 })
const money = new Intl.NumberFormat('zh-CN', { style: 'currency', currency: 'CNY', maximumFractionDigits: 2 })
const chartTime = new Intl.DateTimeFormat('zh-CN', {
  timeZone: 'Asia/Shanghai', month: '2-digit', day: '2-digit',
  hour: '2-digit', minute: '2-digit', hour12: false
})

export const formatNumber = (value: number | null | undefined) => value == null ? '—' : number.format(value)
export const formatMoney = (value: number | null | undefined) => value == null ? '—' : money.format(value)
export const formatPercent = (value: number | null | undefined) => value == null ? '—' : `${number.format(value * 100)}%`
export const formatTime = (value: string | null | undefined) => value ? shanghai.format(new Date(value)).replaceAll('/', '-') : '—'
export const formatChartTime = (unixSeconds: number) => chartTime.format(new Date(unixSeconds * 1000)).replaceAll('/', '-')
export const shortId = (value: string | null | undefined) => value ? `${value.slice(0, 8)}…${value.slice(-6)}` : '—'
export function statusTagType(status: string): 'info' | 'success' | 'warning' | 'error' | 'default' {
  if (status === 'RUNNING') return 'info'
  if (['DONE', 'NOOP', 'ALIGNED'].includes(status)) return 'success'
  if (['PARTIAL', 'STALE', 'DEGRADED'].includes(status)) return 'warning'
  if (['FAILED', 'OFFLINE', 'UNKNOWN'].includes(status)) return 'error'
  return 'default'
}
