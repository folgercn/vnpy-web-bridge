type SessionWindow = {
  label: string
  start: string
  end: string
}

type ConcreteSession = {
  label: string
  start: Date
  end: Date
}

export type TradingSessionStatus = {
  exchange: string
  product: string
  isOpen: boolean
  label: string
  statusText: string
  nextOpenAt: Date | null
  nextOpenText: string
  countdownText: string
  currentSessionText: string
}

const commodityDaySessions: SessionWindow[] = [
  { label: '上午盘', start: '09:00', end: '10:15' },
  { label: '上午盘', start: '10:30', end: '11:30' },
  { label: '下午盘', start: '13:30', end: '15:00' }
]

const cffexDaySessions: SessionWindow[] = [
  { label: '上午盘', start: '09:30', end: '11:30' },
  { label: '下午盘', start: '13:00', end: '15:00' }
]

const productNightClose: Record<string, string> = {
  ru: '23:00',
  bu: '23:00',
  ma: '23:00',
  sa: '23:00',
  ps: '23:00'
}

export function getTradingSessionStatus(exchangeValue: unknown, symbolValue?: unknown, now = new Date()): TradingSessionStatus {
  const exchange = String(exchangeValue || '').toUpperCase()
  const product = symbolRoot(symbolValue)
  const sessions = concreteSessions(exchange, product, now)
  const current = sessions.find((item) => now >= item.start && now < item.end)
  const next = sessions.find((item) => item.start > now) || null

  return {
    exchange,
    product,
    isOpen: Boolean(current),
    label: current ? '开市' : '休市',
    statusText: current ? `${current.label}进行中` : '当前休市',
    nextOpenAt: next?.start || null,
    nextOpenText: next ? formatDateTime(next.start, now) : '-',
    countdownText: next ? formatDuration(next.start.getTime() - now.getTime()) : '-',
    currentSessionText: current ? `${formatTime(current.start)}-${formatTime(current.end)}` : next ? `${next.label} ${formatTime(next.start)}-${formatTime(next.end)}` : '-'
  }
}

export function symbolRoot(value: unknown) {
  return String(value || '').toLowerCase().replace(/\d+.*$/, '')
}

function concreteSessions(exchange: string, product: string, now: Date) {
  const result: ConcreteSession[] = []
  const daySessions = exchange === 'CFFEX' ? cffexDaySessions : commodityDaySessions
  const nightClose = productNightClose[product]

  for (let offset = -1; offset <= 7; offset += 1) {
    const date = localMidnight(now)
    date.setDate(date.getDate() + offset)
    if (!isWeekday(date)) continue

    for (const session of daySessions) result.push(toConcreteSession(date, session))
    if (nightClose) result.push(toConcreteSession(date, { label: '夜盘', start: '21:00', end: nightClose }))
  }

  return result.sort((a, b) => a.start.getTime() - b.start.getTime())
}

function toConcreteSession(date: Date, session: SessionWindow): ConcreteSession {
  const start = withTime(date, session.start)
  const end = withTime(date, session.end)
  if (end <= start) end.setDate(end.getDate() + 1)
  return { label: session.label, start, end }
}

function localMidnight(date: Date) {
  return new Date(date.getFullYear(), date.getMonth(), date.getDate())
}

function withTime(date: Date, time: string) {
  const [hour, minute] = time.split(':').map(Number)
  return new Date(date.getFullYear(), date.getMonth(), date.getDate(), hour, minute, 0, 0)
}

function isWeekday(date: Date) {
  const day = date.getDay()
  return day >= 1 && day <= 5
}

function formatDuration(ms: number) {
  const totalMinutes = Math.max(0, Math.ceil(ms / 60000))
  const days = Math.floor(totalMinutes / 1440)
  const hours = Math.floor((totalMinutes % 1440) / 60)
  const minutes = totalMinutes % 60
  const parts = []
  if (days) parts.push(`${days}天`)
  if (hours) parts.push(`${hours}小时`)
  if (minutes || !parts.length) parts.push(`${minutes}分`)
  return parts.join('')
}

function formatDateTime(date: Date, now: Date) {
  const today = localMidnight(now).getTime()
  const target = localMidnight(date).getTime()
  const dayText = target === today ? '今天' : target - today === 86400000 ? '明天' : `${date.getMonth() + 1}/${date.getDate()}`
  return `${dayText} ${formatTime(date)}`
}

function formatTime(date: Date) {
  return `${String(date.getHours()).padStart(2, '0')}:${String(date.getMinutes()).padStart(2, '0')}`
}
