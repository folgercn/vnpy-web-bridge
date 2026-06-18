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

type ChinaDateParts = {
  year: number
  month: number
  day: number
  hour: number
  minute: number
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

const nightCloseByExchange: Record<string, Record<string, string>> = {
  SHFE: {
    au: '02:30',
    ag: '02:30',
    cu: '01:00',
    al: '01:00',
    zn: '01:00',
    pb: '01:00',
    ni: '01:00',
    sn: '01:00',
    ao: '01:00',
    ad: '01:00',
    ss: '01:00',
    rb: '23:00',
    hc: '23:00',
    wr: '23:00',
    ru: '23:00',
    br: '23:00',
    fu: '23:00',
    sp: '23:00',
    bu: '23:00'
  },
  INE: {
    sc: '02:30',
    bc: '01:00',
    lu: '23:00',
    nr: '23:00'
  },
  DCE: {
    a: '23:00',
    b: '23:00',
    c: '23:00',
    cs: '23:00',
    m: '23:00',
    y: '23:00',
    p: '23:00',
    i: '23:00',
    j: '23:00',
    jm: '23:00',
    l: '23:00',
    v: '23:00',
    pp: '23:00',
    eg: '23:00',
    rr: '23:00',
    eb: '23:00',
    pg: '23:00'
  },
  CZCE: {
    rm: '23:00',
    oi: '23:00',
    cf: '23:00',
    ta: '23:00',
    px: '23:00',
    sr: '23:00',
    ma: '23:00',
    fg: '23:00',
    zc: '23:00',
    sa: '23:00',
    pf: '23:00',
    pr: '23:00'
  }
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
  const nightClose = nightCloseByExchange[exchange]?.[product]
  const today = chinaDateParts(now)

  for (let offset = -1; offset <= 7; offset += 1) {
    const date = addChinaDays(today, offset)
    if (!isWeekday(date)) continue

    for (const session of daySessions) result.push(toConcreteSession(date, session))
    if (nightClose) result.push(toConcreteSession(date, { label: '夜盘', start: '21:00', end: nightClose }))
  }

  return result.sort((a, b) => a.start.getTime() - b.start.getTime())
}

function toConcreteSession(date: ChinaDateParts, session: SessionWindow): ConcreteSession {
  const start = withTime(date, session.start)
  const end = withTime(date, session.end)
  if (end <= start) end.setTime(end.getTime() + 86400000)
  return { label: session.label, start, end }
}

function chinaDateParts(date: Date): ChinaDateParts {
  const parts = new Intl.DateTimeFormat('en-US', {
    timeZone: 'Asia/Shanghai',
    hourCycle: 'h23',
    year: 'numeric',
    month: '2-digit',
    day: '2-digit',
    hour: '2-digit',
    minute: '2-digit'
  }).formatToParts(date)
  const value = (type: string) => Number(parts.find((part) => part.type === type)?.value || 0)
  return {
    year: value('year'),
    month: value('month'),
    day: value('day'),
    hour: value('hour'),
    minute: value('minute')
  }
}

function addChinaDays(date: ChinaDateParts, offset: number): ChinaDateParts {
  const shifted = new Date(Date.UTC(date.year, date.month - 1, date.day + offset))
  return {
    year: shifted.getUTCFullYear(),
    month: shifted.getUTCMonth() + 1,
    day: shifted.getUTCDate(),
    hour: 0,
    minute: 0
  }
}

function chinaMidnight(date: Date) {
  const parts = chinaDateParts(date)
  return toChinaInstant(parts.year, parts.month, parts.day, 0, 0)
}

function withTime(date: ChinaDateParts, time: string) {
  const [hour, minute] = time.split(':').map(Number)
  return toChinaInstant(date.year, date.month, date.day, hour, minute)
}

function toChinaInstant(year: number, month: number, day: number, hour: number, minute: number) {
  return new Date(Date.UTC(year, month - 1, day, hour - 8, minute, 0, 0))
}

function isWeekday(date: ChinaDateParts) {
  const weekday = new Date(Date.UTC(date.year, date.month - 1, date.day)).getUTCDay()
  return weekday >= 1 && weekday <= 5
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
  const today = chinaMidnight(now).getTime()
  const target = chinaMidnight(date).getTime()
  const parts = chinaDateParts(date)
  const dayText = target === today ? '今天' : target - today === 86400000 ? '明天' : `${parts.month}/${parts.day}`
  return `${dayText} ${formatTime(date)}`
}

function formatTime(date: Date) {
  const parts = chinaDateParts(date)
  return `${String(parts.hour).padStart(2, '0')}:${String(parts.minute).padStart(2, '0')}`
}
