import sessionProfiles from '../../../shared/trading_session_profiles.json'

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

type TradingSessionProfiles = typeof sessionProfiles

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
  const daySessions = daySessionWindows(exchange)
  const nightClose = nightCloseTime(exchange, product)
  const today = chinaDateParts(now)

  for (let offset = -1; offset <= 7; offset += 1) {
    const date = addChinaDays(today, offset)

    if (isWeekday(date)) {
      for (const session of daySessions) result.push(toConcreteSession(date, session))
    }
    if (nightClose && isWeekday(addChinaDays(date, 1))) result.push(toConcreteSession(date, { label: '夜盘', start: '21:00', end: nightClose }))
  }

  return result.sort((a, b) => a.start.getTime() - b.start.getTime())
}

function daySessionWindows(exchange: string): SessionWindow[] {
  const profile = sessionProfiles as TradingSessionProfiles
  const profileName = profile.exchange_day_session[exchange as keyof typeof profile.exchange_day_session] || 'commodity'
  return profile.day_sessions[profileName as keyof typeof profile.day_sessions]
}

function nightCloseTime(exchange: string, product: string) {
  const exchangeMap = sessionProfiles.night_sessions[exchange as keyof typeof sessionProfiles.night_sessions]
  return exchangeMap?.[product as keyof typeof exchangeMap]
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
