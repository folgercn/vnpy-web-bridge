import { formatExchange } from '../constants/exchanges'

export type ContractRow = Record<string, unknown>

const mainContractMonths = [1, 5, 9]

const productAliases: Record<string, string[]> = {
  rb: ['螺纹钢', '螺纹', '钢材', '钢'],
  hc: ['热轧卷板', '热卷', '钢材', '钢'],
  ss: ['不锈钢', '钢'],
  wr: ['线材', '钢材', '钢'],
  ru: ['天然橡胶', '橡胶'],
  bu: ['沥青'],
  ma: ['甲醇'],
  sa: ['纯碱'],
  ps: ['多晶硅']
}

export function vtSymbolOf(row: ContractRow) {
  return String(row.vt_symbol || `${row.symbol}.${row.exchange}`)
}

export function symbolRoot(rowOrValue: ContractRow | unknown) {
  const value = typeof rowOrValue === 'object' && rowOrValue !== null ? (rowOrValue as ContractRow).symbol : rowOrValue
  return String(value || '').toLowerCase().replace(/\d+.*$/, '')
}

export function symbolMonth(row: ContractRow) {
  return String(row.symbol || '').match(/\d+$/)?.[0] || ''
}

export function contractYearMonth(row: ContractRow, now = new Date()) {
  const month = symbolMonth(row)
  if (month.length === 4) return Number(month)
  if (month.length === 3) {
    const currentYear = Math.floor(currentChinaYearMonth(now) / 100)
    const decade = Math.floor(currentYear / 10) * 10
    let year = decade + Number(month.slice(0, 1))
    if (year < currentYear - 5) year += 10
    if (year > currentYear + 5) year -= 10
    return year * 100 + Number(month.slice(1))
  }
  return Number(month)
}

export function productNameForRow(row: ContractRow) {
  return productAliases[symbolRoot(row)]?.[0] || ''
}

export function isMainContract(row: ContractRow, now = new Date()) {
  return contractYearMonth(row, now) === nextMainContractYearMonth(now)
}

export function mainContracts(rows: ContractRow[], now = new Date()) {
  const target = availableMainContractYearMonth(rows, now)
  return target ? rows.filter((row) => contractYearMonth(row, now) === target) : []
}

export function preferredMainContract(rows: ContractRow[], now = new Date()) {
  const sorted = rows.slice().sort((a, b) => compareContractMonths(a, b, now))
  return mainContracts(sorted, now)[0] || sorted.find((row) => contractYearMonth(row, now) >= currentChinaYearMonth(now)) || sorted[0]
}

export function isResolvedMainContract(row: ContractRow, rows: ContractRow[], now = new Date()) {
  const target = availableMainContractYearMonth(rows, now)
  return Boolean(target && contractYearMonth(row, now) === target)
}

export function formatContractTitle(row: ContractRow, fallbackProductName = '', options: { main?: boolean } = {}) {
  const symbol = String(row.symbol || '').toUpperCase()
  const name = String(row.name || '')
  const month = symbolMonth(row)
  const exchangeText = formatExchange(row.exchange).replace(`${String(row.exchange || '')} - `, '')
  const rawName = fallbackProductName || (name && name.toLowerCase() !== String(row.symbol || '').toLowerCase() ? name : '')
  const readableName = rawName && month && !rawName.includes(month) ? `${rawName}${month}` : rawName || symbol
  return `${readableName} / ${symbol} · ${exchangeText}${options.main ? ' · 主力' : ''}`
}

export function contractSearchText(row: ContractRow) {
  const root = symbolRoot(row)
  const aliases = productAliases[root] || []
  return normalizeKeyword(`${formatContractTitle(row, productNameForRow(row))} ${vtSymbolOf(row)} ${row.symbol || ''} ${row.name || ''} ${root} ${aliases.join(' ')}`)
}

export function normalizeKeyword(value: string) {
  return value.trim().toLowerCase()
}

export function compareContractMonths(a: ContractRow, b: ContractRow, now = new Date()) {
  const monthDiff = contractYearMonth(a, now) - contractYearMonth(b, now)
  return monthDiff || vtSymbolOf(a).localeCompare(vtSymbolOf(b))
}

export function currentChinaYearMonth(now = new Date()) {
  const parts = new Intl.DateTimeFormat('en-US', {
    timeZone: 'Asia/Shanghai',
    hourCycle: 'h23',
    year: '2-digit',
    month: '2-digit'
  }).formatToParts(now)
  const value = (type: string) => parts.find((part) => part.type === type)?.value || '0'
  return Number(`${value('year')}${value('month')}`)
}

export function nextMainContractYearMonth(now = new Date()) {
  const current = currentChinaYearMonth(now)
  const year = Math.floor(current / 100)
  const month = current % 100
  const nextMonth = mainContractMonths.find((item) => item >= month)
  if (nextMonth) return year * 100 + nextMonth
  return (year + 1) * 100 + mainContractMonths[0]
}

export function availableMainContractYearMonth(rows: ContractRow[], now = new Date()) {
  const current = currentChinaYearMonth(now)
  const months = Array.from(
    new Set(
      rows
        .map((row) => contractYearMonth(row, now))
        .filter((month) => Number.isFinite(month) && month >= current && mainContractMonths.includes(month % 100))
    )
  ).sort((a, b) => a - b)
  return months[0]
}
