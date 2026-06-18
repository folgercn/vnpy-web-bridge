import { formatExchange } from '../constants/exchanges'

export type ContractRow = Record<string, unknown>

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

export function productNameForRow(row: ContractRow) {
  return productAliases[symbolRoot(row)]?.[0] || ''
}

export function formatContractTitle(row: ContractRow, fallbackProductName = '') {
  const symbol = String(row.symbol || '').toUpperCase()
  const name = String(row.name || '')
  const month = symbolMonth(row)
  const exchangeText = formatExchange(row.exchange).replace(`${String(row.exchange || '')} - `, '')
  const rawName = fallbackProductName || (name && name.toLowerCase() !== String(row.symbol || '').toLowerCase() ? name : '')
  const readableName = rawName && month && !rawName.includes(month) ? `${rawName}${month}` : rawName || symbol
  return `${readableName} / ${symbol} · ${exchangeText}`
}

export function contractSearchText(row: ContractRow) {
  const root = symbolRoot(row)
  const aliases = productAliases[root] || []
  return normalizeKeyword(`${formatContractTitle(row, productNameForRow(row))} ${vtSymbolOf(row)} ${row.symbol || ''} ${row.name || ''} ${root} ${aliases.join(' ')}`)
}

export function normalizeKeyword(value: string) {
  return value.trim().toLowerCase()
}
