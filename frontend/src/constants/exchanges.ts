export const exchangeNameMap: Record<string, string> = {
  SHFE: '上期所',
  DCE: '大商所',
  CZCE: '郑商所',
  CFFEX: '中金所',
  INE: '能源中心',
  GFEX: '广期所'
}

export const exchangeOptions = Object.entries(exchangeNameMap).map(([value, name]) => ({
  label: `${value} - ${name}`,
  value
}))

export function formatExchange(value: unknown) {
  const code = String(value || '')
  return exchangeNameMap[code] ? `${code} - ${exchangeNameMap[code]}` : code
}
