import { readFile, readdir } from 'node:fs/promises'
import { join, relative } from 'node:path'

const root = new URL('..', import.meta.url).pathname
const srcRoot = join(root, 'src')
const pageRoot = join(srcRoot, 'pages')
const featureRoot = join(srcRoot, 'features')
const failures = []
const labRoot = join(featureRoot, 'simnow-lab-dashboard')
const pageExceptions = new Map([
  ['src/pages/Market.vue', '行情图表、订阅管理和自选合约仍待后续独立迁移；本次禁止继续增长。']
])

for (const file of await walk(srcRoot, '.vue')) {
  const path = relative(root, file)
  const content = await readFile(file, 'utf8')
  if (/\sstyle\s*=/.test(content)) failures.push(`${path}: 禁止新增行内 style`)
}

for (const file of [...await walk(pageRoot, '.vue'), ...await walk(featureRoot, 'Page.vue')]) {
  const path = relative(root, file)
  const lines = (await readFile(file, 'utf8')).split('\n').length
  if (lines > 500 && !pageExceptions.has(path)) failures.push(`${path}: ${lines} 行，页面上限为 500 行`)
}

for (const file of await walk(labRoot, '')) {
  const path = relative(root, file)
  const content = await readFile(file, 'utf8')
  const lines = content.split('\n').length
  if (/\sstyle\s*=/.test(content)) failures.push(`${path}: #466 禁止行内 style`)
  if (/(?:#[0-9a-f]{3,8}|rgba?\(|hsla?\()/i.test(content)) failures.push(`${path}: #466 禁止 literal color`)
  if (/Record<string,\s*unknown>/.test(content)) failures.push(`${path}: #466 已知 DTO 禁止 Record<string, unknown>`)
  if (/\b(?:POST|PUT|PATCH|DELETE)\b|下单|撤单|恢复|重启/.test(content)) failures.push(`${path}: #466 Dashboard 禁止 mutation API 或操作文案`)
  if (path.endsWith('Page.vue') && lines > 220) failures.push(`${path}: ${lines} 行，#466 Page 上限为 220 行`)
  if (path.includes('/components/') && lines > 260) failures.push(`${path}: ${lines} 行，#466 组件上限为 260 行`)
  if (path.endsWith('/store.ts') && lines > 300) failures.push(`${path}: ${lines} 行，#466 store 上限为 300 行`)
  if (path.endsWith('Page.vue') && /from ['"].*\/api['"]/.test(content)) failures.push(`${path}: #466 Page 不得直接 import API client`)
}

const labPage = await readFile(join(labRoot, 'pages', 'SimNowLabDashboardPage.vue'), 'utf8')
for (const required of ['LabOverview', 'LabPerformanceChart', 'LabPortfolioTable', 'LabRuns', 'LabActivity']) {
  if (!labPage.includes(required)) failures.push(`SIMNOW_LAB Dashboard 缺少 ${required}`)
}
const labChart = await readFile(join(labRoot, 'components', 'LabPerformanceChart.vue'), 'utf8')
for (const required of ['equity', 'cumulative_pnl', 'drawdown', 'daily_pnl']) {
  if (!labChart.includes(required)) failures.push(`SIMNOW_LAB 图表缺少 ${required}`)
}

const main = await readFile(join(srcRoot, 'main.ts'), 'utf8')
if (/\.component\s*\(/.test(main)) failures.push('src/main.ts: 禁止全局注册普通 UI 组件')

if (failures.length) {
  console.error(failures.join('\n'))
  process.exitCode = 1
} else {
  console.log('Frontend architecture contracts passed')
}

async function walk(directory, suffix) {
  const files = []
  for (const entry of await readdir(directory, { withFileTypes: true })) {
    const path = join(directory, entry.name)
    if (entry.isDirectory()) files.push(...await walk(path, suffix))
    else if (entry.name.endsWith(suffix)) files.push(path)
  }
  return files
}
