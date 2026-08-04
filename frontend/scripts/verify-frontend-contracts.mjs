import { readFile, readdir } from 'node:fs/promises'
import { join, relative } from 'node:path'

const root = new URL('..', import.meta.url).pathname
const srcRoot = join(root, 'src')
const pageRoot = join(srcRoot, 'pages')
const featureRoot = join(srcRoot, 'features')
const failures = []
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
