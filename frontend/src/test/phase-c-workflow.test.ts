import { readFileSync } from 'node:fs'
import { resolve } from 'node:path'
import { describe, expect, it } from 'vitest'

describe('Phase C offline workflow surface', () => {
  it('uses only the typed Phase C API and declares no browser signing/execution authority', () => {
    const api = readFileSync(resolve(process.cwd(), 'src/api/phaseCWorkflow.ts'), 'utf8')
    const page = readFileSync(resolve(process.cwd(), 'src/features/phase-c/pages/PhaseCWorkflowPage.vue'), 'utf8')
    expect(api).toContain('/api/phase-c/signing-requests/export')
    expect(api).toContain('/api/phase-c/artifacts/upload-install')
    expect(api).toContain('/api/phase-c/authorization/commands')
    expect(api).not.toMatch(/commodity-simnow|sendOrder|cancelOrder|signArtifact/i)
    expect(page).toContain('本页面不会签名')
    expect(page).toContain('execution_mutation_allowed')
  })
})
