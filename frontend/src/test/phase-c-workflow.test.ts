import { readFileSync } from 'node:fs'
import { resolve } from 'node:path'
import { afterEach, describe, expect, it, vi } from 'vitest'
import { uploadPhaseCSignedArtifactWithRecovery } from '../api/phaseCWorkflow'

afterEach(() => { vi.restoreAllMocks(); localStorage.clear() })

describe('Phase C offline workflow surface', () => {
  it('uses only the typed Phase C API and declares no browser signing/execution authority', () => {
    const api = readFileSync(resolve(process.cwd(), 'src/api/phaseCWorkflow.ts'), 'utf8')
    const page = readFileSync(resolve(process.cwd(), 'src/features/phase-c/pages/PhaseCWorkflowPage.vue'), 'utf8')
    expect(api).toContain('/api/phase-c/signing-requests/export')
    expect(api).toContain('/api/phase-c/artifacts/upload-install')
    expect(api).toContain('/api/phase-c/authorization/commands')
    expect(api).toContain('pendingUploadKey')
    expect(api).toContain('getPhaseCCustodyReceiptByIdempotency')
    expect(api).toContain('recoverPendingPhaseCAuthorization')
    expect(api).not.toMatch(/commodity-simnow|sendOrder|cancelOrder|signArtifact/i)
    expect(page).toContain('本页面不会签名')
    expect(page).toContain('execution_mutation_allowed')
    expect(page).toContain('recoverPendingPhaseCAuthorization')
  })

  it('queries the same custody idempotency key after an upload network ambiguity', async () => {
    const fetchMock = vi.fn()
      .mockRejectedValueOnce(new TypeError('network interrupted'))
      .mockResolvedValueOnce(new Response(JSON.stringify({ ok: true, data: { receipt_id: 'receipt-1' } }), { status: 200 }))
    vi.stubGlobal('fetch', fetchMock)
    const result = await uploadPhaseCSignedArtifactWithRecovery({
      idempotency_key: 'custody-key-0001', expected_custody_version: 0,
      signing_request_id: 'request-0001', correlation_id: 'correlation-0001', signed_artifact: {}
    })
    expect(result.receipt_id).toBe('receipt-1')
    expect(fetchMock.mock.calls[1][0]).toContain('/custody/receipts-by-idempotency/custody-key-0001')
    expect(localStorage.getItem('phase-c.custody.pending.v1')).toBeNull()
  })
})
