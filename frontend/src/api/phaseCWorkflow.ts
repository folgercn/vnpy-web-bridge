import { request } from './client'

export interface PhaseCNegativeAuthority {
  production_allowed: false
  live_trading_authorized: false
  countable_forward: false
}

export interface PhaseCWorkflowStatus extends PhaseCNegativeAuthority {
  map_status: 'PENDING' | 'READY'
  c_fast_status: 'PENDING' | 'READY'
  signing: 'EXPORT_ONLY'
  browser_signing: false
  custody_writer: string
  execution_writer: string
  execution_mutation_allowed: false
}

export interface SigningRequestExport {
  request_id: string
  domain: 'map_acceptance' | 'c_fast_acceptance' | 'runtime_authorization'
  key_id: string
  key_version: string
  requested_at: string
  expires_at: string
  artifact: Record<string, unknown>
}

export interface CustodyReceipt extends PhaseCNegativeAuthority {
  receipt_id: string
  artifact_id: string
  custody_version: number
  verified: true
  installed: true
  fake_adapter: true
}

export interface AuthorizationStatus extends PhaseCNegativeAuthority {
  version: number
  requested_state: 'DISABLED' | 'ENABLE_REQUESTED' | 'REVOKED'
  effective_state: 'DISABLED'
  artifact_id: string | null
  receipt_id: string | null
  runtime_mutation_allowed: false
}

export interface ExecutionProjection extends PhaseCNegativeAuthority {
  status: 'OFFLINE_FAKE' | 'ARCHIVED'
  execution_mutation_allowed: false
  runtime_state_owner: 'execution-adapter'
  custody_state_owner: 'custody-adapter'
  audit: Record<string, unknown>[]
  archive: Record<string, unknown>[]
}

export const getPhaseCWorkflowStatus = () => request<PhaseCWorkflowStatus>('/api/phase-c/workflow/status')
export const getPhaseCAuthorizationStatus = () => request<AuthorizationStatus>('/api/phase-c/authorization/status')
export const getPhaseCExecutionProjection = () => request<ExecutionProjection>('/api/phase-c/execution/status')

export const exportPhaseCSigningRequest = (payload: {
  request_id: string
  domain: SigningRequestExport['domain']
  key_id: string
  key_version: string
  requested_at: string
  expires_at: string
  artifact: Record<string, unknown>
}) => request<SigningRequestExport>('/api/phase-c/signing-requests/export', {
  method: 'POST', body: JSON.stringify(payload)
})

export const uploadAndInstallPhaseCSignedArtifact = (payload: {
  idempotency_key: string
  expected_custody_version: number
  signing_request_id: string
  correlation_id: string
  signed_artifact: Record<string, unknown>
}) => request<CustodyReceipt>('/api/phase-c/artifacts/upload-install', {
  method: 'POST', body: JSON.stringify(payload)
})

export const commandPhaseCAuthorization = (payload: {
  command_id: string
  idempotency_key: string
  expected_version: number
  action: 'enable' | 'revoke'
  authorization_artifact_id: string
  custody_receipt_id: string
  reason: string
}) => request<AuthorizationStatus>('/api/phase-c/authorization/commands', {
  method: 'POST', body: JSON.stringify(payload)
})

const pendingKey = 'phase-c.authorization.pending.v1'
type PendingAuthorization = { payload: Parameters<typeof commandPhaseCAuthorization>[0], payloadHash: string }

async function payloadHash(payload: unknown): Promise<string> {
  const bytes = new TextEncoder().encode(JSON.stringify(payload))
  const digest = await crypto.subtle.digest('SHA-256', bytes)
  return Array.from(new Uint8Array(digest), value => value.toString(16).padStart(2, '0')).join('')
}

export const getPhaseCAuthorizationReceipt = (idempotencyKey: string) =>
  request<AuthorizationStatus>(`/api/phase-c/authorization/receipts/${encodeURIComponent(idempotencyKey)}`)

export async function submitPhaseCAuthorizationWithRecovery(payload: Parameters<typeof commandPhaseCAuthorization>[0]): Promise<AuthorizationStatus> {
  const pending: PendingAuthorization = { payload, payloadHash: await payloadHash(payload) }
  localStorage.setItem(pendingKey, JSON.stringify(pending))
  try {
    const result = await commandPhaseCAuthorization(payload)
    localStorage.removeItem(pendingKey)
    return result
  } catch (error) {
    // A network error is never permission to generate a second command: first
    // query the durable receipt using exactly the persisted idempotency key.
    try {
      const result = await getPhaseCAuthorizationReceipt(payload.idempotency_key)
      localStorage.removeItem(pendingKey)
      return result
    } catch { throw error }
  }
}

export async function recoverPendingPhaseCAuthorization(): Promise<AuthorizationStatus | null> {
  const raw = localStorage.getItem(pendingKey)
  if (!raw) return null
  const pending = JSON.parse(raw) as PendingAuthorization
  if (pending.payloadHash !== await payloadHash(pending.payload)) throw new Error('pending Phase C payload hash mismatch')
  try {
    const result = await getPhaseCAuthorizationReceipt(pending.payload.idempotency_key)
    localStorage.removeItem(pendingKey)
    return result
  } catch {
    // Retry only the same persisted payload/key after its unknown-outcome query.
    const result = await commandPhaseCAuthorization(pending.payload)
    localStorage.removeItem(pendingKey)
    return result
  }
}
