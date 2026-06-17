import { describe, expect, it, vi } from 'vitest'
import { ApiClientError, request } from '../api/client'

describe('api client', () => {
  it('unwraps successful unified response', async () => {
    vi.stubGlobal(
      'fetch',
      vi.fn(async () => ({
        ok: true,
        json: async () => ({ ok: true, data: { status: 'ok' } })
      }))
    )

    await expect(request('/api/status')).resolves.toEqual({ status: 'ok' })
  })

  it('throws unified api error', async () => {
    vi.stubGlobal(
      'fetch',
      vi.fn(async () => ({
        ok: false,
        statusText: 'Forbidden',
        json: async () => ({ ok: false, error: { code: 'PERMISSION_DENIED', message: '权限不足' } })
      }))
    )

    await expect(request('/api/orders')).rejects.toBeInstanceOf(ApiClientError)
  })
})
