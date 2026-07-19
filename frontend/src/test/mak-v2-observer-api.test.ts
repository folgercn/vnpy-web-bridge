import { afterEach, describe, expect, it, vi } from 'vitest'
import { getMakV2SafetyAuditLatest, listMakV2SafetyAudits } from '../api/makV2Observer'

describe('mak v2 observer api', () => {
  afterEach(() => {
    vi.unstubAllGlobals()
  })

  it('requests latest safety audit with default GET', async () => {
    const fetchMock = stubOkFetch({})

    await expect(getMakV2SafetyAuditLatest()).resolves.toEqual({})

    const [path, init] = fetchMock.mock.calls[0] as [string, RequestInit]
    expect(path).toBe('/api/mak-v2/testnet-observer/safety-audit/latest')
    expect(init.method).toBeUndefined()
  })

  it('requests safety audit history with limit query and default GET', async () => {
    const fetchMock = stubOkFetch([])

    await expect(listMakV2SafetyAudits(25)).resolves.toEqual([])

    const [path, init] = fetchMock.mock.calls[0] as [string, RequestInit]
    expect(path).toBe('/api/mak-v2/testnet-observer/safety-audits?limit=25')
    expect(init.method).toBeUndefined()
  })
})

function stubOkFetch(data: unknown) {
  const fetchMock = vi.fn(async () => ({
    ok: true,
    json: async () => ({ ok: true, data })
  }))
  vi.stubGlobal('fetch', fetchMock)
  return fetchMock
}
