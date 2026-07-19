import { flushPromises, mount } from '@vue/test-utils'
import { defineComponent, h } from 'vue'
import { beforeEach, describe, expect, it, vi } from 'vitest'
import MakV2TestnetObserver from '../pages/MakV2TestnetObserver.vue'

const api = vi.hoisted(() => ({
  disableMakV2Observer: vi.fn(),
  dryRunMakV2Signal: vi.fn(),
  enableMakV2Observer: vi.fn(),
  flattenMakV2Testnet: vi.fn(),
  getMakV2DailySummary: vi.fn(),
  getMakV2Guardrails: vi.fn(),
  getMakV2Orders: vi.fn(),
  getMakV2SafetyAuditLatest: vi.fn(),
  getMakV2Signals: vi.fn(),
  getMakV2Status: vi.fn(),
  listMakV2SafetyAudits: vi.fn(),
  runMakV2SafetyAudit: vi.fn()
}))

const messages = vi.hoisted(() => ({
  success: vi.fn(),
  warning: vi.fn(),
  error: vi.fn()
}))

vi.mock('naive-ui', () => ({
  useMessage: () => messages
}))

vi.mock('../composables/useMediaQuery', () => ({
  useMediaQuery: () => false
}))

vi.mock('../api/makV2Observer', () => api)

const auditResult = {
  audit_time_utc: '2026-07-19T12:00:00+00:00',
  mode: 'MAK_V2_PRB_SAFETY_AUDIT',
  overall: 'PASS',
  single_order_smoke_allowed: true,
  checks: [],
  rpc: { connected: true },
  observer: { enabled: true, manual_approval: true, testnet_mode: true },
  snapshot: { accounts: [], gfex_contracts: [] },
  next_actions: []
}

beforeEach(() => {
  vi.clearAllMocks()
  api.getMakV2Status.mockResolvedValue({
    enabled: true,
    mode: 'TESTNET_OBSERVER',
    capacity_status: 'READY',
    dry_run_intents_total: 1,
    dry_run_only: true,
    production_allowed: false
  })
  api.getMakV2Signals.mockResolvedValue([{ trace_id: 'core-signal' }])
  api.getMakV2Orders.mockResolvedValue([{ trace_id: 'core-order' }])
  api.getMakV2Guardrails.mockResolvedValue([{ trace_id: 'core-guardrail' }])
  api.getMakV2DailySummary.mockResolvedValue([{ date: '2026-07-19' }])
  api.getMakV2SafetyAuditLatest.mockResolvedValue({})
  api.listMakV2SafetyAudits.mockResolvedValue([])
  api.runMakV2SafetyAudit.mockResolvedValue(auditResult)
})

describe('MAK v2 observer page audit error handling', () => {
  it('keeps core observer data when audit history refresh fails', async () => {
    api.getMakV2SafetyAuditLatest.mockRejectedValueOnce(new Error('history unavailable'))

    const wrapper = mountPage()
    await flushPromises()

    expect(wrapper.text()).toContain('enabled')
    expect(wrapper.text()).toContain('TESTNET_OBSERVER')
    expect(wrapper.text()).toContain('core-signal')
    expect(messages.warning).toHaveBeenCalledWith('safety audit history refresh failed: history unavailable')
    expect(messages.error).not.toHaveBeenCalled()
  })

  it('does not report audit execution failure when only history refresh fails', async () => {
    const wrapper = mountPage()
    await flushPromises()

    api.getMakV2SafetyAuditLatest.mockRejectedValueOnce(new Error('history unavailable'))
    const runButton = wrapper.findAll('button').find((button) => button.text() === 'Run audit')
    expect(runButton).toBeDefined()

    await runButton!.trigger('click')
    await flushPromises()

    expect(api.runMakV2SafetyAudit).toHaveBeenCalledTimes(1)
    expect(messages.success).toHaveBeenCalledWith('safety audit passed')
    expect(messages.warning).toHaveBeenCalledWith('audit completed, but history refresh failed: history unavailable')
    expect(messages.error).not.toHaveBeenCalled()
  })
})

function mountPage() {
  const SlotStub = defineComponent({ template: '<div><slot /></div>' })
  const ButtonStub = defineComponent({
    emits: ['click'],
    template: '<button @click="$emit(\'click\')"><slot /></button>'
  })
  const DataTableStub = defineComponent({
    props: {
      data: { type: Array, default: () => [] }
    },
    setup(props) {
      return () => h('div', { class: 'data-table' }, JSON.stringify(props.data))
    }
  })
  const StatisticStub = defineComponent({
    props: ['value'],
    template: '<span>{{ value }}</span>'
  })

  return mount(MakV2TestnetObserver, {
    global: {
      stubs: {
        NCard: SlotStub,
        NSpace: SlotStub,
        NTag: SlotStub,
        NForm: SlotStub,
        NFormItem: SlotStub,
        NButton: ButtonStub,
        NDataTable: DataTableStub,
        NStatistic: StatisticStub,
        NInput: true,
        NCheckbox: true,
        NSelect: true,
        NInputNumber: true
      }
    }
  })
}
