import { flushPromises, mount } from '@vue/test-utils'
import { defineComponent } from 'vue'
import { beforeEach, describe, expect, it, vi } from 'vitest'
import Strategies from '../pages/Strategies.vue'

const strategyStore = vi.hoisted(() => ({
  rows: [{ strategy_name: 'alpha', trading: true }],
  loading: false,
  error: '',
  pendingKey: '',
  load: vi.fn(),
  operate: vi.fn()
}))
const messages = vi.hoisted(() => ({ success: vi.fn(), error: vi.fn() }))

vi.mock('../features/strategies/store', () => ({
  useStrategiesStore: () => strategyStore
}))
vi.mock('../stores/auth', () => ({
  useAuthStore: () => ({ role: 'admin' })
}))
vi.mock('naive-ui', async (importOriginal) => ({
  ...await importOriginal<typeof import('naive-ui')>(),
  useMessage: () => messages
}))

beforeEach(() => {
  vi.clearAllMocks()
  strategyStore.operate.mockResolvedValue(undefined)
})

describe('CTA strategy stop confirmation', () => {
  it('does not stop on the first click and only calls the operation after confirmation', async () => {
    const wrapper = mountPage()

    await wrapper.get('[data-testid="stop"]').trigger('click')

    expect(strategyStore.operate).not.toHaveBeenCalled()
    expect(wrapper.text()).toContain('停止策略 alpha 后，该策略将中断运行且不再产生新委托')

    await wrapper.get('[data-testid="confirm"]').trigger('click')
    await flushPromises()

    expect(strategyStore.operate).toHaveBeenCalledTimes(1)
    expect(strategyStore.operate).toHaveBeenCalledWith('stop', 'alpha')
  })
})

function mountPage() {
  const SlotStub = defineComponent({ template: '<div><slot /><slot name="danger" /></div>' })
  const StrategyTableStub = defineComponent({
    emits: ['operate', 'requestStop'],
    template: '<button data-testid="stop" @click="$emit(\'requestStop\', \'alpha\')">停止</button>'
  })
  const DangerDialogStub = defineComponent({
    props: {
      show: Boolean,
      description: { type: String, default: '' }
    },
    emits: ['update:show', 'confirm'],
    template: '<div v-if="show"><p>{{ description }}</p><button data-testid="confirm" @click="$emit(\'confirm\')">确认</button></div>'
  })

  return mount(Strategies, {
    global: {
      stubs: {
        PageHeader: true,
        PageSection: SlotStub,
        AsyncContent: SlotStub,
        ActionBar: SlotStub,
        StrategyTable: StrategyTableStub,
        DangerActionDialog: DangerDialogStub,
        Button: SlotStub,
        NButton: SlotStub
      }
    }
  })
}
