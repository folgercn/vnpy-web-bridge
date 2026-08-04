import { computed, ref } from 'vue'
import { defineStore } from 'pinia'
import {
  getCommodityPositionManagerShakedownStatus,
  getCommoditySimNowStatus,
  previewCommodityPositionManagerShakedown,
  startCommodityPositionManagerShakedown,
  startCommodityStrategyTemplate,
  stopCommodityPositionManagerShakedown,
  stopCommodityStrategyTemplate,
  type CommodityPositionManagerShakedownStatus,
  type CommoditySimNowStatus
} from '../../api/commoditySimnow'

const activeStatuses = new Set([
  'READY_CLOSE', 'READY_OPEN', 'CLOSE_SUBMITTED', 'OPEN_SUBMITTED',
  'CANCEL_PENDING', 'SUBMISSION_OUTCOME_UNKNOWN', 'HALTED_RECONCILE_REQUIRED'
])

export const useCommoditySimNowStore = defineStore('commodity-simnow', () => {
  const status = ref<CommoditySimNowStatus>({})
  const shakedown = ref<CommodityPositionManagerShakedownStatus>({})
  const selectedProducts = ref<string[]>([])
  const loading = ref(false)
  const shakedownLoading = ref(false)
  const error = ref('')
  const template = computed(() => status.value.strategy_template || {})
  const positionManager = computed(() => status.value.position_manager_shadow || {})
  const sessionStatus = computed(() => shakedown.value.session?.status || '')
  const pollingActive = computed(() => activeStatuses.has(sessionStatus.value))
  const previewAllowed = computed(() =>
    Boolean(shakedown.value.configured && positionManager.value.valid) &&
    ['active', 'completed'].includes(positionManager.value.baseline_link_state || '') &&
    ['genesis', 'verified'].includes(positionManager.value.continuity_state || '') &&
    selectedProducts.value.length > 0
  )
  const startAllowed = computed(() =>
    Boolean(shakedown.value.execution_enabled) &&
    ['PREVIEW_READY', 'HALTED_PRE_SUBMIT_SAFE'].includes(sessionStatus.value) &&
    Boolean(shakedown.value.session?.plan_hash)
  )
  const stopAllowed = computed(() => [
    'READY_CLOSE', 'READY_OPEN', 'CLOSE_SUBMITTED', 'OPEN_SUBMITTED',
    'CANCEL_PENDING', 'SUBMISSION_OUTCOME_UNKNOWN', 'HALTED_PRE_SUBMIT_SAFE'
  ].includes(sessionStatus.value))

  async function loadAll() {
    loading.value = true
    error.value = ''
    try {
      const [nextStatus, nextShakedown] = await Promise.all([
        getCommoditySimNowStatus(),
        getCommodityPositionManagerShakedownStatus()
      ])
      status.value = nextStatus
      shakedown.value = nextShakedown
    } catch (reason) {
      error.value = reason instanceof Error ? reason.message : '商品 SimNow 状态不可用'
    } finally {
      loading.value = false
    }
  }

  async function loadShakedown() {
    shakedown.value = await getCommodityPositionManagerShakedownStatus()
  }

  async function startTemplate() {
    await withLoading(loading, async () => {
      await startCommodityStrategyTemplate()
      status.value = await getCommoditySimNowStatus()
    })
  }

  async function stopTemplate() {
    await withLoading(loading, async () => {
      await stopCommodityStrategyTemplate()
      status.value = await getCommoditySimNowStatus()
    })
  }

  async function previewShakedown() {
    await withLoading(shakedownLoading, async () => {
      shakedown.value = await previewCommodityPositionManagerShakedown(selectedProducts.value)
    })
  }

  async function startShakedown() {
    const planHash = shakedown.value.session?.plan_hash
    if (!planHash) return
    await withLoading(shakedownLoading, async () => {
      shakedown.value = await startCommodityPositionManagerShakedown(planHash)
    })
  }

  async function stopShakedown() {
    await withLoading(shakedownLoading, async () => {
      shakedown.value = await stopCommodityPositionManagerShakedown('operator requested candidate shakedown stop')
    })
  }

  return {
    status, shakedown, selectedProducts, loading, shakedownLoading, error,
    template, positionManager, sessionStatus, pollingActive,
    previewAllowed, startAllowed, stopAllowed,
    loadAll, loadShakedown, startTemplate, stopTemplate,
    previewShakedown, startShakedown, stopShakedown
  }
})

async function withLoading(flag: { value: boolean }, task: () => Promise<void>) {
  if (flag.value) return
  flag.value = true
  try {
    await task()
  } finally {
    flag.value = false
  }
}
