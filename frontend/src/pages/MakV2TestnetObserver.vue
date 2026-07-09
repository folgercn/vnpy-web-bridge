<template>
  <div class="page">
    <div class="grid-4">
      <n-card title="Mode" size="small">
        <n-tag :type="status.enabled ? 'success' : 'warning'" round>{{ status.enabled ? 'enabled' : 'disabled' }}</n-tag>
        <div class="muted mono">{{ status.mode || '-' }}</div>
      </n-card>
      <n-card title="Capacity" size="small">
        <n-tag type="warning" round>{{ status.capacity_status || '-' }}</n-tag>
        <div class="muted">pass: false</div>
      </n-card>
      <n-card title="Orders" size="small">
        <n-statistic label="dry-run intents" :value="status.dry_run_intents_total ?? 0" />
      </n-card>
      <n-card title="Boundary" size="small">
        <n-space size="small">
          <n-tag :type="status.dry_run_only ? 'info' : 'error'" round>dry-run</n-tag>
          <n-tag :type="status.production_allowed ? 'error' : 'success'" round>no production</n-tag>
        </n-space>
      </n-card>
    </div>

    <n-card size="small">
      <div class="toolbar">
        <n-input v-model:value="enableForm.reason" placeholder="manual waiver reason" class="toolbar-control-md" />
        <n-checkbox v-model:checked="enableForm.manual_approval">manual approval</n-checkbox>
        <n-checkbox v-model:checked="enableForm.testnet_mode">testnet</n-checkbox>
        <n-checkbox v-model:checked="enableForm.confirm_testnet_only">testnet only</n-checkbox>
        <n-checkbox v-model:checked="enableForm.confirm_no_production">no production</n-checkbox>
        <n-checkbox v-model:checked="enableForm.confirm_max_one_lot">max 1 lot</n-checkbox>
        <n-checkbox v-model:checked="enableForm.confirm_no_auto_promotion">no promotion</n-checkbox>
        <n-button type="primary" :loading="loading" @click="submitEnable">Enable</n-button>
        <n-button type="warning" :loading="loading" @click="submitDisable">Disable</n-button>
        <n-button type="error" ghost :loading="loading" @click="submitFlatten">Flatten</n-button>
        <n-button :loading="loading" @click="refresh">刷新</n-button>
      </div>
    </n-card>

    <n-card title="Dry-run Signal" size="small">
      <n-form :model="signalForm" :label-placement="isMobile ? 'top' : 'left'" label-width="120">
        <div class="form-grid">
          <n-form-item label="instrument">
            <n-select v-model:value="signalForm.instrument" :options="instrumentOptions" @update:value="syncContract" />
          </n-form-item>
          <n-form-item label="contract"><n-input v-model:value="signalForm.exact_contract" /></n-form-item>
          <n-form-item label="side"><n-select v-model:value="signalForm.side" :options="sideOptions" /></n-form-item>
          <n-form-item label="z"><n-input-number v-model:value="signalForm.z_score" /></n-form-item>
          <n-form-item label="bid"><n-input-number v-model:value="signalForm.bid_price_1" :min="0" /></n-form-item>
          <n-form-item label="ask"><n-input-number v-model:value="signalForm.ask_price_1" :min="0" /></n-form-item>
          <n-form-item label="bid lot"><n-input-number v-model:value="signalForm.bid_volume_1" :min="0" /></n-form-item>
          <n-form-item label="ask lot"><n-input-number v-model:value="signalForm.ask_volume_1" :min="0" /></n-form-item>
          <n-form-item label="quote age"><n-input-number v-model:value="signalForm.quote_age_ms" :min="0" /></n-form-item>
          <n-form-item label="overlap"><n-input-number v-model:value="signalForm.active_overlap_900s" :min="0" /></n-form-item>
        </div>
        <n-button type="primary" :disabled="!status.enabled" :loading="loading" @click="submitDryRun">生成 dry-run intent</n-button>
      </n-form>
    </n-card>

    <div class="grid-2">
      <n-card title="Signals" size="small">
        <n-data-table :columns="signalColumns" :data="signals" :pagination="{ pageSize: 8 }" :scroll-x="1250" size="small" />
      </n-card>
      <n-card title="Order Intents" size="small">
        <n-data-table :columns="intentColumns" :data="orders" :pagination="{ pageSize: 8 }" :scroll-x="1100" size="small" />
      </n-card>
    </div>

    <div class="grid-2">
      <n-card title="Guardrails" size="small">
        <n-data-table :columns="guardrailColumns" :data="guardrails" :pagination="{ pageSize: 8 }" :scroll-x="980" size="small" />
      </n-card>
      <n-card title="Daily Summary" size="small">
        <n-data-table :columns="summaryColumns" :data="dailySummary" :pagination="false" :scroll-x="980" size="small" />
      </n-card>
    </div>
  </div>
</template>

<script setup lang="ts">
import { onMounted, reactive, ref } from 'vue'
import { useMessage, type DataTableColumns } from 'naive-ui'
import { useMediaQuery } from '../composables/useMediaQuery'
import {
  disableMakV2Observer,
  dryRunMakV2Signal,
  enableMakV2Observer,
  flattenMakV2Testnet,
  getMakV2DailySummary,
  getMakV2Guardrails,
  getMakV2Orders,
  getMakV2Signals,
  getMakV2Status,
  type MakV2DryRunSignalPayload,
  type MakV2ObserverStatus
} from '../api/makV2Observer'

const message = useMessage()
const isMobile = useMediaQuery('(max-width: 640px)')
const loading = ref(false)
const status = ref<Partial<MakV2ObserverStatus>>({})
const signals = ref<Record<string, unknown>[]>([])
const orders = ref<Record<string, unknown>[]>([])
const guardrails = ref<Record<string, unknown>[]>([])
const dailySummary = ref<Record<string, unknown>[]>([])
const enableForm = reactive({
  manual_approval: false,
  testnet_mode: false,
  reason: 'manual controlled testnet observer waiver',
  confirm_testnet_only: false,
  confirm_no_production: false,
  confirm_max_one_lot: false,
  confirm_no_auto_promotion: false
})
const signalForm = reactive<MakV2DryRunSignalPayload>({
  instrument: 'ps',
  exact_contract: 'GFEX.ps2609',
  side: 'long',
  z_score: -1.6,
  rolling_mean: null,
  rolling_std: null,
  last_price: 39155,
  bid_price_1: 39150,
  ask_price_1: 39155,
  bid_volume_1: 1,
  ask_volume_1: 1,
  quote_age_ms: 250,
  cluster_id: 'manual_dry_run',
  active_overlap_900s: 0,
  cooldown_state: 'clear',
  data_quality_status: 'pass'
})
const instrumentOptions = [
  { label: 'ps', value: 'ps' },
  { label: 'lc', value: 'lc' }
]
const sideOptions = [
  { label: 'long', value: 'long' },
  { label: 'short', value: 'short' }
]
const signalColumns = cols([
  'signal_time_local',
  'instrument',
  'exact_contract',
  'side',
  'z_score',
  'spread_ticks',
  'top_lot',
  'eligible_for_testnet',
  'ineligible_reason',
  'trace_id'
])
const intentColumns = cols(['intent_time', 'instrument', 'exact_contract', 'side', 'requested_lots', 'limit_price', 'dry_run_only', 'trace_id'])
const guardrailColumns = cols(['trigger_time', 'guard_name', 'severity', 'action', 'threshold', 'trace_id'])
const summaryColumns = cols(['date', 'signals_total', 'eligible_signals', 'dry_run_intents', 'guardrail_triggers', 'daily_decision'])

onMounted(() => {
  refresh().catch(() => undefined)
})

function cols(keys: string[]): DataTableColumns<Record<string, unknown>> {
  return keys.map((key) => ({ title: key, key, ellipsis: { tooltip: true } }))
}

function syncContract(value: 'lc' | 'ps') {
  if (value === 'lc') {
    signalForm.exact_contract = 'GFEX.lc2609'
    signalForm.last_price = 165070
    signalForm.bid_price_1 = 165060
    signalForm.ask_price_1 = 165080
  } else {
    signalForm.exact_contract = 'GFEX.ps2609'
    signalForm.last_price = 39155
    signalForm.bid_price_1 = 39150
    signalForm.ask_price_1 = 39155
  }
}

async function refresh() {
  loading.value = true
  try {
    const [statusResult, signalRows, orderRows, guardrailRows, summaryRows] = await Promise.all([
      getMakV2Status(),
      getMakV2Signals(),
      getMakV2Orders(),
      getMakV2Guardrails(),
      getMakV2DailySummary()
    ])
    status.value = statusResult
    signals.value = signalRows
    orders.value = orderRows
    guardrails.value = guardrailRows
    dailySummary.value = summaryRows
  } finally {
    loading.value = false
  }
}

async function submitEnable() {
  try {
    const result = await enableMakV2Observer(enableForm)
    status.value = result
    if (result.enabled === true) {
      message.success('observer enabled')
    } else {
      message.warning(result.enable_rejected ? 'enable rejected: waiver incomplete' : 'observer not enabled')
    }
    await refresh()
  } catch (exc) {
    message.error(exc instanceof Error ? exc.message : 'enable failed')
    await refresh().catch(() => undefined)
  }
}

async function submitDisable() {
  try {
    status.value = await disableMakV2Observer({ reason: 'manual disable from MAK v2 page' })
    message.success('observer disabled')
    await refresh()
  } catch (exc) {
    message.error(exc instanceof Error ? exc.message : 'disable failed')
  }
}

async function submitFlatten() {
  try {
    await flattenMakV2Testnet()
    message.success('flatten guardrail recorded')
    await refresh()
  } catch (exc) {
    message.error(exc instanceof Error ? exc.message : 'flatten failed')
  }
}

async function submitDryRun() {
  try {
    await dryRunMakV2Signal(signalForm)
    message.success('dry-run intent evaluated')
    await refresh()
  } catch (exc) {
    message.error(exc instanceof Error ? exc.message : 'dry-run failed')
  }
}
</script>

<style scoped>
.form-grid {
  display: grid;
  grid-template-columns: repeat(5, minmax(0, 1fr));
  gap: 10px 14px;
}

@media (max-width: 1100px) {
  .form-grid {
    grid-template-columns: repeat(2, minmax(0, 1fr));
  }
}

@media (max-width: 640px) {
  .form-grid {
    grid-template-columns: 1fr;
  }
}
</style>
