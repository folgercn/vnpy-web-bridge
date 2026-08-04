<template>
  <main class="page">
    <page-header
      title="商品 SimNow"
      description="STATIC_CORE_EQUAL 模板、仓位管理 Shadow 与受控候选测试。"
    />
    <status-summary
      title="运行状态"
      :type="store.status.enabled ? 'success' : 'warning'"
      :description="store.status.enabled ? '商品策略服务已启用' : '商品策略服务未启用或已停止'"
      :items="statusItems"
    />
    <async-content :loading="store.loading" :error="store.error">
      <page-section title="STATIC_CORE_EQUAL 商品组合">
        <key-value-grid :items="templateItems" />
        <action-bar class="section-offset">
          <permission-guard :allowed="isAdmin">
            <n-button
              type="primary"
              :loading="store.loading"
              :disabled="!store.template.configured"
              @click="run(store.startTemplate, '策略模板已启动')"
            >恢复持续授权</n-button>
            <n-button quaternary :loading="store.loading" @click="store.loadAll">刷新状态</n-button>
            <template #fallback="{ reason }"><span class="muted">{{ reason }}</span></template>
          </permission-guard>
          <template #danger>
            <n-button type="error" secondary :disabled="!isAdmin || !store.status.enabled" @click="templateStopOpen = true">
              停止
            </n-button>
          </template>
        </action-bar>
        <n-alert v-if="!store.template.configured" type="warning" class="section-offset">
          部署环境需配置签名目标源；页面不允许手选品种、周期或合约。
        </n-alert>
      </page-section>

      <page-section title="仓位管理候选 · 只读 Shadow">
        <key-value-grid :items="shadowItems" />
        <status-summary
          class="section-offset"
          title="Shadow 无交易权限"
          type="info"
          description="只与冻结基线并行观测，不会自动晋级或替换 STATIC_CORE_EQUAL。"
        />
      </page-section>

      <page-section title="SimNow 候选测试">
        <n-alert type="warning">
          非正式、不可计数，但会真实发送 SimNow 模拟委托。启动仅绑定当前 plan hash；停止只撤销当前会话委托并进入只读对账。
        </n-alert>
        <n-checkbox-group v-model:value="store.selectedProducts" class="section-offset">
          <n-space>
            <n-checkbox
              v-for="row in store.positionManager.targets || []"
              :key="row.product"
              :value="row.product"
              :disabled="row.shadow_target_quantity === row.baseline_target_quantity"
            >
              {{ row.product }} · {{ row.exact_contract }} · Δ{{ row.shadow_target_quantity - row.baseline_target_quantity }}
            </n-checkbox>
          </n-space>
        </n-checkbox-group>
        <key-value-grid v-if="store.shakedown.session?.plan" class="section-offset" :items="planItems" />
        <div v-if="store.shakedown.session?.plan_hash" class="section-offset">
          <span class="muted">计划哈希：</span>
          <hash-value :value="store.shakedown.session.plan_hash" />
        </div>
        <action-bar class="section-offset">
          <n-button
            type="primary"
            secondary
            :loading="store.shakedownLoading"
            :disabled="!isAdmin || !store.previewAllowed"
            @click="run(store.previewShakedown, '候选测试预览已固化；未发送订单')"
          >准备预览</n-button>
          <n-button
            type="primary"
            :loading="store.shakedownLoading"
            :disabled="!isAdmin || !store.startAllowed"
            @click="run(store.startShakedown, '候选测试已启动')"
          >{{ startText }}</n-button>
          <template #danger>
            <n-button type="error" secondary :disabled="!isAdmin || !store.stopAllowed" @click="shakedownStopOpen = true">
              {{ stopText }}
            </n-button>
          </template>
        </action-bar>
      </page-section>
    </async-content>

    <danger-action-dialog
      v-model:show="templateStopOpen"
      title="停止商品策略"
      description="停止后将撤销持续授权，并阻止新的自动派单。"
      confirm-text="确认停止"
      :loading="store.loading"
      @confirm="confirmTemplateStop"
    />
    <danger-action-dialog
      v-model:show="shakedownStopOpen"
      title="停止候选测试"
      description="将停止新单并对当前会话执行定向撤单和对账。"
      confirm-text="停止并对账"
      :loading="store.shakedownLoading"
      @confirm="confirmShakedownStop"
    />
  </main>
</template>

<script setup lang="ts">
import { computed, onMounted, ref } from 'vue'
import { NAlert, NButton, NCheckbox, NCheckboxGroup, NSpace, useMessage } from 'naive-ui'
import {
  ActionBar, AsyncContent, DangerActionDialog, HashValue, KeyValueGrid,
  PageHeader, PageSection, PermissionGuard, StatusSummary
} from '../../../components/common'
import { usePolling } from '../../../composables/usePolling'
import { useAuthStore } from '../../../stores/auth'
import { useCommoditySimNowStore } from '../store'

const auth = useAuthStore()
const store = useCommoditySimNowStore()
const message = useMessage()
const templateStopOpen = ref(false)
const shakedownStopOpen = ref(false)
const isAdmin = computed(() => auth.role === 'admin')
const startText = computed(() => store.sessionStatus === 'HALTED_PRE_SUBMIT_SAFE' ? '重新授权并恢复' : '启动候选测试')
const stopText = computed(() => store.sessionStatus === 'HALTED_PRE_SUBMIT_SAFE' ? '放弃并收口' : '停止测试')
const statusItems = computed(() => [
  { label: store.template.configured ? '目标源已配置' : '缺少签名目标源', type: store.template.configured ? 'success' as const : 'warning' as const },
  { label: store.status.auto_dispatch_allowed ? '自动派单已授权' : '自动派单未授权', type: store.status.auto_dispatch_allowed ? 'success' as const : 'default' as const },
  { label: store.status.plan_status || 'IDLE', type: 'info' as const }
])
const templateItems = computed(() => [
  { label: '品种', value: store.template.products?.join(', ') || '固定十品种' },
  { label: '周期', value: store.template.rebalance_cycle || 'monthly' },
  { label: '主力合约', value: 'PIT OI 自动选择' },
  { label: '执行', value: 'SimNow 自动两阶段' },
  { label: '换主力', value: '先平旧仓、对账、再开新仓' },
  { label: '交割保护', value: `SHFE 第 ${store.template.delivery_month_cutoff_day || 1} 日；SC 前月第 ${store.template.sc_pre_delivery_cutoff_day || 15} 日` }
])
const shadowItems = computed(() => [
  { label: '候选', value: store.positionManager.position_manager_id || 'MONTHLY_RELATIVE_VOL_THERMOSTAT_V1' },
  { label: '状态', value: shadowStatus.value },
  { label: '月度 scale', value: formatScale(store.positionManager.smoothed_scale) },
  { label: '基线关联', value: store.positionManager.baseline_link_state },
  { label: '平滑链', value: store.positionManager.continuity_state },
  { label: '板块映射', value: store.positionManager.sector_map_id },
  { label: '21 日波动', value: formatPercent(store.positionManager.fast_annual_vol) },
  { label: '126 日波动', value: formatPercent(store.positionManager.slow_annual_vol) },
  { label: '输入截止日', value: store.positionManager.input_cutoff_day },
  { label: '整数手差异', value: `${store.positionManager.target_change_count ?? 0} 个品种 / 最大 ${store.positionManager.maximum_abs_target_quantity_delta ?? 0} 手` }
])
const shadowStatus = computed(() => {
  if (!store.positionManager.configured) return '未配置'
  if (!store.positionManager.valid) return `无效 (${store.positionManager.error_type || 'validation'})`
  return '只读 Shadow'
})
const planItems = computed(() => {
  const plan = store.shakedown.session?.plan
  return [
    { label: '阶段', value: plan?.phase_status },
    { label: '平仓委托', value: plan?.close_orders?.length || 0 },
    { label: '开仓委托', value: plan?.open_orders?.length || 0 },
    { label: '总手数', value: plan?.total_lots || 0 }
  ]
})

onMounted(() => void store.loadAll())
usePolling(store.loadShakedown, { intervalMs: 2000, immediate: false, active: () => store.pollingActive })

async function run(action: () => Promise<void>, success: string) {
  try {
    await action()
    message.success(success)
    return true
  } catch (reason) {
    message.error(reason instanceof Error ? reason.message : '操作失败')
    return false
  }
}

async function confirmTemplateStop() {
  if (await run(store.stopTemplate, '商品策略已停止')) templateStopOpen.value = false
}

async function confirmShakedownStop() {
  if (await run(store.stopShakedown, '已停止新单并开始定向撤单/对账')) shakedownStopOpen.value = false
}

function formatPercent(value?: number) {
  return typeof value === 'number' && Number.isFinite(value) ? `${(value * 100).toFixed(2)}%` : '-'
}

function formatScale(value?: number) {
  return typeof value === 'number' && Number.isFinite(value) ? value.toFixed(4) : '-'
}
</script>
