<template>
  <div class="page">
    <n-card title="STATIC_CORE_EQUAL 商品组合 · SimNow" size="small">
      <div class="template-grid">
        <div><span class="muted">品种</span><strong>{{ commodityTemplate.products?.join(', ') || '固定十品种' }}</strong></div>
        <div><span class="muted">周期</span><strong>{{ commodityTemplate.rebalance_cycle || 'monthly' }}</strong></div>
        <div><span class="muted">主力合约</span><strong>PIT OI 自动选择</strong></div>
        <div><span class="muted">执行</span><strong>SimNow 自动两阶段</strong></div>
        <div><span class="muted">换主力</span><strong>先平旧仓、对账、再开新仓</strong></div>
        <div>
          <span class="muted">交割保护</span>
          <strong>
            SHFE 交割月第 {{ commodityTemplate.delivery_month_cutoff_day || 1 }} 日；
            SC 交割前月第 {{ commodityTemplate.sc_pre_delivery_cutoff_day || 15 }} 日熔断
          </strong>
        </div>
      </div>
      <n-space size="small" style="margin-top: 12px">
        <n-tag :type="commodityTemplate.authorized ? 'success' : commodityStatus.enabled ? 'warning' : 'default'" round>
          {{ commodityTemplate.authorized ? '运行中' : commodityStatus.enabled ? '已停机 / 待重新授权' : '未启动' }}
        </n-tag>
        <n-tag :type="commodityTemplate.configured ? 'success' : 'warning'" round>
          {{ commodityTemplate.configured ? '目标源已配置' : '缺少签名目标源' }}
        </n-tag>
        <n-tag :type="commodityStatus.auto_dispatch_allowed ? 'success' : 'default'" round>
          {{ commodityStatus.auto_dispatch_allowed ? '自动派单已授权' : '自动派单未授权' }}
        </n-tag>
        <n-tag type="info" round>{{ commodityStatus.plan_status || 'IDLE' }}</n-tag>
      </n-space>
      <div class="toolbar" style="margin-top: 12px">
        <n-button
          type="primary"
          :loading="commodityLoading"
          :disabled="auth.role !== 'admin' || !commodityTemplate.configured"
          @click="startCommodity"
        >
          一键启动
        </n-button>
        <n-button
          type="warning"
          :loading="commodityLoading"
          :disabled="auth.role !== 'admin' || !commodityStatus.enabled"
          @click="stopCommodity"
        >
          停止
        </n-button>
        <n-button :loading="commodityLoading" @click="loadCommodity">刷新状态</n-button>
      </div>
      <n-alert v-if="!commodityTemplate.configured" type="warning" style="margin-top: 12px">
        部署环境需配置 COMMODITY_SIMNOW_TEMPLATE_BATCH_PATH；目标文件由冻结研究流水线自动更新，页面不允许手选品种、周期或合约。
      </n-alert>
    </n-card>
    <n-card title="仓位管理候选 · 只读 Shadow" size="small">
      <div class="template-grid">
        <div><span class="muted">候选</span><strong>{{ positionManager.position_manager_id || 'MONTHLY_RELATIVE_VOL_THERMOSTAT_V1' }}</strong></div>
        <div><span class="muted">状态</span><strong>{{ positionManagerStatusText }}</strong></div>
        <div><span class="muted">月度 scale</span><strong>{{ formatScale(positionManager.smoothed_scale) }}</strong></div>
        <div><span class="muted">基线关联</span><strong>{{ positionManager.baseline_link_state || '-' }}</strong></div>
        <div><span class="muted">平滑链</span><strong>{{ positionManager.continuity_state || '-' }}</strong></div>
        <div><span class="muted">板块映射</span><strong>{{ positionManager.sector_map_id || '-' }}</strong></div>
        <div><span class="muted">21 日波动</span><strong>{{ formatPercent(positionManager.fast_annual_vol) }}</strong></div>
        <div><span class="muted">126 日波动</span><strong>{{ formatPercent(positionManager.slow_annual_vol) }}</strong></div>
        <div><span class="muted">输入截止日</span><strong>{{ positionManager.input_cutoff_day || '-' }}</strong></div>
        <div>
          <span class="muted">整数手差异</span>
          <strong>{{ positionManager.target_change_count ?? 0 }} 个品种 / 最大 {{ positionManager.maximum_abs_target_quantity_delta ?? 0 }} 手</strong>
        </div>
      </div>
      <n-space size="small" style="margin-top: 12px">
        <n-tag :type="positionManager.valid ? 'success' : positionManager.configured ? 'error' : 'default'" round>
          {{ positionManager.valid ? '签名与公式已核验' : positionManager.configured ? '快照无效' : '未配置快照' }}
        </n-tag>
        <n-tag :type="positionManager.continuity_verified ? 'success' : 'warning'" round>
          {{ positionManager.continuity_verified ? '月度链已核验' : '月度链未关联' }}
        </n-tag>
        <n-tag type="warning" round>不发单</n-tag>
        <n-tag type="default" round>authority=false</n-tag>
      </n-space>
      <n-alert type="info" style="margin-top: 12px">
        候选仅与冻结基线并行观测；Web Bridge 不会用 shadow 目标生成委托，也不会自动晋级或替换 STATIC_CORE_EQUAL。
      </n-alert>
      <n-divider />
      <n-space vertical size="small">
        <strong>SimNow 候选测试预览（非正式、不可计数）</strong>
        <n-checkbox-group v-model:value="selectedPositionManagerProducts">
          <n-space>
            <n-checkbox v-for="row in positionManager.targets || []" :key="row.product" :value="row.product" :disabled="row.shadow_target_quantity === row.baseline_target_quantity">
              {{ row.product }} · {{ row.exact_contract }} · Δ{{ row.shadow_target_quantity - row.baseline_target_quantity }}
            </n-checkbox>
          </n-space>
        </n-checkbox-group>
        <n-space>
          <n-button type="primary" :loading="positionManagerLoading" :disabled="!positionManagerPreviewAllowed" @click="previewPositionManagerShakedown">准备预览</n-button>
          <n-tag type="warning" round>{{ positionManagerShakedown.session?.status || '未创建会话' }}</n-tag>
        </n-space>
        <span v-if="positionManagerShakedown.session?.plan_hash" class="muted">plan hash: {{ positionManagerShakedown.session.plan_hash }}</span>
        <div v-if="positionManagerShakedown.session?.plan" class="template-grid">
          <div><span class="muted">阶段</span><strong>{{ positionManagerShakedown.session.plan.phase_status }}</strong></div>
          <div><span class="muted">平仓委托</span><strong>{{ positionManagerShakedown.session.plan.close_orders?.length || 0 }}</strong></div>
          <div><span class="muted">开仓委托</span><strong>{{ positionManagerShakedown.session.plan.open_orders?.length || 0 }}</strong></div>
          <div><span class="muted">总手数</span><strong>{{ positionManagerShakedown.session.plan.total_lots || 0 }}</strong></div>
        </div>
        <n-alert type="info">本阶段只固化选择和计划哈希，不会调用订单接口；启动、停止与自动执行在后续受控实现中接入。</n-alert>
      </n-space>
    </n-card>
    <n-card size="small">
      <div class="toolbar">
        <n-button @click="load">刷新</n-button>
      </div>
    </n-card>
    <n-card title="策略" size="small">
      <n-data-table size="small" :columns="columns" :data="strategies" :pagination="{ pageSize: 12 }" :scroll-x="980" />
      <n-alert v-if="error" type="warning" style="margin-top: 12px">{{ error }}</n-alert>
    </n-card>
  </div>
</template>

<script setup lang="ts">
import { computed, h, onMounted, ref } from 'vue'
import { NButton, useMessage } from 'naive-ui'
import {
  getCommoditySimNowStatus,
  getCommodityPositionManagerShakedownStatus,
  previewCommodityPositionManagerShakedown,
  startCommodityStrategyTemplate,
  stopCommodityStrategyTemplate,
  type CommoditySimNowStatus,
  type CommodityPositionManagerShakedownStatus
} from '../api/commoditySimnow'
import { getStrategies, initStrategy, startStrategy, stopStrategy } from '../api/strategy'
import { useAuthStore } from '../stores/auth'

const auth = useAuthStore()
const message = useMessage()
const strategies = ref<Record<string, unknown>[]>([])
const error = ref('')
const commodityStatus = ref<CommoditySimNowStatus>({})
const commodityLoading = ref(false)
const positionManagerLoading = ref(false)
const positionManagerShakedown = ref<CommodityPositionManagerShakedownStatus>({})
const selectedPositionManagerProducts = ref<string[]>([])
const commodityTemplate = computed(() => commodityStatus.value.strategy_template || {})
const positionManager = computed(() => commodityStatus.value.position_manager_shadow || {})
const positionManagerStatusText = computed(() => {
  if (!positionManager.value.configured) return '未配置'
  if (!positionManager.value.valid) return `无效 (${positionManager.value.error_type || 'validation'})`
  return '只读 shadow'
})
const positionManagerPreviewAllowed = computed(() => auth.role === 'admin' && positionManagerShakedown.value.configured && positionManager.value.valid && ['active', 'completed'].includes(positionManager.value.baseline_link_state || '') && ['genesis', 'verified'].includes(positionManager.value.continuity_state || '') && selectedPositionManagerProducts.value.length > 0)
const columns = [
  ...['strategy_name', 'class_name', 'vt_symbol', 'status', 'inited', 'trading'].map((key) => ({ title: key, key })),
  {
    title: '操作',
    key: 'actions',
    render(row: Record<string, unknown>) {
      const disabled = auth.role !== 'admin'
      const name = String(row.strategy_name)
      return h('div', { class: 'toolbar' }, [
        h(NButton, { size: 'small', disabled, onClick: () => operate(initStrategy, name) }, { default: () => '初始化' }),
        h(NButton, { size: 'small', disabled, onClick: () => operate(startStrategy, name) }, { default: () => '启动' }),
        h(NButton, { size: 'small', disabled, onClick: () => operate(stopStrategy, name) }, { default: () => '停止' })
      ])
    }
  }
]

onMounted(() => {
  load().catch(() => undefined)
  loadCommodity().catch(() => undefined)
  loadPositionManagerShakedown().catch(() => undefined)
})

async function load() {
  error.value = ''
  try {
    strategies.value = await getStrategies()
  } catch (exc) {
    error.value = exc instanceof Error ? exc.message : '策略接口不可用'
  }
}

async function loadCommodity() {
  commodityLoading.value = true
  try {
    commodityStatus.value = await getCommoditySimNowStatus()
  } catch (exc) {
    message.error(exc instanceof Error ? exc.message : '商品策略状态不可用')
  } finally {
    commodityLoading.value = false
  }
}

async function loadPositionManagerShakedown() {
  positionManagerShakedown.value = await getCommodityPositionManagerShakedownStatus()
}

async function previewPositionManagerShakedown() {
  positionManagerLoading.value = true
  try {
    positionManagerShakedown.value = await previewCommodityPositionManagerShakedown(selectedPositionManagerProducts.value)
    message.success('候选测试预览已固化；未发送订单')
  } catch (exc) {
    message.error(exc instanceof Error ? exc.message : '候选测试预览失败')
  } finally {
    positionManagerLoading.value = false
  }
}

async function startCommodity() {
  commodityLoading.value = true
  try {
    await startCommodityStrategyTemplate()
    message.success('策略模板已启动，签名目标将自动派单')
    commodityStatus.value = await getCommoditySimNowStatus()
  } catch (exc) {
    message.error(exc instanceof Error ? exc.message : '一键启动失败')
  } finally {
    commodityLoading.value = false
  }
}

async function stopCommodity() {
  commodityLoading.value = true
  try {
    await stopCommodityStrategyTemplate()
    message.success('商品策略已停止')
    commodityStatus.value = await getCommoditySimNowStatus()
  } catch (exc) {
    message.error(exc instanceof Error ? exc.message : '停止失败')
  } finally {
    commodityLoading.value = false
  }
}

async function operate(fn: (name: string) => Promise<unknown>, name: string) {
  try {
    await fn(name)
    message.success('操作已提交')
    await load()
  } catch (exc) {
    message.error(exc instanceof Error ? exc.message : '操作失败')
  }
}

function formatPercent(value?: number) {
  return typeof value === 'number' && Number.isFinite(value) ? `${(value * 100).toFixed(2)}%` : '-'
}

function formatScale(value?: number) {
  return typeof value === 'number' && Number.isFinite(value) ? value.toFixed(4) : '-'
}
</script>

<style scoped>
.template-grid {
  display: grid;
  grid-template-columns: repeat(4, minmax(0, 1fr));
  gap: 12px;
}

.template-grid > div {
  display: flex;
  flex-direction: column;
  gap: 4px;
}

@media (max-width: 760px) {
  .template-grid {
    grid-template-columns: repeat(2, minmax(0, 1fr));
  }
}
</style>
