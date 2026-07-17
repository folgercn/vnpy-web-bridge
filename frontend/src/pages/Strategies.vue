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
  startCommodityStrategyTemplate,
  stopCommodityStrategyTemplate,
  type CommoditySimNowStatus
} from '../api/commoditySimnow'
import { getStrategies, initStrategy, startStrategy, stopStrategy } from '../api/strategy'
import { useAuthStore } from '../stores/auth'

const auth = useAuthStore()
const message = useMessage()
const strategies = ref<Record<string, unknown>[]>([])
const error = ref('')
const commodityStatus = ref<CommoditySimNowStatus>({})
const commodityLoading = ref(false)
const commodityTemplate = computed(() => commodityStatus.value.strategy_template || {})
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
