<template>
  <div class="page">
    <div class="grid-4">
      <n-card title="Backend" size="small">{{ terminal.backendStatus.status || '-' }}</n-card>
      <n-card title="RPC" size="small">{{ terminal.rpcStatus.connected ? 'connected' : 'disconnected' }}</n-card>
      <n-card title="Gateway" size="small">{{ terminal.gatewayStatus.gateway_name || '-' }}</n-card>
      <n-card title="Trade" size="small">{{ terminal.webTradeEnabled ? 'enabled' : 'disabled' }}</n-card>
    </div>
    <div class="grid-4">
      <n-card title="Monitor" size="small">
        <n-statistic label="Active" :value="monitorSummary.active_count ?? 0" />
      </n-card>
      <n-card title="Severity" size="small">
        <n-tag :type="severityTagType(String(monitorSummary.highest_severity || 'info'))" round>
          {{ monitorSummary.highest_severity || 'info' }}
        </n-tag>
      </n-card>
      <n-card title="Telegram" size="small">
        <n-space size="small">
          <n-tag :type="telegramConfig.enabled ? 'success' : 'default'" round>{{ telegramConfig.enabled ? 'enabled' : 'disabled' }}</n-tag>
          <n-tag :type="telegramConfig.configured ? 'success' : 'warning'" round>{{ telegramConfig.configured ? 'configured' : 'missing' }}</n-tag>
        </n-space>
      </n-card>
      <n-card title="Last Check" size="small">
        <div class="card-line">
          <span>{{ lastCheckText }}</span>
          <n-button size="small" quaternary circle :loading="monitorLoading" @click="refreshMonitoring">
            <template #icon><n-icon><ReloadOutlined /></n-icon></template>
          </n-button>
        </div>
      </n-card>
    </div>
    <n-card title="Active Incidents" size="small">
      <n-data-table :columns="incidentColumns" :data="monitorIncidents" :pagination="false" :scroll-x="980" size="small" />
    </n-card>
    <n-card title="交易时段" size="small">
      <n-data-table :columns="sessionColumns" :data="sessionRows" :pagination="false" :scroll-x="1030" size="small" />
    </n-card>
    <div class="grid-2">
      <data-panel title="资金摘要" :columns="accountColumns" :rows="terminal.accounts" />
      <data-panel title="持仓摘要" :columns="positionColumns" :rows="terminal.positions" />
    </div>
    <div class="grid-2">
      <n-card title="当日统计" size="small">
        <n-statistic label="委托" :value="terminal.orders.length" />
        <n-statistic label="成交" :value="terminal.trades.length" />
      </n-card>
      <data-panel title="最近日志" :columns="logColumns" :rows="terminal.logs.slice(0, 8)" />
    </div>
  </div>
</template>

<script setup lang="ts">
import { computed, h, onBeforeUnmount, onMounted, ref } from 'vue'
import { NButton, NIcon, NSpace, NTag, type DataTableColumns } from 'naive-ui'
import { ReloadOutlined } from '@vicons/antd'
import DataPanel from '../components/common/DataPanel.vue'
import { getMonitorIncidents, getMonitorSummary, getTelegramConfig, type MonitorIncident, type MonitorSummary } from '../api/monitoring'
import { useTerminalStore } from '../stores/terminal'
import { getTradingSessionStatus, symbolRoot } from '../utils/tradingSessions'
import { isResolvedMainContract, preferredMainContract, vtSymbolOf, type ContractRow } from '../utils/marketContracts'

const terminal = useTerminalStore()
const now = ref(new Date())
const accountColumns = cols(['accountid', 'balance', 'available', 'frozen'])
const positionColumns = cols(['vt_symbol', 'direction', 'volume', 'price', 'pnl'])
const logColumns = cols(['type', 'action', 'message'])
const monitorSummary = ref<MonitorSummary>({})
const monitorIncidents = ref<MonitorIncident[]>([])
const telegramConfig = ref<Record<string, unknown>>({})
const monitorLoading = ref(false)
let timer: number | undefined
const sessionItems = computed(() => {
  return defaultSessionContracts.map((item) => {
    const contracts = terminal.contracts.filter(
      (row) => symbolRoot(row.symbol) === item.root && String(row.exchange || '').toUpperCase() === item.exchange
    )
    const contract = preferredMainContract(contracts as ContractRow[])
    return {
      name: item.name,
      symbol: String(contract?.symbol || item.symbol),
      exchange: String(contract?.exchange || item.exchange),
      vt_symbol: contract ? vtSymbolOf(contract) : `${item.symbol}.${item.exchange}`,
      is_main: contract ? isResolvedMainContract(contract, contracts as ContractRow[]) : true
    }
  })
})
const sessionRows = computed(() =>
  sessionItems.value.map((item) => {
    const status = getTradingSessionStatus(item.exchange, item.symbol, now.value)
    return {
      ...item,
      key: item.vt_symbol,
      status_label: status.label,
      status_type: status.isOpen ? 'success' : 'warning',
      status_text: status.statusText,
      session_text: status.currentSessionText,
      next_open: status.isOpen ? '-' : status.nextOpenText,
      countdown: status.isOpen ? '-' : status.countdownText
    }
  })
)
const sessionColumns: DataTableColumns = [
  { title: '品种', key: 'name', width: 120, fixed: 'left' },
  { title: '主力合约', key: 'symbol', width: 120 },
  { title: '交易所', key: 'exchange', width: 90 },
  {
    title: '标识',
    key: 'role',
    width: 90,
    render: (row) => (row.is_main ? h(NTag, { type: 'success', round: true }, { default: () => '主力' }) : '-')
  },
  {
    title: '状态',
    key: 'status_label',
    width: 90,
    render: (row) =>
      h(
        NTag,
        { round: true, type: row.status_type as 'success' | 'warning' },
        { default: () => String(row.status_label || '-') }
      )
  },
  { title: '当前', key: 'status_text', width: 130 },
  { title: '时段', key: 'session_text', width: 150 },
  { title: '下次开市', key: 'next_open', width: 120 },
  { title: '倒计时', key: 'countdown', width: 110 }
]
const incidentColumns: DataTableColumns<MonitorIncident> = [
  { title: 'Incident', key: 'incident_id', width: 240, fixed: 'left', ellipsis: { tooltip: true } },
  {
    title: 'Severity',
    key: 'severity',
    width: 110,
    render: (row) => h(NTag, { type: severityTagType(row.severity), round: true }, { default: () => row.severity })
  },
  { title: 'Status', key: 'status', width: 120 },
  { title: 'Scope', key: 'scope_id', width: 160, ellipsis: { tooltip: true } },
  { title: 'Summary', key: 'summary', width: 300, ellipsis: { tooltip: true } },
  { title: 'Last Seen', key: 'last_seen', width: 190 }
]
const lastCheckText = computed(() => {
  const lastCheck = monitorSummary.value.last_check as Record<string, unknown> | undefined
  return String(lastCheck?.checked_at || monitorSummary.value.last_updated_at || '-')
})

const defaultSessionContracts = [
  { name: '天然橡胶', root: 'ru', symbol: 'ru2609', exchange: 'SHFE' },
  { name: '沥青', root: 'bu', symbol: 'bu2609', exchange: 'SHFE' },
  { name: '甲醇', root: 'ma', symbol: 'ma609', exchange: 'CZCE' },
  { name: '纯碱', root: 'sa', symbol: 'sa609', exchange: 'CZCE' },
  { name: '多晶硅', root: 'ps', symbol: 'ps2609', exchange: 'GFEX' }
]

onMounted(() => {
  if (!terminal.contracts.length) terminal.refreshContracts().catch(() => undefined)
  refreshMonitoring().catch(() => undefined)
  timer = window.setInterval(() => {
    now.value = new Date()
  }, 30000)
})

onBeforeUnmount(() => {
  if (timer) window.clearInterval(timer)
})

function cols(keys: string[]) {
  return keys.map((key) => ({ title: key, key }))
}

async function refreshMonitoring() {
  monitorLoading.value = true
  try {
    const [summary, incidents, telegram] = await Promise.all([
      getMonitorSummary(),
      getMonitorIncidents(false),
      getTelegramConfig()
    ])
    monitorSummary.value = summary
    monitorIncidents.value = incidents
    telegramConfig.value = telegram
  } finally {
    monitorLoading.value = false
  }
}

function severityTagType(severity: string) {
  if (severity === 'critical') return 'error'
  if (severity === 'warning') return 'warning'
  return 'default'
}
</script>
