<template>
  <div class="page">
    <div class="grid-4">
      <n-card title="Backend" size="small">{{ terminal.backendStatus.status || '-' }}</n-card>
      <n-card title="RPC" size="small">{{ terminal.rpcStatus.connected ? 'connected' : 'disconnected' }}</n-card>
      <n-card title="Gateway" size="small">{{ terminal.gatewayStatus.gateway_name || '-' }}</n-card>
      <n-card title="Trade" size="small">{{ terminal.webTradeEnabled ? 'enabled' : 'disabled' }}</n-card>
    </div>
    <n-card title="交易时段" size="small">
      <div class="session-grid">
        <div v-for="item in sessionItems" :key="item.symbol" class="session-item">
          <div class="session-name">{{ item.name }}</div>
          <trading-session-badge :exchange="item.exchange" :symbol="item.symbol" />
        </div>
      </div>
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
import { computed, onMounted } from 'vue'
import DataPanel from '../components/common/DataPanel.vue'
import TradingSessionBadge from '../components/common/TradingSessionBadge.vue'
import { useTerminalStore } from '../stores/terminal'
import { symbolRoot } from '../utils/tradingSessions'

const terminal = useTerminalStore()
const accountColumns = cols(['accountid', 'balance', 'available', 'frozen'])
const positionColumns = cols(['vt_symbol', 'direction', 'volume', 'price', 'pnl'])
const logColumns = cols(['type', 'action', 'message'])
const sessionItems = computed(() => {
  return defaultSessionContracts.map((item) => {
    const contract = terminal.contracts.find(
      (row) => symbolRoot(row.symbol) === item.root && String(row.exchange || '').toUpperCase() === item.exchange
    )
    return {
      name: item.name,
      symbol: String(contract?.symbol || item.symbol),
      exchange: String(contract?.exchange || item.exchange)
    }
  })
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
})

function cols(keys: string[]) {
  return keys.map((key) => ({ title: key, key }))
}
</script>

<style scoped>
.session-grid {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(220px, 1fr));
  gap: 12px;
}

.session-item {
  min-width: 0;
  padding: 10px 0;
}

.session-name {
  margin-bottom: 8px;
  font-weight: 600;
}
</style>
