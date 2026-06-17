<template>
  <div class="page">
    <div class="grid-4">
      <n-card title="Backend" size="small">{{ terminal.backendStatus.status || '-' }}</n-card>
      <n-card title="RPC" size="small">{{ terminal.rpcStatus.connected ? 'connected' : 'disconnected' }}</n-card>
      <n-card title="Gateway" size="small">{{ terminal.gatewayStatus.gateway_name || '-' }}</n-card>
      <n-card title="Trade" size="small">{{ terminal.webTradeEnabled ? 'enabled' : 'disabled' }}</n-card>
    </div>
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
import DataPanel from '../components/common/DataPanel.vue'
import { useTerminalStore } from '../stores/terminal'

const terminal = useTerminalStore()
const accountColumns = cols(['accountid', 'balance', 'available', 'frozen'])
const positionColumns = cols(['vt_symbol', 'direction', 'volume', 'price', 'pnl'])
const logColumns = cols(['type', 'action', 'message'])

function cols(keys: string[]) {
  return keys.map((key) => ({ title: key, key }))
}
</script>
