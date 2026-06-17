<template>
  <div class="page">
    <n-card title="行情订阅" size="small">
      <div class="toolbar">
        <n-input v-model:value="symbol" placeholder="rb2610" style="max-width: 180px" />
        <n-select v-model:value="exchange" :options="exchangeOptions" style="max-width: 160px" />
        <n-button type="primary" @click="subscribe">订阅</n-button>
        <n-button @click="terminal.refreshContracts">刷新合约</n-button>
      </div>
    </n-card>
    <div class="grid-2">
      <data-panel title="合约" :columns="contractColumns" :rows="terminal.contracts.slice(0, 200)" />
      <data-panel title="最新 Tick" :columns="tickColumns" :rows="Object.values(terminal.ticks)" />
    </div>
  </div>
</template>

<script setup lang="ts">
import { ref } from 'vue'
import { useMessage } from 'naive-ui'
import DataPanel from '../components/common/DataPanel.vue'
import { useTerminalStore } from '../stores/terminal'

const message = useMessage()
const terminal = useTerminalStore()
const symbol = ref('rb2610')
const exchange = ref('SHFE')
const exchangeOptions = ['SHFE', 'DCE', 'CZCE', 'CFFEX', 'INE', 'GFEX'].map((value) => ({ label: value, value }))
const contractColumns = cols(['vt_symbol', 'name', 'exchange', 'product', 'gateway_name'])
const tickColumns = cols(['vt_symbol', 'last_price', 'bid_price_1', 'ask_price_1', 'volume', 'open_interest', 'limit_up', 'limit_down'])

async function subscribe() {
  try {
    await terminal.subscribe(symbol.value, exchange.value)
    message.success('订阅请求已发送')
  } catch (exc) {
    message.error(exc instanceof Error ? exc.message : '订阅失败')
  }
}

function cols(keys: string[]) {
  return keys.map((key) => ({ title: key, key }))
}
</script>
