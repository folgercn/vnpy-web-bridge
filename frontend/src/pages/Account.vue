<template>
  <div class="page">
    <n-card size="small">
      <n-button @click="terminal.refreshSnapshots">刷新</n-button>
    </n-card>
    <data-panel title="账户资金" :columns="columns" :rows="terminal.accounts" />
    <n-card title="资金曲线" size="small">
      <div class="muted">资金曲线待接入历史权益数据。</div>
    </n-card>
  </div>
</template>

<script setup lang="ts">
import DataPanel from '../components/common/DataPanel.vue'
import { useTerminalStore } from '../stores/terminal'

const terminal = useTerminalStore()
const columns = ['accountid', 'balance', 'available', 'frozen', 'commission', 'close_profit', 'holding_profit'].map((key) => ({ title: key, key }))
</script>
