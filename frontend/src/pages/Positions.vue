<template>
  <div class="page">
    <n-card size="small">
      <div class="toolbar">
        <n-input v-model:value="filter" placeholder="按合约过滤" style="max-width: 220px" />
        <n-button @click="terminal.refreshSnapshots">刷新</n-button>
      </div>
    </n-card>
    <data-panel title="持仓" :columns="columns" :rows="rows" />
  </div>
</template>

<script setup lang="ts">
import { computed, ref } from 'vue'
import DataPanel from '../components/common/DataPanel.vue'
import { useTerminalStore } from '../stores/terminal'

const terminal = useTerminalStore()
const filter = ref('')
const columns = ['vt_symbol', 'exchange', 'direction', 'volume', 'yd_volume', 'frozen', 'price', 'pnl'].map((key) => ({ title: key, key }))
const rows = computed(() => terminal.positions.filter((row) => String(row.vt_symbol || row.symbol || '').includes(filter.value)))
</script>
