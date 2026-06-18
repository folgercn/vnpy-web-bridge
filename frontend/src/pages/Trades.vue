<template>
  <div class="page">
    <n-card size="small">
      <div class="toolbar">
        <n-input v-model:value="filter" placeholder="按合约过滤" class="toolbar-control-md" />
        <n-button @click="terminal.refreshSnapshots">刷新</n-button>
      </div>
    </n-card>
    <data-panel title="成交" :columns="columns" :rows="rows" />
  </div>
</template>

<script setup lang="ts">
import { computed, ref } from 'vue'
import DataPanel from '../components/common/DataPanel.vue'
import { useTerminalStore } from '../stores/terminal'

const terminal = useTerminalStore()
const filter = ref('')
const columns = ['vt_tradeid', 'vt_orderid', 'vt_symbol', 'direction', 'offset', 'price', 'volume', 'datetime'].map((key) => ({ title: key, key }))
const rows = computed(() => terminal.trades.filter((row) => String(row.vt_symbol || row.symbol || '').includes(filter.value)))
</script>
