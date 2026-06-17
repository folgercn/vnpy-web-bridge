<template>
  <div class="page">
    <n-card size="small">
      <div class="toolbar">
        <n-select v-model:value="type" :options="typeOptions" style="max-width: 180px" />
        <n-button @click="terminal.clearLogs">清空前端日志</n-button>
      </div>
    </n-card>
    <data-panel title="实时日志" :columns="columns" :rows="rows" />
  </div>
</template>

<script setup lang="ts">
import { computed, ref } from 'vue'
import DataPanel from '../components/common/DataPanel.vue'
import { useTerminalStore } from '../stores/terminal'

const terminal = useTerminalStore()
const type = ref('all')
const typeOptions = ['all', 'log', 'risk_alert', 'strategy_log', 'strategy_status'].map((value) => ({ label: value, value }))
const columns = ['type', 'action', 'strategy_name', 'level', 'message', 'error_code'].map((key) => ({ title: key, key }))
const rows = computed(() => (type.value === 'all' ? terminal.logs : terminal.logs.filter((row) => row.type === type.value)))
</script>
