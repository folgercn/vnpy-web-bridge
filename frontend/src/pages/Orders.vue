<template>
  <div class="page">
    <n-card size="small">
      <div class="toolbar">
        <n-select v-model:value="status" :options="statusOptions" style="max-width: 180px" />
        <n-button :disabled="!terminal.webTradeEnabled" type="warning" @click="submitCancelAll">全撤</n-button>
        <n-button @click="terminal.refreshSnapshots">刷新</n-button>
      </div>
    </n-card>
    <n-card title="委托" size="small">
      <n-data-table size="small" :columns="columns" :data="rows" :pagination="{ pageSize: 14 }" />
    </n-card>
  </div>
</template>

<script setup lang="ts">
import { computed, h, ref } from 'vue'
import { NButton, useMessage } from 'naive-ui'
import { cancelAll, cancelOrder } from '../api/trade'
import { useTerminalStore } from '../stores/terminal'

const terminal = useTerminalStore()
const message = useMessage()
const status = ref('all')
const statusOptions = ['all', 'submitting', 'not_traded', 'part_traded', 'all_traded', 'cancelled', 'rejected'].map((value) => ({ label: value, value }))
const rows = computed(() => (status.value === 'all' ? terminal.orders : terminal.orders.filter((row) => row.status === status.value)))
const columns = [
  ...['vt_orderid', 'vt_symbol', 'direction', 'offset', 'price', 'volume', 'traded', 'status', 'datetime'].map((key) => ({ title: key, key })),
  {
    title: '操作',
    key: 'actions',
    render(row: Record<string, unknown>) {
      return h(
        NButton,
        {
          size: 'small',
          disabled: !terminal.webTradeEnabled || !['submitting', 'not_traded', 'part_traded'].includes(String(row.status)),
          onClick: () => submitCancel(String(row.vt_orderid))
        },
        { default: () => '撤单' }
      )
    }
  }
]

async function submitCancel(vtOrderid: string) {
  try {
    await cancelOrder(vtOrderid)
    message.success('撤单请求已发送')
    await terminal.refreshSnapshots()
  } catch (exc) {
    message.error(exc instanceof Error ? exc.message : '撤单失败')
  }
}

async function submitCancelAll() {
  try {
    const result = await cancelAll()
    message.success(`全撤完成：${String(result.success || 0)} / ${String(result.requested || 0)}`)
    await terminal.refreshSnapshots()
  } catch (exc) {
    message.error(exc instanceof Error ? exc.message : '全撤失败')
  }
}
</script>
