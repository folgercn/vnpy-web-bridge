<template>
  <div class="page">
    <n-card size="small">
      <div class="toolbar">
        <n-button @click="load">刷新</n-button>
      </div>
    </n-card>
    <n-card title="策略" size="small">
      <n-data-table size="small" :columns="columns" :data="strategies" :pagination="{ pageSize: 12 }" />
      <n-alert v-if="error" type="warning" style="margin-top: 12px">{{ error }}</n-alert>
    </n-card>
  </div>
</template>

<script setup lang="ts">
import { h, onMounted, ref } from 'vue'
import { NButton, useMessage } from 'naive-ui'
import { getStrategies, initStrategy, startStrategy, stopStrategy } from '../api/strategy'
import { useAuthStore } from '../stores/auth'

const auth = useAuthStore()
const message = useMessage()
const strategies = ref<Record<string, unknown>[]>([])
const error = ref('')
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

onMounted(load)

async function load() {
  error.value = ''
  try {
    strategies.value = await getStrategies()
  } catch (exc) {
    error.value = exc instanceof Error ? exc.message : '策略接口不可用'
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
