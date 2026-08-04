<template>
  <main class="page">
    <page-header title="CTA 策略" description="管理传统 CTA 策略的初始化、启动与停止。" />
    <page-section title="策略列表">
      <async-content :loading="store.loading" :error="store.error" :empty="!store.rows.length">
        <strategy-table
          :rows="store.rows"
          :can-operate="auth.role === 'admin'"
          :pending-key="store.pendingKey"
          @operate="operate"
        />
      </async-content>
      <action-bar class="section-offset">
        <n-button quaternary :loading="store.loading" @click="store.load">刷新状态</n-button>
      </action-bar>
    </page-section>
  </main>
</template>

<script setup lang="ts">
import { onMounted } from 'vue'
import { NButton, useMessage } from 'naive-ui'
import { ActionBar, AsyncContent, PageHeader, PageSection } from '../components/common'
import StrategyTable from '../features/strategies/components/StrategyTable.vue'
import { useStrategiesStore, type StrategyAction } from '../features/strategies/store'
import { useAuthStore } from '../stores/auth'

const auth = useAuthStore()
const store = useStrategiesStore()
const message = useMessage()

onMounted(() => void store.load())

async function operate(action: StrategyAction, name: string) {
  try {
    await store.operate(action, name)
    message.success('操作已提交')
  } catch (reason) {
    message.error(reason instanceof Error ? reason.message : '操作失败')
  }
}
</script>
