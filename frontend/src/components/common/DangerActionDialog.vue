<template>
  <n-modal :show="show" :mask-closable="false" @update:show="emit('update:show', $event)">
    <n-card class="danger-dialog" :title="title" role="dialog" aria-modal="true">
      <n-alert type="error">{{ description }}</n-alert>
      <div v-if="$slots.default" class="section-offset"><slot /></div>
      <action-bar class="section-offset">
        <n-button @click="emit('update:show', false)">取消</n-button>
        <template #danger>
          <n-button type="error" :loading="loading" @click="emit('confirm')">{{ confirmText }}</n-button>
        </template>
      </action-bar>
    </n-card>
  </n-modal>
</template>

<script setup lang="ts">
import { NAlert, NButton, NCard, NModal } from 'naive-ui'
import ActionBar from './ActionBar.vue'

withDefaults(defineProps<{
  show: boolean
  title: string
  description: string
  confirmText?: string
  loading?: boolean
}>(), {
  confirmText: '确认执行',
  loading: false
})
const emit = defineEmits<{ 'update:show': [value: boolean]; confirm: [] }>()
</script>

<style scoped>
.danger-dialog {
  width: min(520px, calc(100vw - var(--space-6)));
}
</style>
