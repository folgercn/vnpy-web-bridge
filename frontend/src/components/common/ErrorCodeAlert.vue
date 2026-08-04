<template>
  <n-alert :type="type" :title="title">
    <span v-if="code" class="mono">{{ code }}</span>
    <span v-if="code"> · </span>{{ message }}
  </n-alert>
</template>

<script setup lang="ts">
import { NAlert } from 'naive-ui'

withDefaults(defineProps<{
  title?: string
  code?: string
  message: string
  type?: 'error' | 'warning' | 'info'
}>(), {
  title: '操作未完成',
  code: '',
  type: 'error'
})
</script>
