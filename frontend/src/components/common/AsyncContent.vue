<template>
  <n-spin :show="loading">
    <n-alert v-if="error" type="error" :title="errorTitle">{{ error }}</n-alert>
    <n-empty v-else-if="empty && !loading" :description="emptyText" />
    <slot v-else />
  </n-spin>
</template>

<script setup lang="ts">
import { NAlert, NEmpty, NSpin } from 'naive-ui'

withDefaults(defineProps<{
  loading?: boolean
  error?: string
  empty?: boolean
  errorTitle?: string
  emptyText?: string
}>(), {
  loading: false,
  error: '',
  empty: false,
  errorTitle: '加载失败',
  emptyText: '暂无数据'
})
</script>
