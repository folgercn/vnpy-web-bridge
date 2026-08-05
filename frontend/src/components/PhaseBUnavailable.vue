<template>
  <main class="page">
    <n-alert type="warning" title="PHASE_B_UNAVAILABLE">
      {{ surface }} 属于 Phase B；Phase A 不加载旧单体页面，也不会读取或调用旧策略执行 API 或其他旧 API。
    </n-alert>
  </main>
</template>

<script setup lang="ts">
import { NAlert } from 'naive-ui'

withDefaults(defineProps<{ surface?: string }>(), {
  surface: '该业务面'
})
</script>
