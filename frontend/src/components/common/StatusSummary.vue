<template>
  <n-alert :type="type" :title="title" :show-icon="true">
    <div class="status-summary">
      <span v-if="description">{{ description }}</span>
      <n-space v-if="items.length" size="small">
        <n-tag v-for="item in items" :key="item.label" :type="item.type ?? 'default'" round>
          {{ item.label }}
        </n-tag>
      </n-space>
      <slot />
    </div>
  </n-alert>
</template>

<script setup lang="ts">
import { NAlert, NSpace, NTag, type TagProps } from 'naive-ui'

interface StatusSummaryItem {
  label: string
  type?: TagProps['type']
}

withDefaults(defineProps<{
  title: string
  description?: string
  type?: 'default' | 'error' | 'info' | 'success' | 'warning'
  items?: StatusSummaryItem[]
}>(), {
  type: 'info',
  items: () => []
})
</script>

<style scoped>
.status-summary {
  display: grid;
  gap: var(--space-2);
}
</style>
