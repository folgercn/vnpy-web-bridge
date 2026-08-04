<template>
  <span class="hash-value">
    <code :title="value">{{ expanded ? value : shortValue }}</code>
    <n-button v-if="value.length > shortLength" text size="tiny" @click="expanded = !expanded">
      {{ expanded ? '收起' : '展开' }}
    </n-button>
    <n-button v-if="copyable" text size="tiny" @click="copy">复制</n-button>
  </span>
</template>

<script setup lang="ts">
import { computed, ref } from 'vue'
import { NButton, useMessage } from 'naive-ui'

const props = withDefaults(defineProps<{ value: string; shortLength?: number; copyable?: boolean }>(), {
  shortLength: 12,
  copyable: true
})
const expanded = ref(false)
const message = useMessage()
const shortValue = computed(() => props.value.length > props.shortLength ? `${props.value.slice(0, props.shortLength)}…` : props.value)

async function copy() {
  await navigator.clipboard.writeText(props.value)
  message.success('已复制')
}
</script>

<style scoped>
.hash-value {
  display: inline-flex;
  align-items: center;
  gap: var(--space-2);
  min-width: 0;
}

code {
  overflow-wrap: anywhere;
}
</style>
