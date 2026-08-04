<template>
  <n-card :title="title" :size="size">
    <template v-if="$slots.headerExtra" #header-extra><slot name="headerExtra" /></template>
    <slot />
  </n-card>
</template>

<script setup lang="ts">
import { NCard } from 'naive-ui'

withDefaults(defineProps<{ title?: string; size?: 'small' | 'medium' | 'large' | 'huge' }>(), {
  size: 'small'
})
</script>
