<template>
  <slot v-if="allowed" />
  <slot v-else name="fallback" :reason="reason" />
</template>

<script setup lang="ts">
withDefaults(defineProps<{ allowed: boolean; reason?: string }>(), { reason: '当前账号无权执行此操作' })
</script>
