<template>
  <n-tag :type="active ? 'success' : 'error'" size="small" round>
    {{ label }}: {{ active ? 'connected' : 'off' }}
  </n-tag>
</template>

<script setup lang="ts">
defineProps<{ label: string; active: boolean }>()
</script>
