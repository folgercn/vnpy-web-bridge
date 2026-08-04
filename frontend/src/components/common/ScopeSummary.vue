<template><key-value-grid :items="items" /></template>

<script setup lang="ts">
import KeyValueGrid from './KeyValueGrid.vue'

defineProps<{ items: Array<{ label: string; value?: string | number | null; monospace?: boolean }> }>()
</script>
