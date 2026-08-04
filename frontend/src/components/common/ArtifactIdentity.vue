<template>
  <div class="artifact-identity">
    <strong>{{ name }}</strong>
    <span v-if="id" class="muted mono">{{ id }}</span>
    <hash-value v-if="hash" :value="hash" />
  </div>
</template>

<script setup lang="ts">
import HashValue from './HashValue.vue'

defineProps<{ name: string; id?: string; hash?: string }>()
</script>

<style scoped>
.artifact-identity {
  display: grid;
  gap: var(--space-1);
}
</style>
