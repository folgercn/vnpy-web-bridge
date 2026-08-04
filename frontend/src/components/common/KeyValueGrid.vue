<template>
  <dl class="key-value-grid">
    <div v-for="item in items" :key="item.label">
      <dt>{{ item.label }}</dt>
      <dd :class="{ mono: item.monospace }">{{ item.value ?? emptyText }}</dd>
    </div>
  </dl>
</template>

<script setup lang="ts">
interface KeyValueItem {
  label: string
  value?: string | number | null
  monospace?: boolean
}

withDefaults(defineProps<{ items: KeyValueItem[]; emptyText?: string }>(), { emptyText: '-' })
</script>

<style scoped>
.key-value-grid {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(180px, 1fr));
  gap: var(--space-3);
  margin: 0;
}

.key-value-grid > div {
  display: grid;
  gap: var(--space-1);
}

dt {
  color: var(--app-muted);
  font-size: 12px;
}

dd {
  margin: 0;
  overflow-wrap: anywhere;
  font-weight: 600;
}
</style>
