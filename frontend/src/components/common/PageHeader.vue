<template>
  <header class="page-header">
    <div>
      <p v-if="eyebrow" class="page-header__eyebrow">{{ eyebrow }}</p>
      <h1>{{ title }}</h1>
      <p v-if="description" class="page-header__description">{{ description }}</p>
    </div>
    <div v-if="$slots.actions" class="page-header__actions"><slot name="actions" /></div>
  </header>
</template>

<script setup lang="ts">
defineProps<{ title: string; description?: string; eyebrow?: string }>()
</script>

<style scoped>
.page-header {
  display: flex;
  align-items: flex-start;
  justify-content: space-between;
  gap: var(--space-4);
}

h1,
p {
  margin: 0;
}

h1 {
  font-size: 24px;
  line-height: 1.3;
}

.page-header__eyebrow,
.page-header__description {
  color: var(--app-muted);
}

.page-header__eyebrow {
  margin-bottom: var(--space-1);
  font-size: 12px;
  text-transform: uppercase;
}

.page-header__description {
  margin-top: var(--space-2);
}

@media (max-width: 640px) {
  .page-header {
    flex-direction: column;
  }

  .page-header__actions {
    width: 100%;
  }
}
</style>
