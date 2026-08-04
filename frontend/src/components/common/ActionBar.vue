<template>
  <div class="action-bar">
    <div class="action-bar__main"><slot /></div>
    <div v-if="$slots.danger" class="action-bar__danger"><slot name="danger" /></div>
  </div>
</template>

<style scoped>
.action-bar,
.action-bar__main,
.action-bar__danger {
  display: flex;
  flex-wrap: wrap;
  align-items: center;
  gap: var(--space-2);
}

.action-bar {
  justify-content: space-between;
  min-width: 0;
}

.action-bar__danger {
  margin-left: var(--space-5);
}

@media (max-width: 640px) {
  .action-bar,
  .action-bar__main,
  .action-bar__danger {
    align-items: stretch;
    flex-direction: column;
    width: 100%;
  }

  .action-bar__danger {
    margin: var(--space-2) 0 0;
  }
}
</style>
