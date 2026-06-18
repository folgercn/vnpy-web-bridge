<template>
  <div class="trading-session" :class="{ compact }">
    <n-tag :type="status.isOpen ? 'success' : 'warning'" round>{{ status.label }}</n-tag>
    <div class="session-copy">
      <div class="session-main">{{ status.statusText }}</div>
      <div class="session-sub">
        {{ status.isOpen ? `本段 ${status.currentSessionText}` : `下次 ${status.nextOpenText}` }}
        <span v-if="!status.isOpen"> · {{ status.countdownText }}</span>
      </div>
    </div>
  </div>
</template>

<script setup lang="ts">
import { computed, onBeforeUnmount, onMounted, ref } from 'vue'
import { getTradingSessionStatus } from '../../utils/tradingSessions'

const props = defineProps<{
  exchange: string
  symbol?: string
  compact?: boolean
}>()

const now = ref(new Date())
let timer: number | undefined

const status = computed(() => getTradingSessionStatus(props.exchange, props.symbol, now.value))

onMounted(() => {
  timer = window.setInterval(() => {
    now.value = new Date()
  }, 30000)
})

onBeforeUnmount(() => {
  if (timer) window.clearInterval(timer)
})
</script>

<style scoped>
.trading-session {
  display: flex;
  align-items: center;
  gap: 10px;
  min-width: 0;
}

.trading-session.compact {
  align-items: flex-start;
}

.session-copy {
  min-width: 0;
}

.session-main {
  font-weight: 600;
  line-height: 1.3;
}

.session-sub {
  margin-top: 2px;
  color: var(--app-muted);
  font-size: 12px;
  line-height: 1.4;
}
</style>
