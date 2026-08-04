import { onBeforeUnmount, onMounted, ref, type Ref } from 'vue'

export interface PollingOptions {
  intervalMs?: number
  maxIntervalMs?: number
  immediate?: boolean
  active?: () => boolean
}

export function usePolling(task: () => Promise<unknown>, options: PollingOptions = {}) {
  const running = ref(false)
  const error: Ref<unknown> = ref(null)
  const baseInterval = options.intervalMs ?? 5000
  const maxInterval = options.maxIntervalMs ?? 60000
  let currentInterval = baseInterval
  let timer: number | undefined
  let stopped = false

  function schedule() {
    if (stopped || document.hidden) return
    timer = window.setTimeout(run, currentInterval)
  }

  async function run() {
    if (running.value || stopped || document.hidden) return
    if (options.active?.() === false) {
      schedule()
      return
    }
    running.value = true
    try {
      await task()
      error.value = null
      currentInterval = baseInterval
    } catch (reason) {
      error.value = reason
      currentInterval = Math.min(currentInterval * 2, maxInterval)
    } finally {
      running.value = false
      schedule()
    }
  }

  function handleVisibility() {
    if (document.hidden) {
      if (timer) window.clearTimeout(timer)
      timer = undefined
      return
    }
    void run()
  }

  onMounted(() => {
    stopped = false
    document.addEventListener('visibilitychange', handleVisibility)
    if (options.immediate !== false) void run()
    else schedule()
  })

  onBeforeUnmount(() => {
    stopped = true
    if (timer) window.clearTimeout(timer)
    document.removeEventListener('visibilitychange', handleVisibility)
  })

  return { running, error, refresh: run }
}
