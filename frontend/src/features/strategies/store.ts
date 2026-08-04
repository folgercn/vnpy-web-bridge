import { defineStore } from 'pinia'
import { ref } from 'vue'
import {
  getStrategies,
  initStrategy,
  startStrategy,
  stopStrategy,
  type StrategySummary
} from '../../api/strategy'

export type StrategyAction = 'init' | 'start' | 'stop'

const actions: Record<StrategyAction, (name: string) => Promise<unknown>> = {
  init: initStrategy,
  start: startStrategy,
  stop: stopStrategy
}

export const useStrategiesStore = defineStore('strategies', () => {
  const rows = ref<StrategySummary[]>([])
  const loading = ref(false)
  const error = ref('')
  const pendingKey = ref('')

  async function load() {
    loading.value = true
    error.value = ''
    try {
      rows.value = await getStrategies()
    } catch (reason) {
      error.value = reason instanceof Error ? reason.message : '策略接口不可用'
    } finally {
      loading.value = false
    }
  }

  async function operate(action: StrategyAction, name: string) {
    const key = `${action}:${name}`
    if (pendingKey.value) return
    pendingKey.value = key
    try {
      await actions[action](name)
      await load()
    } finally {
      pendingKey.value = ''
    }
  }

  return { rows, loading, error, pendingKey, load, operate }
})
