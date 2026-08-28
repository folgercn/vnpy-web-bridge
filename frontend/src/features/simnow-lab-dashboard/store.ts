import { defineStore } from 'pinia'
import { computed, ref } from 'vue'
import { usePolling } from '../../composables/usePolling'
import { getLabDashboard, getLabRun } from './api'
import type { LabDashboard, LabRunDetail } from './types'

export const useSimNowLabDashboardStore = defineStore('simnow-lab-dashboard', () => {
  const dashboard = ref<LabDashboard | null>(null)
  const stale = ref(false)
  const lastSuccessAt = ref<string | null>(null)
  const webVersion = ref('unknown')
  const selectedRun = ref<LabRunDetail | null>(null)
  const drawerOpen = ref(false)

  async function load() {
    const response = await getLabDashboard()
    dashboard.value = response.dashboard
    stale.value = response.stale
    lastSuccessAt.value = response.last_success_at
    webVersion.value = response.web_version
  }

  async function selectRun(runId: string) {
    selectedRun.value = (await getLabRun(runId)).run
    drawerOpen.value = true
  }

  function closeDrawer() {
    drawerOpen.value = false
  }

  const polling = usePolling(load, { intervalMs: 10_000, maxIntervalMs: 60_000 })
  return {
    dashboard, stale, lastSuccessAt, webVersion, selectedRun, drawerOpen,
    loading: polling.running, error: polling.error,
    hasData: computed(() => dashboard.value !== null),
    refresh: polling.refresh, selectRun, closeDrawer
  }
})
