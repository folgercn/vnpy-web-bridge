<template>
  <main class="page lab-page">
    <PageHeader title="SIMNOW_LAB" description="STATIC_CORE_EQUAL 自动运行与只读观测">
      <template #actions><n-button quaternary size="small" :loading="store.loading" @click="store.refresh">刷新</n-button></template>
    </PageHeader>
    <n-alert v-if="store.stale" type="warning" title="STALE">
      当前展示最近成功数据，最后成功：{{ formatTime(store.lastSuccessAt) }}
    </n-alert>
    <n-alert v-if="store.dashboard?.summary.blocker" type="error" title="运行阻塞">
      {{ store.dashboard.summary.blocker }}
    </n-alert>
    <AsyncContent :loading="store.loading && !store.hasData" :error="errorText" :empty="!store.dashboard">
      <template v-if="store.dashboard">
        <LabOverview :summary="store.dashboard.summary" :metrics="store.dashboard.metrics" />
        <LabPerformanceChart :series="store.dashboard.series" />
        <LabPortfolioTable :rows="store.dashboard.portfolio" />
        <LabRuns :runs="store.dashboard.runs" :detail="store.selectedRun" :open="store.drawerOpen" @select="store.selectRun" @close="store.closeDrawer" />
        <LabActivity :orders="store.dashboard.orders" :trades="store.dashboard.trades" :incidents="store.dashboard.incidents" />
      </template>
    </AsyncContent>
    <footer class="version-line">
      <span>Web {{ store.webVersion }}</span><span>Windows {{ store.dashboard?.runtime_version || 'unknown' }}</span><span>数据时间 {{ formatTime(store.dashboard?.generated_at) }}</span>
    </footer>
  </main>
</template>

<script setup lang="ts">
import { computed } from 'vue'
import { NAlert, NButton } from 'naive-ui'
import AsyncContent from '../../../components/common/AsyncContent.vue'
import PageHeader from '../../../components/common/PageHeader.vue'
import LabActivity from '../components/LabActivity.vue'
import LabOverview from '../components/LabOverview.vue'
import LabPerformanceChart from '../components/LabPerformanceChart.vue'
import LabPortfolioTable from '../components/LabPortfolioTable.vue'
import LabRuns from '../components/LabRuns.vue'
import { formatTime } from '../formatters'
import { useSimNowLabDashboardStore } from '../store'

const store = useSimNowLabDashboardStore()
const errorText = computed(() => store.error ? String(store.error) : '')
</script>

<style scoped>
.lab-page { padding: var(--page-padding); color: var(--text-primary); }
.version-line { display: flex; flex-wrap: wrap; gap: var(--space-4); color: var(--text-muted); font-size: var(--font-caption-size); line-height: var(--font-caption-line); }
</style>
