<template>
  <n-card class="lab-card" size="small" title="最近运行">
    <ResponsiveDataTable :columns="columns" :data="runs" :pagination="pagination" :scroll-x="1050" />
  </n-card>
  <n-drawer :show="open" :width="drawerWidth" placement="right" @update:show="(value) => !value && emit('close')">
    <n-drawer-content title="运行详情" closable>
      <template v-if="detail">
        <n-descriptions label-placement="left" :column="1" bordered size="small">
          <n-descriptions-item label="Run ID"><span class="mono">{{ detail.run.run_id }}</span></n-descriptions-item>
          <n-descriptions-item label="Target ID"><span class="mono">{{ detail.run.target_id }}</span></n-descriptions-item>
          <n-descriptions-item label="状态"><LabStatusTag :status="detail.run.status" /></n-descriptions-item>
          <n-descriptions-item label="开始">{{ formatTime(detail.run.started_at) }}</n-descriptions-item>
          <n-descriptions-item label="结束">{{ formatTime(detail.run.ended_at) }}</n-descriptions-item>
          <n-descriptions-item label="错误">{{ detail.run.error || '—' }}</n-descriptions-item>
        </n-descriptions>
        <h3>快照</h3>
        <ResponsiveDataTable :columns="snapshotColumns" :data="detail.snapshots" :scroll-x="760" />
      </template>
    </n-drawer-content>
  </n-drawer>
</template>

<script setup lang="ts">
import { computed, h } from 'vue'
import { NButton, NDescriptions, NDescriptionsItem, NDrawer, NDrawerContent, NCard, type DataTableColumns } from 'naive-ui'
import ResponsiveDataTable from '../../../components/common/ResponsiveDataTable.vue'
import { useMediaQuery } from '../../../composables/useMediaQuery'
import { formatMoney, formatTime, shortId } from '../formatters'
import type { LabRun, LabRunDetail, LabSnapshot } from '../types'
import LabStatusTag from './LabStatusTag.vue'

defineProps<{ runs: LabRun[]; detail: LabRunDetail | null; open: boolean }>()
const emit = defineEmits<{ select: [runId: string]; close: [] }>()
const mobile = useMediaQuery('(max-width: 640px)')
const drawerWidth = computed(() => mobile.value ? '100%' : 720)
const pagination = { pageSize: 20, pageSizes: [20, 50, 100], showSizePicker: true }
const columns: DataTableColumns<LabRun> = [
  { title: 'Run ID', key: 'run_id', render: (row) => h('span', { class: 'mono', title: row.run_id }, shortId(row.run_id)) },
  { title: '开始时间', key: 'started_at', render: (row) => formatTime(row.started_at) },
  { title: '结束时间', key: 'ended_at', render: (row) => formatTime(row.ended_at) },
  { title: '状态', key: 'status', render: (row) => h(LabStatusTag, { status: row.status }) },
  { title: '异常', key: 'error', render: (row) => row.error || '—' },
  { title: '操作', key: 'actions', render: (row) => h(NButton, { size: 'small', text: true, onClick: () => emit('select', row.run_id) }, { default: () => '查看详情' }) }
]
const snapshotColumns: DataTableColumns<LabSnapshot> = [
  { title: '阶段', key: 'phase' }, { title: '时间', key: 'observed_at', render: (row) => formatTime(row.observed_at) },
  { title: '权益', key: 'equity', align: 'right', render: (row) => formatMoney(row.equity) },
  { title: '可用', key: 'available', align: 'right', render: (row) => formatMoney(row.available) },
  { title: '保证金', key: 'margin', align: 'right', render: (row) => formatMoney(row.margin) }
]
</script>

<style scoped>
.lab-card { border-radius: var(--card-radius); }
.mono { font-family: SFMono-Regular, Consolas, monospace; overflow-wrap: anywhere; }
h3 { margin: var(--space-5) 0 var(--space-3); font-size: var(--font-section-size); line-height: var(--font-section-line); }
</style>
