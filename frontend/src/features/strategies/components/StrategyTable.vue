<template>
  <responsive-data-table
    :columns="columns"
    :data="rows"
    :pagination="{ pageSize: 12 }"
    :scroll-x="980"
  />
</template>

<script setup lang="ts">
import { h } from 'vue'
import { NButton, type ButtonProps, type DataTableColumns } from 'naive-ui'
import ResponsiveDataTable from '../../../components/common/ResponsiveDataTable.vue'
import type { StrategySummary } from '../../../api/strategy'
import type { StrategyAction } from '../store'

const props = defineProps<{
  rows: StrategySummary[]
  canOperate: boolean
  pendingKey?: string
}>()
const emit = defineEmits<{ operate: [action: StrategyAction, name: string] }>()

const columns: DataTableColumns<StrategySummary> = [
  { title: '策略名称', key: 'strategy_name', fixed: 'left', width: 180 },
  { title: '策略类', key: 'class_name', width: 180 },
  { title: '合约', key: 'vt_symbol', width: 140 },
  { title: '状态', key: 'status', width: 100 },
  { title: '已初始化', key: 'inited', width: 100, render: (row) => row.inited ? '是' : '否' },
  { title: '交易中', key: 'trading', width: 90, render: (row) => row.trading ? '是' : '否' },
  {
    title: '操作',
    key: 'actions',
    width: 260,
    fixed: 'right',
    render(row) {
      const name = row.strategy_name
      const button = (label: string, action: StrategyAction, options: Pick<ButtonProps, 'type' | 'secondary'> = {}) =>
        h(NButton, {
          size: 'small',
          disabled: !props.canOperate || Boolean(props.pendingKey),
          loading: props.pendingKey === `${action}:${name}`,
          onClick: () => emit('operate', action, name),
          ...options
        }, { default: () => label })
      return h('div', { class: 'toolbar' }, [
        button('初始化', 'init'),
        button('启动', 'start', { type: 'primary', secondary: true }),
        button('停止', 'stop', { type: 'error', secondary: true })
      ])
    }
  }
]
</script>
