<template>
  <n-layout class="admin-shell" has-sider>
    <n-layout-sider bordered collapse-mode="width" :collapsed-width="64" :width="230">
      <div class="brand">VnPy Bridge</div>
      <n-menu :value="$route.path" :options="menuOptions" @update:value="router.push" />
    </n-layout-sider>
    <n-layout>
      <n-layout-header bordered class="topbar">
        <div class="toolbar">
          <status-badge label="RPC" :active="Boolean(terminal.rpcStatus.connected)" />
          <status-badge label="WS" :active="eventSocket.status.value === 'connected'" />
          <status-badge label="Trade" :active="terminal.webTradeEnabled" />
          <n-tag type="info">{{ auth.user?.role }}</n-tag>
        </div>
        <n-button size="small" @click="logout">退出</n-button>
      </n-layout-header>
      <n-layout-content class="content">
        <router-view />
      </n-layout-content>
    </n-layout>
  </n-layout>
</template>

<script setup lang="ts">
import { h, onMounted } from 'vue'
import { NIcon } from 'naive-ui'
import {
  AccountBookOutlined,
  AreaChartOutlined,
  DashboardOutlined,
  DatabaseOutlined,
  FileTextOutlined,
  LineChartOutlined,
  OrderedListOutlined,
  SecurityScanOutlined,
  SwapOutlined
} from '@vicons/antd'
import { useRouter } from 'vue-router'
import StatusBadge from './common/StatusBadge.vue'
import { useAuthStore } from '../stores/auth'
import { useTerminalStore } from '../stores/terminal'
import { eventSocket } from '../ws/events'

const router = useRouter()
const auth = useAuthStore()
const terminal = useTerminalStore()

const menuOptions = [
  item('Dashboard', '/dashboard', DashboardOutlined),
  item('行情', '/market', LineChartOutlined),
  item('交易', '/trading', SwapOutlined),
  item('持仓', '/positions', DatabaseOutlined),
  item('委托', '/orders', OrderedListOutlined),
  item('成交', '/trades', AreaChartOutlined),
  item('资金', '/account', AccountBookOutlined),
  item('策略', '/strategies', SecurityScanOutlined),
  item('日志', '/logs', FileTextOutlined)
]

onMounted(async () => {
  await terminal.refreshStatus().catch(() => undefined)
  await terminal.refreshSnapshots().catch(() => undefined)
  eventSocket.connect()
})

function item(label: string, key: string, icon: unknown) {
  return { label, key, icon: () => h(NIcon, null, { default: () => h(icon as never) }) }
}

function logout() {
  auth.logout()
  eventSocket.close()
  router.push('/login')
}
</script>

<style scoped>
.admin-shell {
  min-height: 100vh;
}

.brand {
  height: 54px;
  display: flex;
  align-items: center;
  padding: 0 18px;
  font-weight: 700;
  letter-spacing: 0;
}

.topbar {
  height: 54px;
  display: flex;
  align-items: center;
  justify-content: space-between;
  padding: 0 16px;
}

.content {
  padding: 16px;
}
</style>
