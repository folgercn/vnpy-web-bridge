<template>
  <n-layout class="admin-shell" :has-sider="!isMobile">
    <n-layout-sider v-if="!isMobile" bordered collapse-mode="width" :collapsed-width="64" :width="230">
      <div class="brand">VnPy Bridge</div>
      <n-menu :value="$route.path" :options="menuOptions" @update:value="router.push" />
    </n-layout-sider>
    <n-layout>
      <n-layout-header bordered class="topbar">
        <div class="topbar-main">
          <n-button v-if="isMobile" quaternary circle aria-label="打开菜单" @click="mobileMenuOpen = true">
            <template #icon>
              <n-icon><menu-outlined /></n-icon>
            </template>
          </n-button>
          <div v-if="isMobile" class="mobile-title">VnPy Bridge</div>
        </div>
        <div class="topbar-status">
          <status-badge label="RPC" :active="Boolean(terminal.rpcStatus.connected)" />
          <status-badge label="WS" :active="eventSocket.status.value === 'connected'" />
          <status-badge label="Trade" :active="terminal.webTradeEnabled" />
          <n-tag type="info">{{ auth.user?.role }}</n-tag>
        </div>
        <div class="topbar-actions">
          <n-dropdown trigger="click" :options="themeOptions" @select="theme.setMode">
            <n-button size="small" quaternary :circle="isMobile" class="theme-button" aria-label="主题设置">
              <template #icon>
                <n-icon><setting-outlined /></n-icon>
              </template>
              <span v-if="!isMobile">{{ themeLabel }}</span>
            </n-button>
          </n-dropdown>
          <n-button size="small" @click="logout">退出</n-button>
        </div>
      </n-layout-header>
      <n-layout-content class="content">
        <router-view />
      </n-layout-content>
    </n-layout>
    <n-drawer v-model:show="mobileMenuOpen" placement="left" :width="280">
      <n-drawer-content title="VnPy Bridge" closable>
        <n-menu :value="$route.path" :options="menuOptions" @update:value="go" />
      </n-drawer-content>
    </n-drawer>
  </n-layout>
</template>

<script setup lang="ts">
import { computed, h, onMounted, ref } from 'vue'
import { NIcon } from 'naive-ui'
import {
  AccountBookOutlined,
  AreaChartOutlined,
  BulbOutlined,
  DashboardOutlined,
  DatabaseOutlined,
  DesktopOutlined,
  FileTextOutlined,
  LineChartOutlined,
  MenuOutlined,
  OrderedListOutlined,
  SecurityScanOutlined,
  SettingOutlined,
  SwapOutlined
} from '@vicons/antd'
import { useRouter } from 'vue-router'
import StatusBadge from './common/StatusBadge.vue'
import { useAuthStore } from '../stores/auth'
import { useTerminalStore } from '../stores/terminal'
import { useThemeStore, type ThemeMode } from '../stores/theme'
import { eventSocket } from '../ws/events'
import { useMediaQuery } from '../composables/useMediaQuery'

const router = useRouter()
const auth = useAuthStore()
const terminal = useTerminalStore()
const theme = useThemeStore()
const isMobile = useMediaQuery('(max-width: 760px)')
const mobileMenuOpen = ref(false)

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
const themeOptions = [
  themeItem('跟随系统', 'system', DesktopOutlined),
  themeItem('亮色', 'light', BulbOutlined),
  themeItem('暗色', 'dark', SettingOutlined)
]
const themeLabel = computed(() => {
  if (theme.mode === 'light') return '亮色'
  if (theme.mode === 'dark') return '暗色'
  return '跟随系统'
})

onMounted(async () => {
  await terminal.refreshStatus().catch(() => undefined)
  await terminal.refreshSnapshots().catch(() => undefined)
  eventSocket.connect()
})

function item(label: string, key: string, icon: unknown) {
  return { label, key, icon: () => h(NIcon, null, { default: () => h(icon as never) }) }
}

function themeItem(label: string, key: ThemeMode, icon: unknown) {
  return { label, key, icon: () => h(NIcon, null, { default: () => h(icon as never) }) }
}

function go(path: string) {
  mobileMenuOpen.value = false
  router.push(path)
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
  min-height: 54px;
  display: flex;
  align-items: center;
  justify-content: space-between;
  padding: 0 16px;
  gap: 12px;
}

.topbar-main,
.topbar-status,
.topbar-actions {
  display: flex;
  align-items: center;
  gap: 10px;
}

.topbar-actions {
  flex-shrink: 0;
}

.theme-button {
  flex-shrink: 0;
}

.mobile-title {
  font-weight: 700;
  letter-spacing: 0;
}

.content {
  padding: 16px;
}

@media (max-width: 760px) {
  .topbar {
    min-height: 48px;
    padding: 6px 10px;
  }

  .topbar-status {
    margin-left: auto;
    gap: 6px;
  }

  .topbar-actions {
    gap: 6px;
  }

  .theme-button {
    width: 28px;
    min-width: 28px;
  }

  .content {
    padding: 10px;
  }
}

@media (max-width: 420px) {
  .mobile-title {
    display: none;
  }

  .topbar-status :deep(.n-tag:first-child) {
    display: none;
  }
}
</style>
