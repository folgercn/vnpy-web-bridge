import { createRouter, createWebHistory, type RouteRecordRaw } from 'vue-router'
import { useAuthStore } from '../stores/auth'
import AppLayout from '../components/AppLayout.vue'
import Login from '../pages/Login.vue'
import Dashboard from '../pages/Dashboard.vue'
import Market from '../pages/Market.vue'
import Trading from '../pages/Trading.vue'
import Positions from '../pages/Positions.vue'
import Orders from '../pages/Orders.vue'
import Trades from '../pages/Trades.vue'
import Account from '../pages/Account.vue'
import Strategies from '../pages/Strategies.vue'
import Logs from '../pages/Logs.vue'
import DataManagement from '../pages/DataManagement.vue'

const routes: RouteRecordRaw[] = [
  { path: '/login', component: Login },
  {
    path: '/',
    component: AppLayout,
    meta: { requiresAuth: true },
    children: [
      { path: '', redirect: '/dashboard' },
      { path: 'dashboard', component: Dashboard, meta: { title: 'Dashboard' } },
      { path: 'market', component: Market, meta: { title: '行情' } },
      { path: 'trading', component: Trading, meta: { title: '交易' } },
      { path: 'positions', component: Positions, meta: { title: '持仓' } },
      { path: 'orders', component: Orders, meta: { title: '委托' } },
      { path: 'trades', component: Trades, meta: { title: '成交' } },
      { path: 'account', component: Account, meta: { title: '资金' } },
      { path: 'strategies', component: Strategies, meta: { title: '策略' } },
      { path: 'data', component: DataManagement, meta: { title: '数据管理' } },
      { path: 'logs', component: Logs, meta: { title: '日志' } }
    ]
  }
]

export const router = createRouter({
  history: createWebHistory(),
  routes
})

router.beforeEach(async (to) => {
  const auth = useAuthStore()
  if (auth.token && !auth.user) await auth.restore()
  if (to.meta.requiresAuth && !auth.isLoggedIn) return '/login'
  if (to.path === '/login' && auth.isLoggedIn) return '/dashboard'
})
