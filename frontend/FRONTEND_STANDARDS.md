# Web 前端开发规范

本目录统一采用 Vue 3、TypeScript、Pinia、Vue Router、Naive UI、Vite 与 Vitest。

## 分层

- `pages/` 和 `features/*/pages/` 只组合页面、读取路由参数，不承载 API、轮询、权限状态机。
- 稳定领域 DTO 放在 feature `types.ts` 或 `api/*.ts`；禁止用 `Record<string, unknown>` 代替已知 DTO。
- 跨页面状态使用 Pinia；可复用异步逻辑使用 composable。
- SFC 超过 300 行应优先拆分，超过 500 行必须拆分或在门禁脚本中记录例外原因。
- `Market.vue` 是现存例外；不得继续增大，后续按图表、自选管理、行情表拆分。

### SIMNOW_LAB Dashboard（#466）

- 固定目录为 `features/simnow-lab-dashboard/{api.ts,types.ts,store.ts,formatters.ts,components/,pages/SimNowLabDashboardPage.vue}`；可合并 1–2 个小组件，不得形成巨型页面。
- Page 只做布局、tab/drawer 开关；`api.ts` 只做 typed GET；`store.ts` 管加载、轮询、stale、选中 run；`formatters.ts` 管时间/数值/金额/比例/ID；图表、表格、Drawer 只收 typed props，不得请求 API 或计算 PnL/回撤。
- 页面原则 ≤220 行，业务组件 ≤260 行，store ≤300 行；超限须在 PR 说明并优先拆分，禁止压缩排版规避。
- Dashboard 只读：不得出现 apply、下单、撤单、恢复或重启按钮，不得调用 mutation API，也不得让浏览器直连 Windows RPC。

## 组件与样式

- 每个 SFC 显式 import 使用的 Naive UI 组件；`main.ts` 只安装 Provider 和全局基础设施。
- 公共组件从 `components/common/index.ts` 导出，业务组件放在对应 feature。
- 间距、圆角、页面宽度与断点使用 `styles/tokens.css`；禁止行内 `style` 和硬编码亮色背景。
- 页面优先使用 `PageHeader`、`PageSection`、`ActionBar`、`AsyncContent`、`ResponsiveDataTable`。
- hash、ID、合约和订单号使用等宽文本；长 hash 使用 `HashValue`。

### #466 固定视觉系统

- 颜色、间距、字号、圆角、阴影、控件高度、断点及 chart config 只来自 `styles/tokens.css` 与唯一集中的 Naive UI theme overrides；feature/SFC 禁止 literal hex/rgb/hsl、行内 style、私有按钮色、渐变、圆角、阴影或断点。
- 固定语义色：primary/running `#2563EB`，info `#0284C7`，success/DONE/NOOP/正 PnL `#16A34A`，warning/PARTIAL/STALE `#D97706`，error/FAILED/OFFLINE/UNKNOWN/active/负 PnL `#DC2626`，neutral/IDLE/no-data `#64748B`。状态和盈亏必须同时显示文字、符号或数值。
- 固定表面：Light `#F5F7FA/#FFFFFF/#F8FAFC/#E2E8F0/#0F172A/#64748B`，Dark `#0B1118/#111827/#172033/#263244/#E5E7EB/#94A3B8`（page/card/subtle/border/text/muted）。
- 使用 4px scale `4/8/12/16/24/32`；max-width `1600px`，桌面/移动 padding `16/10px`，section gap/card padding `16px`，card radius `8px`。标题 `20/28`、section `16/24`、正文 `14/22`、辅助 `12/18`、metric `24/32` semibold；核心数字使用 `tabular-nums`。
- 时间统一 Asia/Shanghai `YYYY-MM-DD HH:mm:ss`；金额、数量、比例右对齐并走统一 formatter；ID 默认短等宽显示、详情可复制。

### #466 布局、状态与数据展示

- 页面顺序固定：`PageHeader → stale/blocker banner → LabStatusStrip → LabMetricGrid → performance charts → 10-product portfolio → recent runs → orders/trades/incidents tabs → run drawer`；禁止改成卡片拼盘。
- 宽屏指标 4 列/图表 2 列，平板 2/1，手机全 1 列且表格横滚；只用统一断点，关键状态、目标差额、UNKNOWN、active order 不得隐藏。
- `LabStatusTag`/共享状态组件是唯一映射：RUNNING primary；DONE/NOOP/ALIGNED success；PARTIAL/STALE/DEGRADED warning；FAILED/OFFLINE/UNKNOWN error；IDLE/NO_DATA neutral。
- 表格统一 `ResponsiveDataTable`/共享 wrapper，`small`、header/row 40px、数字右对齐、默认分页 20（20/50/100），业务中文表头，长 ID 截断可复制；不得使用私有 hover、斑马或整行彩色。
- 只用已有 `lightweight-charts`：Equity 蓝线、Cumulative PnL 绿线、Drawdown 红 area/line、Daily PnL 正绿负红 histogram；桌面/移动高度 `280/220px`，统一 grid/axis/crosshair/tooltip/legend；无数据用共享 empty，禁止伪造零曲线。

## 按钮语义

- 每个 `ActionBar` 最多一个实心 `primary`；主操作位于左侧。
- 普通辅助操作使用默认、secondary 或 quaternary；“刷新状态”使用 quaternary。
- 谨慎但非破坏动作使用 warning secondary。
- 停止、撤权、删除、放弃统一使用 error；危险动作放右侧并通过 `DangerActionDialog` 二次确认。
- 同组按钮尺寸一致；表格行操作统一 small；loading 时禁止重复提交。
- Dashboard 手工刷新固定 `quaternary + small`，查看详情 `text/quaternary + small`；原则上无实心 primary。icon button `32×32`，文本按钮最小宽度 `72px`；禁止私设尺寸、色彩和圆角。

## 异步、权限和测试

- loading/error/empty 使用 `AsyncContent`；长期 blocker 留在页面。
- 轮询统一使用 `usePolling`：页面隐藏/卸载停止、请求不并发、失败指数退避。
- 前端权限仅控制展示和提示，后端必须独立校验。
- 提交前运行 `npm run check`；关键页面覆盖桌面、移动端和暗色模式测试。
- Dashboard 使用统一 `usePolling`/store：默认 10 秒、不可并发、隐藏/卸载停止、失败指数退避上限 60 秒；失败保留成功数据并显示 `STALE + last_success_at`，长期错误留 banner，skeleton 保持布局高度。
- run detail 用右侧 Drawer（桌面 720px、最大 80vw；移动 100%），不得嵌套 Drawer/Modal；键盘可开关，状态不得只依赖颜色。
- 扩展 `scripts/verify-frontend-contracts.mjs`，仅检查 #466 feature：禁 inline style/literal color、行数、Page 直连 API、已知 DTO `Record<string, unknown>`、mutation API/按钮文案。PR 附真实 `1440×900` light/dark 和 `390×844` mobile 截图；违反视觉或分层按 P1。
