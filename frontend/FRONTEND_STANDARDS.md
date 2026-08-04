# Web 前端开发规范

本目录统一采用 Vue 3、TypeScript、Pinia、Vue Router、Naive UI、Vite 与 Vitest。

## 分层

- `pages/` 和 `features/*/pages/` 只组合页面、读取路由参数，不承载 API、轮询、权限状态机。
- 稳定领域 DTO 放在 feature `types.ts` 或 `api/*.ts`；禁止用 `Record<string, unknown>` 代替已知 DTO。
- 跨页面状态使用 Pinia；可复用异步逻辑使用 composable。
- SFC 超过 300 行应优先拆分，超过 500 行必须拆分或在门禁脚本中记录例外原因。
- `Market.vue` 是现存例外；不得继续增大，后续按图表、自选管理、行情表拆分。

## 组件与样式

- 每个 SFC 显式 import 使用的 Naive UI 组件；`main.ts` 只安装 Provider 和全局基础设施。
- 公共组件从 `components/common/index.ts` 导出，业务组件放在对应 feature。
- 间距、圆角、页面宽度与断点使用 `styles/tokens.css`；禁止行内 `style` 和硬编码亮色背景。
- 页面优先使用 `PageHeader`、`PageSection`、`ActionBar`、`AsyncContent`、`ResponsiveDataTable`。
- hash、ID、合约和订单号使用等宽文本；长 hash 使用 `HashValue`。

## 按钮语义

- 每个 `ActionBar` 最多一个实心 `primary`；主操作位于左侧。
- 普通辅助操作使用默认、secondary 或 quaternary；“刷新状态”使用 quaternary。
- 谨慎但非破坏动作使用 warning secondary。
- 停止、撤权、删除、放弃统一使用 error；危险动作放右侧并通过 `DangerActionDialog` 二次确认。
- 同组按钮尺寸一致；表格行操作统一 small；loading 时禁止重复提交。

## 异步、权限和测试

- loading/error/empty 使用 `AsyncContent`；长期 blocker 留在页面。
- 轮询统一使用 `usePolling`：页面隐藏/卸载停止、请求不并发、失败指数退避。
- 前端权限仅控制展示和提示，后端必须独立校验。
- 提交前运行 `npm run check`；关键页面覆盖桌面、移动端和暗色模式测试。
