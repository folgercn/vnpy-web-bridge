# Antigravity Network MCP Server for Codex

网络版 Antigravity (Gemini/Claude) MCP 代理桥接服务，专为 Codex 等智能 Agent 设计。集成 **Antigravity-Manager** 高精度模型额度监控与 **Cockpit-Tools** 毫秒级无感热切号能力。

---

## 核心特性

1. **双工具启动自检与平滑降级（Graceful Degradation）**：
   - 服务启动时自动检测 `~/.antigravity_tools/`（Antigravity-Manager）与 `~/.antigravity_cockpit/`（Cockpit-Tools）；
   - **完全体模式（双工具均就绪）**：完整提供多账号聚合额度池（含 Gemini 3.1 Pro 5h、周全局硬顶额度）与毫秒级热切号；
   - **工具缺失时优雅降级**：若未安装或未运行相关工具，工具返回友好说明（告知功能受限与建议），**核心派单功能（`submit`、`projects`、`watch`、`status` 等）100% 始终稳定可用**。

2. **双层额度穿透（Gemini 3.1 Pro + 周全局硬顶）**：
   - 突破 Antigravity 原生仅能查询 1 个当前账号的限制；
   - 在 `list_accounts` 中穿透展示全账号池的：
     - **`gemini_3_1_pro`**：当前 5 小时滑动窗口剩余比例与恢复时间；
     - **`gemini_weekly_limit`**：**整整 7 天全局总配额硬顶剩余百分比与重置时间**；
     - **`risk_warnings`**：周额度濒临耗尽时自动输出风险警告，指导 Codex 合理分配任务。

3. **Agent 自主感知与显式调度（No Blackbox）**：
   - 不在 MCP 内部做黑盒强行切号；
   - 暴露 `list_accounts` 供 Codex 查看额度，暴露 `switch_account(email_or_id)` 供 Codex 自主切号；
   - 暴露 `account_leaderboard` 查看账号用量统计与任务分布排行榜。

4. **安全访问鉴权**：
   - 支持通过环境变量 `AGY_MCP_API_KEY` 开启 Bearer Token / URL `?api_key=` 访问鉴权。

---

## 快速启动

```bash
# 1. 默认 SSE 网络模式启动 (端口 8765)
./research_lab/agent_control/antigravity_mcp/start_server.sh

# 2. 自定义端口与安全鉴权启动
AGY_MCP_PORT=9000 AGY_MCP_API_KEY=my_secret_token ./research_lab/agent_control/antigravity_mcp/start_server.sh
```

---

## Codex MCP 配置接入

在 Codex 的 MCP 配置文件中添加：

```json
{
  "mcpServers": {
    "antigravity": {
      "url": "http://127.0.0.1:8765/sse"
    }
  }
}
```
*(若配置了 `AGY_MCP_API_KEY=xxx`，url 可设为 `http://127.0.0.1:8765/sse?api_key=xxx`)*
