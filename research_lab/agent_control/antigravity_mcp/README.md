# Antigravity Network MCP Server

网络版 Antigravity (Gemini/Claude) MCP 代理桥接服务，专为智能 Agent 设计。基于 **Antigravity-Manager** 官方本地服务实现高精度模型额度监控与安全切号（通过关闭旧进程并官方拉起 `/Applications/Antigravity.app` 重启生效）。

---

## 核心特性

1. **单源工具自检与平滑降级（Graceful Degradation）**：
   - 自动检测并对接本地常驻运行的 Antigravity-Manager（端口 8045）；
   - **集成管理模式**：完整提供多账号聚合额度池（含 Gemini 3.1 Pro 5h、周全局硬顶额度）与官方安全切号；
   - **工具缺失时优雅降级**：若未运行 Antigravity-Manager，自动降级为单账号原生模式，**核心派单功能（`submit`、`projects`、`watch`、`status` 等）100% 始终稳定可用**。

2. **多账号额度穿透（Gemini 3.1 Pro + 周全局硬顶）**：
   - 突破原生仅能查询 1 个当前账号的限制；
   - 在 `list_accounts` 与 `account_usage` 中穿透展示全账号池的：
     - **`gemini_5h_fraction`**：当前 5 小时滑动窗口剩余比例与恢复时间；
     - **`gemini_weekly_fraction`**：**整整 7 天全局总配额硬顶剩余百分比与重置时间**；
     - 详细模型（29+）配额百分比与重置时间。

3. **Agent 自主感知与显式安全调度（No Blackbox）**：
   - 不在 MCP 内部做黑盒数据库热注入，采用 Antigravity-Manager 官方认证与应用重启机制；
   - 暴露 `list_accounts` 供 Agent 查看额度，暴露 `switch_account(email_or_id)` 供 Agent 自主安全切号；
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
