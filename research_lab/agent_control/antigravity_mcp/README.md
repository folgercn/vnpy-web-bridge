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

4. **双通信模式（网络 SSE + 本地 Unix Domain Socket）**：
   - **网络模式 (Network SSE)**：通过 TCP HTTP/SSE（默认 `127.0.0.1:8765/sse`）对外服务；
   - **本地 Socket 模式 (Local UDS)**：通过本机 Unix Domain Socket（默认 `data/antigravity_mcp.sock`）进行零端口冲突、低开销通信；
   - **安全策略**：本地 Socket 走操作系统文件权限隔离，**默认免 Token（开箱即用）**；网络模式支持 `AGY_MCP_API_KEY` 开启 Bearer Token / `?api_key=` 校验。

5. **实时传输状态与可观测性（Model-visible Progress）**：
   - **`watch` 60 秒分段活动快照**：每 60 秒返回一次结构化 `progress_update`，携带包含模型轮数（`model_rounds`）、文件读取数（`file_reads`）、编辑步骤（`observed_edit_steps`）与最近活动秒数的 `activity` 快照；
   - **双通道流式推送**：基于 MCP Logging (`send_log_message`) 推送底层 step 详情，基于 MCP Progress (`report_progress`) 推送状态机跃迁；
   - **`status(job_id)` 会话就绪态诊断**：穿透 Desktop Trajectory 实时计算未结束步骤（`unfinished_steps`），返回确定性的 `readiness: 'ready' | 'busy' | 'unknown'` 与 `can_continue` 指引。

---

## 标准工作流与工具接口

| 工具名称 | 核心用途 | 调用时机与输入规范 |
|---|---|---|
| `account_usage` | 查询当前账号实时配额与周全局额度 | 派单前或周期性只读巡检；免调模型。 |
| `list_accounts` | 穿透多账号聚合额度池 | 额度紧缺时查询全账号状态以供决策。 |
| `switch_account` | 官方安全重启切号 | 传入目标邮箱或 ID，安全重启 `/Applications/Antigravity.app` 使新凭据生效。 |
| `projects` | 目录与项目唯一绑定 | 传入 `cwd="/path/to/repo"`，解析出绑定的项目。 |
| `submit` | 提交工作块任务 | 传入 `task_id`、`request_id`、`cwd`、`prompt`，立即返回 `job_id`。 |
| `watch` | 实时观察任务进度 | 传入 `job_id` 与 `cursor`。每 60s 返回一次 `activity` 快照，收到后按 `resume.cursor` 续订。 |
| `status` | 会话就绪诊断与排队查看 | 无参看全局队列；传入 `job_id` 诊断该任务会话是否 `can_continue`。 |
| `events` | 显式原始事件读取 | 传入 `cursor`，按字节游标回放未处理的原始流式事件。 |
| `result` | 终态结果分页读取 | 任务完成后传入 `offset` 分页读取成果，含 `efficiency` 与 `recovery` 证据。 |
| `cancel` | 取消任务请求 | 仅取消本 bridge 拥有的 job，绝不杀底层桌面共享应用。 |

---

## 快速启动

```bash
# 1. 网络模式启动 (默认 SSE, 端口 8765)
./research_lab/agent_control/antigravity_mcp/start_server.sh

# 2. 网络模式 (自定义端口与 Token 鉴权)
AGY_MCP_PORT=9000 AGY_MCP_API_KEY=my_secret_token ./research_lab/agent_control/antigravity_mcp/start_server.sh

# 3. 本地 Socket 模式启动 (默认免 Token, 生成 data/antigravity_mcp.sock)
./research_lab/agent_control/antigravity_mcp/start_server.sh --transport socket

# 4. 本地 Socket 模式 (自定义 socket 路径)
./research_lab/agent_control/antigravity_mcp/start_server.sh --transport socket --socket /path/to/custom.sock
```

---

## MCP 配置接入

### 方式一：网络模式接入 (TCP SSE)
```json
{
  "mcpServers": {
    "antigravity": {
      "url": "http://127.0.0.1:8765/sse"
    }
  }
}
```
*(若配置了 `AGY_MCP_API_KEY=xxx`，url 设为 `http://127.0.0.1:8765/sse?api_key=xxx`)*

### 方式二：本地 Socket 模式接入 (UDS)
支持通过 Unix Domain Socket 客户端或代理直连：
- Socket 路径：`research_lab/agent_control/antigravity_mcp/data/antigravity_mcp.sock`
- 免 Token 开箱即用。
