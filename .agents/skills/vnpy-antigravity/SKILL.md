---
name: vnpy-antigravity
description: 在 vnpy 仓库通过 Antigravity MCP 委派工作时使用，固定校验桌面 vnpy 项目归属，避免会话进入 gzgs 或其他项目。
---

# vnpy 的 Antigravity 项目绑定

调用流程复用全局 [antigravity-delegate](/Users/fujun/.codex/skills/antigravity-delegate/SKILL.md)，本 Skill 补充本仓库的固定项目约束。

## 固定目标

- Antigravity 项目名称：`vnpy`
- 项目 ID：`a173ba08-8e0c-4c26-8604-0d462da55529`
- 已登记目录：`/Users/fujun/node/vnpy`

提交前调用 `projects(cwd="/Users/fujun/node/vnpy")`，确认名称、ID、目录均与上述目标一致。当前 MCP 的 `submit` 按 `cwd` 解析项目，不接受 `project_id` 参数；不要虚构参数，也不要仅在提示词中写项目名称代替接口绑定。

实际任务使用本次授权的工作目录。若用户指定另一个 worktree，应查询该实际目录的 `projects(cwd=...)`，同时确认后端执行环境确实是该 worktree 且仍属于上述 vnpy 项目。现有入口未提供独立 worktree 环境选择；不能满足时停止委派并说明，不得悄悄改用主目录或 gzgs 项目。

项目不存在、匹配歧义、ID 改变或返回目录不符时，不提交任务；报告实际映射，待项目绑定修复。不得自动创建替代项目、选择当前界面项目或迁移旧会话。

## 会话与验收

- 每个完整 Issue/工作块使用一个 `vnpy-...` 任务 ID；只有同一目标、目录和项目绑定一致才能续用。
- 旧会话位于 gzgs 或没有已验证绑定时，不直接续用。先核对旧任务结果与执行状态；若旧任务仍在执行、已取消或结果不确定，必须检查桌面状态和实际变更，确认执行已结束并查清已发生的效果后，才可建立 vnpy 新会话携带必要交接。不得用新任务 ID 绕过不确定结果或重复执行。
- 检查任务事件/最终结果的 `project` 信息；协议完成不等于业务验收通过。
- 正常等待优先单次 `watch`；不可用时最多每 3–5 分钟检查一次状态，不以反复读取事件分页代替等待。
- 生产、交易、提交、推送及发布权限仍由本次用户授权与仓库 AGENTS 决定；项目绑定不扩大授权。

## 等待中断与错误恢复

- watch 断线只结束订阅：保留相同 job_id，从最后完整收到的通知 cursor 续读；没有收到 cursor 就从 0 重放，不能重新提交或用新 task_id 绕过不确定状态。
- 历史错误不等于当前阻塞。先读新状态及后续输出；`recovery.error_history` 中 `exact_retry_succeeded` 必须关联同命令、同 cwd、同 shell 的后续 DONE/exit 0。其他命令成功不能证明旧错误恢复，重试成功也不证明交付验收通过。
- 正常执行保留单次 watch；不可用时每 180–300 秒检查状态，事件分页仅用于定向取证。宿主超时需大于 watch 最大 3600 秒；磁盘改为 3660 秒不代表已运行连接加载，不能为此重启共享 Antigravity 或干扰其他任务。

- 后台更新优先只改业务模块 `agy_service.py`、`agy_desktop.py`、`agy_account.py`；稳定 MCP 外壳、工具参数和宿主配置尽量不改。新外壳首次加载后，每次调用读取最新业务代码，已运行任务按原代码完成。`status.runtime.business_reload=per_call` 可确认当前连接已使用此架构；只有外壳/工具协议/宿主配置变更才需要另行重载。
