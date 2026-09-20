# Agent Access Control and Provider-Neutral Router Architecture

> **Milestone 0 Contract Specification (#573)**
> 状态：**FROZEN** | 模式：`research-json-v1` SHA-256 Canonical Digest | Fail-Closed

本文档定义 SIMNOW_LAB 下 Agent 系统的访问控制（Access Control）、执行路由（Provider-Neutral Router）、不可变数据契约与安全/科学边界。为 Milestone 1（Antigravity MCP Adapter 实现）及后续阶段提供直接、可执行的指导依据。

---

## 1. 业务角色 (Role)

业务角色代表智能体在量化研究流水线中的**功能职责**，与具体执行后端（Provider）和模型（Model）彻底解耦。严禁出现 `GeminiAlphaGenerator` 或 `GPTResearcher` 等硬编码耦合。

| Role | 职责定义 | 默认权限范围 | 委派权限 (can_delegate) |
|---|---|---|---|
| `alpha_generator` | 生成/修改候选 Alpha 假设；不得执行评测或终审 | `read_research_memory`, `create_hypothesis`, `revise_hypothesis` | `False` (Worker) |
| `research_synthesizer` | 检索并综合历史研究报告、文献与结论 | `read_research_memory`, `read_result_store` | `False` (Worker) |
| `data_researcher` | 探索数据集特征、数据分布与有效性 | `read_research_memory`, `read_result_store` | `False` (Worker) |
| `code_researcher` | 检查研究工具实现、计算逻辑与因子代码 | `read_result_store` | `False` (Worker) |
| `external_researcher` | 检索外部公开文献与宏观资料 | 仅限外部公开信息，禁止内部私有仓写权限 | `False` (Worker) |

- **未知角色处理**：任何未在闭合集合注册的 role 名称均触发 `PermissionDeniedError`（Fail-Closed）。

---

## 2. 显式权限模型 (Permission)

所有操作权限必须显式声明，默认全部拒绝（Fail-Closed）：

- `read_research_memory`: 读取 ResearchMemory 中的历史假说与评测记录
- `read_result_store`: 只读访问 ResultStore 中的工件与运行状态
- `create_hypothesis`: 产出符合 `research_lab.alpha_hypothesis.v1` 契约的新假说候选
- `revise_hypothesis`: 基于前序版本修改假说，生成递增修订（rev.N）
- `request_screening`: 提议评测方法清单（仅作为计划建议，非执行授权）
- `execute_screening`: **仅限确定性引擎**（AlphaDiscoveryEngine）调用，普通 Agent 永久禁用
- `write_research_memory`: **仅限科学裁判**（Critic/Engine）写入，普通 Agent 永久禁用
- `invoke_critic`: **仅限管线编排器**触发 CriticGate 决策，普通 Agent 永久禁用
- `production_trading`: **绝对硬不变式禁令（Hard Invariant: FALSE）**
- `live_trading_authorized`: **绝对硬不变式禁令（Hard Invariant: FALSE）**

### Hard Invariant 门禁
无论任何角色、任何模型或运行时参数配置：
```text
production_trading = false
live_trading_authorized = false
```
任何显式请求或策略配置尝试引入上述两项权限，均在 `authorize()` 阶段被无条件拦截并抛出 `PermissionDeniedError`。

---

## 3. Provider-Neutral 抽象 (Provider)

Provider 为智能体执行能力的提供方（如 Antigravity MCP、OpenAI、本地推理等）。核心业务域严禁包含具体提供商 SDK 或专有概念（如 MCP tools 名、Cursor API 等）。

Provider 必须实现 `AgentProvider` 协议：
```python
class AgentProvider(Protocol):
    def describe(self) -> AgentProviderDescriptor: ...
    def availability(self, role: str, context: dict[str, Any] | None = None) -> ProviderAvailability: ...
    def submit(self, task: AgentTask, route: AgentRoute) -> AgentExecutionHandle: ...
    def status(self, handle: AgentExecutionHandle) -> str: ...
    def result(self, handle: AgentExecutionHandle) -> AgentResult: ...
    def cancel(self, handle: AgentExecutionHandle) -> bool: ...
```

---

## 4. 路由契约 (Route)

`AgentRoute` 记录将抽象 `role` 解析为具体 `provider` + `resolved_model` 的可审计决策事实：

- `route_id`: 确定性摘要 `route-{sha256[:32]}`
- `role`: 业务角色
- `provider`: 选定的后端名称
- `resolved_model`: 具体的模型版本（如 `gemini-3.8-flash-high`）
- `policy_version`: 策略版本（如 `2026-09-m0`）
- `route_reason`: 路由成因文本说明
- `usage_snapshot_ref`: 配额快照引用（若有）
- `project_binding`: 严格绑定的工作区与项目 ID
- `authorized_permissions`: 该路线承载的已授权权限列表
- `route_content_hash`: 符合 `research-json-v1` 标准的 SHA-256 载荷摘要

路由选择采用**固定优先级与可用性驱动**的纯净骨架逻辑，严禁引入 ML 评分、竞价或成本黑盒优化。

---

## 5. 任务契约与确定性身份 (Task)

`AgentTask` 代表一次自包含的研究工作任务：

- `task_id`: **确定性身份**。由核心科学业务字段（`role`, `objective`, `work_block`, `input_refs`, `project_binding`, `requested_permissions`, `authorized_permissions`, `delegation_depth`, `parent_task_ref`, `provider_policy_ref`）通过 `v2.digest` 确定性计算，绝对不依赖系统时间 `now()` 或随机 UUID。
- `delegation_depth`: 委派层级（0 为编排器，>=1 为执行 Worker）。
- `created_at`: 仅作为审计记录字段，不参与 `task_id` 生成。
- `task_content_hash`: 整个任务规范的防篡改哈希，去除 `task_content_hash` 自身后计算。

---

## 6. 结果契约与验收状态 (Result)

Provider 自报的执行成功不等于系统的业务验收成功。`AgentResult` 明确区分终端状态：

- `terminal_status`: 必须取自闭合枚举：
  - `SUCCESS`: 后端完成且格式解析无误
  - `FAILED`: 执行出错或异常终止
  - `UNCERTAIN`: 网络中断、中间断连或超时未知
  - `CANCELLED`: 用户或编排器主动撤销
  - `REJECTED_BY_ACCEPTANCE`: 输出通过技术执行，但未通过下游 Schema 或防篡改验收门禁
- `acceptance_status`: 下游业务层给出的验收判定（如 `ACCEPTED` / `REJECTED`）。
- `result_content_hash`: 结果全载荷的 canonical SHA-256 防篡改摘要。

---

## 7. 配额用量快照契约 (Usage)

`AgentUsageSnapshot` 记录调度时的提供商配额窗口状态：

- 支持多窗口：`hourly`, `daily`, `monthly`。
- **未知状态显式保留**：必须完整支持 `status="unknown"` 及 `remaining_fraction=None`。严禁将未知配额隐式假定为 0%（导致饥饿）或 100%（导致过载超限）。
- `usage_content_hash`: 配额快照的 canonical SHA-256 摘要。

---

## 8. Append-Only 审计契约 (Audit)

每次调用在生命周期各环节生成 `AgentAuditRecord`：

- 涵盖 `role`, `provider`, `resolved_model`, `task_ref`, `route_ref`, `provider_job_ref`, `project_binding`, `requested_permissions`, `authorized_permissions`, `terminal_status`, `result_ref`, `acceptance_status`。
- **Append-Only 原则**：存储后端只增不删不改，严禁使用 SQL `UPDATE` 覆盖历史记录。
- **全链防篡改核验**：通过 `validate_audit_hash(record)` 核验单条记录，通过 `AppendOnlyAuditTrail.verify_all()` 核验审计链完整性。

---

## 9. 错误分类体系 (Error Taxonomy)

系统定义 10 类标准 Provider/Control 错误代码（`ProviderErrorCode`）：

1. `PROVIDER_UNAVAILABLE`: 提供商离线、未注册或接口不可达
2. `QUOTA_UNAVAILABLE`: 配额耗尽或触发严格限流
3. `PROJECT_BINDING_FAILED`: 项目 ID 或工作区目录与绑定声明不符
4. `SUBMISSION_FAILED`: 任务向提供商提交时被拒绝
5. `EXECUTION_FAILED`: 执行过程中遭遇致命错误
6. `EXECUTION_UNCERTAIN`: 连接中断，无法断定后端任务实际完成状态
7. `CANCEL_REQUESTED`: 取消请求已发起
8. `CANCEL_CONFIRMED`: 取消操作经提供商确认生效
9. `RESULT_REJECTED_BY_ACCEPTANCE`: 结果载荷未通过下游验收门禁
10. `PERMISSION_DENIED`: 越权请求、未知角色/权限或硬不变式违背

**防污染原则**：任何 ProviderError 属于基础设施与调用层异常，严禁将其直接转化为假说的 `REJECT`、`PROMOTE`、`ADMISSION_FAILED` 或 Critic 决策。

---

## 10. No Nested Agent 规则

为杜绝无限递归委派、不可控成本放大与权限泄漏：

```text
delegation_depth = 0: Orchestrator 级别，允许调用 router 委派 worker 任务。
delegation_depth >= 1: Worker 级别，禁止再次调用 router 委派或创建子智能体。
```
任何 `delegation_depth >= 1` 的 Worker 尝试委派子任务，立即触发 `PermissionDeniedError(PERMISSION_DENIED)`。

---

## 11. 研究与交易权威边界 (Research/Trading Authority Boundary)

1. **Agent 不是 Critic**：Agent 输出仅为文本、建议或结构化候选数据，不能签发 `CriticDecision`。
2. **Agent 不是 Evidence Authority**：Evidence 必须由确定性评测管线（`ScreeningPipeline` / `run_statistical_screening`）计算得出，Agent 不能伪造证据。
3. **Agent 不是 Research Memory 科学写入者**：只有通过 Critic 终审的决策才由 Engine 写入 ResearchMemory。
4. **Agent 绝无交易权限**：SIMNOW_LAB 下，执行器仅 Windows Lab 独占，任何 Agent 均无法取得交易凭据与交易权限。

---

## 12. 后续接入指南：Antigravity MCP Adapter (Milestone 1 Preview)

在 Milestone 1 中，将实现 `research_lab/agent_control/providers/antigravity.py`：

1. 实现 `AgentProvider` 协议接口：
   - `describe()`: 声明支持 `alpha_generator` 等角色，支持 `gemini-3.8-flash-high` 等模型。
   - `availability()`: 检查 Antigravity MCP 连接状态与配额状态。
   - `submit()`: 校验 `ProjectBinding(project_id="vnpy", workspace_identity="/Users/fujun/node/vnpy")`，通过 MCP 发起任务。
   - `status()` / `result()`: 轮询/监听任务执行结果，构造 `AgentResult` 并计算 `result_content_hash`。
2. 保持完全透明：调用方仅依赖 `AgentProvider` 与 `select_agent()`，不改动任何 Alpha Discovery 核心业务逻辑。
