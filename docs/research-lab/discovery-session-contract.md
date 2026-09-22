# Astra Discovery Session Contract & Admission Gate Specification

> **Milestone A Contract Specification (#502)**
> 状态：**Milestone A 实现待付哥 Stage1 复核** | 模式：`research-json-v1` SHA-256 Canonical Digest | Fail-Closed

本文档定义 Research Lab 下 Astra Discovery Session 的准入契约、受控记忆上下文投影、以及纯确定性 N 槽位（Candidate Slot）规划模型。该文档作为 Issue #502 Milestone A 的技术规范说明。

---

## 1. 契约架构与职责定位

Discovery Session 是 Astra 自主假说探索周期的首要安全与准入边界：
- **上游连接**：受控只读记忆视图（`ResearchMemoryView`）、访问控制凭证（`AgentPermissionScope`）以及项目精确绑定（`ProjectBinding`）。
- **下游输出**：一组纯确定性的候选槽位（`PlannedCandidateSlot`），每个槽位严格绑定一个符合 Milestone 5 规范的 `AlphaGenerationRequest`（`requested_candidate_count = 1`）与预构建的 `AgentTask`。
- **零副作用硬边界**：Session 创建与槽位规划为**纯函数式逻辑**，不触发 Provider submit、不调用 Screening 执行、不调用 Critic 裁判、不向 ResearchMemory 写入任何数据，永久隔离于任何交易环境。

### 1.1 可信边界与职责划分
- **受控上游假定**：调用方须从既有受控 Memory 入口（如 Milestone 4 授权查询入口）取得 `ResearchMemoryView` 真实实例。
- **快照摘要职责**：本模块计算的完整 `snapshot_hash`（由视图排除易变时钟 `generated_at` 后的全量字段规范序列化计算）用于会话/槽位与该视图的强绑定及防内容替换，不重新计算原 M4 query/policy hash。
- **不自证原始真实性**：本模块不自证原始 Memory 底层存储的真实性，亦不替代底层存储系统的 Access Control；准入校验聚焦于当前 Session 对传入视图与权限凭据的规范性及约束一致性核验。

---

## 2. 核心数据结构与契约定义

### 2.1 DiscoverySession

不可变（`frozen=True`）、防篡改（tamper-evident）的会话信封。

```python
@dataclass(frozen=True)
class DiscoverySession:
    session_id: str                          # 确定性 ID: f"disc-session-{content_hash[:32]}"
    session_content_hash: str                # v2.digest() 规范哈希 (64 字符 hex, 排除 created_at)
    objective: str                           # 非空且 <= 2,000 字符的研究目标
    project_binding: dict[str, str]          # 精确匹配的 ProjectBinding
    authorized_scope_ref: dict[str, Any]     # 最小权限 AgentPermissionScope 引用
    memory_view_ref: dict[str, Any]          # 受控 ResearchMemoryView 凭据字典
    memory_view_id: str                      # 引用的 ResearchMemoryView ID
    memory_view_content_hash: str            # 引用的 ResearchMemoryView 顶层哈希
    memory_view_snapshot_hash: str           # 引用的 ResearchMemoryView 全量受控快照摘要 (排除 generated_at)
    candidate_budget: int                    # 严格整数 1..10 (严格拒绝 bool/float/str)
    allowed_universe: tuple[str, ...] | str  # 允许的标的范围 (如 "all_futures", ("RB", "HC"))
    allowed_frequency: str                   # 允许的时间周期 (如 "1d", "5m")
    allowed_signal_families: tuple[str, ...] # 允许的信号族 (如 ("momentum", "mean_reversion"))
    generation_policy_version: str           # 生成策略版本 (支持 "discovery_generation_policy.v1" 与 "alpha_generator_prompt.v1")
    created_at: str                          # 审计时间戳 (默认固定值是可重现占位，不参与语义 identity；调用方可显式传入真实审计时间)
    schema_version: str                      # 契约架构版本 ("research_lab.discovery_session.v1")
    memory_view: InitVar[ResearchMemoryView] # 必需受控记忆视图上下文 (防伪造、重签与内容替换)
```

#### 2.1.1 序列化表示 (`to_dict`)
`DiscoverySession.to_dict()` 输出实际序列化的字典表示（`memory_view: InitVar` 仅作为构造与校验上下文，不直接输出在序列化字典中）：
- **基础与审计字段**：`session_id`, `session_content_hash`, `schema_version`, `created_at`
- **探索约束字段**：`objective`, `project_binding`, `candidate_budget`, `allowed_universe`, `allowed_frequency`, `allowed_signal_families`, `generation_policy_version`
- **凭据与受控记忆字段**：`authorized_scope_ref`, `memory_view_ref`, `memory_view_id`, `memory_view_content_hash`, `memory_view_snapshot_hash`

#### 2.1.2 严格准入校验规则 (Fail-Closed)
1. **预算硬边界**：`candidate_budget` 必须为**严格 Python 整数**（`type(val) is int`，显式拒绝 `bool`、`float`、字符串数字 `"5"`、`None` 或集合），且必须满足 `1 <= candidate_budget <= 10`。违规无条件抛出 `DiscoverySessionBudgetError`。
2. **目标约束**：`objective` 必须为严格 `str`（禁止对非字符串进行强转或静默转换），非空且非纯空白，长度不得超过 2,000 字符。
3. **角色与最小权限 Access Control**：
   - 必须通过 `AgentPermissionScope` 真实反序列化与语义校验，强校验 `is_authorized is True`，并限制 `policy_version` 必须处于白名单内。
   - 角色必须严格为 `alpha_generator`。
   - 权限集合必须严格匹配最小权限子集：`{"read_research_memory", "create_hypothesis"}`。任何越权权限（如 `execute_screening`, `write_research_memory`, `invoke_critic`, `read_result_store`）均拒绝。
   - 委派限制：`can_delegate` 必须为 `False`，`max_delegation_depth` 必须为 `0`（严禁嵌套委派）。
   - 权限凭证完整性：`authorized_scope_ref` 必须包含合法的 `scope_content_hash`，并经 `validate_scope_hash` 验证防篡改。
4. **项目三方对齐**：Session 的 `project_binding`、`authorized_scope_ref.project_binding` 和 `memory_view_ref.project_binding` 必须三方逐字段完全一致，拒绝任何跨项目引用。
5. **受控记忆视图深度绑定与全量快照摘要**：
   - `memory_view_ref` 必须包含受控视图元数据：`view_id`, `view_content_hash`, `snapshot_hash`, `role`, `project_binding`, `policy_version`, `source_refs`。
   - 必需真实上下文：`DiscoverySession.create`、直接 `DiscoverySession(...)` 构造、以及 `from_dict` 均强制要求传入真实的 `ResearchMemoryView` 实例，杜绝脱离受控记忆实例直接反序列化或伪造快照。
   - 全量快照一致性：校验 `memory_view_snapshot_hash`（由视图去除 `generated_at` 后全字段规范计算），有效防范伪造 `view_id`/`content_hash` 重签、内容替换或跨会话替换。
   - 槽位规划时同步执行 `validate_session_memory_view` 全量核验。
6. **自封签与输入规范化稳定性**：
   - `session_content_hash` 涵盖所有语义定义与约束字段；`created_at` 仅作为审计时间戳（默认固定值为可重现占位，调用方可显式传入真实审计时间，但不参与 Session 语义 identity）。
   - 统一输入规范化：`objective` 与 `allowed_frequency` 自动 strip 空白；`allowed_universe` 与 `allowed_signal_families` 元素自动 strip 空白并按字典序排序（`tuple(sorted(...))`）规范化存储与序列化。直接构造、`create()` 以及 `from_dict()` 均执行相同规范化，保证相同语义输入（无论元素顺序或空格差异，或未重封反序列化重排）均获得完全相同的 `session_id`、存储、序列化结果与下游 Prompt/Task，消除身份歧义与去重失效。
7. **容器深度冻结**：所有嵌套映射与序列使用只读代理（`MappingProxyType`）或元组（`tuple`）深度冻结，杜绝属性就地篡改。
8. **生成策略版本白名单**：`generation_policy_version` 必须处于统一支持的策略集合（`{"discovery_generation_policy.v1", "alpha_generator_prompt.v1"}`），与下游 Milestone 5 单候选请求支持策略保持一致，拒绝任何未知或未注册策略（如 `discovery_session_policy.v1`）。

---

## 2.2 SessionMemoryContext

从只读 `ResearchMemoryView` 中提取的安全投影上下文，供槽位规划使用。

```python
@dataclass(frozen=True)
class SessionMemoryContext:
    view_id: str
    view_content_hash: str
    total_entries: int
    is_empty: bool
    is_truncated: bool
    research_gaps: tuple[dict[str, Any], ...]
    nme_backlog: tuple[dict[str, Any], ...]
    failed_approaches: tuple[dict[str, Any], ...]
    recent_rejects: tuple[dict[str, Any], ...]
    promoted_summaries: tuple[dict[str, Any], ...]
    valid_entry_ids: tuple[str, ...]
    view_source_refs: tuple[str, ...]
    schema_version: str = "research_lab.session_memory_context.v1"
```

- **投影条目字段**：提取到各分类元组中的字典包含实际字段：`entry_id`, `hypothesis_id`, `decision`, `summary`, `source_refs`, `source_hashes`, `evidence_refs`。
- **空视图安全**：当 `ResearchMemoryView` 的 `total_entries == 0` 时，`is_empty=True`，正常执行 cold-start 规划。
- **截断感知**：忠实保留 `ResearchMemoryView` 的 `is_truncated` 标志。
- **引用白名单**：收集所有有效 `valid_entry_ids`，为假说生成阶段的引用合法性校验提供先验上下文。

---

## 2.3 PlannedCandidateSlot 与纯确定性槽位规划

```python
@dataclass(frozen=True)
class PlannedCandidateSlot:
    session_id: str
    session_content_hash: str
    slot_index: int                       # 0-based 索引 (0 .. budget-1)
    ordinal: int                          # 1-based 序号 (1 .. budget)
    slot_id: str                          # 稳定逻辑槽位 ID
    slot_content_hash: str                # 槽位防篡改哈希
    attempt: int                          # 尝试轮次 (从 1 开始严格正整数)
    request: AlphaGenerationRequest       # Milestone 5 单假说请求
    task: AgentTask                       # 对应构建的执行任务
    session: DiscoverySession             # 真实持有且受控校验的 Session 上下文
    memory_view: ResearchMemoryView       # 必需绑定的真实受控 ResearchMemoryView 实例
```

#### 2.3.1 序列化表示 (`to_dict`)
`PlannedCandidateSlot.to_dict()` 输出实际序列化字典（`session` 与 `memory_view` 作为运行时核验上下文，不冗余输出到序列化字典中）：
- 槽位元数据：`slot_id`, `slot_index`, `ordinal`, `attempt`, `slot_content_hash`
- 会话绑定：`session_id`, `session_content_hash`
- 下游关联：`request` (`dict`), `task_id` (`str`)

#### 2.3.2 跨对象与完整重建比对校验
`PlannedCandidateSlot` 在 `__post_init__` 中执行严格的一致性强校验：
1. **真实上下文绑定**：槽位必须同时持有受控的 `session: DiscoverySession` 与 `memory_view: ResearchMemoryView`，并调用 `validate_session_memory_view` 验证两者强一致；同时校验 `slot.session_id == session.session_id` 与 `slot.session_content_hash == session.session_content_hash`。
2. **序号与预算硬约束**：`ordinal` 必须严格等于 `slot_index + 1`，且必须满足 `1 <= ordinal <= session.candidate_budget`（严禁槽位序号超出当前会话预算）。
3. **轮次严格正整数**：`attempt` 必须为严格 Python 整数（`type(attempt) is int` 且 `attempt >= 1`，显式拒绝 `bool`、`float`、字符串或非正数）。重试规划时必须满足 `attempt > slot.attempt`。
4. **完整 Expected Request 映射重建与比对**：
   - 使用绑定的 `session`、`memory_view` 与槽位参数纯函数式重建 `expected_request`。
   - 对比 `self.request.to_dict()` 与 `expected_request.to_dict()` 规范全量字典，包括 `objective`, `authorized_scope_ref`, `project_binding`, `allowed_universe`, `allowed_frequency`, `allowed_signal_families`, `generation_policy_version`, `memory_view_id`, `memory_view_content_hash`, `session_id`, `slot_id`, `ordinal`, `attempt`。
   - 拦截部分字段遗漏与使用未授权请求重封替换。
5. **完整 Expected Task 重建与比对**：
   - 使用 `create_alpha_generation_task(expected_request, memory_view, created_at=task.created_at)` 重建预期的全量任务。
   - 对比 `self.task.to_dict()` 与 `expected_task.to_dict()` 规范全量字典，深度核验 `work_block`, `role`, `requested_permissions`, `authorized_permissions`, `objective`, `input_refs` (slot/memory audit hashes), `provider_policy_ref`, `project_binding`, `created_by`。
   - 拦截仅修改 `work_block` 或任务内部字段的伪造替换。
6. **就地篡改防护（Deep-Freeze）**：
   - `AlphaGenerationRequest` 的 `project_binding` 与 `authorized_scope_ref` 在构造时深度冻结（`MappingProxyType`），杜绝槽位构造后通过 `x.request.project_binding[...]` 进行就地静默篡改。
   - `to_dict()` 统一解冻返回可变字典副本，完全保留历史 M5 序列化行为。

#### 2.3.3 约束范围穿透与可审计性
Session 中配置的探索约束无损穿透至下游请求与任务：
1. `allowed_universe`、`allowed_frequency`、`allowed_signal_families` 与 `generation_policy_version` 完整绑定至每个槽位的 `AlphaGenerationRequest`。
2. 约束边界显式注入到 `task.work_block` 的 Prompt 中，指导模型在受限空间内探索。
3. `task.input_refs` 中除记录受控记忆视图引用（`memory_view_id`, `view_content_hash`）外，增加包含所有探索约束与槽位元数据的规范哈希条目，实现端到端完整可审计。

---

## 3. 契约验证矩阵与测试证据

本规范在 `tests/research_lab/agent_control/test_agent_control_discovery_session.py` 中实现了正反例、防篡改校验与无副作用 Spy 测试套件（本模块 91 项专项测试，结合 Milestone 5 79 项与 Milestone 4 45 项通过/1 项跳过，相关模块总计 215 项通过、1 项跳过）：

| 校验分类 | 场景描述 | 预期行为 / 异常 |
|---|---|---|
| **正例：槽位规划** | 单候选槽位创建 (`budget=1`) | 成功创建，产出 1 个槽位，`requested_candidate_count=1` |
| **正例：边界预算** | 最大候选槽位创建 (`budget=10`) | 成功创建，产出 10 个独立槽位，各自拥有唯一定义的 `slot_id` |
| **正例：记忆投影** | 空记忆视图冷启动 (`total_entries=0`) | 成功创建，`is_empty=True`，冷启动槽位规划正常 |
| **正例：上下文映射** | 非空受控视图上下文映射 | 完整投影各分类条目并保留 `source_refs`, `source_hashes`, `evidence_refs` |
| **正例：截断传递** | 记忆截断状态传递 (`is_truncated=True`) | 忠实传递截断状态，槽位规划受控 |
| **正例：序列化** | 序列化双向无损转换 (`to_dict` / `from_dict`) | 属性 bit-for-bit 完全一致，哈希验证通过 |
| **正例：确定性** | 确定性重复规划 (Determinism) | 相同输入多次规划结果逐字段一致 |
| **正例：重试规划** | 槽位重试递增 (`replan_slot_attempt`) | `slot_id` 保持稳定不变，`attempt` 递增，`task_id` 正确区分 |
| **正例：策略准入** | 支持策略全链路准入 (`discovery_generation_policy.v1`, `alpha_generator_prompt.v1`) | 三入口（create, direct, from_dict）顺利准入并规划出对应策略槽位任务 |
| **正例：规范化稳定性** | universe/families 乱序、元素空格及未重封 from_dict 重排 | 规范化存储，产生一致 session_id、request 与 task |
| **反例：预算边界** | 预算越界 (`budget` $\in \{0, 11, -1, 100\}$) | 立即抛出 `DiscoverySessionBudgetError` (Fail-Closed) |
| **反例：类型强校验** | 预算非严格整数 (`True`, `1.0`, `"5"`, `None`, `[1]`) | 立即抛出 `DiscoverySessionBudgetError` (Fail-Closed) |
| **反例：目标约束** | 空目标或纯空白目标 (`""`, `"   "`, `"\n\t"`) | 立即抛出 `DiscoverySessionError` |
| **反例：目标超长** | 目标超长 (> 2,000 字符) | 立即抛出 `DiscoverySessionError` |
| **反例：策略白名单** | 未注册策略 (如 `discovery_session_policy.v1`, `unknown.v99`) | 在 create、直接构造、from_dict 三入口均立即拒绝 (Fail-Closed) |
| **反例：角色校验** | 非 `alpha_generator` 角色 (如 `data_researcher`) | 立即抛出 `PermissionDeniedError` |
| **反例：权限缺失** | 缺失必要权限 (如缺少 `create_hypothesis`) | 立即抛出 `PermissionDeniedError` |
| **反例：越权拦截** | 包含越权权限 (如包含 `execute_screening`) | 立即抛出 `PermissionDeniedError` |
| **反例：委派防御** | 尝试嵌套委派 (`can_delegate=True` 或 `max_delegation_depth>0`) | 立即抛出 `PermissionDeniedError` |
| **反例：项目隔离** | ProjectBinding 跨项目不一致 | 立即抛出 `ProjectBindingError` |
| **反例：记忆篡改** | 记忆视图哈希被篡改或伪造 ID | 立即抛出 `TamperDetectionError` 或 `DiscoverySessionError` |
| **反例：重封攻击** | 篡改 `memory_view_ref` 角色或项目重新封包 | 立即抛出 `DiscoverySessionError` 或 `ProjectBindingError` |
| **反例：槽位混入** | 槽位与任务错位替换或跨 Session 槽位混入 | 立即抛出 `DiscoverySessionError` 或 `TamperDetectionError` |
| **反例：重试轮次** | 槽位尝试轮次为 `bool`、非正数或非递增 | 立即抛出 `DiscoverySessionError` |
| **反例：分组字段** | M5 session 字段部分缺失 (非成组提供) | 立即抛出 `AlphaGenerationError` |
| **反例：未知字段** | 反序列化载荷包含未知未知字段 | 立即抛出 `DiscoverySessionError` |
| **安全：零副作用** | 显式 Mock/Spy 验证各核心外部调用点 | 拦截断言：Provider submit=0, Screening execute=0, Critic invoke=0, Memory write=0 |
| **安全：非交易隔离** | 研究环境与实盘交易隔离验证 | 验证当前模块硬边界：永久 `production=False`, `live_trading_authorized=False` |

---

## 4. 与生产交易环境的硬隔离

根据 `AGENTS.md` 长期硬边界：
1. **模块归属与环境隔离**：Discovery Session 属于 Research Lab 自主假说探索周期，永久保持 `production=false`、`live_trading_authorized=false`、`countable_forward=false`、`official_forward_claimed=false`。本模块不是 SIMNOW_LAB 交易执行链路，本契约亦非生产系统全量验收。
2. **无实盘链路**：本模块不引用任何 CTP/RPC 交易接口，不包含订单、持仓或账户修改逻辑。
3. **零外部写入**：本模块在内存中进行确定性计算与规划，不直接写磁盘、不修改 SQLite、不向外部模型发送请求。
