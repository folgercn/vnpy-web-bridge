# Astra Discovery Session Contract & Admission Gate Specification

> **Milestone A Contract Specification (#502)**
> 状态：**IMPLEMENTED / FROZEN** | 模式：`research-json-v1` SHA-256 Canonical Digest | Fail-Closed

本文档定义 SIMNOW_LAB 下 Astra Discovery Session 的准入契约、受控记忆上下文投影、以及纯确定性 N 槽位（Candidate Slot）规划模型。该规范作为 Issue #502 Milestone A 的权威技术规范与审查基准。

---

## 1. 契约架构与职责定位

Discovery Session 是 Astra 自主假说探索周期的首要安全与准入边界：
- **上游连接**：受控只读记忆视图（`ResearchMemoryView`）、访问控制凭证（`AgentPermissionScope`）以及项目精确绑定（`ProjectBinding`）。
- **下游输出**：一组纯确定性的候选槽位（`PlannedCandidateSlot`），每个槽位严格绑定一个符合 Milestone 5 规范的 `AlphaGenerationRequest`（`requested_candidate_count = 1`）与预构建的 `AgentTask`。
- **零副作用硬边界**：Session 创建与槽位规划为**纯函数式逻辑**，绝对不触发 Provider submit、不调用 Screening 执行、不调用 Critic 裁判、不向 ResearchMemory 写入任何数据，永久隔离于任何交易环境。

---

## 2. 核心数据结构与契约定义

### 2.1 DiscoverySession

不可变（`frozen=True`）、防篡改（tamper-evident）的会话信封。

```python
@dataclass(frozen=True)
class DiscoverySession:
    session_id: str                          # 确定性 ID: f"disc-session-{content_hash[:32]}"
    session_content_hash: str                # v2.digest() 规范哈希 (64 字符 hex)
    objective: str                           # 非空且 <= 2,000 字符的研究目标
    project_binding: dict[str, str]          # 精确匹配的 ProjectBinding
    authorized_scope_ref: dict[str, Any]     # 最小权限 AgentPermissionScope 引用
    memory_view_ref: dict[str, Any]          # 受控 ResearchMemoryView 凭据字典
    memory_view_id: str                      # 引用的 ResearchMemoryView ID
    memory_view_content_hash: str            # 引用的 ResearchMemoryView 哈希
    candidate_budget: int                    # 严格整数 1..10 (严格拒绝 bool/float/str)
    allowed_universe: tuple[str, ...] | str  # 允许的标的范围 (如 "all_futures", ("RB", "HC"))
    allowed_frequency: str                   # 允许的时间周期 (如 "1d", "5m")
    allowed_signal_families: tuple[str, ...] # 允许的信号族 (如 ("momentum", "mean_reversion"))
    generation_policy_version: str           # 生成策略版本 (如 "discovery_generation_policy.v1")
    created_at: str                          # 确定性时间戳
    schema_version: str                      # 契约架构版本 ("research_lab.discovery_session.v1")
```

#### 严格准入校验规则 (Fail-Closed)
1. **预算硬边界**：`candidate_budget` 必须为**严格 Python 整数**（`type(val) is int`，显式拒绝 `bool`、`float`、字符串数字 `"5"`、`None` 或集合），且必须满足 `1 <= candidate_budget <= 10`。违规无条件抛出 `DiscoverySessionBudgetError`。
2. **目标约束**：`objective` 必须为严格 `str`（禁止对非字符串进行强转或静默转换），非空且非纯空白，长度不得超过 2,000 字符。
3. **角色与最小权限**：
   - 角色必须严格为 `alpha_generator`。
   - 权限集合必须严格匹配最小权限子集：`{"read_research_memory", "create_hypothesis"}`。任何越权权限（如 `execute_screening`, `write_research_memory`, `invoke_critic`, `read_result_store`）均拒绝。
   - 委派限制：`can_delegate` 必须为 `False`，`max_delegation_depth` 必须为 `0`（严禁嵌套委派）。
   - 权限凭证完整性：`authorized_scope_ref` 必须包含合法的 `scope_content_hash`，并经 `validate_scope_hash` 验证防篡改。
4. **项目三方对齐**：Session 的 `project_binding`、`authorized_scope_ref.project_binding` 和 `memory_view_ref.project_binding` 必须三方逐字段完全一致，拒绝任何跨项目引用。
5. **受控记忆视图深度绑定 (P1-1)**：
   - `memory_view_ref` 必须包含受控视图元数据：`view_id`, `view_content_hash`, `role`, `project_binding`, `policy_version`, `source_refs`。
   - 三入口统一核验：`DiscoverySession.create`、直接 `DiscoverySession(...)` 构造、以及 `from_dict` 均深度校验记忆视图引用的一致性。
   - 防重封与跨项目攻击：任何篡改 `role`、伪造 `view_id`/`view_content_hash` 或使用异构项目视图的重封请求均会被强一致性校验拦截。
6. **自封签与重签拦截**：`session_content_hash` 与 `session_id` 必须由全量规范字典通过 SHA-256 计算得出。反序列化时如果篡改任何内容，或者伪造哈希重签越权内容，均被立即拦截。
7. **容器深度冻结**：所有嵌套映射与序列使用只读代理（`MappingProxyType`）或元组（`tuple`）深度冻结，杜绝属性就地篡改。

---

### 2.2 SessionMemoryContext

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
    nme_candidates: tuple[dict[str, Any], ...]
    promoted_summaries: tuple[dict[str, Any], ...]
    recent_rejects: tuple[dict[str, Any], ...]
    valid_entry_ids: tuple[str, ...]
```

- **空视图安全**：当 `ResearchMemoryView` 的 `total_entries == 0` 时，`is_empty=True`，正常执行 cold-start 规划。
- **截断感知**：忠实保留 `ResearchMemoryView` 的 `is_truncated` 标志。
- **引用白名单**：收集所有有效 `valid_entry_ids`，为假说生成阶段的引用合法性校验提供先验上下文。

---

### 2.3 PlannedCandidateSlot 与纯确定性槽位规划

```python
@dataclass(frozen=True)
class PlannedCandidateSlot:
    session_id: str
    session_content_hash: str
    slot_index: int                       # 0-based 索引 (0 .. budget-1)
    ordinal: int                          # 1-based 序号 (1 .. budget)
    slot_id: str                          # 稳定逻辑槽位 ID
    slot_content_hash: str                # 槽位防篡改哈希
    attempt: int                          # 尝试轮次 (从 1 开始)
    request: AlphaGenerationRequest       # Milestone 5 单假说请求
    task: AgentTask                       # 对应构建的执行任务
```

#### 2.3.1 跨对象与防混入校验 (P1-2)
`PlannedCandidateSlot` 在 `__post_init__` 中执行严格的一致性强校验：
1. **序号与索引绑定**：`ordinal` 必须严格等于 `slot_index + 1`，且位于 `1 <= ordinal <= 10`。
2. **轮次严格正整数**：`attempt` 必须为严格 Python 整数（`type(attempt) is int` 且 `attempt >= 1`，显式拒绝 `bool`、`float`、字符串或非正数）。重试规划时必须满足 `attempt > slot.attempt`。
3. **防混入与跨 Session 校验**：
   - 槽位请求的 `session_id` 必须严格匹配槽位的 `session_id`。
   - 槽位请求的 `slot_id` 必须严格匹配槽位的 `slot_id`。
   - 槽位任务的 `task.input_refs` 必须包含该槽位的 `slot_id` 及其审计内容哈希，拒绝槽位与任务间或跨会话的错位混入（如使用 `dataclasses.replace` 偷换）。
4. **M5 字段成组原子校验**：
   - `AlphaGenerationRequest` 中的 `session_id`, `slot_id`, `ordinal` 必须作为完整不可分割的组（全有或全无）提供。
   - 缺失任意一个字段均抛出 `AlphaGenerationError`。无 session 上下文的独立 M5 请求在序列化中完全不输出这些字段，保证旧版序列化字节级向后兼容。

#### 2.3.2 约束范围穿透与可审计性 (P1-3)
Session 中配置的探索约束无损穿透至下游请求与任务：
1. `allowed_universe`、`allowed_frequency`、`allowed_signal_families` 与 `generation_policy_version` 完整绑定至每个槽位的 `AlphaGenerationRequest`。
2. 约束边界显式注入到 `task.work_block` 的 Prompt 中，指导模型在受限空间内探索。
3. `task.input_refs` 中除记录受控记忆视图引用（`memory_view_id`, `view_content_hash`）外，增加包含所有探索约束与槽位元数据的规范哈希条目，实现端到端完整可审计。

---

## 3. 契约验证矩阵与测试证据

本规范在 `tests/research_lab/agent_control/test_agent_control_discovery_session.py` 中实现了完整的正反例与防篡改攻击测试套件（本模块 68 项专项测试，所属 `agent_control` 套件总计 457 项测试全部通过）：

| 校验分类 | 场景描述 | 预期行为 / 异常 |
|---|---|---|
| **正例：槽位规划** | 单候选槽位创建 (`budget=1`) | 成功创建，产出 1 个槽位，`requested_candidate_count=1` |
| **正例：边界预算** | 最大候选槽位创建 (`budget=10`) | 成功创建，产出 10 个独立槽位，各自拥有唯一定义的 `slot_id` |
| **正例：记忆投影** | 空记忆视图冷启动 (`total_entries=0`) | 成功创建，`is_empty=True`，冷启动槽位规划正常 |
| **正例：上下文映射** | 非空受控视图上下文映射 | 完整投影各分类条目并保留 `source_refs`, `source_hashes`, `evidence_refs` |
| **正例：截断传递** | 记忆截断状态传递 (`is_truncated=True`) | 忠实传递截断状态，槽位规划受控 |
| **正例：序列化** | 序列化双向无损转换 (`to_dict` / `from_dict`) | 属性 bit-for-bit 完全一致，哈希验证通过 |
| **正例：确定性** | 确定性重复规划 (Determinism) | 相同输入多次规划结果 100% 逐字段完全一致 |
| **正例：重试规划** | 槽位重试递增 (`replan_slot_attempt`) | `slot_id` 保持稳定不变，`attempt` 递增，`task_id` 正确区分 |
| **反例：预算边界** | 预算越界 (`budget` $\in \{0, 11, -1, 100\}$) | 立即抛出 `DiscoverySessionBudgetError` (Fail-Closed) |
| **反例：类型强校验** | 预算非严格整数 (`True`, `1.0`, `"5"`, `None`, `[1]`) | 立即抛出 `DiscoverySessionBudgetError` (Fail-Closed) |
| **反例：目标约束** | 空目标或纯空白目标 (`""`, `"   "`, `"\n\t"`) | 立即抛出 `DiscoverySessionError` |
| **反例：目标超长** | 目标超长 (> 2,000 字符) | 立即抛出 `DiscoverySessionError` |
| **反例：策略版本** | 未注册的策略版本 | 立即抛出 `DiscoverySessionError` |
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
| **安全：非交易隔离** | 生产与实盘交易隔离验证 | 验证全系统硬边界：永久 `production=False`, `live_trading_authorized=False` |

---

## 4. 与生产系统的硬隔离承诺

根据 `AGENTS.md` 长期硬边界：
1. **Lab 隔离**：Discovery Session 属于纯量化研究探索阶段，永久保持 `production=false`、`live_trading_authorized=false`、`countable_forward=false`、`official_forward_claimed=false`。
2. **无实盘链路**：本模块不引用任何 CTP/RPC 交易接口，不包含订单、持仓或账户修改逻辑。
3. **零外部写入**：本模块仅在内存中进行确定性计算与规划，不直接写磁盘、不修改 SQLite、不向外部模型发送请求。
