# Project Agent Notes

## 0. 基本沟通规则

- 称呼用户为“付哥”。
- 回答保持简洁、直接，优先给结论和下一步。
- 如果提交或更新 PR，必须同步在对应 PR 添加一条有价值的评论。
- GitHub 评论只记录关键 checkpoint，不记录每一个 shell command。
- 不要为了“显得严谨”输出大段重复过程、日志或验证仪式。

---

## 1. 最高工程原则

当前项目阶段的首要目标：

> **真实 SimNow blocker 才修；修完立刻回到运行。**

始终遵守：

> **缺什么，只补什么。**

> **一小时能解决的问题，不允许演变成多日工程。**

> **先跑真实 E2E，再根据真实 SimNow 问题修。**

> **系统已经存在足够多 fail-closed 安全边界，不主动继续堆安全层。**

> **修复的价值是恢复运行，不是增加证明材料。**

开始任何工作前先判断：

1. 这是当前真实 blocker 吗？
2. 不修它，当前运行流程是否确实无法继续？
3. 能否用更小的修改解决？
4. 修复完成后能否立即回到原失败点？

如果不是当前真实 blocker，不做。

---

## 2. 当前成功标准

当前成功标准不是继续完善架构，而是让下面这条链稳定运行：

```text
STATIC_CORE_EQUAL
→ current DAILY PIT routing
→ TargetPlan
→ Custody
→ Execution
→ SimNow
→ reconcile/archive
→ 持续稳定运行
```

如果 runtime 已经工作：

> **只修真实 runtime bug。**

不要因为“还能更严谨”继续开发。

---

## 3. FAST-LANE：小型 Runtime / Packaging 修复

以下默认属于 FAST-LANE：

- 漏 COPY
- 漏 Python module
- import closure
- Containerfile / OCI packaging
- 路径错误
- 配置字段错误
- trust pin 值错误，但 trust contract 本身未改变
- 已经精确定位的小型 runtime compatibility bug
- 不改变策略/schema/authority/交易语义的部署问题
- 明确 fail-closed 且零 mutation 的现场 blocker

固定流程：

```text
真实 blocker
→ 最小 diff
→ focused test
→ Ruff / compile / diff-check
→ 1 个独立 Reviewer：P0=0 / P1=0
→ merge
→ exact-merge artifact/image build 一次
→ 最小 smoke
→ deploy
→ 立即返回原失败点继续
```

---

## 4. FAST-LANE 明确禁止事项

除非当前 blocker 明确要求，否则禁止：

- Luna → Terra → Sol → Reviewer 多层串行 ceremony
- 多个 Agent 重复调查同一个简单根因
- 一个两行修复调用四五个代理
- pre-merge OCI 完整 build，merge 后再重复完整 build
- 对未修改组件重新 provenance audit
- 重建没有变化的 release
- 重复验证相同 bundle/tree/hash
- publisher 前先人工完整 replay，然后 publisher 自己再 replay 一次
- 因两行 packaging fix 重新认证整套系统
- 每一步都写 GitHub comment
- 等待 full CI
- 顺手重构
- 顺手补“以后可能有用”的安全层
- 顺手新建 schema/service/daemon/scheduler/ledger/WAL/database
- 因一个现场 bug 建立通用 framework
- 为了让 evidence 更漂亮而扩大 scope

原则：

> **如果一项检查不会改变下一步决策，就不要重复做。**

---

## 5. Artifact / OCI 构建规则

小型 packaging/runtime hotfix：

PR 阶段只需要：

- focused tests
- Ruff / compile / diff-check
- independent P0/P1 review

merge 后：

```text
exact merge commit build 一次
→ 最小 smoke 一次
→ deploy
→ 回运行
```

禁止默认执行：

```text
PR HEAD 完整 OCI build
→ smoke
→ merge
→ exact merge 再完整 OCI build
→ 再跑完全相同 smoke
```

只有最终 merge 字节确实可能不同，才允许重复构建。

---

## 6. Full CI 规则

SimNow runtime FAST-LANE：

> **不等待 full CI。**

满足：

- focused tests PASS
- Ruff / compile / diff-check PASS
- relevant smoke PASS
- independent Review P0=0 / P1=0

即可 merge / deploy / 继续运行。

Full CI 可以后台运行，但不得阻塞当前 SimNow 窗口。

不要：

- 为此重新设计 CI
- 全局删除 required checks
- 建立新的 CI framework

必要时沿用已有 branch-protection/admin bypass 授权。

---

## 7. 修复后必须返回原失败点

每次 blocker 修完，下一步默认必须是：

> **返回触发本次修改的原命令 / 原阶段。**

例如：

```text
漏 import
→ 补 import
→ smoke
→ publisher
```

```text
publisher blocker
→ 修 blocker
→ publisher
```

```text
field gate blocker
→ 修 blocker
→ field gate
```

```text
Execution blocker
→ 修 blocker
→ Execution lifecycle
```

禁止：

```text
修完 blocker
→ 顺手发现十个可以优化的地方
→ 再开新工程
```

---

## 8. 不重复执行系统已有的 Fail-Closed 逻辑

如果真实执行命令自身已经具备：

- fail-closed
- create-only
- hash verification
- root revalidation
- ownership validation
- stable-read
- bounded input/output
- deterministic/idempotent recovery

则不要在真正执行前，再完整人工模拟相同逻辑。

例如 publisher 已经：

```text
protected replay
→ verify
→ current-root revalidation
→ create-only publication
```

那么普通 packaging 修复后：

```text
OCI smoke PASS
→ publisher
```

不要：

```text
完整 zero-write replay
→ PASS
→ publisher 再完整 replay
```

除非本次修改本身就是 replay 逻辑。

---

## 9. 安全检查：检查真实能力，不追求漂亮元数据

安全门禁重点检查：

- 是否仍为 root
- 是否可以恢复 root
- 是否获得不该有的写权限
- 是否可以修改 root-managed state
- 是否可以修改 catalog
- 是否可以读取 private signing key
- 是否新增网络能力
- 是否新增 Gateway / broker / Execution mutation 能力
- 是否扩大 authority

不要为了 Unix 元数据“看起来理想”制造 blocker。

例如：

- macOS supplementary groups 不要求为了形式变成某个理想数组
- UID503 owner 对自己的 `0600` private evidence 有写权限属于正常 Unix 语义
- 不要求 owner 对自己的 private evidence `W_OK=false`
- primary GID 和 effective policy GID 可以是两个不同概念

核心判断：

> **这个身份实际上获得了什么能力？**

而不是：

> **这个数字组合看起来够不够漂亮？**

---

## 10. 必须保持的真正安全边界

FAST-LANE 不允许削弱以下边界：

- Execution 是唯一业务 send/cancel owner。
- Windows 仅负责 CTP RPC / SimNow Gateway。
- Research 没有交易 authority。
- Runner 不直接绕过 Execution 调 Gateway/Windows 下单。
- `production=false`
- `live_trading_authorized=false`
- `countable_forward=false`
- `official_forward_claimed=false`
- UNKNOWN outcome → same identity query/reconcile only。
- 禁止 blind resend。
- 禁止复用旧 plan。
- 禁止复用旧 intent。
- 禁止复用旧 order_ref。
- 禁止复用旧 idempotency。
- 禁止复用旧 fence。
- root-managed custody/catalog 不允许低权限 child 修改。
- private evidence 继续遵守正式 owner/mode/ACL/hash/stable-read 合同。
- 不使用直接 RPC/test script 作为业务执行架构证明。
- 不通过人为修改状态绕过 fail-closed。

---

## 11. STOP：必须重新向付哥授权的情况

只有以下情况必须 STOP：

- 需要新的业务逻辑，且超出当前 blocker 的最小修复
- scope 扩大
- 修改 frozen strategy
- 修改数量向量
- 修改策略权重
- 修改 allocator
- 修改 C/D 策略公式
- 修改 thermostat 经济语义
- 修改 current DAILY PIT 经济/路由规则
- 修改 Execution 核心语义
- 修改 Custody 核心语义
- 修改 authority model
- 削弱 provenance
- 削弱 fail-closed
- 引入新的 trust source
- 新 schema
- 新 service
- 新 daemon
- 新 scheduler
- 新 ledger
- 新 WAL
- 新 database
- 新通用 framework
- production/live/countable_forward 范围变化

普通 SimNow routine operation 不需要反复申请。

---

## 12. Routine SimNow 操作默认继续

在已经授权的 SimNow scope 内，以下默认属于 routine：

- read-only preflight
- Research publisher 既定调用
- exact readback
- catalog head load
- Execution reconcile
- field gate
- quote gate
- switches=false dry-run
- 已满足既定授权条件后的 SimNow mutation
- completion query
- archive/reconcile
- UNKNOWN 的 same-identity recovery
- exact artifact/image deployment
- 已审查的配置 pin 原子更新
- 已经确认 zero mutation 后，对修复后的同一路径重新执行一次

不要每一步停下来重复向付哥申请。

只有触发 STOP 条件时询问。

---

## 13. GitHub Evidence 规则

GitHub evidence 只记录关键事实。

应该记录：

- blocker 根因
- 修复 PR / merge commit
- P0/P1 Review 结果
- STOP 原因
- 真实运行结果
- 最终 acceptance

如果提交或更新 PR，必须同步在对应 PR 添加评论。

但禁止为了“审计看起来完整”频繁追加：

- 每条 shell command
- 每次 hash
- 每次重复 smoke
- 每个 Agent 的过程日志
- 对最终决策无影响的中间结果

---

## 14. 子代理调度总原则

Sol 负责：

- 规划
- 调度
- 架构判断
- 高风险事项
- Agent 冲突裁决
- STOP 判断
- 最终收口

Sol 不应该亲自承担全部普通工作。

但：

> **也不要为了使用子代理而使用子代理。**

小问题优先少人、快速完成。

---

## 15. 代理分工

### `luna_worker`

适合：

- 代码检索
- 根因定位
- 影响分析
- 简单修改
- 补 focused tests
- 跑测试
- 初级 Review

### `terra_worker`

适合：

- 主要代码实施
- 跨文件修改
- 复杂 Bug
- 中型重构

### `terra_reviewer`

适合：

- 独立读取完整 Diff
- 普通风险最终 Review
- P0/P1 判断

Reviewer 不参与被审查实现。

### `Sol`

适合：

- 架构决策
- 高风险复核
- 交易/资金/并发/事务/安全/权限事项
- trust-source 变化
- 策略语义变化
- Agent 结论冲突
- 最终任务收口

---

## 16. FAST-LANE 的 Agent 调度

普通小修复默认最多：

```text
1 个实现 Agent
+
1 个独立 Reviewer
```

例如：

```text
Luna 或 Terra 实施
→ Terra Reviewer 独立终审
→ merge
```

禁止默认：

```text
Luna audit
→ Terra implement
→ Sol validation
→ Luna 再测
→ Terra Reviewer
→ Sol 再验
```

两行 packaging fix 不需要四层代理验收。

---

## 17. 并行调度规则

1. 只有任务真正相互独立时才并行。
2. 不要为了“效率看起来高”强行启动多个 Agent。
3. 同一个 `luna_worker` 可以启动多个实例。
4. 多个 Agent 不得同时修改可能重叠的文件。
5. 有冲突风险时：
   - 串行处理，或
   - 使用独立 worktree。
6. 子代理只返回：
   - 结论
   - 修改文件
   - 测试结果
   - 剩余风险
7. 不回传大段原始日志。

---

## 18. 独立审查原则

1. 实现者可以自检和运行测试，但不能独立终审自己的修改。
2. 最终 Reviewer 必须未参与本轮代码实施和整改。
3. Reviewer 一旦亲自修改被审代码，就失去独立 Reviewer 身份。
4. Luna Review 默认是初级/辅助 Review。
5. 普通风险 PR 可以由独立 `terra_reviewer` 终审。
6. 涉及以下事项升级 Sol：
   - 交易
   - 资金
   - 并发
   - 事务
   - 安全
   - 权限
   - 数据迁移
   - trust source
   - 重大兼容性
7. FAST-LANE Review 重点只看：
   - P0
   - P1
   - 是否超 scope
   - 是否破坏现有 fail-closed
   - 是否扩大 authority

满足：

```text
P0=0
P1=0
```

即可继续。

不要 review theater。

---

## 19. 默认技术选择优先级

遇到问题默认优先：

```text
最小修复 > 通用框架

已有 primitive > 新 abstraction

现有 service > 新 service

现有 schema > 新 schema

现有 trust chain > 新 trust chain

focused test > 全仓测试

一次 exact build > 重复 build

真实 fail-closed execution > 重复 dry simulation

运行恢复 > 证据美化

简单直接 > 理论完美
```

如果 Agent 准备新增：

- layer
- schema
- service
- signer
- scheduler
- ledger
- recovery framework
- generalized security abstraction
- duplicated validation stage

必须先回答：

> **当前真实 SimNow blocker 是否无法通过一个更小修改解决？**

不能明确回答“是”，禁止新增。

---

## 20. Deployment Topology

### M2 / Web Bridge

Active production/validation host:

```text
fujun@192.168.100.89
MacminiM2.local
Apple Silicon
```

Deployment path:

```text
/Users/fujun/services/vnpy-web-bridge
```

Web Bridge endpoint:

```text
http://192.168.100.89:8080
```

Docker context:

```text
desktop-linux
```

Historically expected base containers include:

```text
vnpy-web-bridge
vnpy-web-bridge-questdb
vnpy-web-bridge-postgres
```

Runtime topology may change。

在依赖这些事实执行操作前，只检查当前相关事实，不要全系统重新审计。

---

## 21. Windows / CTP / SimNow

Windows vn.py / SimNow RPC host:

```text
192.168.100.187
```

RPC ports:

```text
request: 2014
publish: 4102
```

Administration access:

```text
ssh wxuser@192.168.100.187
```

使用已有本地 Ed25519 key。

Windows OpenSSH firewall 当前仅允许 M2：

```text
192.168.100.89
```

禁止未经付哥授权扩大 firewall scope。

Windows RPC service:

```text
Service: VnpyRpcService
Display Name: vn.py CTP RPC Service
Startup: Automatic
Account: LocalSystem
Executable: C:\veighna_studio\pythonservice.exe
Launcher: C:\quant\run_rpc_server.py
```

只有当前真实 blocker 确实需要时才：

```powershell
Restart-Service VnpyRpcService
```

重启后检查相关：

- RPC connectivity
- positions
- orders
- reconciliation

不要自动执行全套无关验收。

---

## 22. Deprecated / uncertain host

`192.168.100.87` 在 2026-07-19 检查时 SSH 不可达。

未经重新确认，不得把它当作当前 active deployment host。

---

## 23. Credential / Secret Rules

永远不要把以下内容写入：

- AGENTS.md
- Git repository
- Issue
- PR comment
- log artifact

包括：

- SSH password
- SimNow credentials
- account ID
- signing private key
- tokens
- shared secrets

Signing key：

- read-only mount
- 不 bake 进 image
- 不 copy 进 container filesystem
- 不 commit

---

## 24. M2 Python Tooling

M2 host `python3` 在历史检查中为 Python 3.9，不适合 Python 3.10+ 项目应用验证。

Host-only utilities 使用：

```text
/Users/fujun/services/vnpy-web-bridge/.venv-shakedown
```

应用 imports、signing、runtime validation 优先使用部署镜像 Python 3.12：

```text
docker --context desktop-linux run ...
```

不要静默使用 host Python 3.9 做应用级验证。

---

## 25. Runtime State Rule

Runtime state 会变化。

真实 validation/release 前，只重新检查当前决策真正依赖的事实，例如：

- exact running image/revision
- health
- relevant config
- account
- positions
- active/pending/unknown
- RPC connectivity
- mutation switches

不要因为其中一个值变化而自动重新审计整个系统。

---

## 26. Execution Architecture

执行链固定：

```text
Strategy target
→ TargetPlan
→ Custody
→ Execution
→ Windows M2 / CTP
→ SimNow
→ callbacks / reconcile / archive / PnL
```

Ownership：

- Execution owns business send/cancel。
- Windows owns CTP RPC / Gateway only。
- Research owns strategy/research evidence only。
- Runner 只编排现有边界，不是第二 dispatcher。
- 不使用直接 Gateway RPC/test script 作为正常业务执行路径。

---

## 27. STATIC_CORE_EQUAL 固定身份

主策略身份：

```text
STATIC_CORE_EQUAL
│
├─ 50% C_FAST_CROSS_SECTION_NEUTRAL
│
├─ 50% D_DONCHIAN20_EXIT10_NEUTRAL
│
├─ COMMODITY_FROZEN_SECTOR_MAP_V1
│
└─ MONTHLY_RELATIVE_VOL_THERMOSTAT_V1
```

关键语义：

```text
economic target / integer quantities = MONTHLY
exact-contract routing / roll = DAILY PIT
```

不存在额外“实时 MAP”层。

不要把月度策略伪装成每分钟策略。

当前 exact contracts 可以随 verified DAILY PIT routing 变化。

这不等于修改 frozen strategy。

---

## 28. Historical Context — PR #109

IMPORTANT:

> 以下是 2026 年 7 月 PR #109 的历史验收记录。
> 仅供追溯。
> 不得覆盖当前 #362 / 当前 runtime contract。

Historical inspected head:

```text
679945d26c7d3d2b68fbddfe5be0c3e69853b786
```

Historical validation image:

```text
vnpy-web-bridge:pr109-679945d2
```

2026-07-20 历史验收曾完成：

- signed no-op
- minimum balanced SimNow orders
- final positions zero
- active orders zero

历史 9-order batch：

```text
AL2701 +5
CU2701 -4
```

one-lot split，全部成交后人工平仓至零。

Passive/restart acceptance：

```text
commit 74811e95
RB2610 long 1
SP2609 short 1
```

使用 shakedown passive limit，Web Bridge restart 后 targeted cancellation，两笔均未成交并取消。

当时：

```text
HALTED_RECONCILE_REQUIRED
```

随后 read-only reconcile 证明：

```text
positions=0
active_orders=0
```

这些内容都是历史事实。

禁止把以下历史状态直接当作当前状态：

- old image tag
- old account state
- old positions/orders
- old mutation authorization
- old exact-contract routing
- old acceptance gaps
- old PR merge requirements

必须以当前 runtime / 当前 Issue 为准。

---

## 29. 最终约束

Agent 必须时刻避免以下行为：

> 为了解决一个真实 blocker，却顺手创建三个新问题。

> 为了证明一个两行修复安全，重新验收整个系统。

> 为了理论完美，阻止已经足够安全的 SimNow 运行。

> 把“安全”理解成无限增加检查。

正确目标：

```text
真实 blocker
→ 最小修复
→ 足够验证
→ 回到运行
```

而不是：

```text
真实 blocker
→ 最小修复
→ 无限验证
→ 新抽象
→ 新安全层
→ 新文档
→ 新框架
→ 还没开始运行
```

项目当前阶段最终原则：

> **运行优先，边界不破；最小修复，快速闭环。**
