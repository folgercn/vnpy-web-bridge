# 项目 Agent 规则

## 任务与上下文

- 称呼用户为“付哥”，中文说明，先给结论与下一步；以本次明确的 Issue/需求为目标，不把已完成阶段永久设为当前任务。
- 读取适用的 AGENTS 后，直接定位模块、必要调用链和测试；不默认通读全仓 README、历史方案、图谱或交接。证据不足时定向补读，不为省 tokens 猜测。
- 只做本次最小必要修改。未明确扩展范围，不新增 service、daemon、worker、queue、数据库、RPC、端口、依赖、容器或第二套调度/执行框架，不顺手重构。
- 详细规则在 [SIMNOW_LAB 执行与阶段契约](docs/simnow-lab-agent-contracts.md)。只读取下表与本次有关的章节；涉及该路径的修改、验证或操作前必须取得并满足完整对应条款，无法读取时停止受影响操作，不凭根摘要执行。

| 任务 | 必须核对的专项章节 |
|---|---|
| Lab executor、订单、target、SQLite | 第 2–7、10、13–14 节；M5 target/roll 同时读第 0 节 |
| Dashboard、M2 one-shot、CI/CD | 第 0.1、12 节；自动目标生产同时读第 0 节 |
| 阶段路径与文件/行数预算 | #462 看第 3 节，#466 看第 0.1 节，#473 看第 0 节及对应 Issue；不得混加或自行解除预算 |
| 开市 LIVE-HOTFIX | 第 9–10 节、适用阶段的允许路径/预算及本次有效授权 |
| 已授权主机操作 | 第 15–16 节，只核对操作实际依赖的现状，不重新审计全系统 |

## 长期硬边界

- SIMNOW_LAB 与 audited/production lane 隔离；Lab 永久保持 `production=false`、`live_trading_authorized=false`、`countable_forward=false`、`official_forward_claimed=false`。Lab 验收不是 production/audited 验收。
- Windows Lab executor 是该 lane 唯一 send/query/cancel owner；复用既有 RPC/CTP、一个本地锁、一个 SQLite 文件、最多两个私有 RPC 与四张表。M2 复用现有 `com.folgercn.simnow-lab` LaunchAgent，不接回 Custody/TargetPlan/Execution/authority/completion/successor 等冻结链。
- 未经新的明确授权，不修改 `backend/app/execution/**`、`backend/app/phase_c/**`、shared audited contracts、market-data journal/projection、signer/provenance/trust source、旧 audited runtime 交易语义或 production/live/countable-forward lane；不删除、削弱或重新启用旧链。
- Dashboard 是独立只读面：Windows SQLite reader 使用 `mode=ro` 与 `PRAGMA query_only=ON`；Web/API 故障和发布不得触发交易、恢复、执行服务重启或交易状态写入，具体隔离与发布规则见第 0.1 节。
- `STATIC_CORE_EQUAL` 的策略、C/D、thermostat、allocator、产品池、权重公式和 DAILY PIT 选主算法冻结；quantity 保持 MONTHLY，exact-contract route/roll 使用 DAILY PIT。输入无效不覆盖合法 target，不发送订单；换月先平旧再开新。
- 保留 fresh positions/active orders/tick、平今平昨与 UNKNOWN 禁止盲重发契约。误连真实账户、尚未查清的 active/UNKNOWN order 或超出允许路径/预算时，按第 10 节 STOP；不得用新增 lifecycle 框架处理。
- 代码修改、合并、部署和柜台 mutation 分别遵循有效授权；离线测试通过不授权交易。已明确授权的 SimNow 操作不反复请示，也不得扩展到真实账户或无关主机。
- 不把 SSH 密码、SimNow credentials、account ID、私钥、token 或 shared secret 写入仓库、Issue、PR 或日志 artifact。

## 实施、验证与 Code Review Rules

- 默认一个 implementer 连续完成定位、修改、focused 验证和整改；仅必要的独立检索最多加一个 worker，不继续分派，不多代理重复调查，不拆子 Issue 或增加审查层。模型与档位由角色 TOML 指定。
- 普通修改保留一次未参与实现的独立 P0/P1 Review，同时检查本轮 scope、条款遗漏与错误扩大授权；独立读 diff、必要代码和测试证据，不列 style/nit 或假想未来需求。整改交回原执行者，只复核新增修改及影响范围。
- 运行改动相关测试和仓库现有必需检查，保留 required `CI Gate`；不恢复全仓 replay、旧 Phase-C/OCI 等无关检查，不改 branch protection。有新修改、失败、证据缺失或具体未决风险才重复或扩大验证。
- 仅在既有条件及有效授权满足时，LIVE-HOTFIX 保留“focused 验证→现场恢复→补 PR/CI/独立 Review”的顺序；须先读第 9–10 节，不把例外扩展为普通任务可跳过 CI/Review 或先部署。
- GitHub 用中文直接提交实质评论，只记录根因、修复、验证和关键结论，不逐条播报命令；未发现 P0/P1 不等于全部验收成功，如实说明未验证项，不假称独立审查通过。
- 长期规则只保留稳定约束与入口；阶段进度、时限和授权留在当前 Issue。未经本次明确授权，不自行改写 AGENTS、角色配置、权限或 CI 门禁来绕过约束。

## 项目 Skills

- 任务匹配时使用 `.agents/skills/` 中对应项目 Skill，不批量预加载全部 Skill。
- Skill 复用现有脚本与专项契约，不增加无关前置检查或子代理。
- 巡检和收益核验保持只读；发布遵循本次有效授权。Skill 与项目规则冲突时指出具体条款，不自行改写权限或冻结契约。
