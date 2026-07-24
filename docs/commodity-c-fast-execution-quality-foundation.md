# C_FAST execution-quality 非激活基础

本文档对应 Issue #114 的 PR-C0。当前切片只冻结虚拟 intent 的严格
DTO、纯编译规则和确定性哈希；它不是 execution-quality observer，也
不会开始收集 forward evidence。

## 当前边界

固定状态：

```text
activation_state=FOUNDATION_ONLY_NOT_ACTIVATABLE
collection_authorized=false
authority_granted=false
dispatch_allowed=false
replacement_allowed=false
production_allowed=false
```

本切片没有配置项、startup hook、worker、API、QuestDB adapter、行情订阅、
RPC、TradeService、订单 reference、价格或账户字段。现有 C_FAST Shadow
status 继续返回 `execution_quality_implemented=false`。

## 输入与身份绑定

`compile_virtual_intent_plan` 只接受：

1. 已解析的 `CommodityCFastShadowDTO`；
2. 调用方提供的 unsigned snapshot SHA256 receipt；
3. 显式 `CFastVirtualIntentPolicyDTO`。

编译器会重新计算 unsigned snapshot SHA256 和
`formula_target_binding_sha256`，避免把另一个 snapshot 的 receipt
配到当前对象。它不会自行验证 Ed25519 签名；未来运行接线必须只传入已经
由 `CommodityCFastShadowService` 接受的签名 snapshot。

## 纯虚拟计划语义

编译器按产品排序，先生成全部 `virtual_close`，再生成全部
`virtual_open`：

- 换月：旧 exact contract 全部虚拟平仓，再在新 exact contract
  建立目标；
- 同约减仓：生成 `reduce_previous`；
- 同约加仓：生成 `establish_target`；
- 多空反转：先完整减少旧方向，再建立新方向；
- 零差异：不生成 intent；
- 每条 leg 按 policy 中的 `max_child_order_lots` 精确拆分。

编译器在拆分前复用冻结目标的资源边界：
`abs(previous_target_quantity) <= 500` 且
`abs(target_quantity) <= 500`；plan DTO 额外限制最多 10,000 条
intents。这是防止未接受或损坏的 DTO 放大内存/CPU 的资源上限，不是新的
策略参数、目标裁剪或仓位管理规则。越界输入直接失败，绝不截断后继续。

每个 leg、child intent 和完整 plan 都由 canonical JSON 产生确定性
SHA256。相同 snapshot 和 policy 的重复编译必须得到完全相同的对象；
policy 或目标发生变化时 hash 必须变化。DTO 不包含实际订单使用的
`offset`、`reference`、gateway、账户和委托价格字段。

严格 DTO 在 JSON reload 时会按相同 canonical JSON 规则重新验证
`policy_hash`、`leg_id`、`intent_id` 和 `plan_hash`。持久化内容中任一
hash 或其绑定字段被改写都会 fail closed；不能只依赖调用方事后运行
hash helper。

这些 SHA256 只是 checksum，不是签名、身份认证或运行 authority。能够
同步改写内容和全部 checksum 的主体仍可构造自洽 plan。因此未来任何
持久化 reload 都必须调用
`reload_and_verify_virtual_intent_plan`：先完成严格 DTO 校验，再用当前
accepted signed snapshot receipt 和独立冻结 policy 重新编译，并要求
完整 plan（含每个 intent 及 `plan_hash`）全等。不允许只做 DTO reload
后直接进入 horizon 或持久化流程。

## execution policy 尚未获得运行授权

签名 C_FAST snapshot 当前没有冻结 `max_child_order_lots`。因此 foundation
要求调用者显式提供 policy，并把 policy 全量内容及其 SHA256 写入 plan；
但 policy 固定标记为：

```text
policy_authority_state=UNSIGNED_FOUNDATION_INPUT_REQUIRES_SEPARATE_FREEZE
```

不得从可变的 `commodity_simnow_max_child_order_lots` 偷取默认值，也不得
凭本地测试中的数值开始 forward 收集。运行前需由独立人工 authority
冻结 policy ID、child lots 和后续价格规则。

## 与 T1/P0 的依赖

可以与 QuestDB server-enforced readonly proof 和 one-shot T1 authority
并行的工作只有：

- 当前严格 DTO；
- 当前纯 intent 编译器和哈希；
- 本地失败路径、拆单、换月、反转和幂等测试；
- 后续存储接口的离线设计。

下列工作仍被 T1/P0 正式通过和独立 policy authority 阻塞：

- QuestDB execution-quality 表、repository、DDL 或 DSN；
- runtime tick/horizon worker、恢复和持久化；
- config、startup、API 或页面接线；
- 将 `execution_quality_implemented` 改为 true；
- P2/T2 forward evidence、book-walk、markout、fill bounds 或 PnL。

## 验证

```bash
PYTHONPATH=backend pytest -q \
  backend/tests/unit/test_commodity_c_fast_execution_quality.py

PYTHONPATH=backend pytest -q backend/tests/unit
```
