# vnpy-web-bridge Authority Model v1.0

## 1. Purpose

本文定义 vnpy-web-bridge 中策略研究、验证、部署和交易执行之间的权限传递模型。

核心目标：

- 防止研究能力直接进入交易执行链路；
- 让每一次交易授权都有明确来源；
- 让 AI Agent、开发人员和运行环境遵守统一权限边界。

---

## 2. Authority Chain

系统权限只能单向提升：

```text
Research Result
      |
      v
Evidence Bundle
      |
      v
Acceptance Contract
      |
      v
Deployment Authority
      |
      v
Execution Permit
      |
      v
Live Trading
```

任何阶段失败，都不得自动进入下一阶段。

---

## 3. Authority Definitions

## Research Result

来源：

- 回测
- 模拟
- 策略分析
- Shadow

能力：

- 产生研究结果
- 产生指标
- 生成候选策略

禁止：

- 下单
- 修改真实仓位

---

## Evidence Bundle

证明研究结果来源和完整性。

包含：

- 数据版本
- 策略版本
- 参数哈希
- 运行环境
- 结果文件
- 时间边界

Evidence 只能新增，不允许修改历史证据。

---

## Acceptance Contract

负责判断 Evidence 是否满足进入下一阶段条件。

例如：

- 数据完整
- 风险检查通过
- Shadow完成
- 策略身份一致

Acceptance 不代表拥有交易权限。

---

## Deployment Authority

允许将策略部署到指定运行环境。

限制：

- 指定策略版本
- 指定环境
- 指定有效时间

---

## Execution Permit

交易执行唯一入口。

Execution Plane 只信任有效 Permit。

Permit 必须包含：

- strategy identity
- version
- scope
- expiration
- signature

---

# 4. Forbidden Paths

禁止：

```text
Research  ---> Execution

Shadow    ---> Order

Evidence  ---> Trading

AI Agent  ---> Broker API
```

必须：

```text
Research
   |
Evidence
   |
Control
   |
Execution Permit
   |
Execution
```

---

# 5. Fail Closed

默认拒绝。

任何以下情况：

- signature invalid
- artifact missing
- identity mismatch
- expired permit
- replay detected

必须拒绝执行。

---

# 6. C_FAST Special Rule

C_FAST 永久属于 Research Plane。

允许：

- 研究
- Shadow
- Evidence生成
- execution quality分析

禁止：

- 直接交易
- 持有 TradeService
- 调用 send_order
- 调用 cancel_order

真实成交验证必须经过独立 Control Plane 授权。

---

# 7. Review Requirement

所有涉及权限的 PR 必须说明：

- 新增了什么 Authority；
- Authority 从哪里产生；
- 谁验证 Authority；
- 是否影响 Execution Plane。
