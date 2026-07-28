# vnpy-web-bridge 总体架构设计 v1.0

## 1. 文档目的

本文定义 vnpy-web-bridge 从 Web Bridge 向量化交易基础设施演进后的总体架构。

目标：

- 明确系统分层边界
- 明确权限与授权模型
- 防止研究、验证、控制、执行能力相互污染
- 为后续 Issue、PR 和 LLM 开发提供统一设计依据

---

# 2. 系统定位

vnpy-web-bridge 不再定位为简单的 vn.py Web 接口层。

目标定位：

> 面向量化交易系统的 Research + Control + Execution 基础设施平台。

系统由三个核心平面组成：

```
Research Plane
      |
      v
Control Plane
      |
      v
Execution Plane
```

---

# 3. 三平面架构

## 3.1 Research Plane（研究平面）

职责：

- 策略研究
- 回测
- 数据分析
- Shadow Trading
- C_FAST
- Query Runtime
- 性能分析
- 研究证据生成

允许：

- 读取研究数据
- 生成 Evidence
- 运行模拟环境

禁止：

- 直接调用交易接口
- 下单
- 撤单
- 修改账户状态

---

## 3.2 Control Plane（控制平面）

职责：

- Policy 管理
- Acceptance 验收
- Risk Gate
- Deployment Authority
- Execution Permit
- Audit

Control Plane 不执行交易。

它只回答：

> 某个策略是否具备进入下一阶段的资格。

---

## 3.3 Execution Plane（执行平面）

职责：

- vn.py Engine
- Gateway
- Order Management
- Position Management
- Account Management

Execution Plane 保持简单。

它只接受有效 Execution Permit，不理解策略研究过程。

---

# 4. 权限模型 Authority Model

权限链：

```
Research Result
       |
       v
Evidence
       |
       v
Acceptance
       |
       v
Deployment Authority
       |
       v
Execution Permit
       |
       v
Trading
```

低级结果不能直接升级为交易权限。

例如：

- 回测盈利 ≠ 可以交易
- Shadow 成功 ≠ 可以交易
- Acceptance PASS ≠ 永久权限

必须经过明确授权链。

---

# 5. 核心数据对象

## Strategy Artifact

描述策略身份：

- strategy_id
- version
- code_hash
- parameter_hash

---

## Evidence Bundle

描述策略可信依据：

- Backtest Result
- Shadow Result
- Performance Metrics
- Risk Metrics
- Environment
- Data Version

---

## Acceptance Contract

描述验收结果：

- accepted state
- authority level
- expiration
- evidence reference

---

## Execution Permit

唯一允许执行层交易的授权对象。

包含：

- permit_id
- strategy_id
- symbol scope
- risk limit
- expiration
- signature

---

# 6. 强制架构规则

## 规则1：禁止 Research 直接进入 Execution

禁止：

```
Strategy
  |
  v
Gateway
```

必须：

```
Research
   |
Control
   |
Execution
```

---

## 规则2：默认 Fail Closed

任何：

- 校验失败
- 签名失败
- 状态异常
- Artifact 缺失

必须拒绝继续。

---

## 规则3：Execution 不依赖研究实现

交易执行模块不得依赖：

- C_FAST
- Backtest
- Shadow
- Research Schema

---

# 7. C_FAST 定位

C_FAST 属于：

```
Research Plane
+
Control Plane
```

用途：

- 数据验证
- 查询可信性
- Evidence 管理
- Acceptance 支撑

禁止：

```
C_FAST -> Order
C_FAST -> Gateway
C_FAST -> Broker
```

---

# 8. 后续开发原则

所有 Issue 和 PR 必须回答：

1. 属于哪个 Plane？
2. 是否改变 Authority？
3. 是否影响 Execution？
4. 是否增加新的安全边界？

本架构文档作为后续开发基准。