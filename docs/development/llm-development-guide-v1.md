# vnpy-web-bridge LLM Assisted Development Guide v1.0

## 1. 目的

本文规定 AI Agent（ChatGPT、Codex、Claude 等）参与 vnpy-web-bridge 开发时必须遵守的开发规范。

目标：

- 保持总体架构一致
- 防止 AI 破坏系统边界
- 保证代码长期可维护

---

# 2. 开发前要求

任何 AI 开发任务开始前，必须阅读：

```
docs/architecture/vnpy-web-bridge-architecture-v1.md
```

并明确：

```
Architecture Impact:

所属 Plane:
Research / Control / Execution

是否改变 Authority:
Yes / No

是否影响生产交易:
Yes / No
```

---

# 3. 禁止事项

## 3.1 禁止跨层调用

禁止：

```
Research -> Execution
```

例如：

研究代码直接调用下单接口。

必须：

```
Research
  |
Evidence
  |
Control
  |
Permit
  |
Execution
```

---

## 3.2 禁止绕过 Authority

禁止增加类似：

```python
if approved:
    trade()
```

必须使用明确授权对象：

```python
verify_execution_permit()
execute_order()
```

---

## 3.3 禁止为了测试修改生产安全逻辑

禁止：

- 删除验证
- 增加隐藏 bypass
- 根据环境跳过安全检查

测试应使用：

- mock
- sandbox
- fake provider

---

# 4. Issue 实现流程

AI 不允许看到 Issue 后直接编码。

必须按照：

```
Issue
 |
Architecture Review
 |
Design Proposal
 |
Implementation
 |
Testing
 |
PR Review
```

---

# 5. 开发输出规范

AI 在实施前必须输出：

## Architecture Impact

说明：

- 所属 Plane
- 修改边界
- 是否影响 Authority

---

## Design

说明：

- 数据流
- 模块关系
- 错误处理

---

## Security Consideration

必须说明：

- 权限变化
- Fail Closed 行为
- Replay 防护
- 数据完整性

---

## Test Plan

至少包含：

- 正常流程
- 非法输入
- 过期状态
- 篡改场景
- Replay 场景

---

# 6. 代码设计原则

## Fail Closed

默认拒绝，而不是默认通过。

失败情况：

- schema 不匹配
- signature 无效
- identity 不一致
- artifact 缺失

必须停止流程。

---

## Immutable Evidence

证据不可覆盖修改。

正确方式：

```
new evidence
new hash
new version
```

---

## Explicit Authority

权限必须显式传递。

禁止隐式授权。

---

# 7. PR Review Checklist

每个 AI 生成 PR 必须检查：

## Architecture

- [ ] 属于正确 Plane
- [ ] 没有跨层调用
- [ ] 没有扩大 Authority

## Security

- [ ] 默认 Fail Closed
- [ ] 防 Replay
- [ ] 防篡改
- [ ] 身份校验完整

## Runtime

- [ ] 是否影响生产交易
- [ ] 是否需要额外权限
- [ ] 是否增加运行风险

## Maintainability

- [ ] 是否重复创建 Schema
- [ ] 是否增加无必要复杂度
- [ ] 是否符合已有设计

---

# 8. C_FAST 特殊规则

C_FAST 永远不是交易执行模块。

允许：

```
C_FAST -> Evidence
C_FAST -> Acceptance
C_FAST -> Validation
```

禁止：

```
C_FAST -> Order
C_FAST -> Gateway
C_FAST -> Broker
```

---

# 9. 最终原则

AI 是开发助手，不是架构决策者。

所有代码修改必须服从：

```
Architecture
      |
      v
Authority Model
      |
      v
Development Guide
      |
      v
Implementation
```
