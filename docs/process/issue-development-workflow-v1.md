# vnpy-web-bridge Issue Development Workflow v1.0

## Purpose

定义 Issue 从提出到合并的标准流程，避免功能驱动开发破坏整体架构。

---

## Issue Creation Rule

所有新 Issue 必须使用 `.github/ISSUE_TEMPLATE/` 中适用的模板，并明确声明：

- Architecture Plane
- Authority Impact
- Security Boundary
- Non-goals

缺少任一项时，不得进入设计或实现阶段。

---

## Workflow

```text
Create Issue
      |
      v
Architecture Classification
      |
      v
Design Review
      |
      v
Implementation
      |
      v
PR Review
      |
      v
Merge
```

---

## Step 1: Architecture Review

Issue 开始前必须回答：

1. 属于哪个 Plane？

- Research
- Control
- Execution

2. 是否改变 Authority？

3. 是否影响生产执行链路？

---

## Step 2: Design Proposal

必须明确：

- 修改范围
- 数据流
- 权限边界
- 新增 Contract
- 测试方案

禁止直接进入代码修改。

---

## Step 3: Implementation

开发要求：

- 优先复用已有 Contract；
- 禁止重复创建类似 Schema；
- 默认 Fail Closed；
- 保持 Evidence 可审计。

---

## Step 4: Security Review

检查：

- 是否扩大权限；
- 是否绕过验证；
- 是否存在 Replay 风险；
- 是否影响 Execution Plane。

---

## Step 5: PR Review

PR 必须包含：

- Architecture Impact
- Design
- Authority Impact
- Security Consideration
- Test Plan
- Risk Assessment

---

## AI Development Rule

使用 LLM/Codex 开发时，必须先阅读：

- `docs/architecture/vnpy-web-bridge-architecture-v1.md`
- `docs/architecture/authority-model-v1.md`
- `docs/development/llm-development-guide-v1.md`

AI 不得自行改变架构边界。
