---
name: vnpy-release
description: 准备或核验 SIMNOW_LAB 定向发布：先检查既有 CD，再按明确 SHA、区域和授权复用发布器。
---

# vnpy release

用于用户明确要求检查、准备或执行 SIMNOW_LAB 发布时。点名本 Skill 不等于获得合并、部署、重启或交易授权。

先读根 `AGENTS.md` 及 `docs/simnow-lab-agent-contracts.md` 第 0.1、12 节。离线检查、代码合并和 CI 成功均不等于已发布；不把普通 bug 修复串联为发布流程。

## 先核对既有 CD

- 读取 `.github/workflows/m2-simnow-lab-cd.yml`、目标 SHA 的 CI/CD 记录和当前 `.release.json`（如授权且可读）。CD 仅对 main 上成功 CI 的精确 `head_sha` 触发。
- 若目标前端或其他区域已由既有 CD 成功发布，报告 SHA、区域和证据，到此停止；不得重复发布，也不得碰 Windows。
- 若 CD 未完成，确认用户明确授权的 SHA、目标环境和发布区域；未明确时只给准备结论。

## 已明确执行授权时

- 复用 `deployments/simnow-lab/release_v1.py`，始终传入精确 40 位 SHA 与显式 `--areas`。该脚本默认 `backend,frontend,windows,m2`，不得省略区域。
- 先确认变更区域：`backend/*`/控制 API、`frontend/*`、Windows executor/Dashboard，或 M2/发布文件；仅选择受授权且确有变更的区域。
- 指定前端或后端时不得顺带选择 Windows/M2；初始 main 发布受现有全区域契约约束，不自行绕过。
- 按现有发布器的构建、切换、健康与 Dashboard smoke 结果验收；失败保留其回滚/错误证据，不手工替代发布器修复现场。

## 输出

说明目标 SHA、当前/目标区域、CD 状态、是否实际发布、验收证据与未验证项。发布后仍单列 Lab 隔离状态；不把运行健康写成交易或策略业务成功。
