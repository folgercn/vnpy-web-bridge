# Issue #291 Phase C：MAP/C_FAST 跨服务离线工作流 v1

状态：`implementation_baseline_offline_fake_only`。本文件定义 #262/#264 的最小可合并闭环；不部署、不迁移旧单体路径，也不对任何交易运行时授予 authority。

## 责任边界

| 单元 | 允许 | 明确禁止 |
| --- | --- | --- |
| MAP / C_FAST producer | 输出候选与只读 status | 签名、安装、runtime enable、订单/RPC |
| Control API / Browser | 读取 projection、导出 canonical signing request、上传已签名交接、发送 typed authorization request | 私钥、浏览器签名、custody volume 写入、Execution state 直写、TradeService/Gateway/RPC |
| Offline signing authority | 在离线 ceremony 中签名 export | HTTP signing endpoint、artifact 安装、runtime enable、订单/RPC |
| Artifact Custody | 验证/保存 signed artifact，写 verify/install receipt | 私钥、Control/Browser state、订单/RPC |
| Execution | 消费 custody receipt，保存 authorization/audit/archive state，生成只读 preview/status | 将 Control RBAC 当作 authority、接收浏览器订单、真实交易（本 Phase C） |

`OfflineFakeWorkflowClient` 仅是测试依赖注入替身，普通运行时没有环境变量可将其选中。默认 Control client 是 fail-closed unconfigured client；真实运行时只可注入独立 custody/execution private HTTP client。不得把 fake adapter 当作部署实现。

## 最小链路

```text
MAP / C_FAST status (read-only)
        |
        v
Control export: signing-request JSON ----------> Offline signer
   (browser_signing=false; no private key)            |
                                                    signed artifact
                                                        |
                                                        v
Control upload/install request --> Artifact Custody --> immutable receipt
                                                        |
                                                        v
Control typed enable/revoke command --> Execution --> status/audit/archive projection
```

1. `POST /api/phase-c/signing-requests/export` 只能导出 `web-bridge-phase-c-signing-request-v1`。浏览器不签名，request 不含私钥或路径。
2. `POST /api/phase-c/artifacts/upload-install` 只接收已经离线签名的 Phase B signed-artifact wrapper，并携带 caller idempotency key、correlation id 与 custody expected version。Control 不缓存 artifact；Custody 是 receipt owner。Custody 从自己的 root-owned public keyring path/raw SHA pin 选择 domain/key-purpose，复验 Ed25519、expiry 及 signed `request_id == upload signing_request_id`，再以 sole-writer ledger 写 publish/install receipt。
3. `POST /api/phase-c/authorization/commands` 只允许 `enable` / `revoke` typed command，必须绑定 custody receipt、artifact id、expected execution version 与 idempotency key。
4. `GET /api/phase-c/execution/{preview,status,audit,archive}` 仅返回 Execution adapter projection；Control 不持有 runtime state。

所有 mutation 的 unknown outcome 都只能以**同一 idempotency key**重试或查询；不得生成新 key 进行 replay。前端把 pending key、完整 payload 和 SHA-256 持久化，网络未知先查同 key receipt 后才可重试原 payload。stale expected version、同 key 不同 payload、receipt/artifact binding 不匹配均 fail closed。

## 访问控制与安全默认值

| Surface | viewer | trader | admin |
| --- | --- | --- | --- |
| MAP/C_FAST/workflow、custody receipt、authorization/execution projection | read | read | read |
| export signing request | deny | deny | allow |
| upload/install handoff | deny | deny | allow |
| enable/revoke typed command | deny | deny | allow |

在此合同和 fake E2E 中，以下字段均为 `false`，不因 `ENABLE_REQUESTED` 改变：`production_allowed`、`live_trading_authorized`、`countable_forward`、`runtime_mutation_allowed`、`execution_mutation_allowed`。`effective_state` 固定为 `DISABLED`。

## 合同文件与验证

- `docs/schemas/issue-291-phase-c-signing-request-v1.schema.json`
- `docs/schemas/issue-291-phase-c-authorization-command-v1.schema.json`
- `shared/phase_c_workflow/v1.py`
- `backend/tests/unit/test_issue291_phase_c_workflow.py`
- `frontend/src/test/phase-c-workflow.test.ts`

建议验证命令：

```bash
PYTHONPATH=backend .venv/bin/python -m pytest backend/tests/unit/test_issue291_phase_c_workflow.py -q
cd frontend && npm test -- --run src/test/phase-c-workflow.test.ts && npm run build
```

这不是任何真实 custody、HSM、Execution 或 SimNow 验收证据。接入真实服务前需独立审查 remote client、pinned keyring/receipt verification、durable storage、fencing 与 release topology；不得恢复 `/api/commodity-simnow/*` 等旧单体路径。
