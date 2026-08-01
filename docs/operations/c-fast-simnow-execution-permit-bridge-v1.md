# C_FAST SimNow Execution Permit Bridge v1 运行手册

## 1. 权限边界

本桥只把 PR #165 的状态
`READY_FOR_HUMAN_SIMNOW_EXECUTION_PERMIT_ONLY` 转换为一次、短时、指定
SimNow 账户和指定 1–2 个品种的 Execution Permit。

PR #165 Research Acceptance、consume marker 和 receipt 都不是执行权限。
PR #154 shakedown snapshot 内的 `control_acceptance_id` /
`execution_permit_id` 也只保留为审计绑定，不能单独触发 preview、start 或
dispatch。真正执行前必须同时通过：

1. 原 PR #165 `verify_signed_acceptance` 的完整重验；
2. 已存在的 one-shot consume marker 和 create-only receipt 精确重验；
3. 独立 Execution signer 和独立 trusted keyring 的验签；
4. adapter snapshot、账户、品种、目标、execution day 和时效闭合；
5. Web Bridge 自身的人工 start、SimNow、reconcile 和最终 submit guards。

`production_allowed`、`live_trading_authorized`、
`deployment_authorized`、`automatic_promotion_authorized` 永远为 `false`。
签发工具不读取账户、不调用 Web Bridge RPC、不发单、不改仓位。

## 2. 前置输入

以下输入必须已经存在；不得再次调用 #165 consume：

- signed Research Acceptance；
- 同一 custody root 中唯一的 `*.acceptance-consume.json`；
- 同一 custody root 中唯一的 `*.acceptance-receipt.json`；
- #160 installed Research bundle / claim / receipt；
- 九件 Research raw artifacts；
- Research keyring、Acceptance keyring及其部署外 pin；
- 已通过 Research/旧 Control 双签验证的 adapter snapshot；
- 独立 Execution keyring。Execution 公钥材料不得复用 Research 或
  Acceptance 公钥材料。

runtime 和 signer 会先解码并验证 Execution keyring 的**全部** entry，再选择
当前 signer。任一备用 key 非 canonical base64、不是 32-byte Ed25519 公钥、
decoded material 重复，或与 Research/Acceptance keyset 有交集，整个 keyring
都会 fail closed；不能预埋跨域 rotation key。

custody root 必须是绝对、规范、无 symlink 的目录，且不能 group/world
writable。consume/receipt 必须是 custody 同设备、同 owner、`0600` 的普通
文件。运行时会 pin root path hash 和包含 device/inode/owner/mode 的 identity
hash。

## 3. 生成 unsigned permit

先复制并人工填写
`docs/operations/c-fast-simnow-execution-permit-v1.template.json` 中的人工字段。
该模板含 `PENDING_NOT_AUTHORITY`，不是 permit，也不能被 verifier 接受。

由受控 Python 进程完成以下步骤：

1. 用 `CommodityCFastResearchAcceptanceEvidenceService` 绑定原
   `verify_signed_acceptance`，执行 full-chain reverify；
2. 用 `commodity_c_fast_shakedown_artifact.verify` 验证旧 snapshot；
3. 调用
   `commodity_c_fast_simnow_execution_permit.prepare_unsigned_execution_permit`；
4. 将返回对象写为 sort-keys、无空格、UTF-8 的 canonical JSON，并保留一个
   结尾换行，文件权限设为 `0600`。

builder 会从真实 receipt 和 acceptance 派生所有 hash、consume id、账户、
selected targets、formula binding 和 custody binding。不要手工复制或改写这些
字段。`expires_at - not_before` 最大为 10 分钟，并且 permit 窗口必须完全位于
Acceptance 窗口内。

## 4. 独立签署

所有下列环境变量先按第 5 节配置，然后执行：

```bash
PYTHONPATH=backend:scripts \
python scripts/commodity_c_fast_simnow_sign_execution_permit.py \
  --unsigned /absolute/private/unsigned-permit.json \
  --snapshot /absolute/private/shakedown-snapshot.json \
  --snapshot-research-public-key /absolute/private/research-public.key \
  --snapshot-control-public-key /absolute/private/legacy-control-public.key \
  --execution-private-key /absolute/private/execution-private.key \
  --output /absolute/private/signed-execution-permit.json
```

signer 在读取 private key 之前会完成全部公共证据、receipt、snapshot 和
Execution keyring 检查；读取 private key 后还会再验一次 #165 全链。输出采用
create-only 写入，目标文件已存在时直接失败。

## 5. Default-off 配置

保持以下开关为 `false`，直至人工核对全部 pin 和路径：

```dotenv
COMMODITY_C_FAST_SIMNOW_SHAKEDOWN_ENABLED=false
COMMODITY_C_FAST_SIMNOW_AUTO_DISPATCH_ENABLED=false
COMMODITY_C_FAST_SIMNOW_EXECUTION_PERMIT_ENABLED=false
```

启用 bridge 前必须填写 `.env.example` 中全部
`COMMODITY_C_FAST_SIMNOW_RESEARCH_*`、
`COMMODITY_C_FAST_SIMNOW_RESEARCH_ACCEPTANCE_*` 和
`COMMODITY_C_FAST_SIMNOW_EXECUTION_PERMIT_*` 字段。九件 artifact path 使用
JSON object，key 必须精确等于：

```text
freeze_contract, research_manifest, signal_evidence, target_evidence,
allocation_evidence, daily_roll_evidence, reference_price_evidence,
calendar_authority, contract_spec_evidence
```

另外必须预创建独立 Execution one-shot custody。生产环境要求 root owner
UID `0`、目录 mode `0700`，其 parent 也必须 root-owned 且不能
group/world writable。运行时不创建该目录；Acceptance-use 与 Permit-consume
均通过已 pin 的 guarded dirfd、`O_EXCL|O_NOFOLLOW` 写入，并在 file fsync 后
执行 directory fsync。可在受控主机上生成首次 pin：

```bash
PYTHONPATH=backend python - <<'PY'
from pathlib import Path
from app.services.commodity_c_fast_one_shot_custody import one_shot_custody_pins

pins = one_shot_custody_pins(
    Path("/absolute/root-owned/cfast-execution-one-shot"),
    expected_owner_uid=0,
)
print("COMMODITY_C_FAST_SIMNOW_EXECUTION_ONE_SHOT_EXPECTED_ROOT_PATH_SHA256="
      + pins.root_path_sha256)
print("COMMODITY_C_FAST_SIMNOW_EXECUTION_ONE_SHOT_EXPECTED_IDENTITY_SHA256="
      + pins.identity_sha256)
PY
```

production image 只打包 #165/#178 runtime 所需的三个 verifier 模块和七份
schema；Research/Acceptance/Execution signer、private key loader、producer 和
其余 `scripts/` 不进入镜像。镜像构建会执行
`app.services.commodity_c_fast_permit_runtime_smoke`，确认 full #165 verifier 可
绑定、schema 路径闭合且三个运行开关默认均为 `false`。任何模块/schema 缺失、
路径漂移或 signer 意外进入镜像都会使构建/测试失败。

base `deployments/docker-compose.prod.yml` 不包含 C_FAST permit custody mount。
如需先做默认关闭的只读部署预检，必须显式叠加：

```bash
docker compose \
  -f deployments/docker-compose.prod.yml \
  -f deployments/docker-compose.c-fast-simnow-permit.yml \
  config
```

overlay 要求人工提供四个已经存在的绝对 host directory；`create_host_path=false`
禁止 Compose 隐式创建或替换 custody：

- `COMMODITY_C_FAST_SIMNOW_ARTIFACTS_HOST_DIR`：#160 install chain、#165
  Acceptance/consume/receipt、九件 artifacts 和 signed Execution Permit，只读；
- `COMMODITY_C_FAST_SIMNOW_KEYRINGS_HOST_DIR`：Research/Acceptance/Execution
  public keyrings，只读；
- `COMMODITY_C_FAST_SIMNOW_SNAPSHOT_HOST_DIR`：已安装 shakedown snapshot，只读；
- `COMMODITY_C_FAST_SIMNOW_ONE_SHOT_HOST_DIR`：独立 root-owned `0700` one-shot
  custody，唯一可写 mount。

container target 固定为 `/run/c-fast-simnow/{artifacts,keyrings,snapshot,one-shot}`。
路径、identity 和 raw SHA pins 必须针对 container 内 target 重新生成，不能复制
host pathname hash。该 overlay 仍强制
`COMMODITY_C_FAST_SIMNOW_SHAKEDOWN_ENABLED=false`、
`COMMODITY_C_FAST_SIMNOW_AUTO_DISPATCH_ENABLED=false` 和
`COMMODITY_C_FAST_SIMNOW_EXECUTION_PERMIT_ENABLED=false`；它只允许挂载后执行
只读检查，不提供启用或下单入口。后续短时启用必须使用另行人工批准的私有
override/release，并重新完成全链 preflight。

## 6. 一次性消费与重放

人工 preview 不消费 Execution Permit。人工 start 在任何订单提交前：

1. 按 Acceptance receipt raw SHA256 创建独立 create-only use marker；
2. 按 permit id 创建 v2 create-only consumption receipt；
3. 持久化 active plan；
4. 才允许进入现有 dispatch / reconcile 状态机。

因此，同一 #165 receipt 即使被重新签出不同 permit id，也会被第一层
Acceptance use marker 拒绝。若 use marker 已创建但后续持久化失败，该
Acceptance 永久烧毁，属于安全失败，不得删除 marker 后重试。

两个 marker 位于同一个独立、path/device/inode/owner/mode identity-pinned
custody 中，而不是从普通 session state path 派生的可替换目录。每次读写都会
在 guarded dirfd 前后复核 root identity；marker 必须是 owner 一致、`0600`、
single-link 的普通文件和 exact canonical JSON。目录被重建、替换或变成
symlink 时，即使路径字符串相同也会 fail closed。此本地机制不替代外部
WORM/append-only 备份；生产 custody 的删除、迁移和 pin rotation 必须单独
人工审批。

## 7. 必须拒绝的情况

- 缺少 full PR #165 verifier；
- Research artifact、installed bundle/claim/receipt 或任一 keyring 变化；
- Acceptance 签名、marker、receipt、raw/canonical hash 或 consume id 变化；
- receipt/marker splice、错误 filename、错误 custody root/identity；
- Acceptance 或 permit 未生效、过期、时钟回退或超 TTL；
- account、execution day、selected products、selected target、formula 或
  snapshot hash 不匹配；
- Execution key material 与 Research/Acceptance key material 相同；
- 任一 unused Execution key 非法、重复或跨 Research/Acceptance key domain；
- one-shot custody root/parent owner、mode、path 或 inode identity 变化；
- marker symlink、非 `0600`、非 exact canonical bytes 或 directory fsync 失败；
- legacy embedded permit 单独出现；
- permit 或 Acceptance receipt 已使用；
- 任何 production/live/deployment/automatic-promotion 字段为 true。

发生任一拒绝时，不得调用 RPC、订单或仓位接口，也不得删除 custody 或
create-only use 证据。
