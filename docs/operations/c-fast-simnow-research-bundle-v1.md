# C_FAST 独立 SimNow Research bundle v1

## 1. 范围与安全边界

本流程只封装 `C_FAST_CROSS_SECTION_NEUTRAL` 的一次性、不可计入
official-forward 的 SimNow 研究事实。它不读取账户或成交数据，不连接
Web Bridge RPC，不生成订单，不修改持仓，也不授予任何 runtime、network、
dispatch、trading 或 production 权限。

Issue #157 只交付 schema、raw verifier、public-check-first signer、
create-only installer/receipt、INVALID/PENDING 模板和测试。仓库没有内置真实
research bundle，也没有把 bundle 接入 Settings、API、RPC、TradeService 或
adapter。现有 official-forward 文件及其行为不变。

签名 bundle 和 install receipt 都只是 Research Evidence，不是 Authority。
即使二者验证通过，仍不得据此启动策略、发单、替换现有 shadow/official
候选或声明 countable forward。

## 2. 外部生产者必须提供的事实

外部研究生产者必须先冻结以下九份非空原始文件；签名后不得转码、排序、
格式化或重导出：

| 参数 | 原始事实 |
| --- | --- |
| `--freeze-contract` | 冻结规则和研究边界 |
| `--research-manifest` | 本次生产批次、来源和 lineage |
| `--signal-evidence` | 21/63/126 official-day 趋势符号及 60 日波动率 |
| `--target-evidence` | 连续权重、buffer 后权重与整数目标 |
| `--allocation-evidence` | 2,000 万 CNY 虚拟 NAV 和约束检查 |
| `--daily-roll-evidence` | 当日 PIT OI 主力、DTE 和次一 official day |
| `--reference-price-evidence` | execution day 的 official open |
| `--calendar-authority` | official-day 日历证据 |
| `--contract-spec-evidence` | exact contract、multiplier 和 price tick |

bundle 必须覆盖 `ag/al/au/bu/cu/rb/ru/sc/sp/zn` 十个品种，使用
`DAILY_PIT_OI_MAIN`、cold-start previous quantity `0`，且
`research_as_of_official_day < execution_day`。有效期必须为 execution day
当日、正数且不超过 24 小时。

verifier 会绑定九份文件的 exact raw bytes 并核对 bundle 内的冻结公式、
约束、DTE 和 contract spec 字段，但不会解析这些外部文件来重放 PIT、
calendar 或 allocator。上述来源事实仍是 signer 的 Research assertion，
不能表述为 runtime 独立重推导。

v1 不允许从 Web Bridge 账户、订单、成交或持仓反推 target，也不允许
dynamic selection、replay 或自动 promotion。它故意固定
`COLD_START_ZERO_ACCOUNT`，避免把模拟账户历史误写入 research fact。

## 3. INVALID/PENDING 模板

模板位于
`docs/operations/c-fast-simnow-research-bundle-v1.template.json`。它故意：

- 带有 schema 禁止的 `template_state`；
- 缺少 `signature`；
- 含 `PENDING_` 文本、零长度 artifacts、无效日期/合约/价格。

因此模板本身不能验证、不能签名。外部生产者必须复制到私有目录，填写全部
研究事实并删除 `template_state`。`bundle_id`、raw artifact bindings、
artifact index、工具/schema/keyring hash 和 formula/target binding 由 signer
从精确字节重新计算，不得手工宣称。

## 4. Trusted keyring 与权限

keyring 必须严格符合
`docs/schemas/commodity-c-fast-simnow-research-bundle-trusted-keys-v1.schema.json`：

```json
{
  "schema_version": "commodity_c_fast_simnow_research_bundle_trusted_keys_v1",
  "purpose": "c_fast_simnow_research_bundle_signer",
  "keys": [
    {
      "key_id": "c-fast-research-key-a01",
      "purpose": "c_fast_simnow_research_bundle_signer",
      "public_key_base64": "<44-char Ed25519 raw public key base64>"
    }
  ]
}
```

私钥、keyring、unsigned draft 和 signed bundle 必须是当前用户所有的普通
非 symlink 文件，权限 `0600` 或更严格。输出父目录必须预先存在、归当前
用户所有、权限 `0700`，且路径中不得经过 symlink。

keyring 和 signer source 的精确 raw SHA256 都必须通过独立渠道冻结；不要
从待验证 bundle 读取这些 pin：

```bash
shasum -a 256 /private/c-fast/trusted-keyring.json
shasum -a 256 scripts/commodity_c_fast_simnow_sign_research_bundle.py
```

key ID 和 public-key material 都必须唯一。raw pin、purpose、schema 或
签名任一不一致都 fail closed。

生产安装目录是独立的 custody 边界：必须预先存在、归 root 所有，且
group/world 不可写。先在目标机器导出路径与 inode identity pin，并通过独立
渠道交给 signer：

```bash
sudo install -d -o root -g root -m 0700 \
  /var/lib/c-fast-simnow-research-custody
sudo python scripts/commodity_c_fast_simnow_research_bundle.py custody-pins \
  --custody-root /var/lib/c-fast-simnow-research-custody
```

`custody_root_path_sha256` 与 `custody_identity_sha256` 会进入签名 payload；
换目录、目录重建或 inode 变化后，旧 bundle 不得继续安装。

## 5. 签名：先公开检查，再读取私钥

先准备公共参数：

```bash
ARTIFACT_ARGS=(
  --freeze-contract /sealed/freeze-contract.json
  --research-manifest /sealed/research-manifest.json
  --signal-evidence /sealed/signal-evidence.json
  --target-evidence /sealed/target-evidence.json
  --allocation-evidence /sealed/allocation-evidence.json
  --daily-roll-evidence /sealed/daily-roll-evidence.json
  --reference-price-evidence /sealed/reference-price-evidence.json
  --calendar-authority /sealed/calendar-authority.json
  --contract-spec-evidence /sealed/contract-spec-evidence.json
)
KEYRING_RAW_SHA256="<out-of-band lowercase sha256>"
SIGNER_SHA256="<out-of-band lowercase signer source sha256>"
CUSTODY_ROOT_PATH_SHA256="<out-of-band custody path pin>"
CUSTODY_IDENTITY_SHA256="<out-of-band custody identity pin>"
```

然后签名：

```bash
python scripts/commodity_c_fast_simnow_sign_research_bundle.py \
  --input /private/c-fast/unsigned-bundle.json \
  --output /private/c-fast/signed-bundle.json \
  --private-key-file /private/c-fast/research-signing-key \
  --trusted-keyring /private/c-fast/trusted-keyring.json \
  --expected-trusted-keyring-raw-sha256 "${KEYRING_RAW_SHA256}" \
  --expected-signer-sha256 "${SIGNER_SHA256}" \
  --expected-custody-root-path-sha256 "${CUSTODY_ROOT_PATH_SHA256}" \
  --expected-custody-identity-sha256 "${CUSTODY_IDENTITY_SHA256}" \
  "${ARTIFACT_ARGS[@]}"
```

signer 会在读取私钥前完成 schema、PENDING、raw artifact、keyring raw pin、
自身 source raw SHA256、时间窗、十品种集合、公式、权重上限、整数
exposure、PIT-main/DTE、contract spec 及工具 hash 检查。输出使用
`O_EXCL` create-only；目标已存在、父目录不私有或 symlink 都会拒绝。

## 6. 独立验证与 create-only 安装

独立验证：

```bash
python scripts/commodity_c_fast_simnow_research_bundle.py verify \
  --bundle /private/c-fast/signed-bundle.json \
  --trusted-keyring /private/c-fast/trusted-keyring.json \
  --expected-trusted-keyring-raw-sha256 "${KEYRING_RAW_SHA256}" \
  --expected-signer-sha256 "${SIGNER_SHA256}" \
  "${ARTIFACT_ARGS[@]}"
```

verifier 只比较签名 payload 内的 `signer_sha256` 与独立 pin；它不 import、
定位或读取 signer 文件。因此未来独立 verifier/custody 环境可以排除私钥和
signer，同时仍保持 signer source identity 的 fail-closed 核验。

安装到签名绑定的 root-owned custody 目录：

```bash
python scripts/commodity_c_fast_simnow_research_bundle.py install \
  --bundle /private/c-fast/signed-bundle.json \
  --trusted-keyring /private/c-fast/trusted-keyring.json \
  --expected-trusted-keyring-raw-sha256 "${KEYRING_RAW_SHA256}" \
  --expected-signer-sha256 "${SIGNER_SHA256}" \
  --custody-root /var/lib/c-fast-simnow-research-custody \
  "${ARTIFACT_ARGS[@]}"
```

installer 先验证 source exact raw 与签名 custody pin，再从 `bundle_id`
唯一推导 claim、bundle、receipt 三个文件名。它先以 `O_EXCL` 写 one-shot
claim（绑定 bundle raw/canonical hash、artifact index 和 custody identity），
再写完全相同的 signed raw bytes，重新读取验证，最后写 receipt；每个阶段
都复核 custody 路径与 inode。并发安装、同 bundle 换目录、目录替换或任何
已存在 claim 都拒绝。若 claim/bundle 已写但 receipt 缺失，视为安装未完成
且无 authority，不得删除 claim 后重试旧 bundle。

receipt 固定为
`RESEARCH_BUNDLE_INSTALLED_NO_RUNTIME_AUTHORITY`，所有 authority 字段仍为
`false`。本版本没有 runtime consumer，安装成功也不会触发 SimNow 发单。

## 7. 失败处理与验证命令

以下情况必须重新生产新的 execution-day bundle，不得修改已签名 JSON：
artifact 任一字节变化、签名失败、keyring pin 变化、过期、公式/target 漂移、
PIT-main/DTE 或 contract spec 不一致、输出冲突。

开发侧验证：

```bash
pytest -q backend/tests/unit/test_commodity_c_fast_simnow_research_bundle.py
pytest -q \
  backend/tests/unit/test_commodity_c_fast_shadow.py \
  backend/tests/unit/test_commodity_c_fast_simnow.py
ruff check \
  scripts/commodity_c_fast_simnow_research_bundle.py \
  scripts/commodity_c_fast_simnow_sign_research_bundle.py \
  backend/tests/unit/test_commodity_c_fast_simnow_research_bundle.py
python -m py_compile \
  scripts/commodity_c_fast_simnow_research_bundle.py \
  scripts/commodity_c_fast_simnow_sign_research_bundle.py
git diff --check
```
