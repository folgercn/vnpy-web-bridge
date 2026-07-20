# STATIC_CORE_EQUAL 商品组合 SimNow 接入

## 接入边界

Web Bridge 接入的是已冻结的商品组合执行控制面，不在运行时重新搜索参数或计算研究信号。研究侧每月输出一个 Ed25519 签名的 exact-contract 整数目标批次，Web Bridge 只在已核验的 SimNow 账户上完成：

1. 校验冻结策略、签名、批次链、合约规格、签名参考价敞口和当前持仓。
2. 用新鲜盘口生成限价拆单计划。
3. 用实时可成交保护价重新核算完整目标组合敞口，并按“持仓 + 活动开仓单 + 本阶段全部子单”校验单合约上限。
4. 在一次显式 SimNow 自动派单授权后，后台 worker 自动提交平仓阶段。
5. 委托结束且持仓对账通过后，自动提交开仓阶段。
6. 最终持仓完全匹配后保存完成状态和真实成交/滑点快照。

策略页提供 `一键启动`。运行参数不是由用户临时选择：品种固定为十品种、再平衡周期固定为月度，主力 exact contract 由冻结研究流水线按 PIT 持仓量链生成并写入签名目标文件。部署环境配置一次目标文件路径后，日常启动不需要手选品种、周期或合约。

控制器固定为：

- `scheduler_id=STATIC_CORE_EQUAL`
- `source_combination_arm=CORE_EQUAL_TARGET`
- 候选权重 `C=0.5, D=0.5`
- guardband：产品 `0.12`、板块 `0.27`、gross `0.8`、目标净敞口 `0`
- 分配器 `FINITE_NEIGHBOURHOOD_BEAM_V1`：半径 `2`、beam `2048`、净敞口惩罚 `1`
- 虚拟 NAV：`20,000,000 CNY`
- 冻结品种：`ag, al, au, bu, cu, rb, ru, sc, sp, zn`
- `simnow_shakedown`：部署后可用当日签名目标立即真实发单，永远标记 `countable_forward=false`
- `official_forward`：第一个可计数 source month 为 `2026-08`，对应执行月份 `2026-09`

它不在运行时自动生成信号、目标或晋级到生产账户；`production_allowed` 永远为 `false`。白名单 SimNow 账户完成 `/enable` 的自动派单确认后，`auto_dispatch_allowed=true`，禁用控制器、紧急停止或部分提交都会停止自动推进。`CTP` gateway 名称本身不能证明是 SimNow，账户 SHA256 白名单才是执行边界。

## 环境配置

先用只读 RPC smoke 确认当前 Web Bridge 确实连到目标 SimNow 进程：

```bash
PYTHONPATH=backend .venv/bin/python test_rpc_readonly.py
```

不要沿用默认 `127.0.0.1` 作为验收证据。实际 RPC 地址应在本地 `.env` 或部署环境中显式配置。获取账户 ID 后，用隐藏输入生成白名单哈希：

```bash
python - <<'PY'
import getpass
import hashlib

account_id = getpass.getpass("SimNow account ID: ")
print(hashlib.sha256(account_id.encode("utf-8")).hexdigest())
PY
```

生成独立 Ed25519 签名密钥。私钥只写入本机 `0600` 文件，仓库和 `.env` 中只放公钥：

```bash
python - <<'PY'
import base64
import json
from pathlib import Path
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

path = Path("~/.config/vnpy-web-bridge/commodity-simnow-ed25519.pem").expanduser()
path.parent.mkdir(parents=True, exist_ok=True)
key = Ed25519PrivateKey.generate()
path.write_bytes(key.private_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PrivateFormat.PKCS8,
    encryption_algorithm=serialization.NoEncryption(),
))
path.chmod(0o600)
public = key.public_key().public_bytes(
    encoding=serialization.Encoding.Raw,
    format=serialization.PublicFormat.Raw,
)
print(json.dumps({"research-key-1": base64.b64encode(public).decode("ascii")}))
PY
```

本地环境至少需要：

```env
VNPY_RPC_REQ_ADDRESS=tcp://<simnow-rpc-host>:2014
VNPY_RPC_PUB_ADDRESS=tcp://<simnow-rpc-host>:4102
VNPY_GATEWAY_NAME=CTP
DEFAULT_GATEWAY_NAME=CTP

WEB_TRADE_ENABLED=true
ORDER_CONFIRM_REQUIRED=true
COMMODITY_SIMNOW_ENABLED=true
COMMODITY_SIMNOW_GATEWAY_NAME=CTP
COMMODITY_SIMNOW_ACCOUNT_HASHES=<上一步生成的64位小写SHA256>
COMMODITY_SIMNOW_TRUSTED_PUBLIC_KEYS_JSON={"research-key-1":"<base64-public-key>"}
COMMODITY_SIMNOW_STATE_PATH=logs/commodity-simnow/state.json
COMMODITY_SIMNOW_MIN_SOURCE_MONTH=2026-08
COMMODITY_SIMNOW_MAX_CHILD_ORDER_LOTS=10
COMMODITY_SIMNOW_MAX_ORDERS_PER_PHASE=128
COMMODITY_SIMNOW_MAX_QUOTE_AGE_SECONDS=5
COMMODITY_SIMNOW_MAX_SPREAD_TICKS=4
COMMODITY_SIMNOW_AUTO_DISPATCH_ENABLED=true
COMMODITY_SIMNOW_AUTO_DISPATCH_INTERVAL_SECONDS=1
COMMODITY_SIMNOW_AUTO_DISPATCH_RECONCILE_GRACE_SECONDS=30
COMMODITY_SIMNOW_SUBMISSION_OUTCOME_GRACE_SECONDS=30
COMMODITY_SIMNOW_SUBMISSION_OUTCOME_MIN_EMPTY_SNAPSHOTS=3
COMMODITY_SIMNOW_ACCEPTANCE_PASSIVE_LIMIT_ENABLED=false
COMMODITY_SIMNOW_ACCEPTANCE_PASSIVE_LIMIT_TTL_SECONDS=15
COMMODITY_SIMNOW_ACCEPTANCE_MAX_TOTAL_ORDERS=2
COMMODITY_SIMNOW_ACCEPTANCE_MAX_TOTAL_LOTS=2
COMMODITY_SIMNOW_TEMPLATE_BATCH_PATH=/absolute/path/to/current-signed-target.json
COMMODITY_SIMNOW_DELIVERY_MONTH_CUTOFF_DAY=1
COMMODITY_SIMNOW_SC_PRE_DELIVERY_CUTOFF_DAY=15
```

研究流水线必须先写临时文件并用同文件系统的原子 rename 替换 `COMMODITY_SIMNOW_TEMPLATE_BATCH_PATH`，不要原地覆盖。控制器只读取单个不超过 2 MiB 的 v2 JSON；文件缺失、半写、schema 错误、签名错误、批次链错误或合约到期保护失败都会撤销本次模板和自动派单授权。

通用风控仍然生效。`RISK_MAX_ORDER_VOLUME` 必须不小于计划中的单笔拆单手数；控制器会在阶段零提交之前，按当前持仓、已有活动开仓委托和本阶段全部子单累计校验 `RISK_MAX_SYMBOL_POSITION`，拆单不能绕过单合约上限。不要为了通过执行而关闭交易所、价格、持仓或日亏损校验。

## 目标批次与签名

研究侧无签名 JSON 必须包含十个冻结品种，并使用以下 schema：

```text
commodity_static_core_equal_target_batch_v2
```

关键约束：

- `execution_lane=simnow_shakedown` 时，`execution_day` 可以是部署或运行当天；`source_month` 只要求不晚于当天所在月份，计划和完成状态均明确标记 `countable_forward=false`。
- `execution_lane=official_forward` 时，`source_month` 不得早于 `2026-08`，且 `execution_day` 必须在 source month 的下一个自然月；计划标记 `countable_forward=true`。
- `execution_day`、shakedown source month 和全部到期保护统一使用期货交易日语义，不是上海自然日；夜盘 21:00 后及跨午夜后的同一夜盘归属同一个 trading day。
- 两条通道都只能在 `execution_day` 对应交易日预览和执行，且都使用相同的签名、SimNow 账户白名单、风控、两阶段派单与持仓对账。
- 冷启动十个 `previous_target_quantity` 都为 `0`，`previous_batch_hash=null`。
- 后续批次必须逐品种携带上一个完成状态的 `previous_exact_contract` 和手数，包括零手品种。
- `exact_contract` 使用 `SHFE.ag2609` 形式；API 下单前转换为 vn.py 的 `ag2609.SHFE`。
- 目标手数、方向、参考开盘价、乘数、最小跳动和权重全部包含在签名中。

## 主力切换与到期保护

主力合约不由 Web 页面猜测，也不采用简单的 1/5/9 月启发式。冻结研究流水线负责按 PIT OI 主力链给出每个品种的 `previous_exact_contract` 和新 `exact_contract`。两者不同时，即使方向和目标手数完全不变，控制器也会把该品种列入 `roll_products` 并固定执行：

```text
旧主力平仓 -> 无活动委托且旧仓持仓对账为 0 -> 新主力开仓 -> 最终持仓对账 -> COMPLETE
```

平仓未全部结束、持仓不匹配或任一阶段部分提交时，绝不会提前开新约。正常换月因此不需要人工选择合约；研究流水线只要按时原子替换新的签名目标，worker 会自动加载并完成迁移。

硬到期保护比交易所强平边界更保守：

- SHFE 冻结品种在所属交易日进入交割月后即拒绝继续持有或新开该交割月合约；月末夜盘按下一交易日判断。
- INE 原油 `sc` 的最后交易日在交割月之前，所属交易日日期达到交割前月 15 日后拒绝该月合约；夜盘同样按所属交易日判断。
- worker 发现目标仍是旧文件、未来文件或已消费文件，同时账户还持有进入保护区间的合约，会进入安全停机、定向撤销本计划活动委托，并记录 `strategy_template_delivery_guard_halted`。

保护触发后不会绕过签名擅自生成清仓目标，也不会静默换到一个未经研究流水线确认的合约；必须检查目标生产任务、委托和持仓后，发布新的已签名换月或目标归零批次再重新一键启动。目标归零批次允许只平旧到期合约且不再开仓。[上期所交割管理办法](https://www.shfe.com.cn/regulation/exchangerules/otherrules/202508/t20250807_828519.html)要求自然人持仓在最后交易日前第五个交易日收盘后归零；[能源中心风险控制管理细则](https://www.ine.cn/regulation/ineregulation/rules/202606/t20260622_832199.html)要求不能交收发票的原油个人客户在最后交易日前第八个交易日收盘后归零。因此这里使用更早的日历硬截止，而不是把交易所强平日当作策略换月日。

签名：

```bash
PYTHONPATH=backend .venv/bin/python scripts/commodity_simnow_sign_target_batch.py \
  --input /path/to/unsigned-target.json \
  --output /path/to/signed-target.json \
  --private-key-file ~/.config/vnpy-web-bridge/commodity-simnow-ed25519.pem
```

脚本拒绝权限宽于 `0600` 的私钥，只输出目标路径和批次哈希，不输出私钥。

## 自动执行顺序

所有变更接口只允许 `admin`；`viewer/trader/admin` 均可读取状态、计划和事件。

```text
POST /api/commodity-simnow/enable
POST /api/commodity-simnow/preview
POST /api/commodity-simnow/template/start（一键启动，自动读取签名目标）
后台 worker：READY_CLOSE -> CLOSE_SUBMITTED -> 对账
后台 worker：READY_OPEN  -> OPEN_SUBMITTED  -> 对账 -> COMPLETE
POST /api/commodity-simnow/auto-advance（可选，管理员立即触发一次推进）
POST /api/commodity-simnow/disable
```

页面的一键启动调用 `/template/start`，一次确认 SimNow 专用、模板固定、自动派单和禁止生产执行；目标文件有效且为当天批次时会在同一请求中加载计划并立即提交第一个阶段。手工运维路径的 `enable` 仍必须显式提交 `confirm_auto_dispatch=true`，示例：

```json
{
  "manual_approval": true,
  "simnow_mode": true,
  "reason": "authorize frozen commodity targets on allowlisted SimNow account",
  "confirm_simnow_only": true,
  "confirm_no_production": true,
  "confirm_cold_start_or_reconciled_state": true,
  "confirm_manual_two_phase_dispatch": true,
  "confirm_auto_dispatch": true,
  "confirm_no_auto_promotion": true
}
```

`preview` 只接受当前期货交易日有效的签名目标；需要部署后立即成交时，研究侧签发当日 `execution_lane=simnow_shakedown` 批次即可，不需要等到 2026-09。preview 和每个开仓阶段提交前都会按最新盘口保护价重新核算完整 `expected_final_positions` 的产品、板块、gross 和净敞口；超限时整阶段零提交。成功后 worker 以一秒间隔自动推进，平仓委托未全部结束、持仓未达到 `expected_after_close` 时不会开仓。

人工 disable、emergency stop、跨交易日、到期保护、部分提交或终态对账超时都会进入安全停机。尚未发送任何订单的 `READY_CLOSE/READY_OPEN` 计划进入：

```text
HALTED_PRE_SUBMIT_SAFE --重新完整授权且阶段前持仓未变化--> 原 READY_CLOSE/READY_OPEN
```

该状态保存 `resume_status` 和 `pre_phase_expected_positions`，不要求账户先交易到阶段后目标；preview 后重启、首单前 disable 和一键启动的 pre-submit 风控失败都可安全重试。成功恢复及阶段推进时会清除旧 `halt` 控制字段，下一阶段停机不会复用旧 phase/resume 状态。已经开始提交或存在潜在活动委托时进入：

```text
CANCEL_PENDING -> 定向撤销本计划活动委托 -> HALTED_RECONCILE_REQUIRED
```

每个 child order 调用 `send_order()` 前都会先原子持久化包含唯一 reference、价格、数量和方向的 send intent；RPC 返回后再将 order id 与 intent 一并确认为 submitted。若进程停在两次落盘之间，或首单同步异常且零 submitted，会统一按 send-intent outcome 分类。确定发生在 RPC 前的本地风控/参数拒绝可直接进入 `HALTED_PRE_SUBMIT_SAFE`；RPC timeout、连接异常、进程崩溃等不确定结果进入：

```text
SUBMISSION_OUTCOME_UNKNOWN
  --宽限期内多次 orders/trades/positions 稳定空快照--> HALTED_PRE_SUBMIT_SAFE
  --任意迟到订单/成交证据--> CANCEL_PENDING -> HALTED_RECONCILE_REQUIRED
```

首次空快照绝不等同于未提交。默认至少等待 30 秒并取得 3 次稳定空快照；重新授权前仍会按当前阶段的全部不确定 reference 再查询 orders/trades，发现迟到证据立即撤单收口，禁止恢复 READY 或重复下单。

撤单意图会先以 `CANCEL_PENDING` 原子落盘，再查询 RPC 和发撤单；RPC 暂时不可用不会阻止后端启动或 disable，而是记录错误并由 worker/`auto-advance` 在 RPC 恢复后重试。撤单完成前保留计划、send intents、submitted order ids 和取消记录；即使自动派单和 Web 交易开关已经关闭，`reconcile` 仍允许执行只读收口对账。持仓匹配后状态为 `HALTED_RECONCILED`；不匹配时保持 `HALTED_RECONCILE_REQUIRED`，绝不会自动进入下一阶段。若停机发生在平仓阶段，只有重新提交完整 SimNow 授权后才会恢复为 `READY_OPEN`。

`GET /api/commodity-simnow/plan` 的 `execution` 包含每笔订单的实际成交量、成交均价、决策价、提交价、adverse slippage ticks、滑点金额和总 fill ratio。负的 adverse slippage 表示价格改善。成交快照来自 vn.py 的真实 order/trade 查询；如果 RPC 不提供成交查询，会明确返回 `available=false`，但仍以活动委托和权威持仓决定是否完成对账。

手工 `execute/reconcile` 接口保留为运维回退路径。未完成计划会原子保存到 `COMMODITY_SIMNOW_STATE_PATH` 同目录的 `*.active.json`，包括状态、send intents、submitted order ids 和停机撤单记录。进程重启后控制器恢复该计划并保持自动授权关闭：尚未提交的 `READY_*` 进入 `HALTED_PRE_SUBMIT_SAFE`；`SUBMITTING_*` 或零成功 `*_SUBMISSION_PARTIAL` 先进入 outcome 分类，未知结果保持 `SUBMISSION_OUTCOME_UNKNOWN`；已有提交证据的计划在 RPC 恢复后定向撤单并进入收口对账。已完成批次链继续保存在配置的状态文件中。

### 被动限价验收（仅 SimNow）

`COMMODITY_SIMNOW_ACCEPTANCE_PASSIVE_LIMIT_ENABLED` 默认必须保持 `false`。启用后仍只允许人工、`simnow_shakedown`、双确认的 `execute`；自动派单和 `official_forward` 会被拒绝。每个阶段还会在任何订单发送前校验 `COMMODITY_SIMNOW_ACCEPTANCE_MAX_TOTAL_ORDERS` 和 `COMMODITY_SIMNOW_ACCEPTANCE_MAX_TOTAL_LOTS`，超过任一上限即整阶段零提交。

请求必须显式声明模式：

```json
{
  "plan_hash": "<preview 返回的 hash>",
  "phase": "open",
  "confirm": true,
  "confirm_simnow_only": true,
  "confirm_manual_one_shot": true,
  "acceptance_passive_limit": true,
  "confirm_acceptance_passive_limit": true,
  "reason": "SimNow passive acceptance"
}
```

买单以买一、卖单以卖一提交，但这不是 post-only 保证：盘口变化、排队和对手盘都可能造成全成或部分成交。操作前必须选择允许真实成交的最小平衡目标，并预先准备平今/持仓对账。提交后控制器会在 `COMMODITY_SIMNOW_ACCEPTANCE_PASSIVE_LIMIT_TTL_SECONDS` 到期时自动进入 `CANCEL_PENDING`，按 reference 定向撤单并进入只读收口对账；RPC 暂不可用或进程重启时保留同一撤单意图并继续恢复。撤单成功不等于验收完成，必须以实际成交和最终持仓为准：有任何成交时先 flatten，再确认持仓与活动委托均为零。

## 验收

代码级验证：

```bash
PYTHONPATH=backend .venv/bin/python -m pytest -q backend/tests/unit/test_commodity_simnow.py
PYTHONPATH=backend .venv/bin/python -m pytest -q backend/tests/unit/test_commodity_simnow_api.py
```

真实 SimNow 验收必须在本地 RPC 地址、账户哈希、公钥和当日合法签名目标都配置完成后执行。至少覆盖：账户哈希核验、签名零目标/no-op、最小平衡手数真实下单、部分成交与撤单、进程重启恢复、紧急停止及活动订单收口。部署验收使用 `simnow_shakedown`；只有 `official_forward` 结果可以计入冻结策略的正式 forward 证据。未满足运行配置时，只能声明控制器和测试已就绪，不能声明真实 SimNow 已运行。
