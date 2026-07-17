# STATIC_CORE_EQUAL 商品组合 SimNow 接入

## 接入边界

Web Bridge 接入的是已冻结的商品组合执行控制面，不在运行时重新搜索参数或计算研究信号。研究侧每月输出一个 Ed25519 签名的 exact-contract 整数目标批次，Web Bridge 只在已核验的 SimNow 账户上完成：

1. 校验冻结策略、签名、批次链、合约规格、敞口和当前持仓。
2. 用新鲜盘口生成限价拆单计划。
3. 在一次显式 SimNow 自动派单授权后，后台 worker 自动提交平仓阶段。
4. 委托结束且持仓对账通过后，自动提交开仓阶段。
5. 最终持仓完全匹配后保存完成状态和真实成交/滑点快照。

控制器固定为：

- `scheduler_id=STATIC_CORE_EQUAL`
- `source_combination_arm=CORE_EQUAL_TARGET`
- 候选权重 `C=0.5, D=0.5`
- guardband：产品 `0.12`、板块 `0.27`、gross `0.8`、目标净敞口 `0`
- 分配器 `FINITE_NEIGHBOURHOOD_BEAM_V1`：半径 `2`、beam `2048`、净敞口惩罚 `1`
- 虚拟 NAV：`20,000,000 CNY`
- 冻结品种：`ag, al, au, bu, cu, rb, ru, sc, sp, zn`
- 第一个可计数 source month：`2026-08`，对应执行月份 `2026-09`

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
```

通用风控仍然生效。`RISK_MAX_ORDER_VOLUME` 必须不小于计划中的单笔拆单手数，`RISK_MAX_SYMBOL_POSITION` 必须覆盖签名目标；不要为了通过执行而关闭交易所、价格、持仓或日亏损校验。

## 目标批次与签名

研究侧无签名 JSON 必须包含十个冻结品种，并使用以下 schema：

```text
commodity_static_core_equal_target_batch_v1
```

关键约束：

- `source_month` 不得早于 `2026-08`。
- `execution_day` 必须在 source month 的下一个自然月，且只能当天预览/执行。
- 冷启动十个 `previous_target_quantity` 都为 `0`，`previous_batch_hash=null`。
- 后续批次必须逐品种携带上一个完成状态的 `previous_exact_contract` 和手数，包括零手品种。
- `exact_contract` 使用 `SHFE.ag2609` 形式；API 下单前转换为 vn.py 的 `ag2609.SHFE`。
- 目标手数、方向、参考开盘价、乘数、最小跳动和权重全部包含在签名中。

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
后台 worker：READY_CLOSE -> CLOSE_SUBMITTED -> 对账
后台 worker：READY_OPEN  -> OPEN_SUBMITTED  -> 对账 -> COMPLETE
POST /api/commodity-simnow/auto-advance（可选，管理员立即触发一次推进）
POST /api/commodity-simnow/disable
```

`enable` 必须显式提交 `confirm_auto_dispatch=true`，示例：

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

`preview` 只接受当日有效的签名目标；成功后 worker 以一秒间隔自动推进。平仓委托未全部结束、持仓未达到 `expected_after_close` 时不会开仓。发生部分提交时状态进入 `*_SUBMISSION_PARTIAL`，自动派单授权立即撤销。若活动委托已消失但持仓在 30 秒宽限期后仍不匹配，则进入 `*_RECONCILIATION_MISMATCH` 并停止自动推进。两种情况都不会自动重试或进入下一阶段，必须人工检查 SimNow 委托和持仓。

`GET /api/commodity-simnow/plan` 的 `execution` 包含每笔订单的实际成交量、成交均价、决策价、提交价、adverse slippage ticks、滑点金额和总 fill ratio。负的 adverse slippage 表示价格改善。成交快照来自 vn.py 的真实 order/trade 查询；如果 RPC 不提供成交查询，会明确返回 `available=false`，但仍以活动委托和权威持仓决定是否完成对账。

手工 `execute/reconcile` 接口保留为运维回退路径。进程重启会丢弃未完成的内存计划并撤销内存中的自动授权，已完成批次链保留在状态文件中；重启后必须重新 enable 和 preview。

## 验收

代码级验证：

```bash
PYTHONPATH=backend .venv/bin/python -m pytest -q backend/tests/unit/test_commodity_simnow.py
PYTHONPATH=backend .venv/bin/python -m pytest -q backend/tests/unit/test_commodity_simnow_api.py
```

真实 SimNow 验收必须在本地 RPC 地址、账户哈希、公钥和当月合法签名目标都配置完成后执行。未满足这些条件时，只能声明控制器和测试已就绪，不能声明真实 SimNow 已运行。
