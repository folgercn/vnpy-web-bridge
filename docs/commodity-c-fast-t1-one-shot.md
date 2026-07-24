# C_FAST T1 一次性只读审计授权

## 结论与边界

本工具把 Issue #114 的真实 QuestDB T1 收紧为一次、短时、人工签名的只读查询：

```text
signed release
  -> offline verify
  -> create-only + fsync consume marker
  -> fixed audit child process
  -> validate evidence/proof cross-bindings
  -> create-only + fsync terminal seal
```

代码合并、镜像构建或 readonly companion proof 都不自动授予 T1。只有同时满足
专用 Ed25519 key purpose、有效期、所有代码/镜像/schema/manifest/endpoint/build
绑定及显式人工文本的 release，才允许 one-shot runner 启动审计子进程。

固定禁止：

```text
write_probe_authorized=false
database_mutation_authorized=false
order_authorized=false
position_mutation_authorized=false
dispatch_authorized=false
deployment_mutation_authorized=false
```

本 PR 不连接 QuestDB、不修改部署、不创建 secret，也不启动 runner。

## 三个不可变事实

### Release

`commodity_c_fast_t1_one_shot_release_v1` 使用 canonical JSON
（UTF-8、key 排序、无空白分隔、拒绝 NaN/Infinity）排除 `signature` 后做
Ed25519 签名。trusted key 的 purpose 必须严格等于：

```text
t1_audit_release_signer
```

研究快照 key、execution-policy key 或其他 key 都不能替代。`human_signature`
是被 Ed25519 签名覆盖的人工审计文本，必须非空且不能以 `PENDING_` 开头。

`attempt_id` 不能手填为任意值：

```python
import hashlib

release_id = "c-fast-t1-20260901-a01"
attempt_id = "attempt-" + hashlib.sha256(
    release_id.encode("utf-8")
).hexdigest()
print(attempt_id)
```

签名脚本会自动生成或核对该值。release 的最长 TTL 为 24 小时，单次 runner
最长为 1,800 秒。

### Consume marker

runner 在读取 DSN 内容、建立网络连接或启动子进程之前，先用 `O_EXCL` 创建并
`fsync` consume marker。marker 存在时永不重跑：

- terminal 已存在：只报告已有终态，退出非零；
- terminal 不存在：报告
  `CONSUMED_WITHOUT_TERMINAL_REQUIRES_NEW_RELEASE`，必须重新人工签发 release。

在同一个部署身份内不能通过更换输出目录复用 release。runner 不接受命令行提供
的任意 custody 作为权威：部署必须独立固定
root-owned 只读文件 `/run/c-fast-t1-pins/custody.path`，release 同时绑定其
canonical absolute path SHA256 和目录中 `custody-identity.json` 的 canonical
SHA256。复制 identity 到另一个路径仍会被拒绝。

custody identity 格式：

```json
{
  "schema_version": "commodity_c_fast_t1_custody_identity_v1",
  "custody_id": "c-fast-t1-custody-prod-a01"
}
```

目录权限必须为 `0700` 或更严，identity、trusted keyring 和 readonly DSN
必须为当前用户所有的 `0600` 普通文件，禁止 symlink。
custody 的父目录必须 root-owned 且 group/world 不可写；runner 全程持有
`O_DIRECTORY|O_NOFOLLOW` directory FD，consume/terminal 和 attempt mkdir
通过 `openat/mkdirat` 相对该 FD 完成，并在 child 前后核对 dev/inode。

### Terminal record

审计退出后总是尝试 create-only terminal record。终态区分：

| 终态 | 含义 |
|---|---|
| `SUCCEEDED_P0_PASS` | exit 0，全部 schema/hash/proof 交叉验证通过，P0 pass |
| `COMPLETED_P0_BLOCKED` | exit 1，证据完整但 P0 有 blocker |
| `FAILED_CHILD` | 启动失败或非审计退出码 |
| `FAILED_OUTPUT_VALIDATION` | exit 0/1，但产物缺失、无效或交叉绑定失败 |
| `TIMED_OUT` | 超过 signed runtime 上限 |
| `INTERRUPTED` | runner 收到人工中断 |

exit 0 本身不能构成 P0 pass。terminal 必须同时绑定 signed release、consume
marker、固定 child argv、四个产物的精确字节 SHA256、endpoint、QuestDB build
和所有零写入/零交易 invariants。已有 terminal 只有在重新核对 consume exact
bytes、release/attempt/manifest/custody bindings 和 state semantics 后才会被
报告。

本地 `O_EXCL + fsync` 记录不是 WORM 或硬件签名证明，固定：

```text
p0_acceptance_authorized=false
terminal_integrity_scope=CREATE_ONLY_LOCAL_RECORD_REQUIRES_EXTERNAL_CUSTODY
```

正式 P0 acceptance 还需外部 append-only/WORM 归档或独立签名。本工具不会把
可修改的本地 `0600` 文件伪称为不可篡改 seal。

## endpoint 与 build 绑定

endpoint identity 从已建立的 psycopg 连接读取 `host/port/dbname` 后计算：

```python
import hashlib
import json

identity = {
    "dbname": "qdb",
    "host": "questdb.internal",
    "port": 8812,
}
endpoint_identity_sha256 = hashlib.sha256(
    json.dumps(
        identity,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    ).encode("utf-8")
).hexdigest()
```

签署者必须按隔离 runner 实际使用的连接参数生成 expectation。审计脚本在连接后
核对它，并在 readonly proof 中保存 hash；不在 proof 中保存 endpoint 原文。
QuestDB build 使用 `SELECT build()` 返回完整字符串的 UTF-8 SHA256，terminal
再从 proof 重算并核对 signed expectation。

## trusted keyring

keyring 是独立 `0600` 文件，release 同时绑定其 canonical SHA256：

```json
{
  "schema_version": "commodity_c_fast_t1_trusted_keys_v1",
  "keys": [
    {
      "key_id": "c-fast-t1-release-key-a01",
      "purpose": "t1_audit_release_signer",
      "public_key_base64": "<32-byte Ed25519 public key base64>"
    }
  ]
}
```

重复 key、未知字段、错误 purpose 或非 32-byte Ed25519 key 全部 fail closed。

release 对 keyring hash 的自我声明不是信任根。隔离 runner 必须从固定路径的
root-owned、group/world 不可写 pin file 读取：

```text
/run/c-fast-t1-pins/trusted-keyring.sha256
```

文件只包含 exact canonical keyring SHA256。runner 先核对 deployment pin，
再使用 keyring 验 release；攻击者自建 keyring、自签 release 并填入匹配 hash
仍会失败。CLI/环境变量不能覆盖 pin 路径或值；任何变更属于另一份人工主审的
部署 release。

## 生成与签署

先由人工在离线环境填写 unsigned release JSON。`attempt_id` 和 `signature`
可以省略；其他字段必须完整，所有 SHA256 必须来自待运行的 exact
commit/image/files/manifest/keyring/custody identity/custody path。审计 bundle
还绑定保留的 evidence v1 schema，因为 evidence v2 离线 resolver 依赖它。

```bash
.venv/bin/python scripts/commodity_c_fast_t1_sign_release.py \
  --input /secure/c-fast-t1-release.unsigned.json \
  --private-key-file /secure/c-fast-t1-release-key.pem \
  --output /secure/c-fast-t1-release.signed.json
```

签名工具要求私钥为当前用户所有的 `0600` 非 symlink 普通文件，并用
create-only `0600` 输出；不会覆盖已有签名 release。

`runtime_image_digest` 和 `source_commit_sha` 来自隔离执行器的外部事实。runner
只把命令行断言与 signed release 比较，不能在容器内部自行证明 Docker
RepoDigest；正式归档不得把这一比较描述为供应链 attestation。

## 执行

只有独立人工部署 release 已完成 readonly principal、secret、隔离网络、
镜像 digest 和回滚核对后，才可运行：

```text
/run/c-fast-t1-pins/trusted-keyring.sha256
/run/c-fast-t1-pins/custody.path
```

上述两个 pin 必须由部署层只读挂载、owner UID 为 0，且 group/world 不可写；
one-shot 调用者不能通过 CLI 或环境变量覆盖。

```bash
.venv/bin/python scripts/commodity_c_fast_t1_one_shot.py \
  --release /run/release/c-fast-t1-release.signed.json \
  --trusted-keyring /run/release/c-fast-t1-trusted-keys.json \
  --manifest /run/release/c-fast-audit-manifest.json \
  --dsn-file /run/secrets/c-fast-t1-readonly.dsn \
  --custody-dir /var/lib/c-fast-t1-custody \
  --source-commit-sha <exact-40-char-git-sha> \
  --runtime-image-digest sha256:<exact-64-char-digest>
```

consume marker 落盘后，runner 把预检时已经读取并核验的 audit script、
manifest 和四个 schema bytes create-only staged 到私有 attempt bundle；
输出进入单独可写 `artifacts/` 子目录，attempt parent 随后收紧为 `0500`，
防止整体替换 verified bundle。child 前后还会重核 staged bytes。子进程不再
打开原始可变代码/manifest 路径。审计脚本会在读取 staged manifest 后、读取
DSN/连接网络前核对 signed canonical manifest SHA256。

子进程使用参数数组、`shell=False`、`stdin=DEVNULL`、固定 staged cwd、白名单
环境和 signed timeout。它只调用：

```text
python -I scripts/commodity_c_fast_l1_l5_audit.py
```

不会调用 Web Bridge API、RPC、TradeService、订单、撤单、持仓或 dispatch。

## 当前仍然阻塞

合并本 PR 后仍不得宣称 `t1_executed=true` 或 `p0_pass=true`。正式 T1 还需要：

1. 人工 L3 部署 release 建立 dedicated readonly principal 和 file secret；
2. 锁定 QuestDB image digest/build、writer continuity、health 与 rollback；
3. 构建 exact source SHA 的隔离 runner image并归档 RepoDigest；
4. 冻结十品种 manifest、endpoint/build expectations 和短 TTL release；
5. 人工主审并签署；
6. 执行后归档 consume、terminal 和四个产物。

任何 `COMPLETED_P0_BLOCKED`、失败、timeout 或 consumed-without-terminal 都不会
自动恢复、重跑、启动 execution-quality collection 或进入 SimNow shakedown。
