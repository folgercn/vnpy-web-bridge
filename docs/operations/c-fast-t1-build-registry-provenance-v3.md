# C_FAST query-v4 build/registry provenance v3

## 结论与边界

本契约对应 Issue #216 的 query-v4 provenance 切片。它把独立签名的
builder/registry assertions 绑定到 query-v4 exact source bundle、OCI content
attestation、RepoDigest 和 runtime bundle。

验证成功只生成：

```text
SIGNED_QUERY_V4_BUILD_REGISTRY_ASSERTIONS_VERIFIED_NO_RUNTIME_AUTHORITY
```

receipt 仅证明签名和各项绑定通过。builder/registry facts 仍是外部签署事实，
offline verifier 不连接 builder 或 registry，因此固定：

```text
external_facts_independently_reverified=false
readiness_authorized=false
production_query_authorized=false
authority_granted=false
```

它不是 readiness、query release、P0 acceptance 或交易权限。

## 与 query-v3 v2 的隔离

v3 使用独立 schema、purpose、signer path、receipt status 和 query-v4 content
contract。v2/v3 payload 不能相互验证或改名升级。为安全复用已审计逻辑，v3
wrapper 显式绑定以下 exact bytes：

- v3 verifier；
- v2 verifier delegate；
- v2 signer delegate；
- delegates 唯一的本地 support module
  `commodity_c_fast_t1_one_shot.py`；
- v3 provenance/receipt schema；
- query-v4 content/source-manifest schema；
- query-v4 content verifier。

任一 wrapper、delegate、schema 或 verifier 漂移都会 fail closed。query-v3
v2 module 的全局 contract 不会被 v3 import 修改。

v2 verifier/signer delegate 不能通过普通 `importlib.exec_module` 直接从路径
执行。v3 wrapper 在任何 delegate `compile/exec` 前完成以下 bootstrap：

- wrapper 内硬编码已审查的 v2 verifier/signer exact SHA256；
- 对 resolved delegate path 使用 `O_NOFOLLOW` 打开；
- 要求 single-link regular file，拒绝 symlink 和 hardlink；
- 对同一 FD 稳定读取两次，并比较 path/FD 的
  device/inode/uid/mode/link-count/size/mtime/ctime；
- 先比较 hard-coded SHA256 pin，再对同一批 retained memory bytes
  `compile/exec`；
- provenance payload 使用 retained digest，不再从执行后的路径重读身份。

因此，恶意 delegate 无法先执行顶层代码再自恢复磁盘文件；signer delegate
在 pin 验证完成前也不能解析参数、读取 private-key path 或接触私钥内容。验证
完成后的路径替换不会改变已执行 module 或 retained digest。

`sign_v3.py` 自身是由 release side 独立 pin 的 signer trust root。它不能普通
import sibling v3 verifier wrapper，而是内嵌同样的 minimal stable-FD reader，
硬编码已审查的 v3 wrapper SHA256，在任何 wrapper `compile/exec` 前完成
single-link/no-symlink、双读、FD/path identity 和 digest 检查，并只执行
retained bytes。随后它把 retained wrapper digest 注入 provenance runtime
identity；验证后的 wrapper 路径漂移不会改变签入的 verifier identity。

v2 signer delegate 顶层需要 import v2 verifier。执行该 delegate 时，
`sign_v3.py` 临时提供 v3 wrapper 已经验证并 retained 的 v2 verifier module，
同时提供预先验证的 `commodity_c_fast_t1_one_shot.py` support module，不允许
Python 再从 sibling path 普通加载另一份未验证代码。support exact SHA256 也
签入 provenance。整个 bootstrap closure 完成前不会解析或打开
`--private-key-file`。

生产 signer 文件没有 shebang，也不是可执行文件。普通 `python3 sign_v3.py`
和 `PYTHONPATH=scripts` 均不受支持：CPython 会在 signer trust root 之前处理
`.pth`、`sitecustomize` 和 `usercustomize`，这些 hook 能从 `sys.argv` 读取
private-key path。

唯一受支持入口必须使用 release side 已固定的 exact interpreter：

```text
<PINNED_PYTHON> -I -S -s -E -B sign_v3.py ...
```

signer 在任何本地 wrapper/support/delegate bootstrap 前验证
`isolated/no_site/no_user_site/ignore_environment/dont_write_bytecode` flags；
不满足立即退出。`-S` 后 signer 只追加一个显式、canonical、非 symlink、
非 group/world-writable 的 site-packages root，并要求 independently supplied
path/inode/owner/mode identity pin。该 root 顶层存在任何 `.pth`、`.egg-link`、
`sitecustomize` 或 `usercustomize` 时直接拒绝。site-packages 的 package bytes
必须来自同一个已独立 pin 的只读 signer image/release；目录 identity pin
不能替代 image/release content pin。

## 签署

复制
[`c-fast-t1-build-registry-provenance-v3.template.json`](c-fast-t1-build-registry-provenance-v3.template.json)
到受控目录，替换全部 `PENDING_` 值。generated identity/hash/signature 字段由
signer 生成，不能手填。

```bash
BOOTSTRAP_SITE_PACKAGES=/opt/c-fast-provenance/lib/python3.12/site-packages

/opt/c-fast-provenance/bin/python3 -I -S -s -E -B \
  scripts/commodity_c_fast_t1_build_registry_provenance_sign_v3.py \
  --bootstrap-site-packages "$BOOTSTRAP_SITE_PACKAGES" \
  --expected-bootstrap-site-packages-identity-sha256 \
    "$BOOTSTRAP_SITE_PACKAGES_IDENTITY_SHA256" \
  --input /secure/query-v4-provenance-v3.unsigned.json \
  --output /secure/query-v4-provenance-v3.signed.json \
  --private-key-file /secure/provenance-ed25519-private.pem \
  --trusted-keyring /secure/provenance-keyring.json \
  --expected-trusted-keyring-sha256 "$PROVENANCE_KEYRING_SHA256" \
  --content-attestation /archive/query-v4-content-attestation.json \
  --expected-runtime-source-commit-sha "$QUERY_V4_SOURCE_SHA" \
  --expected-image-digest "$QUERY_V4_IMAGE_DIGEST" \
  --expected-signing-tool-source-sha256 "$SIGNER_V3_SOURCE_SHA256" \
  --expected-signing-tool-source-commit-sha "$SIGNER_SOURCE_COMMIT_SHA" \
  --t1-authority-keyring /secure/t1-release-keyring.json \
  --expected-t1-authority-keyring-sha256 "$T1_KEYRING_SHA256" \
  --l3-authority-keyring /secure/l3-release-keyring.json \
  --expected-l3-authority-keyring-sha256 "$L3_KEYRING_SHA256"
```

private key 必须属于 dedicated provenance key domain，且不得与 T1/L3
authority key 复用。signer source pin 必须来自待签 artifact 之外的独立审查
渠道。`PINNED_PYTHON`、site-packages identity pin 和 signer environment
image/release pin 也必须来自待签 artifact 与当前 shell environment 之外的
release-side 配置；签署命令不得现场从目标目录反推这些 expected pins。

## 离线验证

```bash
PYTHONPATH=scripts python3 \
  scripts/commodity_c_fast_t1_build_registry_provenance_v3.py \
  --provenance /archive/query-v4-provenance-v3.signed.json \
  --trusted-keyring /secure/provenance-keyring.json \
  --expected-trusted-keyring-sha256 "$PROVENANCE_KEYRING_SHA256" \
  --content-attestation /archive/query-v4-content-attestation.json \
  --expected-runtime-source-commit-sha "$QUERY_V4_SOURCE_SHA" \
  --expected-image-digest "$QUERY_V4_IMAGE_DIGEST" \
  --expected-signing-tool-source-sha256 "$SIGNER_V3_SOURCE_SHA256" \
  --expected-signing-tool-source-commit-sha "$SIGNER_SOURCE_COMMIT_SHA" \
  --t1-authority-keyring /secure/t1-release-keyring.json \
  --expected-t1-authority-keyring-sha256 "$T1_KEYRING_SHA256" \
  --l3-authority-keyring /secure/l3-release-keyring.json \
  --expected-l3-authority-keyring-sha256 "$L3_KEYRING_SHA256" \
  --json-output /new/archive/query-v4-provenance-v3-receipt.json
```

signature、pin、key-domain、commit、content、image、build/registry、delegate
bytes、schema namespace、权限矩阵或 create-only 输出任一不一致均 fail
closed。

## 后续边界

下一步由 query-v4 readiness 直接消费 v3 receipt，并用 root-owned pins 固定
provenance keyring 和 signer identity。完成新的短时 readiness 与人工 query
release 前，不得运行真实 QuestDB one-shot。
