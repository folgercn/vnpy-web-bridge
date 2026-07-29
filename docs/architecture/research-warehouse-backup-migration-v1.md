# Research Warehouse backup、restore 与 migration v1

## 1. 边界

本合同只搬运 Research evidence custody，不授予 Control、Execution、
Deployment、RPC、order、position、dispatch、trading 或 production authority。

备份范围是 warehouse `raw/` 与 `manifests/` 的 exact bytes。`observations/`
属于可丢弃在线采集元数据；DuckDB 与 Parquet 属于可重建 derivative，不作为
备份真相源。

## 2. 分层

- `backup_contracts.py`：inventory、snapshot、rebuild fingerprint 值合同。
- `backup_inventory.py`：稳定双扫描和 exact-byte SHA256 inventory。
- `backup_custody.py`：独立 backup layout、容量门和 create-only copy。
- `backup_anchor.py`：Ed25519 signed append-only anchor chain。
- `rebuild_fingerprint.py`：DuckDB 逻辑表内容哈希及 Parquet exact SHA256。
- `restore_service.py`：空目录恢复、离线 seal chain 校验、catalog/Parquet 重放。
- `migration_contracts.py`：迁移保持的逻辑 lineage。
- `migration_receipt.py`：create-only signed transfer receipt。
- `migration_service.py`：迁移与 receipt replay verification。
- `backup_migration_cli.py`：只负责参数装配。

## 3. Backup anchor

异机 backup root 必须是与源 warehouse 不相同、互不嵌套的私有 custody root。
生产运行应把该 root 放到独立主机或独立远端挂载；代码不把“不同目录”包装成
“已经异机”。

每个 anchor 绑定：

- source/backup custody identity；
- 全量 object relative path、exact byte count、raw SHA256；
- domain-separated snapshot root hash、数量、总字节；
- registry、commit-anchor ledger、manifest genesis/head/head-commit；
- normalizer tool commit、dependency lock；
- DuckDB 四张逻辑表的 canonical content hash；
- 每个 Parquet relative path 与 exact SHA256；
- parent anchor raw SHA256、sequence、可信时间和 signer public-key pin。

anchor 只能向前追加。新 snapshot 必须包含旧 snapshot 的全部相同对象，旧路径
不能删除或改写。调用方必须从独立记录传入当前 parent anchor SHA256；丢失响应
的完全相同重试幂等返回原 anchor，过期 parent/replay fail closed。

## 4. Restore

restore 只能落到不存在的空 root：

1. 以外部 SHA pin 验证完整 backup anchor chain 和当前 object store。
2. create-only 恢复 `raw/`、`manifests/`。
3. 再次计算 snapshot，要求 relative path、byte count、SHA256 全等。
4. 用外部 registry、manifest public key、commit-anchor ledger 验证原 seal chain。
5. 从空 derived root 重建 DuckDB/Parquet。
6. 比较 DuckDB 逻辑内容哈希和每个 Parquet exact SHA256。

DuckDB 数据库物理文件 SHA 不作为跨重建不变量；其内部页布局不是逻辑合同。

## 5. Migration receipt

迁移目标是新的 warehouse custody root。原始 manifest 不重签。receipt 绑定：

- source/destination custody identity；
- snapshot root、object count、total bytes；
- raw/manifest count；
- 每个唯一 raw object 的 object ID、relative path、raw SHA256 和首次出现的
  original batch seal；
- lineage root hash；
- genesis/head/head-commit seal；
- signer key pin、可信时间以及全 false authority。

明确不宣称 `absolute_path`、`device`、`host`、`inode` identity 不变。receipt
在目标 snapshot、manifest chain 和 lineage 全部验证成功后才发布；中途失败
不会产生 receipt。verify 操作重算 source/destination identity，receipt 不能
重放到另一 custody。

## 6. 操作顺序

使用 `scripts/research_warehouse_backup_migration_cli.py`：

1. `init-backup` 初始化独立 backup root。
2. `backup` 传入所有外部 SHA pins、`GENESIS` 或当前 parent anchor、可信时间。
3. 把输出的 `anchor_raw_sha256` 写入独立 append-only anchor store。
4. `restore` 恢复到全新 evidence/derived root 并完成重建验证。
5. `init-receipts` 初始化独立 receipt root。
6. `migrate` 迁移到全新 Research host root，保存输出 receipt SHA256。
7. `verify-migration` 从独立 receipt SHA pin 重放校验。

密钥不得写入仓库、backup object store、migration destination 或本 runbook。

## 7. Drill 与验收

自动化 drill 覆盖：

- 正常 backup → restore → catalog/Parquet rebuild → migration；
- source revision 同时保留旧、新 raw object 与 original batch seal；
- backup raw tamper；
- 错误/stale external anchor replay；
- destination disk-low preflight；
- migration copy failure 不发布 receipt。

合并前汇总执行：

```bash
pytest -q backend/tests/unit/test_research_warehouse_*.py
pytest -q
ruff check $(git diff --name-only --diff-filter=ACMRT main -- '*.py')
python -m py_compile scripts/research_warehouse*.py scripts/research_warehouse/*.py
python -m compileall -q backend/app scripts
git diff --check
```

两个 JSON Schema 必须通过 Draft 2020-12 schema check，并以实际 signed anchor /
receipt payload 验证。M2 isolation evidence 继续由 Issue #172 的独立 verifier
验证；backup/migration receipt 不能替代真实 M2 root-level 激活证据。
