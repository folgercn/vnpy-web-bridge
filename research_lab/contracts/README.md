# v2 离线机器契约校验

**DRAFT_UNFROZEN**。关联 #511/#524/#523。本模块只读文件并检查契约；不执行方法、不调用 Agent、不连接网络，不是 Runner 或完整 S1–S7 准入器。

## 入口

- `Definitions().resolve(kind, ref)`：从唯一受控目录 `docs/research-lab/definitions/catalogue.json` 解析准确 name/revision/hash/locator。bundle 自带同名定义不能替换目录中的定义。
- `Definitions().method(implementation_ref)`：核对登记的不可变方法定义及当前源码原始 SHA；不动态 import 或执行引用字符串。
- `validate_spec(spec, task)`：公共 Spec Schema、记录摘要、Task 引用、固定快照绑定、日期范围、唯一参数/类型/单位、默认值与精确指标定义。返回生效参数，不授予执行资格。
- `validate_manifest(bundle_root, manifest, run)`：公共 Manifest Schema、Run 绑定、角色完整性、唯一条目/路径、内容定义、原始字节长度/摘要、载荷 Schema。返回已检查的受控载荷映射，不证明科学结论正确。
- `validate_handoff(request, objects, response=None, *, payloads=None, root=None)`：当前支持 `review_evidence` 的实际上下文、Run/Spec/Manifest/Evidence 引用、完整产物引用和实际 Review 与请求判据对应。统计/回测 profile 必须传入未经复制或修改的 `validate_manifest` 返回值作为 `payloads`，或传入 `root` 重新核对所需载荷原始字节；普通映射明确拒绝。其他操作明确拒绝，不能把结构合格等同跨对象验证完成。

调用方必须分别完成适用检查。单独调用 Handoff 检查不替代文件内容核验，单独验证 Manifest 不替代实际输入、方法与科学指纹复算。

## 唯一定义源与版本

`docs/research-lab/definitions/` 是本轮选定的唯一离线定义源，不是注册服务。
目录记录定义内容的 research-json-v1 摘要；载荷摘要仍对原始字节计算。
同一 kind/name/revision 不得改语义；修订必须新增版本与引用。不能用 main/latest 名称替代准确摘要。

目前登记 #544 `validation-rev1-ci.tar.gz` 已有的七个载荷定义、source_order 方法与评审判据。
提取时保留定义对象内容，格式化文件不会改变定义对象摘要；旧包及其引用不修改。
原 `materials/payload.schema.json#/$defs/...` locator 作为明确登记的旧引用保留，解析取受控目录对应定义，不信任包内路径提供的替代内容。
方法绑定 `research/phase0_data_quality/quality.py` 的原始源码摘要；Run 的实际依赖/环境/输入指纹仍由 #544 原消费校验负责，本模块不冒充依赖执行兼容认证。

这些载荷定义属于 **phase0 命名空间的受限真实案例**，含案例自己的方法/来源约束，不是所有研究共用的宽松字典。
统计/回测及可选 chart/log 的 role 已在 Manifest Schema 中表达，但未登记具体内容定义时自动拒绝消费。
已登记 rev.1 内容定义为单完整文件；重复分片、partial 交付拒绝。未来分片定义需明确完整集合后才能支持，不凭角色计数猜分片。

## 已机器化及尚未完成

| 条款 | 本轮机器证据 | 保留限制 |
| --- | --- | --- |
| #524 结构、present/unavailable、完整性 | Manifest Schema；必需角色不受 supporting 分类豁免；长度/摘要、重复/缺件、路径和内容 Schema 拒绝测试 | 不发布或修改任何包；未登记内容定义仍是冻结缺口，不能视为延期批准 |
| #524 定义定位与身份 | 固定 catalogue、版本与定义摘要、方法实际源码、未知引用拒绝 | 不为缺失 candidate 猜算法；其他 profile 定义尚未提供 |
| #511 机器可检查部分 | Spec/Task 绑定、方法/参数/默认值、快照摘要、时间与指标定义检查 | 不认证实际数据可得性、完整时间切分、S7 交易语义；confirmation 显式拒绝，未实现暴露核验 |
| #523 消费交接 | 原真实评审链正例；重算记录 hash 后仍拒绝错上下文、错 Evidence/criteria、错响应 | prepare/execute/revise 操作暂无公共跨对象核验；现有 Schema 保持可表达 |

不宣称 #511/#524/#523 或 #498/#538 全部完成，不解锁运行平台。这里的剩余项是具体未实现条款，不是新增架构要求。

## 验证

```sh
.venv/bin/python -m pytest -q research_lab/contracts/test_v2.py
```

测试从 Git 归档解包真实输入与记录；错误测试只改临时副本，并在必要时重算记录摘要，以证明不是只拦截旧 hash。
不重跑研究或改变历史归档。安全读取只支持具备 `dir_fd/O_NOFOLLOW` 的本机 POSIX 环境；不据此承诺 Windows 消费入口。

控制记录结构使用 `definitions/phase0-control.schema.json`：Task/Run/Evidence/Review 的本例封闭字段、类型、摘要、时间与枚举；Spec/Manifest 使用公共 Schema。当前跨对象入口只支持 data_quality/validation。删除 Review 必填字段后重新计算摘要也会被拒绝；不能用自洽 hash 代替评审记录完整性。此受限控制 profile 不代表其他研究类型已有完整公共对象 Schema。

## Trend20 statistical_factor 受限 profile

本轮仅登记 `phase0.trend20_same_exact_contract.*.rev1`：同合约 `t/t-20` 日结算价对数特征、同合约 `t+1..t+6` 前向对数标签、每日截面 Pearson IC 和 top2-minus-bottom2 对数收益；发布数值为 12 位 half-even，聚合保留未舍入日值。它固定为 `exploration`，显式保留标签重叠和未做显著性检验，拒绝 carry、20 日标签、HAC 或未知方法/版本/profile。

#540 的 `factor-summary.json` 与输入摘要在仓内；其完整 `factor-samples.csv`、`factor-daily.csv` 仍为外置引用，当前不可读。因此测试中的 `sample_feature_target`、`daily_ic_series` 是合成结构 fixture，明确不是事前锁定的 v2 执行或 #540 完整证据包。统计 Manifest 必须传入已通过 `validate_spec` 的 Trend20 Spec：`validate_manifest(root, manifest, run, task=task, spec=spec)`。这只验证离线结构、引用与字段语义，完整历史明细缺失前不宣称可重放或完成 #524 的完整真实包验收。

Trend20 structural fixture 的 Run 使用独立、封闭的 `trend20-control.schema.json`：只允许该 profile 的 exploration/non-holdout 标识、Spec 精确引用、方法与 feature/target 参数、产品池、时间窗与固定 snapshot，并要求科学指纹等于该计算清单摘要。它不能通过改名复用 data_quality Run。

## Issue481 trading_backtest profile

`phase0.issue481.*.rev1` 仅表达 #540 的 Issue481 回溯映射：六个独立产品账户、603 个 corrected events 与 `STOP_ECONOMIC_GATE`。`process_exit_code=3` 在该受限 completed structural case 中是经济门槛停止，不能泛化为其他非零退出码成功。仓内可读 `backtest-facts.json` 和控制映射；完整历史 blotter/equity curve 是外置材料，`target-changes.jsonl` 不是其替代。因此此 profile 当前只能接收明确标注的 synthetic structural payload，未实现 S7 交易语义或完整历史 evidence 验收。
