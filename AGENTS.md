# AGENTS.md instructions

- 喊我付哥，回答问题的时候不要啰嗦，简洁回答。
- 如果是提交 PR 更新，需要同步添加评论。
- 本机已安装 Colima。以后涉及 SQL/数据库的改动，先在本机用 Colima 启动对应数据库并完成本地验证，再提交结论。
- 新建 git worktree 后必须先同步并核对本地运行环境：`.env`、`backend/.env`、`frontend/.env` 都是 ignored 文件，不会随 worktree 自动带过去。涉及 RPC、行情、交易、数据库或页面联调时，必须先确认当前 worktree 的 `.env` 与真实本地环境一致，不能直接使用 `.env.example` 或默认 `127.0.0.1` 地址做结论。

## RPC / SimNow smoke tests

根目录已有两个手工 RPC smoke 脚本，不要忽略：

- `test_rpc_readonly.py`
  - 只读 RPC 验证：`get_all_contracts`、`get_all_accounts`、`get_all_positions`
  - 默认连接 `VNPY_RPC_REQ_ADDRESS=tcp://127.0.0.1:2014`
  - 可在已启动 vn.py RPC 服务时运行
  - 优先用本目录虚拟环境运行：`.venv/bin/python test_rpc_readonly.py`

- `test_rpc_trade_flow.py`
  - 真实交易链路 smoke：订阅行情、等待 tick、发一笔远离成交价的限价单、查询委托、撤单
  - 默认连接：
    - `VNPY_RPC_REQ_ADDRESS=tcp://127.0.0.1:2014`
    - `VNPY_RPC_PUB_ADDRESS=tcp://127.0.0.1:4102`
    - `VNPY_GATEWAY_NAME=CTP`
    - `VNPY_TEST_SYMBOL=rb2610`
    - `VNPY_TEST_EXCHANGE=SHFE`
  - 必须显式设置 `VNPY_ALLOW_TRADE_TEST=true` 或传 `--allow-trade` 才会执行真实下单/撤单。
  - 优先用本目录虚拟环境运行：`.venv/bin/python test_rpc_trade_flow.py --allow-trade`

如果 PR 涉及交易链路、RPC、行情订阅或风控：

- 先跑单元测试和前端构建。
- 再检查是否能连接本地或远程 vn.py RPC。
- 如果用户已说明 RPC / SimNow 环境可用，应优先使用上述两个根目录 smoke 脚本验证，不要直接说“没有连接”。
- 如果 smoke 未运行，需要说明具体原因，例如 RPC 地址不可达、缺少 vn.py 依赖、未设置允许交易测试、非交易时段收不到 tick。
