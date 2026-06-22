# ChatGPT 网页版接入本地 DevSpace MCP

## 目标

通过 DevSpace、FRP 和 VPS，让 ChatGPT 网页版能够访问 Mac 上的开发目录，并执行以下操作：

- 读取和搜索代码
- 修改文件
- 执行命令、测试和构建
- 查看 Git diff
- 使用 Git worktree
- 读取项目内的 `AGENTS.md`、`CLAUDE.md`

这里是 **ChatGPT 网页版直接调用 DevSpace 提供的 MCP 工具**，不是 ChatGPT 调用本机 Codex，也不会消耗 Codex 的任务额度。

## 当前架构

```text
ChatGPT 网页版
    |
    | HTTPS / MCP
    v
Caddy（VPS，443）
    |
    +-- mcp-fj.sunnywifi.cn/mcp
    |       -> 127.0.0.1:17001
    |
    +-- mcp-wyc.sunnywifi.cn/mcp
            -> 127.0.0.1:17002
                    ^
                    | FRP 隧道
                    |
              Mac 上的 DevSpace
              127.0.0.1:7676
```

VPS 地址：

```text
la1.sunnywifi.cn
104.194.84.106
```

当前 MCP 地址：

```text
https://mcp-fj.sunnywifi.cn/mcp
https://mcp-wyc.sunnywifi.cn/mcp
```

每个 Mac 使用独立域名和 FRP 远程端口，避免 DevSpace OAuth、回调地址和路由相互冲突。

## 端口说明

| 端口 | 服务 | 是否需要公网放行 |
|---|---|---|
| `443` | Caddy HTTPS / MCP 入口 | 是 |
| `7000` | FRP 客户端控制连接 | 是，或限制为可信来源 |
| `17001` | `mcp-fj` 的 FRP 远程端口 | 否，只供 Caddy 本机访问 |
| `17002` | `mcp-wyc` 的 FRP 远程端口 | 否，只供 Caddy 本机访问 |
| `7676` | Mac 本地 DevSpace | 否 |
| `15655` | VPS 上的 sing-box 代理 | 与 FRP 服务无直接关系 |

如果 Mac 开启了系统代理，FRP 连接可能先经过 VPS 的 sing-box `15655`，再从 VPS 连接 `7000`。这种情况下，即使公网尚未放行 `7000`，FRP 也可能暂时连接成功，服务端日志中的来源地址还会显示为 VPS 自身。

为保证没有使用该代理的其他 Mac 也可以直接接入，VPS 仍需放行 TCP `7000`。

## VPS 配置

### FRP Server

主要文件：

```text
/usr/local/bin/frps
/etc/frp/frps.toml
/etc/systemd/system/frps.service
```

`/etc/frp/frps.toml` 示例：

```toml
bindPort = 7000

transport.tls.force = true
```

FRP 认证配置属于敏感信息，应继续保存在 VPS 和对应 Mac 的本地配置中，本文不记录具体内容。

服务管理：

```bash
systemctl status frps
systemctl restart frps
journalctl -u frps -n 100 --no-pager
```

### Caddy

Caddy 为两个 MCP 提供固定 HTTPS 域名：

```caddyfile
mcp-fj.sunnywifi.cn {
    reverse_proxy 127.0.0.1:17001
}

mcp-wyc.sunnywifi.cn {
    reverse_proxy 127.0.0.1:17002
}
```

修改后验证并重载：

```bash
caddy validate --config /etc/caddy/Caddyfile
systemctl reload caddy
systemctl status caddy
```

### UFW

检查：

```bash
ufw status numbered
ss -lntp
```

必要规则：

```bash
ufw allow 443/tcp
ufw allow 7000/tcp
```

不要对公网放行 `17001`、`17002` 和 Mac 本地 `7676`。

## Mac 配置

### 安装 Node 和 DevSpace

```bash
curl https://get.volta.sh | bash
source ~/.zshrc
volta install node@22
npm install -g @waishnav/devspace
```

检查：

```bash
node -v
npm -v
devspace --help
```

### 初始化 DevSpace

```bash
devspace init
```

关键配置：

- 本地监听端口：`7676`
- 项目目录：填写允许 ChatGPT 操作的本地目录
- Public Base URL：填写对应域名，**不要带 `/mcp`**

`mcp-fj`：

```text
https://mcp-fj.sunnywifi.cn
```

`mcp-wyc`：

```text
https://mcp-wyc.sunnywifi.cn
```

启动：

```bash
devspace serve
```

本地 MCP 地址：

```text
http://127.0.0.1:7676/mcp
```

### 安装 FRP Client

FRPC 配置建议放在：

```text
~/.config/frp/frpc.toml
```

`mcp-fj`：

```toml
serverAddr = "104.194.84.106"
serverPort = 7000

transport.tls.enable = true

[[proxies]]
name = "mcp-fj"
type = "tcp"
localIP = "127.0.0.1"
localPort = 7676
remotePort = 17001
```

`mcp-wyc`：

```toml
serverAddr = "104.194.84.106"
serverPort = 7000

transport.tls.enable = true

[[proxies]]
name = "mcp-wyc"
type = "tcp"
localIP = "127.0.0.1"
localPort = 7676
remotePort = 17002
```

手工启动并检查：

```bash
~/.local/bin/frpc -c ~/.config/frp/frpc.toml
```

稳定使用时应通过 macOS LaunchAgent 分别托管 DevSpace 和 FRPC，使其登录后自动启动。

## ChatGPT 网页版配置

1. 打开 ChatGPT 设置。
2. 进入“应用”，开启开发者模式。
3. 创建自定义应用。
4. 选择“流式 HTTP”。
5. MCP 地址填写对应的完整地址：

```text
https://mcp-fj.sunnywifi.cn/mcp
```

或：

```text
https://mcp-wyc.sunnywifi.cn/mcp
```

6. 保存并连接应用。
7. 按页面提示完成 DevSpace 登录认证。
8. 在聊天窗口的“更多/应用”中启用该应用。

认证信息保存在 Mac 本地：

```text
~/.devspace/auth.json
```

该文件包含敏感认证信息，不能提交到 Git 或发送给他人。

## 验证

### Mac 本地

```bash
curl -i http://127.0.0.1:7676/mcp
```

### VPS

```bash
systemctl status frps caddy
ss -lntp | grep -E ':7000|:17001|:17002|:443'
journalctl -u frps -n 100 --no-pager
```

### 公网

```bash
curl -i https://mcp-fj.sunnywifi.cn/mcp
curl -i https://mcp-wyc.sunnywifi.cn/mcp
```

未携带 DevSpace 认证信息时返回 `401 Unauthorized` 是正常现象，说明公网路由已到达 DevSpace 且认证保护生效。

最后在 ChatGPT 中启用对应应用，要求它：

```text
列出当前项目根目录文件，并读取 AGENTS.md，不要修改任何文件。
```

能正确返回文件和指令内容，即表示完整链路正常。

## 重启顺序

### VPS

```bash
systemctl restart frps
systemctl restart caddy
```

### Mac

```bash
devspace serve
~/.local/bin/frpc -c ~/.config/frp/frpc.toml
```

如果使用 LaunchAgent，应通过 `launchctl` 重启对应服务，而不是同时手工运行第二份进程。

固定域名方案不会像 `trycloudflare.com` 临时隧道一样在重启后改变地址，因此正常重启后不需要重新修改 ChatGPT 应用。

## 常见问题

### ChatGPT 调用的是 Codex 吗？

不是。ChatGPT 调用的是 DevSpace MCP 提供的文件、命令和 Git 工具。效果接近 Codex，但执行层是 DevSpace。

### 为什么 Public Base URL 不带 `/mcp`？

DevSpace 使用根地址生成 OAuth 和服务地址；ChatGPT 客户端连接时才使用标准 MCP 路径 `/mcp`。

### 为什么公网访问返回 401？

DevSpace 拒绝未授权请求，这是正确的安全行为。不能为了消除 401 而关闭认证。

### 为什么没放行 7000 时某台 Mac 仍能连接？

该 Mac 的网络流量可能经过已放行的 sing-box `15655`，再由 VPS 本机访问 FRP `7000`。这不代表 `15655` 是 FRP 端口，也不代表其他 Mac 能直接连接。

### ChatGPT 无法连接时怎么排查？

按以下顺序检查：

1. Mac 上 DevSpace 是否监听 `127.0.0.1:7676`。
2. Mac 上 FRPC 是否成功登录 FRPS。
3. VPS 上是否出现对应的 `17001` 或 `17002` 监听。
4. Caddy 是否正常、域名证书是否有效。
5. 公网 `/mcp` 是否返回 `401`，而不是超时或 `502`。
6. DevSpace 的 Public Base URL 是否与 ChatGPT 中的域名一致。

## 安全要求

- 不在文档、Git、聊天记录中保存 FRP 认证信息或 DevSpace 登录密钥。
- DevSpace 只授权必要的项目目录，不授权整个用户主目录。
- `17001`、`17002`、`7676` 不对公网开放。
- 保留 DevSpace 认证，公网未授权请求应返回 `401`。
- 定期升级 DevSpace、FRP 和 Caddy。
- 不再使用某台 Mac 时，删除对应 FRP 代理、Caddy 域名和 ChatGPT 应用。
