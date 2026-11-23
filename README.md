# chenniXvpn

chenniXvpn 是一个面向个人 VPS 的 VPN 管理面板，用于集中管理 VLESS 与 Hysteria 2 节点、查看流量使用情况，并在本地完成 Cloudflare 入口测速和优选。

## 功能

- 通过浏览器管理 VLESS（WebSocket + TLS）和 Hysteria 2 节点。
- 查看实时上下行速率、月度出口用量、协议服务状态和节点连接信息。
- 生成 VLESS 分享链接、二维码，并管理原始、优选和自选入口。
- 下载 Cloudflare 测速任务，使用 Windows EXE 或 Linux Python 脚本生成可导入面板的报告。
- 通过面板检查并升级项目、Hysteria 2 和 Xray，查看或清理本机历史版本。

## 项目架构

- `server/` 管理 VPN 核心、节点配置、证书和更新。
- `frontend/` 提供 Web 面板和流量统计。
- `client/` 提供在本地网络运行的 Cloudflare 测速工具。

项目使用 Python 标准库和原生 JavaScript，支持 Debian 12+、Ubuntu 22.04+ 以及 Windows x64 测速客户端。

## 让 AI Agent 帮你部署

把下面这段话复制给能使用你现有 SSH 连接和 `sudo` 权限的 Agent。SSH 私钥和口令留在你的 SSH 客户端或 `ssh-agent` 中。

```text
请你阅读 https://github.com/chenni0828/chenniXvpn#在-vps-部署 ，帮我在指定的 VPS 上部署 chenniXvpn 管理面板。

先使用我已有的 SSH 连接检查系统和现有安装，向我确认使用 SSH 隧道还是公网 HTTPS，列出安装版本、实际入口和将要做的变更。我确认后再执行。如果已有部署，请先说明如何保留现有数据。需要交互输入管理员密码时，请让我在终端中输入。

完成后，请给我可用的访问地址或 SSH 转发命令，并报告面板、流量采集服务和认证检查的结果。
```
