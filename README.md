# chenniXvpn

chenniXvpn 是一个面向个人 VPS 的 VPN 管理面板，用于集中管理 VLESS 与 Hysteria 2 节点、查看流量使用情况，并在本地完成 Cloudflare 入口测速和优选。

## 项目架构

- `server/` 管理 VPN 核心、节点配置、证书和更新。
- `frontend/` 提供 Web 面板和流量统计。
- `client/` 提供在本地网络运行的 Cloudflare 测速工具。

## 让 AI Agent 帮你部署

部署前请准备一个已解析到 VPS 的管理域名和证书邮箱，并在防火墙与安全组放行 TCP 80 和面板 HTTPS 端口（默认 443）。将以下内容发送给拥有该 VPS SSH 与 `sudo` 权限的 Agent：

```text
请阅读 https://github.com/chenni0828/chenniXvpn ，在我的 VPS 上部署 chenniXvpn 管理面板。

先通过 SSH 检查系统环境、DNS 解析和现有安装状态，向我确认管理域名、证书邮箱、HTTPS 端口及变更清单，待我确认后再执行（已有部署请保留现有密码、数据库和节点；首次安装需输入管理员密码时请让我在终端输入）。

部署完成后，请提供面板 https:// 访问地址，并报告面板服务、流量采集服务、TLS 证书和认证自检结果；若失败请说明原因和修复步骤。
```
