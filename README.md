# chenniXvpn

chenniXvpn 是一个面向个人 VPS 的 VPN 管理面板，用于集中管理 VLESS 与 Hysteria 2 节点、查看流量使用情况，并在本地完成 Cloudflare 入口测速和优选。

## 功能

- 通过浏览器管理 VLESS（WebSocket + TLS）和 Hysteria 2 节点。
- 查看实时上下行速率、月度出口用量、协议服务状态和节点连接信息。
- 生成 VLESS 分享链接、二维码，并管理原始、优选和自选入口。
- 下载 Cloudflare 测速任务，使用 Windows EXE 或 Linux Python 脚本生成可导入面板的报告。
- 通过面板检查并升级项目、Hysteria 2 和 Xray，查看或清理本机历史版本。

## 项目结构

- `server/`：部署、节点生命周期、认证、发布校验和特权操作。
- `frontend/`：Web 面板、SQLite 流量统计和浏览器资源。
- `client/`：独立的 Cloudflare 入口测速与报告生成工具。
- `install.sh`：Linux 安装与升级入口。

项目使用 Python 标准库和原生 JavaScript，支持 Debian 12+、Ubuntu 22.04+ 以及 Windows x64 测速客户端。
