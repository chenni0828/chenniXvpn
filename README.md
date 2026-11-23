# chenniXvpn

个人 VPS 的 VPN 管理面板。支持 VLESS（WebSocket + TLS）和 Hysteria 2，可查看实时上下行和每月出口用量，VLESS 支持 Cloudflare 自选和优选。

## 项目架构

- `server/` 管理 VPN 核心、节点配置、证书和更新。
- `frontend/` 提供 Web 面板和流量统计。
- `client/` 提供在本地网络运行的 Cloudflare 测速工具。

## 让 AI Agent 帮你部署

把下面这段话复制给能使用你现有 SSH 连接和 `sudo` 权限的 Agent。SSH 私钥和口令留在你的 SSH 客户端或 `ssh-agent` 中。

```text
请你阅读 https://github.com/chenni0828/chenniXvpn#在-vps-部署 ，帮我在指定的 VPS 上部署 chenniXvpn 管理面板。

先使用我已有的 SSH 连接检查系统和现有安装，向我确认使用 SSH 隧道还是公网 HTTPS，列出安装版本、实际入口和将要做的变更。我确认后再执行。如果已有部署，请先说明如何保留现有数据。需要交互输入管理员密码时，请让我在终端中输入。

完成后，请给我可用的访问地址或 SSH 转发命令，并报告面板、流量采集服务和认证检查的结果。
```

## 在 VPS 部署

支持运行 systemd 的 Ubuntu 22.04+ 或 Debian 12+，架构为 amd64 或 arm64。预检使用系统的 `/usr/bin/python3`。从源码部署时，先选定并记录 Git 完整 commit，在干净检出中执行，或用 `git archive` 从该提交打包上传。下列命令从包含 `install.sh` 的目录执行。

**首次安装**可直接运行 `sudo bash install.sh`，选择访问方式、确认配置摘要，再在终端设置 `admin` 密码。

- **SSH 隧道**使用你平时已能登录的 `用户@主机` 或本地 SSH 别名。`--port` 指面板回环端口，默认为 9080；自定义 SSH 登录端口用 `--ssh-port`。在自己的电脑上执行安装器给出的转发命令，再打开显示的本地地址。
- **公网 HTTPS**需要先将管理域名解析到 VPS。主机防火墙和云安全组须放行 TCP 80 以供证书签发和续期，并放行实际管理端口（默认 TCP 443）。安装器检查本机 DNS 和端口，并在安装后通过本机 TLS 连接验证面板认证。

### Agent 与无人值守安装

**v0.1.0** 是部署和后续更新的基准版本。`--dry-run` 会预检配置和主机。它跳过密码读取、软件包安装和服务变更。将示例域名、邮箱换成自己的。

```bash
sudo bash install.sh --dry-run --non-interactive --mode=https \
  --domain=panel.example.com --email=admin@example.com
```

确认摘要后，交互部署可直接使用终端密码提示。自动化使用密钥管理器或受保护的输入文件，将一行 UTF-8 密码（至少 12 个字符）送入标准输入。示例中的文件路径应由运行命令的调用方可读，`sudo -n` 需要预先具备免交互授权。

```bash
sudo -n bash install.sh --non-interactive --mode=https \
  --domain=panel.example.com --email=admin@example.com \
  --admin-password-stdin --quiet < /run/secrets/chennixvpn-admin-password
```

SSH 首装使用相同的密码输入方式，将 HTTPS 参数换成 `--mode=ssh --ssh-host=admin@my-vps`。`--non-interactive` 表示已确认所给参数，`--quiet` 保留部署阶段和失败原因。相同版本与配置再次执行会返回当前状态，并保留现有密码。

从 GitHub 部署时，先在 [Releases](https://github.com/chenni0828/chenniXvpn/releases) 确认目标标签含有 `chennixvpn-server.tar.gz`，再使用对应版本的引导脚本，将 `--from-github TAG` 加到首装或升级命令。此路径需要系统 CA 证书，验证 Release 提供的 SHA-256、包大小和包内版本。单独下载的脚本会在临时目录校验并解包，预览结束后也会清理。尚无所需 Release 时，请使用固定 commit 的完整源码。

### 已安装的 VPS

从 v0.1.0 开始，后续版本可通过面板更新，也可用目标版本的源码执行 `--upgrade`。两种方式都保留数据库、节点、密码和访问模式。

```bash
sudo bash install.sh --status --json
sudo bash install.sh --upgrade
```

升级后可以从已安装目录操作。先用 `--dry-run` 预览，确认后再执行。SSH 和 HTTPS 可以双向切换，切换失败会恢复原面板配置。

```bash
cd /opt/chennixvpn/current
sudo bash install.sh --reconfigure --non-interactive --mode=ssh --ssh-host=admin@my-vps --port=9080
sudo bash install.sh --reconfigure --non-interactive --mode=https --domain=panel.example.com --email=admin@example.com
sudo bash install.sh --status --json
```

`--status` 只读取本机部署状态。加上 `--json` 可获取一份 JSON。查询成功返回 0，可按 `state` 区分 `not_installed`、`incomplete`、`healthy` 和 `degraded`。`services.panel` 与 `services.traffic` 分别含 `active`、`enabled`，`local_auth: true` 表示本机入口返回了预期的 401 和认证头。`public_access: "not_checked"` 表示仍需从客户端验证。SSH 模式的 `ssh_command` 可直接在本地使用。来源信息见 `source`，无法追溯的 commit、包摘要和标签均为 `null`。主机 Swap 总量由 `swap_bytes` 给出。

发布后续版本时，沿用 `chennixvpn-server.tar.gz` 资产名和 `server/deployment.py --upgrade` 入口。已部署的面板通过这个入口调用目标版本的升级逻辑。

### 创建节点

登录面板，在「节点」中点击「创建节点」。将节点域名解析到 VPS，保持 TCP 80 开放以便签发和续期证书，并放行所选节点端口。VLESS 默认用 TCP 443，可与管理面板按域名共用端口；Hysteria 2 默认用 UDP 443，域名设为仅 DNS。节点启动后，在「连接与分享」复制链接或二维码，导入本地 VPN 客户端。

### Cloudflare 测速与优选

1. 在 VLESS 节点的「Cloudflare 诊断」下载测速任务和对应平台的客户端。
2. 在平时连接节点的网络运行测速。Windows 双击 EXE 选择任务，也可以直接把任务文件拖到 EXE 上。Linux 使用 Python 3.10 或更新版本运行 `python3 chennixvpn-cloudflare-linux.py test --task chennixvpn-cf-task.json`。
3. 导入生成的 `*-report.csv`，对照原始入口的握手表现。选择候选 IP 后预览并保存优选入口。

Windows 只将可导入面板的 `*-report.csv` 保存到 EXE 所在目录，不单独保存 TCP 初筛。从终端运行 EXE 时，请使用可写的工作目录供运行时临时解包。Linux 将报告保存到当前工作目录。默认 IPv4 流程从 Cloudflare 网段按 `/24` 随机抽样，采用 200 并发、每地址 4 次 TCP 探测。复测前 40 个可达地址和原始入口的节点握手，再对握手表现最好的最多 10 个通过候选逐个测边缘下载，每个最多 10 秒，请求 99,999,999 字节以内以兼容 Cloudflare 测速端点限制。优选先比较握手成功率；已测下载的候选按边缘下载速度、握手延迟中位数排序，未测下载的候选排在其后。边缘下载只用于比较入口，不等于 VLESS 实际吞吐量。IPv6 使用同一脚本并追加 `--family 6`，默认随机抽样 24 个地址，可用 `--sample` 调整。

### 构建测速发行资产

在 Windows x64 的 Python 3.12 环境从项目根目录执行。把生成的两个文件随 `VERSION` 对应的服务器包放入同一 Release。

```powershell
python -m pip install pyinstaller==6.16.0
$version = (Get-Content VERSION -Raw).Trim()
$assetDir = ".artifacts/$version"
$buildDir = ".artifacts/build-client-$version"
New-Item -ItemType Directory -Force -Path $assetDir, $buildDir | Out-Null
python -m PyInstaller --onefile --console --noupx --runtime-tmpdir '.' --name chennixvpn-cloudflare-windows-x64 --specpath $buildDir --workpath $buildDir --distpath $assetDir client/cf_speedtest.py
Copy-Item client/cf_speedtest.py "$assetDir/chennixvpn-cloudflare-linux.py"
```
