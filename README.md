# Agent Custom

这是配套 `dagve11/nezha` Dashboard 使用的 Agent 仓库，基于哪吒监控 Agent 定制。Agent 负责连接 Dashboard gRPC 服务，上报主机信息、状态指标、GeoIP 信息，并执行 Dashboard 下发的监控、终端、文件管理、配置变更、升级和自删除任务。

本仓库的 Release 资产命名统一为：

```text
agent_${os}_${arch}.zip
```

例如：

```text
agent_windows_amd64.zip
agent_linux_amd64.zip
agent_linux_arm64.zip
```

安装脚本默认从当前仓库的 GitHub Release latest 下载对应平台的压缩包；如果检测到中国大陆网络，会优先从 `https://gitee.com/AGZZY11/agent` 的 latest Release 下载对应压缩包，失败后再回退到 GitHub。

## 当前定制内容

- 默认安装源改为 `dagve11/agent`。
- Windows 安装目录默认为 `C:\Program Files\agent`。
- Linux 安装目录默认为 `/opt/agent/agent`。
- Release 包内二进制名称统一为 `agent` / `agent.exe`。
- 安装脚本重复执行时会保留已有 `uuid`，避免同一台机器重复注册成新服务器。
- 支持 Dashboard 下发 `TaskTypeDestroyAgent = 21` 后自删除。
- 支持服务器 UUID 被 Dashboard 删除后，Agent 在下一次上报被拒绝时触发自删除。
- 支持配置热更新、服务迁移密钥轮换、Web 终端、文件管理、NAT、命令任务。

## 相关仓库

| 项目 | 目录 | 说明 |
| --- | --- | --- |
| Agent | `C:/Users/72366/Desktop/nezha-1/agent` | 当前仓库 |
| Dashboard 后端 | `C:/Users/72366/Desktop/nezha-1/nezha` | 负责接收 Agent 上报和下发任务 |
| 管理后台前端 | `C:/Users/72366/Desktop/nezha-1/nezha-admin-frontend` | 生成安装命令、删除服务器、下发任务 |
| 用户面板前端 | `C:/Users/72366/Desktop/nezha-1/nezha-dash-frontend` | 展示服务器状态 |

## 技术栈

- Go 1.26
- gRPC
- `github.com/nezhahq/service` 系统服务管理
- `gopsutil` 主机指标采集
- `go-github-selfupdate` 自更新

## 目录结构

```text
cmd/agent/
  main.go          Agent 入口、gRPC 连接、任务调度
  destroy.go       Agent 自删除计划生成和执行
  commands/        service / edit 等命令
model/
  config.go        Agent 配置读取、保存、校验
  task.go          Dashboard 与 Agent 约定的任务类型
pkg/
  monitor/         主机状态、IP、GPU、磁盘、网络采集
  fm/              文件管理任务
  processgroup/    命令执行进程组管理
  pty/             Web 终端
proto/             gRPC 协议
install.ps1        Windows 安装脚本
install.sh         Linux / macOS / FreeBSD 安装脚本
build.sh           全平台 Release 包构建脚本
```

## 安装

### Windows

必须使用管理员权限运行 PowerShell。

```powershell
$env:NZ_SERVER="47.74.5.204:8008";$env:NZ_TLS="false";$env:NZ_CLIENT_SECRET="你的 agent_secret_key";[Net.ServicePointManager]::SecurityProtocol=[Net.SecurityProtocolType]::Tls12;set-ExecutionPolicy RemoteSigned;Invoke-WebRequest https://raw.githubusercontent.com/dagve11/agent/main/install.ps1 -OutFile C:\install.ps1;powershell.exe C:\install.ps1
```

默认安装结果：

```text
C:\Program Files\agent\agent.exe
C:\Program Files\agent\config.yml
```

Windows 服务名默认是：

```text
agent.exe
```

### Linux

```bash
export NZ_SERVER="47.74.5.204:8008"
export NZ_TLS="false"
export NZ_CLIENT_SECRET="你的 agent_secret_key"
curl -L https://raw.githubusercontent.com/dagve11/agent/main/install.sh -o install.sh
sh install.sh
```

默认安装结果：

```text
/opt/agent/agent/agent
/opt/agent/agent/config.yml
```

## 环境变量

安装脚本主要读取以下环境变量：

| 变量 | 必填 | 说明 |
| --- | --- | --- |
| `NZ_SERVER` | 是 | Dashboard gRPC 地址，例如 `47.74.5.204:8008` |
| `NZ_CLIENT_SECRET` | 是 | Dashboard 中的 Agent 密钥 |
| `NZ_TLS` | 否 | 是否使用 TLS，`true` 或 `false`，默认 `false` |
| `NZ_UUID` | 否 | 指定 Agent UUID；不指定时自动生成或复用旧配置 |
| `NZ_AGENT_REPO` | 否 | 下载 Release 的仓库，默认 `dagve11/agent` |
| `NZ_GITEE_REPO` | 否 | 国内网络下优先使用的 Gitee Release 仓库，默认 `AGZZY11/agent` |
| `NZ_INSTALL_DIR` | 否 | Windows 安装目录，默认 `C:\Program Files\agent` |
| `NZ_BASE_PATH` | 否 | Unix 安装根目录，默认 `/opt/agent` |

## 配置文件

Windows：

```text
C:\Program Files\agent\config.yml
```

Linux：

```text
/opt/agent/agent/config.yml
```

最小配置：

```yaml
server: '47.74.5.204:8008'
client_secret: 'your-agent-secret'
tls: false
uuid: '自动生成或保留的 UUID'
```

常用字段：

```yaml
debug: false
server: '47.74.5.204:8008'
client_secret: 'your-agent-secret'
uuid: '00000000-0000-0000-0000-000000000000'
tls: false
insecure_tls: false
report_delay: 3
ip_report_period: 1800
disable_auto_update: false
disable_command_execute: false
disable_nat: false
skip_connection_count: false
skip_procs_count: false
use_ipv6_country_code: false
```

说明：

- `report_delay` 允许范围是 `1-4` 秒。
- `ip_report_period` 最小值是 `30` 秒，默认 `1800` 秒。
- `uuid` 是服务器身份标识，重复安装时必须保留，避免重复注册。
- `client_secret` 必须与 Dashboard 中配置的 Agent 密钥一致。

## 服务命令

Windows：

```powershell
& 'C:\Program Files\agent\agent.exe' service status -c 'C:\Program Files\agent\config.yml'
```

```powershell
& 'C:\Program Files\agent\agent.exe' service stop -c 'C:\Program Files\agent\config.yml'
```

```powershell
& 'C:\Program Files\agent\agent.exe' service start -c 'C:\Program Files\agent\config.yml'
```

```powershell
& 'C:\Program Files\agent\agent.exe' service uninstall -c 'C:\Program Files\agent\config.yml'
```

Linux：

```bash
/opt/agent/agent/agent service -c /opt/agent/agent/config.yml status
```

```bash
/opt/agent/agent/agent service -c /opt/agent/agent/config.yml stop
```

```bash
/opt/agent/agent/agent service -c /opt/agent/agent/config.yml start
```

```bash
/opt/agent/agent/agent service -c /opt/agent/agent/config.yml uninstall
```

## 卸载

Windows：

```powershell
sc.exe stop 'agent.exe'
```

```powershell
sc.exe delete 'agent.exe'
```

```powershell
Remove-Item -LiteralPath 'C:/Program Files/agent' -Recurse -Force
```

```powershell
Remove-Item -LiteralPath 'C:/install.ps1' -Force
```

Linux：

```bash
sh install.sh uninstall
```

或手动：

```bash
/opt/agent/agent/agent service -c /opt/agent/agent/config.yml stop || true
```

```bash
/opt/agent/agent/agent service -c /opt/agent/agent/config.yml uninstall || true
```

```bash
rm -rf /opt/agent
```

## 自删除流程

Dashboard 删除服务器时会下发：

```text
TaskTypeDestroyAgent = 21
```

Agent 收到后会先向 Dashboard 返回任务结果：

```text
agent self-removal scheduled
```

然后在临时目录写入清理脚本并脱离当前进程执行。

Windows 自删除会执行：

- 清除服务失败自动重启策略。
- 停止 `agent.exe` 服务。
- 强制结束当前 Agent 进程。
- 删除 `agent.exe` 服务。
- 删除 `C:\Program Files\agent`。
- 删除 `C:\install.ps1`。

Windows 日志位置：

```text
C:\Windows\Temp\agent-destroy-<pid>.log
```

Linux 自删除会执行：

- 通过 Agent 二进制停止服务。
- 通过 Agent 二进制卸载服务。
- 删除 `/opt/agent/agent`。
- 如果 `/opt/agent` 为空则删除 `/opt/agent`。

Linux 日志位置：

```text
/tmp/agent-destroy-<pid>.log
```

如果 Dashboard 已经删除了服务器 UUID，Agent 下一次 `ReportSystemInfo2` 被后端拒绝并包含 `server UUID has been deleted` 时，也会触发同样的自删除流程。

## 构建

执行目录：

```text
C:/Users/72366/Desktop/nezha-1/agent
```

全平台构建：

```powershell
docker run --rm -v "C:/Users/72366/Desktop/nezha-1/agent:/build" -w /build golang:1.26 sh -c "apt-get update -qq && apt-get install -y -qq zip gcc > /dev/null 2>&1 && VERSION=1.0.4 ./build.sh"
```

输出目录：

```text
dist/
```

输出文件示例：

```text
dist/agent_windows_amd64.zip
dist/agent_linux_amd64.zip
dist/agent_linux_arm64.zip
dist/checksums.txt
```

`build.sh` 当前构建目标：

```text
darwin amd64
darwin arm64
freebsd 386
freebsd amd64
freebsd arm
freebsd arm64
linux 386
linux amd64
linux arm
linux arm64
linux loong64
linux mips
linux mipsle
linux riscv64
linux s390x
windows 386
windows amd64
windows arm64
```

只构建 Windows amd64 可直接执行本地辅助脚本：

```text
build-windows-amd64.bat
```

该脚本是本地调试辅助文件，不作为正式 Release 流程要求。

## Release 上传

安装脚本会下载 GitHub latest release：

```text
https://github.com/dagve11/agent/releases/latest/download/agent_windows_amd64.zip
```

因此发布新版本时需要保证：

- Release tag 使用 semver，例如 `v1.0.4`。
- 不要让非 semver tag 成为 latest，否则安装脚本和自更新逻辑会出现版本分裂。
- 上传的资产名称必须是 `agent_${os}_${arch}.zip`。
- `agent_windows_amd64.zip` 内必须包含 `agent.exe`。
- `agent_linux_amd64.zip` 内必须包含 `agent`。

## 验证

查看版本：

```bash
./agent -v
```

查看服务：

```bash
./agent service -c ./config.yml status
```

运行测试：

```bash
go test ./...
```

Windows 自删除排查：

```powershell
Get-ChildItem $env:TEMP -Filter 'agent-destroy-*' | Sort-Object LastWriteTime -Descending
```

Linux 自删除排查：

```bash
ls -la /tmp/agent-destroy-*
```

## 注意事项

- Agent、Dashboard 后端、管理后台前端的任务协议必须保持一致，尤其是 `TaskTypeDestroyAgent = 21`。
- Windows 安装和自删除需要管理员权限。
- Linux 安装和自删除需要 root 或 sudo。
- 重复安装时不要删除旧 `config.yml` 中的 `uuid`，否则会被 Dashboard 识别成新服务器。
- 如果手动创建非 semver Release tag，Agent 自更新会跳过该版本。

## License

本项目基于 [Apache License 2.0](LICENSE)。
