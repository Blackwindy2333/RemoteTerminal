# RemoteTerminal（远程终端）

一个 Windows 单文件应用（Rust 编写）：在局域网内远程操作另一台 Windows 主机 —— 执行
`cmd`/`pwsh` 命令、在强制路径监狱（path jail）中浏览与传输文件、读取系统状态、截取屏幕与
窗口画面；入口有四种：原生 GUI、命令行、REST/WebSocket 接口，以及供 Agent Harness 调用的
MCP 服务。

同一个 exe 既是客户端也是服务端：在每台机器上按需开启服务（也可以完全不开），用密码或 API
Key 配对，然后从一个窗口统一控制。

```
┌─────────────────────── remote-terminal.exe ───────────────────────┐
│  GUI (egui)   CLI   REST + WebSocket server   MCP bridge (stdio)  │
└───────────────────────────────────────────────────────────────────┘
          rt-app
             ├── rt-client  ── 带类型的 API 客户端（GUI 与 MCP 共用）
             ├── rt-server  ── axum 应用、TLS 1.3、鉴权、WebSocket 流
             └── rt-core    ── 配置、日志、密码学、路径监狱、
                               文件操作、命令执行、系统信息、屏幕截图
                                  └── rt-protocol ── 共享数据结构
```

## 功能

| 模块 | 能力 |
| --- | --- |
| 命令执行 | `cmd`、`powershell`、`pwsh`（或自定义 shell）；支持 cwd、环境变量、stdin、超时、输出上限、WebSocket 实时流式回传、超时/取消时杀进程树 |
| 文件管理 | 列出 / 详情 / 新建目录 / 删除 / 重命名 / 复制 / 区间读 / 流式上传与下载（带 SHA-256）；每个会话可选**工作区监狱**或**完全访问** |
| 系统信息 | CPU、内存、磁盘、网卡、显示器、电池、开机时长、进程列表、应用与服务端状态 |
| 屏幕画面 | 枚举显示器与窗口，单帧 PNG/JPEG 截图（主屏 / 指定屏 / 全部屏 / 指定窗口），可选低帧率实时预览 |
| 对外接口 | REST + WebSocket + `openapi.json` + MCP stdio 服务（18 个工具） |
| 安全 | TLS 1.3 + 自签证书指纹固定、argon2id 密码、会话令牌只存哈希、API Key、登录锁定 + 限流 + IP 白名单、审计日志、路径监狱、破坏性 MCP 工具审批门 |
| 运维 | `config.toml` 配置（首次运行自动生成）、按日滚动日志、JSONL 审计、单实例保护 |

## 编译

环境要求：Rust 1.85 及以上（实测 1.98.1）、**MSVC 工具链**（Visual Studio Build Tools +
Windows SDK）。目标机器**不需要**任何 C++ 运行库：可执行文件静态链接 CRT。

```powershell
# 在仓库根目录执行
cargo build --release
# → target\release\remote-terminal.exe   （单文件，无 DLL 依赖）
```

依赖通过 `.cargo/config.toml` 里配置的 rsproxy 镜像拉取
（`rustflags = ["-C", "target-feature=+crt-static"]` 让 exe 自包含）。如果想改用 crates.io，
删掉 `.cargo/config.toml` 即可。

`[profile.release]` 使用 `lto = "fat"`、`codegen-units = 1`、`strip = "symbols"`，因此首次
release 构建需要几分钟；产物体积约 10–15 MB。

### 开发期命令

```powershell
cargo check --workspace --all-targets      # 快速检查
cargo test  --workspace                    # 单元测试 + 集成测试
cargo run   --release -- --help            # 查看 CLI 帮助
cargo run   --release                      # 启动桌面 GUI
```

## 首次运行

```powershell
.\remote-terminal.exe            # 打开 GUI；在 exe 同目录创建 config.toml
.\remote-terminal.exe config     # 打印解析后的各项路径
```

`config.toml` 以合理默认值创建，且**服务端默认关闭**。日志写入 `logs/`，路径监狱根目录为
exe 同级的 `workspace/`（按需创建）。配置文件与日志都不会被 git 跟踪。

### 把一台机器变成服务端

```powershell
.\remote-terminal.exe hash-password       # 把打印出的 [[server.users]] 片段粘进配置
notepad .\config.toml                     # 设置 server.enabled = true
.\remote-terminal.exe serve               # 打印 URL 与证书指纹
```

也可以全程在 GUI 里完成：**设置 → 服务端 → 启用服务端**，添加用户后保存。GUI 可以在进程内
直接运行服务端，所以一台机器可以同时当服务端和客户端。

### 从另一台机器连接

1. `.\remote-terminal.exe fingerprint 192.168.1.10:46666` —— 打印服务端证书指纹。
2. 在 GUI 的**总览**页填写地址、端口、用户名、密码，粘贴指纹后连接。不填指纹时客户端会退化为
   首次信任（TOFU），并把实际看到的指纹显示出来，供你确认后再固定。

## 命令行

```
remote-terminal [--config PATH] [-v] <命令>

gui                       桌面界面（默认）
serve                     无界面 REST/WebSocket 服务端，Ctrl+C 停止
mcp                       stdin/stdout 上的 MCP 服务（供 harness 工具调用）
config                    显示配置文件与数据目录的实际路径
hash-password [密码]      生成可写进 config.toml 的 argon2id 密码哈希
gen-key [名称] [--scope] [--write]
                          生成 API Key（只打印一次，配置里只保存摘要）
fingerprint <host[:port]> 获取服务端 TLS 证书指纹
approve [工具] [--minutes N] [--revoke] [--list]
                          为破坏性 MCP 工具授予/查看/撤销限时审批
rotate-cert               重新生成自签证书（旧文件留作 *.old，之后需重新固定指纹）
exec <命令...>            通过服务端在远程执行命令
info                      打印远程服务端的身份信息
```

示例：

```powershell
.\remote-terminal.exe exec --host 192.168.1.10:46666 --password secret `
    --fingerprint "AB:CD:…" "Get-Service | Where-Object Status -eq 'Running'"
```

## 外部集成

* **REST/WebSocket：** 见 [`docs/API.md`](docs/API.md)，以及运行中服务端的
  `https://host:46666/api/v1/openapi.json`。
* **MCP（harness）：** 把这个可执行文件注册成 stdio 服务：

```json
{
  "version": 1,
  "servers": {
    "remote-terminal": {
      "transport": "stdio",
      "enabled": true,
      "command": "D:\\Tools\\RemoteTerminal\\remote-terminal.exe",
      "args": ["mcp"],
      "env": {
        "RT_HOST": "192.168.1.10:46666",
        "RT_PASSWORD": "…",
        "RT_FINGERPRINT": "AB:CD:…（来自 remote-terminal fingerprint 192.168.1.10:46666）"
      }
    }
  }
}
```

> MCP 侧没有终端可以让人确认证书，因此**未固定指纹的 TLS 连接一律拒绝发送密码**：首次登录前
> 必须先设置 `RT_FINGERPRINT`（或 `[[client.hosts]]` 里的 `fingerprint`）。没设置时工具会返回
> 错误并附上它看到的指纹，复制过来即可，只需两步。

### 破坏性工具的审批门

MCP 是被模型驱动的，一次提示注入或一次幻觉调用就等于在远端执行命令。为此
`rt_exec`、`rt_fs_write`、`rt_fs_delete`、`rt_fs_rename`、`rt_fs_copy`、`rt_fs_upload` 默认
**需要操作者授权**（限时租约，写到 `<数据目录>/mcp-approvals.json`）：

```powershell
.\remote-terminal.exe approve --list              # 查看当前有哪些租约
.\remote-terminal.exe approve rt_exec --minutes 30  # 允许 30 分钟
.\remote-terminal.exe approve rt_exec --revoke      # 立刻收回
```

只读工具（`rt_info`、`rt_fs_read`、`rt_fs_list`、`rt_sysinfo` 等）不受限制，Agent 可以自由
探查。租约到期自动失效，忘记回收也不会长期留下口子；确实在自有审查流程里跑的自动化，可用
`RT_REQUIRE_APPROVAL=0` 关闭这道门。

### MCP 相关环境变量

| 变量 | 作用 |
| --- | --- |
| `RT_HOST` / `RT_PORT` | 目标地址，可写成 `host:port` |
| `RT_USER` / `RT_PASSWORD` | 密码登录 |
| `RT_TOKEN` | 用 API Key 代替密码 |
| `RT_FINGERPRINT` | 固定的证书指纹（**推荐，首次登录前必须**） |
| `RT_REQUIRE_APPROVAL` | `0` 关闭破坏性工具审批门（默认开启） |
| `RT_DOWNLOAD_DIR` / `RT_CAPTURE_DIR` | 本地下载、截图允许写入的目录（默认当前工作目录） |
| `RT_INSECURE` + `RT_ALLOW_PLAINTEXT` | 两个都要设为 `1` 才允许明文连接（不建议） |

## 安全说明

* 默认值偏保守：服务端关闭、TLS 开启、会话 720 分钟、登录 5 次失败锁定、每 IP 每分钟 240 次。
* **作用域就是能力边界：** `workspace` 会话只能在 `server.workspace.root` 下浏览与修改文件、
  读取 `sysinfo`；**命令执行、屏幕截图、日志尾部需要 `full`**。工作区令牌永远无法变成远程
  shell。
* 自动化任务优先使用 **workspace** 作用域。`full` 作用域等于把整台机器的 root 权限放到网络
  上，请谨慎发放。
* 即使是 `full` 会话也碰不到 `config.toml`/`.bak`、TLS 私钥、`logs/audit.jsonl`、
  `data/instance.lock`（启动时加入拒绝名单），因此会话无法悄悄给自己提权、替换证书或抹掉审计。
  完整威胁模型与逐项攻击面审计见 [`docs/SECURITY.md`](docs/SECURITY.md)。
* `server.allow_insecure_lan` 会关闭 TLS，只建议在调试时的本机回环上使用。`serve`（CLI 与
  GUI 都是）会拒绝启动 `validate()` 不通过的配置，所以一个笔误不会把密码悄悄变成明文。
* **不建议**把端口暴露到公网。必须暴露时，请套 VPN 或反向代理，并保持指纹固定。
* 审计日志（`logs/audit.jsonl`）记录每一次有副作用的调用（命令执行记「前 200 字符 + 完整命令
  sha256」，事后仍可核对）；默认按 16 MiB 轮转、保留 10 份。把 `logging.audit_fail_closed`
  设为 `true` 后，写不进审计的破坏性请求会直接 `503` 而不会静默改机器（读操作不受影响）。
* 证书需要轮换时用 `remote-terminal rotate-cert`：旧文件留作 `*.old`，之后所有已固定的客户端都要
  重新 `fingerprint` 并更新固定值。
* 服务端自带过载保护：阻塞型工作（文件 I/O、起进程、截屏）共用 64 个准入名额，2 秒内拿不到就
  `503` + `Retry-After`；登录的密码校验**不占**这个名额，池满时仍能登录。

## 目录结构

```
crates/rt-protocol   共享数据结构与常量（无异步、无 I/O）
crates/rt-core       配置、日志、密码学、路径作用域、文件/执行/系统信息/截图
crates/rt-server     axum HTTP + WebSocket 服务端、鉴权中间件、TLS
crates/rt-client     带类型客户端（GUI 与 MCP 共用）
crates/rt-app        二进制：CLI、启动引导、GUI、MCP 服务
docs/                ARCHITECTURE.md、API.md、SECURITY.md
```

## 测试

```powershell
cargo test --workspace
```

覆盖范围：路径监狱越狱对抗测试、配置校验与迁移、密码/令牌处理、日志环形缓冲、临时目录上的
文件系统操作、命令执行的超时与输出上限、客户端 URL 与错误处理、端到端（真实 TLS + 进程内
服务端，含作用域边界断言）。
