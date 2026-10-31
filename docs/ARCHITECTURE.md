# RemoteTerminal — 架构与协作契约

> 本文件是并行开发的**唯一契约**。任何跨模块的改动都必须先改这里，再改代码。
> 语言：文档中文、代码注释英文、UI 文案中文（可切换）。

## 1. 目标与边界

一个 Windows 单体可执行文件（`remote-terminal.exe`），同时是：

1. **GUI**（eframe/egui）：本机管理界面、连接管理、文件浏览、终端、屏幕查看、日志。
2. **服务端**（可选开启）：TLS + HTTP/WS，供其他机器或 harness 调用。
3. **客户端**：连接任意开启服务端的 RemoteTerminal 实例。
4. **MCP 服务器**（`remote-terminal.exe mcp`）：stdio JSON-RPC，可写进 dsh-mcp.json 直接被 Agent 当工具调用。
5. **CLI**：无 GUI 场景下的脚本入口。

非目标：不实现"无人值守的持久后门"、不实现端口内网穿透、不做多用户权限组（用户是配置里扁平列表）。

## 2. Crate 图与文件归属

```
rt-protocol  ← 纯契约类型（serde），无 IO
    ↑
rt-core      ← 配置/日志/加密/鉴权/路径监狱/exec/fs/sysinfo/capture（阻塞实现，含单测）
    ↑
rt-server    ← axum 路由 + WS + TLS 监听（把 rt-core 暴露成 API）
rt-client    ← 基于 API 的类型化客户端（GUI 与 MCP 共用）
    ↑
rt-app       ← main.rs（CLI 分发）+ GUI + MCP 桥
```

**文件归属（并行开发时不要跨域修改）**

| 归属 | 文件 |
|---|---|
| Lead | `Cargo.toml`(根)、`.cargo/`、`.gitignore`、`docs/**`、`crates/rt-protocol/**`、`crates/rt-core/src/{error,config,logging,crypto,pathscope,auth,util,lib}.rs` |
| files | `crates/rt-core/src/fsops.rs` |
| exec+sysinfo | `crates/rt-core/src/exec.rs`、`crates/rt-core/src/sysinfo.rs` |
| capture | `crates/rt-core/src/capture.rs` |
| server | `crates/rt-server/**` |
| client+mcp | `crates/rt-client/**`、`crates/rt-app/src/mcp/**` |
| gui | `crates/rt-app/**`（除 `mcp/**`） |

约定：需要改别人的模块（比如给 `PathGuard` 加方法）→ 先在自己的 PR/提交说明里写清，或直接找 Lead。**不要**重排整文件、不要全局格式化别人的文件。

## 3. 安全模型（必须全部实现）

1. **传输**：默认 TLS 1.3（自签证书，首次使用由客户端固定指纹 TOFU；`require_pinned_fingerprint=true` 时指纹不匹配直接拒绝）。`server.tls=false` 仅在 `allow_insecure_lan=true` 且绑定回环时允许，否则配置校验报错。
2. **认证**：
   - 密码：Argon2id PHC 串存配置；长度 ≥ 8；比对失败也执行一次 decoy 校验以抹平时序。
   - 会话令牌：32 字节随机（base64url），服务端只存 SHA-256；TTL 可配置（默认 720 分钟）；`max_sessions` 上限。
   - API Key：`rt_` 前缀 + 43 字符，配置只存 SHA-256，作用域独立。
   - WebSocket 不能带自定义头 → 先 `POST /api/v1/auth/ws-ticket` 拿 60 秒一次性 ticket，再 `GET /api/v1/ws?ticket=...`。
3. **限流与锁定**：每 IP 登录失败 `login_max_attempts` 次 → 锁定 `login_lockout_secs`；全局限流 `rate_limit_per_min` 令牌桶；`ip_allowlist` 非空时只放行匹配前缀。
4. **路径监狱**（`rt-core::pathscope`，唯一入口）：所有文件/执行操作必须先 `guard.resolve(virtual_path)`。Workspace 作用域下 `\a\b` 是虚拟路径、物理落点在 `workspace.root`；Full 作用域下也禁止 UNC、`\\.\`、`\\?\GLOBALROOT`、ADS（`:`）、保留设备名、魔法通配符，并做 canonicalize 后前缀比对防符号链接逃逸。
5. **执行**：`shell` 只接受白名单枚举（Cmd/Powershell/Pwsh/Custom）；Custom 必须是已存在的可执行文件绝对路径；`cwd` 过 guard；超时强制 kill 进程树；输出上限截断并标记 `truncated`。
6. **上传/下载**：上传流式写临时文件再原子 rename，强制 `max_upload_bytes`；下载支持 Range，路径必须过 guard；不允许写 `config.toml`/证书私钥（guard 之外再加黑名单）。
7. **审计**：所有写操作、登录、exec、截屏都写 `logs/audit.jsonl`（`AuditEvent`），同时镜像到 tracing。
8. **默认最小暴露**：`server.enabled=false` 默认关闭；默认 `bind=0.0.0.0` 但必须 TLS + 有密码用户才能启用；启动日志打印指纹与监听地址。
9. **作用域即能力边界**：`Scope::Workspace` 会话只能做文件读写与查询；**exec、截屏/窗口、日志读取要求 `Scope::Full`**（`require_full_scope`），workspace 令牌不得等于全盘 RCE。
10. **控制文件黑名单**（`pathscope::protect_paths`，启动时安装一次）：无论作用域，`config.toml`/`config.toml.bak`/`data/instance.lock`/TLS 目录（含私钥）/`logs/audit.jsonl` 及其祖先目录全部拒绝 —— 否则 Full 会话可自行加用户、替换私钥或抹掉审计。
11. **凭据只在已固定的证书上发送**：证书指纹未固定时（TOFU），客户端（CLI/MCP）只允许发一次**未认证**的 `health` 探针来获取指纹，随后报错要求把指纹写进配置或 `RT_FINGERPRINT`，**绝不在未固定连接上传输密码**。
12. **`serve` 强制校验配置**：`rt-app` 的 `serve` 与 `rt_server::serve` 在绑定端口前调用 `Config::validate()`，有 error 即拒绝启动（防止 `tls=false` 静默明文上线）。

## 4. 配置文件

- 路径解析顺序：`--config` → 环境变量 `REMOTE_TERMINAL_CONFIG` → **当前工作目录** `config.toml` → exe 同目录 → `%APPDATA%`（取第一个可写的）。
- 首次启动若无文件：写默认 `config.toml`（带注释头），并创建 `workspace/`、`logs/`、`data/`。
- 写入：`write_atomic`（tmp + fsync + rename），保留 `config.toml.bak`。
- 版本号 `config_version = 1`；未来迁移在 `Config::migrate` 中做（当前只接受 1）。
- `.gitignore` 已排除 `config.toml`、`*.local.toml`、`logs/`、`audit/`、`workspace/`、`data/`、`downloads/`、`uploads/`、`captures/`。

关键结构见 `crates/rt-core/src/config.rs`（`AppConfig`/`LoggingConfig`/`ServerConfig`/`ClientConfig`）。**默认值**：

```
server.enabled=false  port=46666  tls=true  bind=0.0.0.0
session_ttl_minutes=720  max_sessions=32  login_max_attempts=5  login_lockout_secs=300
rate_limit_per_min=240  max_upload_mb=2048  max_json_kb=256
exec_timeout_secs=300  exec_max_output_kb=8192  max_concurrent_exec=8
capture_max_fps=15  status_max_fps=5  max_list_entries=5000
workspace.root="workspace"  users=[]  api_keys=[]
client.require_pinned_fingerprint=true  request_timeout_secs=60  default_shell="pwsh"
```

## 5. REST API（冻结的路由表）

统一前缀 `/api/v1`。错误统一 `ApiErrorBody`：`{"error":{"code","message","detail?","request_id?","retry_after_secs?"}}`。鉴权头 `Authorization: Bearer <token|api-key>`。

| Method | Path | 鉴权 | 说明 |
|---|---|---|---|
| GET | `/healthz` | 无 | `{"status":"ok","version":"0.1.0"}` |
| GET | `/api/v1/info` | 无 | `ServerInfo`（含指纹、能力、端点）；**不含任何秘密** |
| POST | `/api/v1/auth/login` | 无 | `LoginRequest` → `LoginResponse` |
| POST | `/api/v1/auth/logout` | 有 | `Ack` |
| GET | `/api/v1/auth/me` | 有 | `SessionInfo` |
| POST | `/api/v1/auth/ws-ticket` | 有 | `WsTicketResponse` |
| GET | `/api/v1/exec/shells` | 有 | `ShellListResponse` |
| POST | `/api/v1/exec` | 有 | `ExecRequest` → `ExecResult` |
| GET | `/api/v1/fs/roots` | 有 | `FsRoots` |
| GET | `/api/v1/fs/list?path=` | 有 | `ListDirResponse` |
| GET | `/api/v1/fs/stat?path=` | 有 | `StatResponse` |
| POST | `/api/v1/fs/mkdir` | 有 | `MkdirRequest` → `FsEntry` |
| POST | `/api/v1/fs/delete` | 有 | `DeleteRequest` → `DeleteResult` |
| POST | `/api/v1/fs/rename` | 有 | `RenameRequest` → `Ack` |
| POST | `/api/v1/fs/copy` | 有 | `CopyRequest` → `WriteResult` |
| GET | `/api/v1/fs/read?path=&offset=&length=` | 有 | `ReadFileResult`（base64 + 文本） |
| GET | `/api/v1/fs/download?path=` | 有 | 原始字节流，支持 `Range`，`Content-Disposition` |
| POST | `/api/v1/fs/write?path=&overwrite=&create_parents=` | 有 | body = 原始字节 → `WriteResult` |
| POST | `/api/v1/fs/upload?path=&overwrite=&create_parents=` | 有 | multipart（字段 `file`）→ `WriteResult` |
| GET | `/api/v1/sysinfo` | 有 | `SysInfoSnapshot` |
| GET | `/api/v1/sysinfo/quick` | 有 | `QuickStatus` |
| GET | `/api/v1/sysinfo/processes?limit=&query=&sort=&descending=` | 有 | `ProcessListResponse` |
| GET | `/api/v1/capture/screens` | 有 | `ScreenListResponse` |
| GET | `/api/v1/capture/windows` | 有 | `WindowListResponse` |
| POST | `/api/v1/capture` | 有 | `CaptureRequest` → `CaptureResponse`（base64） |
| GET | `/api/v1/capture/raw?target=primary&format=png&quality=80` | 有 | 原始图片字节（浏览器可直接 `<img>`） |
| GET | `/api/v1/ws` | ticket | WebSocket，见 `rt-protocol::ws` |
| GET | `/api/v1/ws/info` | 有 | `WsInfo` |
| GET | `/api/v1/openapi.json` | 无 | OpenAPI 3.1 文档（手写 JSON） |
| GET | `/api/v1/logs?limit=` | 有 | 最近日志 `Vec<LogEvent>` |
| GET | `/api/v1/audit?limit=` | 有 | 最近审计（仅 Full 作用域） |

中间件顺序：`Timeout` → `Trace` → `RequestBodyLimit` → `Auth` → handler。`RequestId` 由中间件生成并回写到错误体与审计。

## 6. WebSocket

握手：`GET /api/v1/ws?ticket=<one-time>`。消息见 `crates/rt-protocol/src/ws.rs`：
`exec`（流式执行）/`cancel`/`capture_stream`/`subscribe_logs`/`subscribe_status`/`unsubscribe`/`ping`；
服务端回 `accepted`/`exec_started`/`exec_output`/`exec_finished`/`capture_frame`/`capture_stopped`/`log`/`status`/`error`。

实现要点：每个 `id` 一个任务；`exec` 用 `spawn_blocking` + `mpsc::UnboundedSender`（核心层是阻塞回调）；`capture_stream` 用 `tokio::time::interval`，帧率上限 `capture_max_fps`；所有流在断开时中止。

## 7. rt-client（GUI/MCP 共用）

```rust
pub struct Target { pub host: String, pub port: u16, pub tls: bool, pub fingerprint: Option<String> }
pub struct RemoteClient { /* reqwest::Client + base url + token */ }
impl RemoteClient {
    pub fn new(target: &Target) -> Result<Self>;                    // 按指纹/TOFU 建 TLS
    pub async fn info(&self) -> Result<ServerInfo>;
    pub async fn login(&self, user: &str, pass: &str, device: &str) -> Result<LoginResponse>;
    pub async fn logout(&self) -> Result<()>;
    pub async fn me(&self) -> Result<SessionInfo>;
    pub async fn exec(&self, req: &ExecRequest) -> Result<ExecResult>;
    pub async fn shells(&self) -> Result<ShellListResponse>;
    pub async fn roots(&self) -> Result<FsRoots>;
    pub async fn list(&self, path: &str) -> Result<ListDirResponse>;
    pub async fn stat(&self, path: &str) -> Result<StatResponse>;
    pub async fn mkdir/delete/rename/copy/read/write/upload/download ...;
    pub async fn sysinfo(&self, quick: bool) -> ...;
    pub async fn processes(&self, q: &ProcessQuery-ish) -> ...;
    pub async fn screens(&self) -> Vec<ScreenInfo>; windows(); capture(&CaptureRequest) -> Vec<u8>;
    pub async fn ws(&self) -> Result<WsClient>;                     // 自动换 ticket
}
```
下载走流式（`futures_util::Stream` → 文件），上传用 `Body::wrap_stream` 或 `bytes`。

## 8. GUI（eframe/egui）设计规范落地

参考 `D:\TemporaryFiles\UIDevelopInstructions.md` 的可落地子集（毛玻璃无原生支持 → 降级）：

- **响应即时**：hover/press 变化 ≤ 100ms；拖拽 1:1 跟手。
- **弹簧动画**：`Spring { value, velocity, tension: 220.0, damping: 26.0 }`，每帧 `dt` 步进，用于侧栏展开、面板切换、Toast 出现；`response 0.3s / damping 1.0` 对应到 `tension≈210, damping≈24`。
- **可中断**：动画只追随目标值，不播放完再改。
- **空间一致性**：列表滚动位置、选中项跨视图保留；过渡沿进入方向。
- **层次**：窗口背景 `#0F1115`(dark)/`#F6F7F9`(light)；卡片 `#161A20`/`#FFFFFF` + 1px 边框 `rgba(255,255,255,.06)`；强调色 `#3B82F6`；成功 `#10B981`；警告 `#F59E0B`；危险 `#EF4444`。
- **排版**：标题 20/600，正文 14/400，辅助 12/400；行高 = 字号 × 1.45；`prefers-reduced-motion` → 配置里 `app.reduce_motion=true` 时 dt 直接置 1（无动画）。
- **降级项**：backdrop-filter → 半透明叠层 + 边框；材质高光 → 1px 顶部渐变描边。

视图：`Overview`（状态卡片 + 快捷动作）、`Files`（双栏：本机/远程，或远程单栏 + 面包屑）、`Terminal`（命令历史 + 流式输出）、`Screen`（屏幕/窗口列表 + 预览，2 fps 轮询）、`Server`（开关/端口/密码/指纹/用户与 API Key 管理）、`Logs`（tracing 尾部 + 过滤）、`Settings`（主题/语言/路径/动画）。

状态机：`Disconnected → Probing(信息/指纹) → Login → Connected`。所有网络调用走 `tokio` 后台任务 + `mpsc` 回 UI 线程，UI 线程**绝不阻塞**。

## 9. MCP 桥（`remote-terminal.exe mcp`）

stdio JSON-RPC 2.0（手写，不引 rmcp）：
- `initialize` → `{"protocolVersion":"2024-11-05","capabilities":{"tools":{}},"serverInfo":{...}}`
- `tools/list` → 工具表
- `tools/call` → 执行并返回 `{"content":[{"type":"text","text":...}],"isError":false}`
- `ping` / `notifications/initialized`（忽略）/ `resources/list`（空）

工具：`rt_connect`、`rt_info`、`rt_exec`、`rt_fs_list`、`rt_fs_read`、`rt_fs_write`、`rt_fs_mkdir`、`rt_fs_delete`、`rt_fs_rename`、`rt_download`、`rt_upload`、`rt_sysinfo`、`rt_processes`、`rt_screens`、`rt_windows`、`rt_capture`（返回图片路径或 base64）。
配置来源：`--config` 里的 `client.hosts[0]` 或环境变量 `RT_HOST`/`RT_PORT`/`RT_USER`/`RT_PASSWORD`/`RT_FINGERPRINT`。

## 10. CLI

```
remote-terminal                     # 默认：GUI
remote-terminal gui [--config P]
remote-terminal serve [--config P]  # 无界面运行服务端
remote-terminal mcp  [--config P]   # MCP stdio
remote-terminal hash-password       # 交互式生成 argon2 串
remote-terminal gen-key             # 生成 API Key
remote-terminal fingerprint [--config P]
remote-terminal exec --host H --port P --user U --pass W "dir"
remote-terminal info  --host H ...
remote-terminal call  --host H ...  # 任意 REST 调用（调试用）
```

## 11. 构建与测试

```
cargo test  -p rt-protocol -p rt-core          # 单测
cargo check --workspace --all-targets          # 全量编译检查
cargo build --release -p rt-app                # 产物 target/release/remote-terminal.exe
```
单文件：`.cargo/config.toml` 已设 `-C target-feature=+crt-static`（静态 CRT）+ release `lto=fat/panic=abort/strip`。

## 12. 编码规范

- 注释英文、简洁；每个 `pub` 项一句 doc。`unsafe` 只允许在确有必要的系统调用处，并写安全说明。
- 错误一律 `RtError`（core）/ `ApiErrorBody`（server），不 `unwrap()` 生产路径（测试可以）。
- 阻塞操作（exec/fs/sysinfo）只在 `spawn_blocking` 里跑。
- 日志：`tracing::info!(target: "exec", ...)`；敏感字段（密码/token/key）**永不入日志**。
- 提交信息：`feat: ...` / `fix: ...` / `bug: ...` / `docs: ...` / `chore: ...`，一次提交只做一件事。
- 每完成一个可编译的功能就提交一次，提交前必须 `cargo check`（自己的 crate 至少）通过。
