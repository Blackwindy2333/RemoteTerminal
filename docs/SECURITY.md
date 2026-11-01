# RemoteTerminal 安全威胁模型与加固审计

> 审计对象：本仓库 `main` 分支（`crates/rt-core`、`crates/rt-server`、`crates/rt-client`、`crates/rt-app`、`crates/rt-protocol`）。
> 审计方式：逐文件通读真实实现 + 对照 `docs/ARCHITECTURE.md` 的契约声明 + 关键路径手工推演（路径解析、TLS 校验、上传流控、WS 出口）。
> 本文所有结论都带 `文件:行号` 证据；标记 **已防** 的条目同样给证据，便于回归时验证没有退化。
> 本文只写结论与修复建议，**不改任何代码**；修复由各模块负责人执行。

## 0. 执行摘要

RemoteTerminal 的**密码学底座与路径监狱实现质量很高**：Argon2id + 常量时间比较、令牌只存摘要、TLS 1.3 单版本 + 指纹固定（ct_eq）、`PathGuard` 对 `..`/UNC/`\\.\`/`\\?\`/ADS/尾点空格/保留名全部做了显式拒绝，并且 `deepest_canonical` 的"最短存在祖先 + 后缀回填"逻辑让含 `..` 的路径**要么被 canonicalize 吃掉、要么直接报错**，不会带着 `..` 通过前缀比对。这部分可以判定为**已防**（§3.1）。

真正的风险集中在**授权边界被绕过**、**服务启动不校验配置**、**TLS 监听可被单连接拖死**、**MCP/CLI 的 TOFU 时序**、以及**WS/exec 出口队列无界**这五类。最严重的是 `POST /exec`：**workspace 作用域只约束了文件 API，没有约束命令执行**——低权 agent 拿到 workspace 令牌即可获得服务器用户的全盘读写与任意代码执行，`scope` 作为安全边界的假设被完全推翻。

| 级别 | 数量 | 代表条目 |
|---|---|---|
| CRITICAL | 1 | S-01 exec 无作用域校验（workspace 会话 = 全盘 RCE） |
| HIGH | 7 | S-02 截屏无作用域校验；S-03 WS 日志绕过 Full 限制；S-04 `serve` 不校验配置可明文绑定 0.0.0.0；S-05 TLS 握手无超时；S-06 TOFU 先登录后提示；S-07 WS/exec 出口无界；S-08 配置文件/私钥黑名单缺失 |
| MEDIUM | 17 | S-09…S-25（审计缺口、DNS rebinding、XFF 信任、stdin 超时、进程树、API Key 不可吊销、私钥 ACL、磁盘配额、MCP 注入面、锁定策略等） |
| LOW | 17 | S-26…S-42（panic 日志、路径信息泄漏、保留名变体、RTL 伪装、`C:` 残余、TOCTOU、信息回显等） |

**最该马上修的三件事**：S-01（exec 加作用域校验）、S-04（`serve` 入口强制 `validate()`）、S-05（TLS 握手加超时）。这三条改动量都在 10 行以内，但分别对应"越权"、"明文暴露"、"远程 DoS"三个最坏结果。

> **修复状态（2026-11-01 更新）：本文列出的 S-01…S-42 共 42 条发现已全部修复，并逐条附了提交哈希与验证方式，见 §9「修复状态对照表」。** §2–§4 保留审计当时的原始证据（行号、`✘` 标记都是修复**前**的），它们的作用是回归与复盘：改动相关文件时按这些证据逐条复查，确认没有被改回去。

---

## 1. 威胁模型

### 1.1 资产

| 资产 | 说明 | 一旦失窃/被控的后果 |
|---|---|---|
| A1 远程 shell | `POST /api/v1/exec`、WS `exec`、MCP `rt_exec` | 以服务端用户身份任意代码执行 → 其余资产全部失守 |
| A2 全盘文件 | Full 作用域下的 `fs/*` 端点 | 读取文档/浏览器凭据/SSH 私钥，写入启动项 |
| A3 屏幕 | `capture/*`、WS `capture_stream` | 屏幕上的密码、聊天、密钥、内网拓扑 |
| A4 凭据 | 配置里的密码哈希、API Key 摘要、TLS 私钥、会话令牌 | 长期免密访问、服务端冒充 |
| A5 审计日志 | `logs/audit.jsonl` | 事后追溯与取证能力 |
| A6 可用性 | 单 exe 桌面工具，常跑在用户工作机上 | 本机不可用、磁盘打满 |

### 1.2 攻击者能力

| 编号 | 攻击者 | 能力 |
|---|---|---|
| A-1 | 同网段嗅探者 / 中间人 | 可 TCP 重定向、可看明文、可在首次连接时冒充（TOFU 窗口） |
| A-2 | 拿到一个 **workspace 作用域**会话的低权用户/agent | 可调所有 REST/WS 端点，受文件监狱约束 |
| A-3 | 恶意 MCP 提示注入 | 诱导 LLM 调用任意工具（含 `rt_exec`），参数由攻击者构造 |
| A-4 | 暴力破解者 | 可高频 `POST /auth/login`，可轮换源 IP |
| A-5 | DoS 攻击者 | 可开大量 TCP/WS 连接、发慢请求、发大请求体 |
| A-6 | 宿主上的低权本地用户 | 可读数据目录 ACL 允许读的文件、可在 workspace 内创建 junction |
| A-7 | 恶意网页（浏览器 + 本机已开服务端） | 可对 `127.0.0.1:46666` 发起跨站请求（DNS rebinding 时同源读取） |

### 1.3 信任边界

| 边界 | 机制 | 代码位置 | 失效后果 |
|---|---|---|---|
| B1 网络 → 服务 | 可选 TLS 1.3 + 证书指纹固定 | `crates\rt-core\src\crypto.rs:169-188`、`crypto.rs:341-439` | 凭据与内容明文，或中间人 |
| B2 请求 → 会话 | `Authorization: Bearer`（会话令牌/API Key） | `crates\rt-server\src\middleware.rs:282-350` | 未授权访问 A1/A2/A3 |
| B3 会话 → 作用域 | `Scope::{Workspace,Full}` + `PathGuard` | `crates\rt-core\src\pathscope.rs:85-105`、`crates\rt-server\src\state.rs:296-303` | 越狱读全盘 |
| B4 请求 → 资源 | 体积/条目/超时/并发上限 | `state.rs:272-278`、`middleware.rs:472-504`、`routes/fs.rs:345-352` | 内存/磁盘/线程耗尽 |
| B5 工具 → 远端 | MCP stdio + 环境变量凭据 | `crates\rt-app\src\mcp\mod.rs`、`mcp\tools.rs` | 提示注入直达 A1/A2 |
| B6 进程 → 本机数据 | 文件系统 ACL（**未额外加固**） | `crates\rt-core\src\config.rs:750-777` | 本地用户读私钥/改配置 |

### 1.4 不在范围内

供应链（crate 依赖审计）、Windows 内核/驱动提权、物理访问、社工运维人员、`targets.rs` 之外的第三方 MCP 客户端行为。

---

## 2. 攻击面清单

图例：**✔已防** / **△部分** / **✘未防**。所有 REST 端点前缀 `/api/v1`。

### 2.1 REST

| 端点 | 鉴权 | 校验点 | 结论 |
|---|---|---|---|
| `GET /healthz` | 无 | `middleware.rs:163-168` 明确公开；限流豁免 `:305-309` | ✔已防（无信息） |
| `GET /info` | 无 | `routes/health.rs:20-22`；`state.rs:354-367` 排除秘密 | △部分（泄漏 hostname/端点/证书指纹，见 S-27） |
| `POST /auth/login` | 无 | JSON-only `middleware.rs:476-489`；锁定 `routes/auth.rs:36-56`；恒时校验 `rt-core/auth.rs:250-278` | △部分（S-22 仅按 IP 锁定；S-32 泄漏剩余次数） |
| `POST /auth/logout` | Bearer | `routes/auth.rs:129-151` | △部分（S-14 API Key 不可吊销） |
| `GET /auth/me`、`POST /auth/ws-ticket` | Bearer | `routes/auth.rs:154-191` | ✔已防 |
| `POST /exec` | Bearer | `routes/exec.rs:30-40`：`validate()` + `try_acquire_owned` + 审计 | ✘**S-01 无作用域校验** |
| `GET /exec/shells` | Bearer | `routes/exec.rs:17-19` | ✔已防（只回枚举名） |
| `fs/roots,list,stat,read` | Bearer | `routes/fs.rs:80-219` 全部经 `fsops` → `guard.resolve` | ✔已防（S-09 read 未审计） |
| `fs/mkdir,delete,rename,copy,write,upload,download` | Bearer | `routes/fs.rs:318-467`、`fsops::*`；流式计数 `:345-352`、`:431-438` | ✔已防（S-08 自身文件、S-16 磁盘） |
| `sysinfo`、`sysinfo/quick`、`sysinfo/processes` | Bearer | `routes/sysinfo.rs:57-63` 限条目 | △部分（S-21 进程列表/命令行泄漏） |
| `capture`、`capture/screens`、`capture/windows`、`capture/raw` | Bearer | `routes/capture.rs`（无作用域校验） | ✘**S-02** |
| `logs` | Bearer | `routes/meta.rs:33` `require_full_scope` | ✔已防 |
| `audit` | Bearer | `routes/meta.rs:45` `require_full_scope` | ✔已防（S-35 全量读） |
| `openapi.json` | 无 | `routes/mod.rs:30-76` | ✔已防（纯文档） |

### 2.2 WebSocket

| 入口/消息 | 鉴权 | 校验点 | 结论 |
|---|---|---|---|
| `GET /ws?ticket=` | ticket（一次性 60 s） | `middleware.rs:163-168` 公开 + `routes/ws.rs:43-60` | △部分（S-24 ticket 在 URL 中） |
| `exec` / `cancel` | ticket→会话 | `routes/ws.rs:313-439` | ✘**S-01**（无作用域）、S-07（出口无界） |
| `capture_stream` | ticket→会话 | `routes/ws.rs:442-521`（限 fps/宽度） | ✘**S-02** |
| `subscribe_logs` / `subscribe_status` | ticket→会话 | `routes/ws.rs:227-273`（**无** `require_full_scope`） | ✘**S-03** |
| `ping` / 未知类型 | ticket→会话 | `routes/ws.rs:106-131` | ✔已防（错误帧不关连接、有大小上限 1 MiB） |

### 2.3 MCP 桥（stdio）

| 项 | 校验点 | 结论 |
|---|---|---|
| 传输 | 本进程 stdin/stdout，无网络监听 | ✔已防（仅本机） |
| 凭据来源 | `RT_PASSWORD`/`RT_TOKEN`/`RT_FINGERPRINT`（`mcp/tools.rs:52-99`） | △部分（S-06 TOFU、S-20 明文、S-38 环境/配置持久化） |
| 工具集（17 个） | `mcp/tools.rs:146-285` | △部分（S-17 无审批、S-18 内存缓冲、S-19 任意本地落盘） |
| 参数校验 | `inputSchema` + `additionalProperties:false`（`tools.rs:555-576`） | ✔已防（服务端二次校验，`rt_fs_delete` 默认 `recursive=false`、`rt_fs_write` 默认 `overwrite=false`） |

### 2.4 CLI / 进程

| 项 | 结论 |
|---|---|
| `--password` / `--token` 在 argv（`cli.rs:120-124`） | ✘ S-38（进程列表/历史可见） |
| `remote-terminal serve` | ✘ S-04（不校验配置）；`enabled=false` 时仅 warn（`main.rs:159-162`，显式请求下可接受） |
| `hash-password` 无参数时读 stdin 提示 | ✔已防 |
| 单实例锁（`bootstrap.rs:99-120`） | ✔已防（避免多实例共享数据目录） |

---

## 3. 重点审查结论（逐项，含证据）

### 3.1 路径监狱（`crates\rt-core\src\pathscope.rs`）

唯一入口 `PathGuard::resolve`（`:85-105`）：`validate_syntax` → `compose` → `deepest_canonical` → 前缀比对（`:90`，失败 `:98` 返回 `scope_violation`）。所有文件/执行入口均先 resolve（fsops 13 个公开函数、`exec::prepare:309-316`、`routes/fs.rs` 全部 handler）。**总判定：监狱成立**，逐项如下。

| 攻击向量 | 结论 | 证据 |
|---|---|---|
| `..` 穿越 | ✔已防 | `deepest_canonical`（`:316-360`）自底向上弹组件，遇到 `.`/`..` 时 `file_name()` 为 `None` → 直接 `Err`（`:332-355`）。因此返回路径不含 `..`；含 `..` 且无法被 OS canonicalize 的请求**报错而非放行**。手工推演：workspace=`C:\ws`，`\nope\..\..\outside.txt` → `NotFound`，不会得到 `C:\outside.txt`。 |
| 绝对路径越界 | ✔已防 | `compose:113` 放行盘符绝对路径，但 canonicalize 后 `:90` 前缀比对拒绝 `C:\ws2`（组件级比较，`components_ci:363-382`）。单测 `:508-518`。 |
| UNC `\\host\share` | ✔已防 | `:204-208` 先按字符串拒绝，`Component::Prefix::UNC/VerbatimUNC` 再拒（`:230-234`）。 |
| 设备命名空间 `\\.\`、`\\.?\` | ✔已防 | `:192-201` 字符串拒绝 + `Prefix::DeviceNS`（`:235-239`）。 |
| `\\?\GLOBALROOT` | ✔已防 | `:197` 显式拒绝（且 `:204` 的 `\\` 分支已覆盖所有 verbatim 形式）。 |
| `\\?\C:\...`（超长前缀注入） | ✔已防 | 同上；`to_extended`（`:397-406`）只在 `is_absolute() && len>=240` 时补 `\\?\`，且发生在**校验之后**，用户无法注入。 |
| ADS `file:stream` | ✔已防 | `Normal` 组件含 `:` → `InvalidPath`（`:249-253`）。 |
| 通配符 `* ? < > \| "` | ✔已防 | `:254-258`。 |
| 结尾点/空格 | ✔已防 | `:259-263`。 |
| 保留设备名 `CON`/`COM1`… | ✔已防（主表） | 取首个 `.` 前主干大写比对 `RESERVED`（`:264-269`，表 `:21-24`）。**变体缺口见 S-28**。 |
| 8.3 短名 | ✔已防 | `canonicalize` 经 `GetFinalPathNameByHandle` 返回长名，前缀比对看到的是真实长路径。 |
| junction / symlink **穿越** | ✔已防 | resolve 后 canonicalize 会解析链接再比对前缀 → 链到外面即拒绝。`list` 用 `symlink_metadata`（`crates\rt-core\src\fsops.rs` 内 `entry_for`），不跟随；`delete` 对链接用 `remove_dir`/`remove_file` 且**不递归进入**；`copy_dir_tree` 跳过 reparse point。 |
| junction/symlink **创建** | ✔已防（远程不可创建） | 远程 API 只有 `write`(文件)、`mkdir`(真实目录)、`copy`(跳过链接)，不能造 junction/symlink。 |
| 大小写 / Unicode 归一化 | ✔已防 | 前缀两端都来自文件系统真实大小写，ASCII 折叠足够；NTFS 不做 Unicode 归一化，无同义路径。 |
| 盘符相对 `C:foo` | ✔已防 | `:213-221` 拒绝。残余 `C:`（无尾随）→ S-30。 |
| resolve→IO 的 TOCTOU | △部分 | 校验与真正 IO 之间有时间窗（`fsops.rs` 全流程）；远程无法制造 junction，本地攻击者可以 → S-31。 |

其它路径相关结论：
- 返回给客户端的 `path`/`parent` 一律 `guard.display()`（`pathscope.rs:136-154`）；`strip_prefix` 失败时回退绝对路径（信息泄漏，但仅路径本身）。
- `display`/错误消息中**不含**文件内容，只含路径。
- 根保护：`delete` 拒删 workspace root 与盘符根（`fsops::ensure_deletable`）；`rename/copy` 拒把目录搬进自己子树。

### 3.2 认证与授权

| 项 | 结论 | 证据 |
|---|---|---|
| 会话令牌熵 | ✔已防 | `crypto::random_token(32)` = 32 字节 `OsRng`（`crypto.rs:90-95`）→ 256 bit；`auth.rs:116`。 |
| 令牌存储 | ✔已防 | 服务端只存 `sha256_hex`（`auth.rs:229-231`），内存被 dump 也拿不到可用令牌。 |
| 过期 / 上限 / 吊销 | ✔已防（会话） | TTL `auth.rs:97`（默认 720 分钟 → `config.rs:238`）；`max_sessions` 驱逐最早过期（`auth.rs:130-140`）；`lookup` 懒清过期（`:162-177`）；`revoke`/`revoke_user`（`:179-227`）。 |
| API Key 不可吊销 | ✘ S-14 | `routes/auth.rs:129-151`：`logout` 只吊销密码会话，key 无状态；泄漏只能改配置重启。 |
| API Key 比对 | ✔已防 | 先 SHA-256 再 `ct_eq`（`crypto.rs:140-149`、`82-87`）；`verify_api_key` 全表扫描不提前返回（`auth.rs:285-302`）。 |
| 密码哈希 | ✔已防 | Argon2id `Argon2::default()`（m≈19 MiB,t=2,p=1，OWASP 基线），长度 ≥8 强制（`crypto.rs:112-123`）。 |
| 时序侧信道 | ✔已防 | 未知用户也跑一次 decoy 校验（`auth.rs:274`），错误文案统一（`:270/:275`）。 |
| scope 解析失败 | ✔已防 | `scope_of` 与 key scope 解析失败一律回落 `Workspace`（`auth.rs:280-282`、`:297`）。 |
| **exec 作用域** | ✘ **S-01** | `routes/exec.rs:22-86`、`routes/ws.rs:313-439` 均未调用 `require_full_scope`；`require_full_scope` 全仓库只出现在 `routes/meta.rs:33,45`。 |
| **capture 作用域** | ✘ S-02 | `routes/capture.rs` 全文件无作用域检查；`routes/ws.rs:191-225` 同。 |
| **WS 日志作用域** | ✘ S-03 | `routes/ws.rs:227-273` 无检查，而 REST `logs` 需要 Full（`meta.rs:33`）。 |
| 登录锁定 | △ S-22 | 按 **IP** 计（`routes/auth.rs:38,71,97`）：NAT 下连坐；分布式来源对单账号无上限。 |
| `X-Forwarded-For` 信任 | ✘ S-11 | `middleware.rs:365-411` 只要 `trust_forwarded_for=true` 就取首个可解析 IP；默认 `false`（`config.rs:244`）**已防**，但一旦在无反代环境打开，白名单/锁定/限流/审计全部可伪造。 |
| IP 白名单 | ✔已防 | `auth.rs:483-495`：空前缀才匹配，`192.168.` 需带尾分隔符；`::ffff:` 只展开点分形式，展开失败即拒绝（fail-closed）。 |
| 会话数上限 | ✔已防 | `state.rs:105`、`auth.rs:130-140`。 |

### 3.3 传输与 PKI

| 项 | 结论 | 证据 |
|---|---|---|
| TLS 版本 | ✔已防 | 仅 TLS 1.3（`crypto.rs:183`），无降级路径。 |
| 套件 | ✔已防 | rustls 默认套件（AEAD 全前向保密），ring provider 一次性安装（`crypto.rs:191-198`）。 |
| 指纹固定 | ✔已防 | 只比叶子证书 SHA-256，`ct_eq`（`crypto.rs:346-375`），不匹配即 `ApplicationVerificationFailure`。 |
| `danger_accept_invalid_certs(true)` | ✔已防（组合正确） | `crypto.rs:412-422`：自定义 verifier **完全接管**校验，`dangerous()` 只是绕过硬校验，不削弱固定逻辑。 |
| TOFU 语义 | ✘ S-06 | `PinMode::Tofu` 接受任意证书（`crypto.rs:370-373`）本身是设计；问题是 GUI 之外没人拦：`RemoteClient::new` 无指纹即 TOFU（`rt-client/lib.rs:239-243`），而 **MCP 桥与 CLI 先登录再提示指纹**（`mcp/tools.rs:124-144`、`rt-app/main.rs:275-289`）。`client.require_pinned_fingerprint` 只在 GUI 读（`ui/app.rs:499`）。 |
| 明文模式 | △ S-04 | `allow_insecure_lan` 语义：`config.rs:637-642` 只在 **绑定非回环** 时要求该开关；文档 `ARCHITECTURE.md:47` 声称"仅回环+开关"。实际 `tls=false, bind=0.0.0.0, allow_insecure_lan=true` 可过校验，且 `serve` 不读校验结果 → 明文可对全网。 |
| 私钥保护 | ✘ S-15 | `crypto.rs:291-292` 走 `config::write_atomic`，**未设 ACL**；`data\tls\server.key` 继承目录权限。本地低权用户可读 → 冒充服务器。 |
| 证书有效期 | △ 可接受 | 2024→2099（`crypto.rs:278-279`），固定指纹模式下可接受（S-40）。 |
| 自签重建 | ✔已防 | 解析失败才重建（`crypto.rs:239-246`），客户端会因指纹不符拒绝（fail-closed）。 |
| 握手 DoS | ✘ **S-05** | `crates\rt-server\src\tls.rs:34-54`：`acceptor.accept(stream).await` 直接在 accept 循环里做，**无超时**；rustls 不设默认握手计时器 → 一个不发 ClientHello 的 TCP 连接即可让 TLS 监听不再接受新连接。 |

### 3.4 命令执行（`crates\rt-core\src\exec.rs`）

| 项 | 结论 | 证据 |
|---|---|---|
| shell 选择 | ✔已防 | 枚举 `Cmd/Powershell/Pwsh/Custom`；`Custom` 必须是**已存在的绝对路径**（`:513-534`）。 |
| 参数注入 | ✔已防 | 命令作为**最后一个参数**传给 shell（`:723-727`），不拼字符串执行。 |
| cwd 过 guard | ✔已防 | `guard.resolve_existing` 且必须是目录（`:309-316`）；默认 guard 根（`:319-325`）。 |
| env | △ 部分 | REST/WS 允许客户端任意 env（`:735-737`）——对已有 RCE 的会话无增量风险，但会让 `PATH`/`PSModulePath` 劫持成为可能；MCP 强制清空（`mcp/tools.rs:441`）✔。 |
| 输出上限 | ✔已防（缓冲路径） | 每流 `min(req, limits)`，默认 8 MiB（`:712-715`），`StreamState::capture` 到上限即停但继续 drain（`:182-196`）。 |
| 输出上限（流式路径） | ✘ S-07 | 流式用 **`mpsc::channel()` 无界**（`:765`）并直连 WS 无界出口（`routes/ws.rs:78,90-99`）→ 8 MiB 上限对 WS 不生效。 |
| 超时 kill | △ S-13 | `child.kill()` + `taskkill /PID /T /F`（`:670-688`），但 **无 Job Object** → `start /b`、计划任务派生出的孙进程可存活；`taskkill` 走 PATH（S-42）。 |
| stdin | ✘ S-12 | 在超时循环**之前**阻塞 `write_all`（`:755-760`），子进程不读 stdin 时（`Start-Sleep 600`）线程永久卡住，超时形同虚设。 |
| 默认超时 | ✔已防 | 300 s / 上限 3600 s（`:67-90`）。 |
| 审计 | ✔已防 | 成功/失败都记 `exec.run`，命令截断 400 字符（`routes/exec.rs:52-82`、`routes/ws.rs:408-417`）→ S-41。 |

### 3.5 上传 / 下载 / 文件操作

| 项 | 结论 | 证据 |
|---|---|---|
| 上传限额 | ✔已防 | `/fs/write`、`/fs/upload` 路由级 `DefaultBodyLimit::disable()`（`routes/mod.rs:55,59`），改由流式计数器强制 `max_upload_bytes`（`routes/fs.rs:345-352`、`:431-438`）。 |
| `Content-Length` 欺骗 | ✔已防 | 从不使用该头做限额，边读边计。 |
| multipart 分块绕过 | ✔已防 | 逐字段累加 `received`，超限即 `PayloadTooLarge`（`fs.rs:431-438`）。 |
| 临时文件与原子性 | ✔已防 | `fsops::write_stream` 同目录随机 tmp + `create_new` + `sync_all` + rename；失败路径删除 tmp；`write_atomic` 同目录（`config.rs:750-777`）。 |
| 失败路径残留 | ✔已防 | 早退时不等待 writer 任务，但 `write_stream` 自己清理（`fs.rs:318-352`）。 |
| Range 越界 | ✔已防 | `parse_range`（`fs.rs:488-534`）限制 `start<size`、`start<=end`、`end<=size-1`，多个 range 取第一个，416 带 `Content-Range: bytes */size`（`:545-553`）；实际读取 `handle.take(length)`（`:262`）不会多读。 |
| 路径穿越（下载/上传） | ✔已防 | 下载 `open_for_read` 过 guard；上传文件名 `util::sanitize_filename`（`fs.rs:591`）+ 目标再 resolve。 |
| 响应头注入 | ✔已防 | 文件名消毒 + `HeaderValue` 编码，无法注入 CRLF。 |
| `nosniff` | △ S-39 | 缺 `X-Content-Type-Options`；`Content-Disposition: attachment` 已降低风险。 |
| 磁盘容量 | ✘ S-16 | 单请求可写 2048 MiB、复制 8 GiB，**不检查剩余空间**；重复请求可打满磁盘（含服务端自身日志卷）。 |
| 覆盖语义 | ✔已防 | `write` 默认 `overwrite=false`（`fs.rs:321`），存在即 `Conflict`；`copy/rename` 同。 |
| 只读属性 | ✔已防 | `delete` 在 `even_if_readonly=false` 时对只读项前置拒绝（`fsops.rs` `check_readonly`），不依赖 OS。 |

### 3.6 可用性 / DoS

| 项 | 结论 | 证据 |
|---|---|---|
| 全局请求体上限 | ✔已防 | `DefaultBodyLimit::max(max_json)`，默认 256 KiB（`routes/mod.rs:82`、`config.rs:246`）。 |
| WS 帧上限 | ✔已防 | `max_message_size(1 MiB)`（`routes/ws.rs:58`）、`WS_MAX_MESSAGE_BYTES`（`state.rs:32`）。 |
| WS 出口背压 | ✘ **S-07** | `unbounded_channel`（`routes/ws.rs:78`），客户端不读即无限积压；单 socket 16 路流 × 15 fps × 1280px 帧。 |
| WS 生命周期 | △ S-24 | 无心跳/空闲超时、无全局 socket 上限（`ws.rs:77-305`）。 |
| 并发执行 | ✔已防 | 信号量 `try_acquire_owned` 满即 503（`routes/exec.rs:34-40`）；WS 侧 `acquire_owned` 在 spawn 之后（`ws.rs:336`）→ 等待队列无界（并入 S-07）。 |
| 阻塞池 | ✘ S-23 | `max_blocking_threads(32)`（`bootstrap.rs:127`）+ `blocking()` 无准入控制（`middleware.rs:144-154`）→ 32 个慢上传（每块可占 300 s，`streams.rs:19`）即可拖垮全部文件/截屏/sysinfo 调用。 |
| 截屏成本 | △ S-02/S-16 | 单张最多 64 Mpx（`capture.rs:44`）→ RGBA 最多 256 MB；REST 无频率限制，每次约 165 ms CPU。 |
| 列表上限 | ✔已防 | `max_list_entries` 默认 5000（`fsops.rs` list 截断并置 `truncated`）。 |
| 日志/审计磁盘 | △ S-25/S-26 | 普通日志按天轮转保留 14 份 ✔；审计 16 MiB 轮转但**永不清理**（`logging.rs:311-392`），`panic.log` 无界（`:559-579`）。 |

### 3.7 MCP 桥

| 项 | 结论 | 证据 |
|---|---|---|
| 无网络监听 | ✔已防 | 仅 stdio（`mcp/mod.rs:30-86`）。 |
| 协议纯净 | ✔已防 | MCP 模式关掉控制台日志（`mcp/mod.rs:37-38`、`cli.rs:156-158`）。 |
| 凭据 | △ S-20/S-38 | env 变量进入 MCP 客户端配置（明文）；`RT_INSECURE=1` 直接明文。 |
| 工具默认值 | ✔已防 | `recursive=false`、`overwrite=false`（`tools.rs:305-358`），危险默认关闭。 |
| 审批 | ✘ S-17 | 无任何确认层：提示注入 = 立即在远端执行。 |
| 大写入 | ✘ S-18 | base64 全量解码到内存后 `write_file(Vec<u8>)`（`tools.rs:305-318`）→ 可申请到服务端上限（2048 MiB）的内存。 |
| 任意本地落盘 | ✘ S-19 | `rt_fs_download`/`rt_capture` 的 `local_path` 不受约束（`tools.rs:448-548`）→ 可写入启动目录。 |
| 错误回显 | △ S-36 | 服务端错误文本进 LLM 上下文（`mcp/mod.rs:192-196`），无凭据但含路径/命令。 |
| 工具描述 | ✔已防 | 无任何秘密（`tools.rs:146-285`）。 |
| `rt_exec` env | ✔已防 | 强制清空（`tools.rs:441`）。 |

### 3.8 审计与日志

| 项 | 结论 | 证据 |
|---|---|---|
| 字段设计 | ✔已防 | `AuditEvent` 无密码/token/内容字段（`logging.rs:233-254`）；路由只放客户端路径与截断命令。 |
| 覆盖度 | △ S-09 | 写类 + exec + 登录 + 下载 + POST capture 有审计（`routes/fs.rs:614-635`、`exec.rs:52-82`）；**`fs/read`、`fs/list`、`fs/stat`、`fs/roots`、`capture/screens`、`capture/windows`、WS `capture_stream` 无审计**。 |
| 敏感字段入日志 | ✔已防 | 全仓 `tracing::*!` 宏中无 password/token/api_key 字段（grep 验证）；`RUST_LOG` 只改级别不引入内容。 |
| 失败语义 | ✘ S-25 | 写审计失败只记日志，不 fail-closed（`logging.rs:337-369`）。 |
| 完整性 | △ | 纯文本追加，无签名/链式哈希，本机 root 可改。 |

### 3.9 浏览器攻击面（专项：CSRF / DNS rebinding）

- **经典 CSRF：已防**。凭据只走 `Authorization` 头（`middleware.rs:317-322`），**不用 Cookie**；跨站 `fetch` 无法自动附加该头；JSON 端点强制 `Content-Type: application/json`（`middleware.rs:476-489`）→ 浏览器必须预检，而服务端**没有 CORS 层**（`routes/mod.rs:78-91` 无 `CorsLayer`）→ 预检失败。WS 也不吃 Cookie，需要 ticket。
- **DNS rebinding：部分防**（S-10）。全栈**不校验 `Host`/`Origin`/`Sec-Fetch-*`**（grep 无匹配）。恶意页面把域名 rebinding 到 `127.0.0.1:46666` 后，浏览器认为同源，于是：
  1. 可读 `GET /api/v1/info`（`routes/health.rs:20-22`）→ 主机名、端点、证书指纹、`max_scope`；
  2. 可 `POST /api/v1/auth/login`（同源，无需预检）→ 用受害者浏览器发起爆破，制造该 IP 的锁定（`routes/auth.rs:36-56`）；受害者自己也随之被锁死；
  3. 仍拿不到 token（不落 Cookie），所以不能直接读全盘。
  修复：校验 `Host` 白名单（bind 地址 + localhost），或对 `Origin`/`Sec-Fetch-Site: cross-site` 返回 403；成本极低。

---

## 4. 风险分级与修复建议

> 修复动作尽量具体到函数；行号为当前 `main` 版本。

| ID | 级别 | 位置 | 问题 | 建议修复 |
|---|---|---|---|---|
| S-01 | **CRITICAL** | `routes/exec.rs:22-86`、`routes/ws.rs:313-439` | exec 不检查作用域：workspace 会话 = 全盘 RCE，scope 边界失效 | 在 `POST /exec` 与 WS exec 分支加 `require_full_scope(&ctx, "running commands")?`；如需保留 workspace 执行，另加"仅白名单命令"模式 |
| S-02 | HIGH | `routes/capture.rs`（全文件）、`routes/ws.rs:442-521` | 截屏不检查作用域 | 同上，加 `require_full_scope`；WS 的 `capture_stream` 在 `accepted` 处判定 |
| S-03 | HIGH | `routes/ws.rs:227-273` | WS 日志/状态订阅无 Full 校验，绕过 REST 限制 | `subscribe_logs` 前加 `require_full_scope`；`subscribe_status` 可保留（不含敏感内容） |
| S-04 | HIGH | `main.rs:159-172`、`lib.rs:112-150` | `serve` 忽略 `validate()` 错误 → `tls=false` 可明文绑定 0.0.0.0 | `serve` 入口：`let report = cfg.validate(); if !report.is_ok() { bail!(...) }` |
| S-05 | HIGH | `tls.rs:34-54` | 握手在 accept 循环内且无超时 → 单连接 DoS | `tokio::time::timeout(Duration::from_secs(10), acceptor.accept(stream))` 或把握手 `spawn` 出去 |
| S-06 | HIGH | `mcp/tools.rs:124-144`、`main.rs:265-291` | 无固定指纹时先发凭据、后提示指纹；`require_pinned_fingerprint` 未在 MCP/CLI 执行 | 在 `connect` 前先 `info()` 探测并比对/要求指纹；无指纹且 `require_pinned_fingerprint` 为真时拒绝 |
| S-07 | HIGH | `routes/ws.rs:78-99`、`exec.rs:765` | WS 出口与 exec 流式通道都是无界队列 | 改 `mpsc::channel(N)`（如 256 帧）+ 满则丢弃/断开；exec 流式同样加界 |
| S-08 | HIGH | `docs/ARCHITECTURE.md:56`（声明）/ 无实现 | "guard 之外再加黑名单"未实现：Full 会话可改 `config.toml`、覆盖 `data\tls\server.key` | 在 `pathscope::PathGuard` 增加受保护路径集合（config、data/tls、logs），`fsops` 写/删/改名时先 `ensure_not_protected` |
| S-09 | MEDIUM | `routes/fs.rs:614-635` | `fs/read`/`list`/`stat` 无审计 → 分块外泄无痕 | 给 `read` 加审计（记录 path/offset/returned），或对 read 累计字节限速 |
| S-10 | MEDIUM | `middleware.rs`（全栈） | 无 Host/Origin 校验 → DNS rebinding | 加 `Host` 白名单中间件 + `Sec-Fetch-Site` 检查 |
| S-11 | MEDIUM | `middleware.rs:365-411` | `trust_forwarded_for=true` 时 IP 全可伪造 | 保持默认 false；文档写明"仅在可信反代后开启"，或改为"只信任来自 loopback 代理的 XFF" |
| S-12 | MEDIUM | `exec.rs:755-760` | stdin 先于超时写入 | 把 stdin 写入放进 select 循环，受 timeout 约束，或丢到独立线程并 `join` 带超时 |
| S-13 | MEDIUM | `exec.rs:691-742` | 无 Job Object，孙进程逃逸；契约 §3.5 要求杀进程树 | 用 `CreateJobObject` + `JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE` 承载子进程 |
| S-14 | MEDIUM | `routes/auth.rs:129-151` | API Key 无法运行时吊销 | 为 key 增加可选的会话表，或在 `config` 里记录 key 的 `revoked` 标记并每分钟热加载 |
| S-15 | MEDIUM | `crypto.rs:291-292`、`config.rs:750-777` | 私钥/配置无 ACL 加固 | 写入后 `icacls` 等价 API：仅当前用户 + SYSTEM 可读（`SetNamedSecurityInfoW`） |
| S-16 | MEDIUM | `state.rs:272-278`、`fsops` | 无剩余空间检查 | 写入前 `GetDiskFreeSpaceExW` 校验 `free > incoming`（或保留 1 GiB）；复制同样 |
| S-17 | MEDIUM | `mcp/mod.rs:170-197` | 无审批层，提示注入直达 RCE | 为 `rt_exec`/`rt_fs_delete`/`rt_fs_write` 增加 `RT_REQUIRE_APPROVAL` 门（或默认 workspace + 只读工具集） |
| S-18 | MEDIUM | `tools.rs:305-318` | `rt_fs_write` 全量 base64 解码 | 超过 N MiB（建议 64）改走 `upload_file` 流式；或直接对 `content_b64` 长度设上限 |
| S-19 | MEDIUM | `tools.rs:448-548` | 下载/截屏可写任意本地路径 | 强制落在 `RT_DOWNLOAD_DIR`/`RT_CAPTURE_DIR` 内（`path_starts_with` 校验） |
| S-20 | MEDIUM | `tools.rs:81-91` | `RT_INSECURE=1` 明文携带密码 | 启动时打印醒目警告；或要求同时设置 `RT_ALLOW_PLAINTEXT=1` |
| S-21 | MEDIUM | `routes/sysinfo.rs`、`capture.rs:232-310` | 进程/窗口/命令行对 workspace 会话可见 | 进程列表与窗口标题要求 Full，或脱敏命令行 |
| S-22 | MEDIUM | `routes/auth.rs:36-56` | 锁定只按 IP | 增加"按用户名"的全局计数（阈值更高，例如 50/小时），或对同一用户名的失败做指数退避 |
| S-23 | MEDIUM | `bootstrap.rs:127`、`middleware.rs:144-154` | 阻塞池 32 线程 + 无准入 | 把 `blocking()` 包一层信号量（如 64 并发），超时快速 503 |
| S-24 | MEDIUM | `state.rs:306-343`、`routes/ws.rs:43-74` | WS ticket 在 URL、不绑 IP、吊销后仍有效 ≤60 s | ticket 绑定 `remote` IP；缩短到 15 s；文档提示反代不要记录 query |
| S-25 | MEDIUM | `logging.rs:311-392` | 审计轮转不清理 + 失败不 fail-closed | 保留 N 份轮转文件并删除更旧的；审计写失败可选择 503 |
| S-26 | LOW | `logging.rs:559-579` | `panic.log` 无界 | 追加大小上限与轮转 |
| S-27 | LOW | `state.rs:354-367` | `/sysinfo` 泄漏 `config_path`/`data_dir`/`workspace_root` | 仅 Full 作用域返回真实路径，workspace 返回虚拟根 |
| S-28 | LOW | `pathscope.rs:21-24,264-269` | 保留名变体：`CON .txt`（主干含内部空格）、`CONOUT$`/`CONIN$`、`COM¹` | 主干去尾部空格后再比对；补 `CONIN$`/`CONOUT$`；匹配 `COM`+上标数字 |
| S-29 | LOW | `pathscope.rs:184` | RTL override（U+202E）等 `Cf` 字符可通过 | 拒绝 `Unicode::Cf`（或至少 U+202A..U+202E、U+2066..U+2069） |
| S-30 | LOW | `pathscope.rs:213-221` | `C:`（无尾随）仍可解析到盘符当前目录 | `rest.is_empty()` 时也拒绝，提示用 `C:\` |
| S-31 | LOW | `fsops.rs` | resolve→IO 之间 TOCTOU | 打开/删除时尽量用 `open` 后的句柄做校验（`GetFinalPathNameByHandle`），或文档标注本地攻击者不在威胁模型内 |
| S-32 | LOW | `routes/auth.rs:80-93` | 失败响应泄漏 `remaining_attempts` | 只回统一错误，剩余次数放到审计 |
| S-33 | LOW | `auth.rs:440-442` | `rate_limit_per_min=0` 直接关闭限流 | 视为非法配置（`validate` 报错） |
| S-34 | LOW | `config.rs:750-777` | 临时文件用 `File::create` 而非 `create_new` | 改 `create_new` 或先写随机名 |
| S-35 | LOW | `routes/meta.rs:58-71` | `tail_json_lines` 全量读审计文件 | 反向按块读，或先 seek 到文件尾部 N KiB |
| S-36 | LOW | `mcp/mod.rs:192-196` | 错误文本进 LLM 上下文 | 对路径/命令做截断与转义（已有 JSON 转义） |
| S-37 | LOW | `mcp/mod.rs:64` | stdin 行无长度上限 | `tokio::io::Lines` 外层加长度检查（如 8 MiB） |
| S-38 | LOW | `cli.rs:120-124` | `--password`/`--token` 在 argv | 优先 env/stdin；文档标注风险；可加 `--password-stdin` |
| S-39 | LOW | `routes/fs.rs:281-295` | 缺 `X-Content-Type-Options: nosniff` | 统一加该响应头 |
| S-40 | LOW | `crypto.rs:278-279` | 证书 75 年有效期 | 可接受（固定指纹）；如需轮换提供 `--rotate-cert` |
| S-41 | LOW | `routes/exec.rs:52-82` | 审计命令截断 400 字符 | 记录完整命令的 SHA-256 + 截断前缀 |
| S-42 | LOW | `exec.rs:670-688` | `taskkill` 依赖 PATH | 用 `%SystemRoot%\System32\taskkill.exe` 绝对路径 |

---

## 5. 明确"不做"的取舍

1. **不引入客户端证书（mTLS）**：单用户桌面工具的证书分发成本高于收益；服务器身份用指纹固定、客户端身份用 256-bit 令牌已足够。前提是 S-06 修好（不允许无固定指纹登录）。
2. **不做 RBAC/多租户**：`Workspace`/`Full` 两级 + 扁平用户表是刻意的最小化；但 S-01~S-03 必须修，否则这两级形同虚设。
3. **不做按用户名的账号锁定**：会带来对受害者的定向 DoS；改为"按 IP 锁 + 按用户名慢速退避"（S-22），不引入硬锁定。
4. **不做 CORS**：没有浏览器内客户端；不设 `Access-Control-Allow-Origin` 反而是防线（§3.9）。因此 DNS rebinding 用 `Host` 校验解决，而不是加 CORS 白名单。
5. **不强制密码复杂度**：局域网工具的可用性优先，仅强制 ≥8；文档建议 ≥16 或改用 API Key。
6. **审计不 fail-closed**：写审计失败时保持业务可用（记录到 tracing），完整性交由外部日志收集（如转发到 syslog/ELK）。
7. **接受 TOFU 首次信任**：GUI 有明确指纹确认弹窗（`ui/app.rs:199-223`、`dashboard.rs:1109-1114`）；这是"首次信任"的固有成本，只要求其它入口（MCP/CLI）同样先确认再发凭据。

---

## 6. 部署与加固建议

1. **网络**：只监听需要的地址——把 `server.bind` 从 `0.0.0.0` 改为内网具体 IP；Windows 防火墙只放行内网网段：
   `netsh advfirewall firewall add rule name="RT" dir=in action=allow protocol=TCP localport=46666 remoteip=192.168.0.0/16`
2. **TLS**：保持 `tls=true`；`allow_insecure_lan` 只在回环调试时临时打开，生产禁用（S-04 修复后才会真正拦）。
3. **固定指纹**：客户端 `client.hosts[].fingerprint` 与 MCP `RT_FINGERPRINT` 必须显式设置；保持 `client.require_pinned_fingerprint=true`。轮换证书（重建 `data\tls`）后同步更新所有客户端指纹。
4. **作用域**：给 agent/MCP 的凭证一律 `scope="workspace"`；`full` 只给可信本机管理。**在 S-01 修复前，workspace 凭证等同 full**，不要把 workspace 令牌交给不受信 LLM。
5. **workspace 根位置**：放在独立目录/卷，例如 `D:\RT\workspace`，用 `icacls` 只授权运行服务端的账号：
   `icacls D:\RT /inheritance:r /grant:r "%USERNAME%:(OI)(CI)F" /grant:r "SYSTEM:(OI)(CI)F"`
6. **私钥/配置**：`data\tls\server.key`、`config.toml` 同样收紧 ACL（S-15）；`config.toml` 不要放进 workspace 根。
7. **运行身份**：用**非管理员**专用账号运行（`serve` 用计划任务/服务）。这样 exec 与截屏的破坏面被限制在该账号；UAC 提权窗口本身也截不到。
8. **MCP 桥**：用 `RT_TOKEN` + workspace 作用域，不用 `RT_PASSWORD`；把 `RT_DOWNLOAD_DIR`/`RT_CAPTURE_DIR` 指到沙箱目录；不要把密码放进 MCP 客户端配置的明文 env（S-20）。启用 S-17 的审批开关（修好后）。
9. **限流**：`rate_limit_per_min ≥ 60`、`login_max_attempts ≤ 5`、`max_sessions ≤ 16`；`ip_allowlist` 至少填内网前缀（注意需带尾点，如 `192.168.`）。
10. **监控**：`logs\audit.jsonl` 里关注 `result:"denied"`（白名单拦截）、`action:"exec.run"`（异常命令）、`action:"auth.locked"`（爆破）。审计轮转不清理（S-25），上线前配好外部收集或定期归档。
11. **默认关闭**：`server.enabled=false` 是好的默认（`config.rs:229`），保持；需要时用 GUI 启动（会跑 `validate()`），或在 S-04 修复后用 `serve`。
12. **磁盘**：`max_upload_mb` 按卷剩余空间设定（默认 2048 偏大）；给日志/审计所在卷留出至少 2× 最大上传的空间（S-16）。

---

## 7. 与 `docs/ARCHITECTURE.md` 契约的偏离

> 下表是审计当时（修复前）的状态。其中 S-04、S-06、S-08、S-12、S-13、S-22、S-02、S-09 相关的偏离均已在 §9 中修复；`docs/ARCHITECTURE.md` 的相应条目也已同步（§3 安全模型 9–12 条、scope 能力边界、控制文件黑名单、凭据只在已固定证书上发送、`serve` 强制校验）。

| 契约 | 声明 | 实际 | 对应条目 |
|---|---|---|---|
| §3.1 传输 | `tls=false` 仅允许"回环 + allow_insecure_lan" | 校验只要求"非回环时必须 allow_insecure_lan"，且 `serve` 不执行校验 | S-04 |
| §3.1 传输 | 首次 TOFU 固定指纹；`require_pinned_fingerprint` 不匹配即拒 | 仅 GUI 询问与执行；MCP/CLI 无条件 TOFU 且登录在前 | S-06 |
| §3.3 限流 | "全局限流 `rate_limit_per_min`" | 实际是**每 IP** 令牌桶（`middleware.rs:305-309`） | S-22 |
| §3.5 执行 | "超时强制 kill 进程树" | 无 Job Object；`taskkill /T` 覆盖不到分离的孙进程；stdin 可让超时失效 | S-12、S-13 |
| §3.6 文件 | "不允许写 `config.toml`/证书私钥（guard 之外再加黑名单）" | **黑名单不存在**（全仓 grep 无匹配） | S-08 |
| §3.7 审计 | "所有写操作、登录、exec、**截屏**都写 audit" | 截屏只审 POST `/capture` 与 `capture/raw`；`screens`/`windows`/WS `capture_stream` 未审；`fs/read` 也未审 | S-02、S-09 |
| §3.4 路径监狱 | "Full 作用域下也禁止…" | 实现与声明一致 ✔ | — |
| §3.2 认证 | 令牌 32 字节、只存 SHA-256、TTL、`max_sessions` | 实现与声明一致 ✔ | — |
| §3.8 默认暴露 | `enabled=false`、必须 TLS+密码用户、启动打印指纹 | 实现一致（`lib.rs:206-211` 打印指纹与地址）✔；但 `serve` 绕过校验 | S-04 |
| §9 MCP 工具表 | `rt_connect`/`rt_download`/`rt_upload` | 实际为 `rt_fs_download`/`rt_fs_upload` 等 17 个，无 `rt_connect` | 文档待更新 |
| §4 配置 | `session_ttl_minutes=0` → 警告"永不过期" | 运行时把 0 映射为 86400 s（`auth.rs:97`），警告与行为矛盾 | 文档/实现对齐 |
| §6 WebSocket | "exec 用 mpsc::UnboundedSender" | 与实现一致，但该选择本身是 S-07 的根因 | S-07 |

---

## 8. 审计方法与已确认安全的项（回归清单）

**方法**：逐文件通读（core 11 个模块、server 全部路由与中间件、client 2 个文件、app 的 mcp/cli/bootstrap/ui 连接层、protocol 契约），并用 `grep` 交叉验证：`require_full_scope` 调用点、`blacklist|denylist`（无）、`tracing!` 中的密码字段（无）、`Origin|Host` 校验（无）。路径监狱做过手工推演（含 `.`/`..` 丢失组件、绝对路径、verbatim）与既有单测比对（`pathscope.rs:426-518`、`fsops` 27 个测试）。

**回归时必须保持的"已防"项**：

1. 所有文件/exec 入口先 `guard.resolve`，返回路径用 `guard.display`（`pathscope.rs:85-105`、`fsops.rs` 全部、`exec.rs:309-316`）。
2. `..` 不可能出现在返回路径中（`deepest_canonical` 的 `file_name()==None` 分支，`pathscope.rs:332-355`）——**改动该函数时这是第一回归项**。
3. `list` 只用 `symlink_metadata`；删除不递归进 reparse point；`copy_dir_tree` 跳过链接。
4. 会话令牌 256-bit、只存 SHA-256、TTL/上限/吊销（`auth.rs`）。
5. 密码 Argon2id + decoy 常量时间；API Key `ct_eq` 全表扫描（`crypto.rs:112-149`）。
6. TLS 1.3 单版本 + 指纹 `ct_eq`（`crypto.rs:169-188,341-375`）；WS 复用同一 connector（`rt-client/ws.rs:33-48`）。
7. 上传不相信 `Content-Length`、边读边计、tmp+fsync+rename、失败清理（`routes/fs.rs:318-467`、`fsops::write_stream`）。
8. Range 解析边界（`routes/fs.rs:488-553`）、下载 `take(length)` 不超读。
9. 请求体全局 256 KiB；JSON-only 415；WS 1 MiB；无 Cookie、无 CORS（§3.9 已防）。
10. 审计字段不含秘密；`tracing!` 不含凭据。
11. 危险默认关闭：`server.enabled=false`、`fs_ops` 的 `overwrite=false`、MCP `recursive=false`、API Key 默认 `workspace`、scope 解析失败回落 `workspace`。
12. `serve`/GUI 启动都会打印监听地址与证书指纹（`lib.rs:206-218`）。

---

## 9. 修复状态对照表（2026-11-01）

42 条发现全部修复。下表给出每条的级别、修复提交与实现要点；「验证」列给出可以重跑的测试名或命令。
回归建议：改动 `pathscope.rs` / `fsops.rs` / `exec.rs` / `middleware.rs` / `mcp/tools.rs` 时，对照本表逐条复查，并至少跑一遍 `cargo test --workspace --all-targets`（当前 200+ 用例）。

### 9.1 CRITICAL / HIGH

| ID | 级别 | 提交 | 修复要点 | 验证 |
|---|---|---|---|---|
| S-01 | CRITICAL | `7c4df3b` | `POST /exec` 与 WS `Exec` 分支调用 `require_full_scope`，workspace 会话执行命令返回 403 `forbidden` | `cargo test -p rt-app --test e2e`（workspace 用户 exec → 403）；`workspace_sessions_cannot_execute_or_capture` |
| S-02 | HIGH | `7c4df3b` | `/capture`、`/capture/raw`、`/capture/windows` 与 WS `capture_stream` 全部 Full-only（`/capture/screens` 只含显示器几何，保持开放） | 同上 e2e；`workspace_sessions_cannot_execute_or_capture` |
| S-03 | HIGH | `7c4df3b` | WS `subscribe_logs` 加 Full 校验，`subscribe_status` 保留（无敏感内容） | `crates/rt-server/tests/api.rs` |
| S-04 | HIGH | `da1ecc8` + `7c4df3b` | `main.rs::serve` 绑定前 `config.validate()` 失败即 `bail!`；`rt_server::serve` 内部用副本探针再校验一次（避开 port 0 的合法场景） | `remote-terminal serve` 配 `tls=false, bind=0.0.0.0` → 立即退出并报错 |
| S-05 | HIGH | `7c4df3b` | TLS 握手包在 `tokio::time::timeout(HANDSHAKE_TIMEOUT = 10s)` 里，超时只 `continue`，不阻塞 accept 循环 | 单连接不发 ClientHello 时服务仍可服务新连接 |
| S-06 | HIGH | `da1ecc8` | CLI 与 MCP 在发凭据前先做一次未认证 `health()` 探针，未固定指纹时**拒绝登录**并打印 `--fingerprint` 指引；MCP 无终端可确认，一律拒绝 | 无 `RT_FINGERPRINT` 的 MCP 调用报 `refusing to send credentials over an unpinned TLS connection …` |
| S-07 | HIGH | `7c4df3b` + `45f698c` | WS 出口 `mpsc::channel(256)` + `try_send`（丢弃计数、恢复时补发 error 帧）；exec 流式改 `tokio::sync::mpsc::channel(256)`，消费者消失或 1s 投不进即杀进程树 | `dropped_consumer_stops_the_reader_and_kills_the_child`、`stalled_consumer_aborts_the_run_and_reports_cancelled` |
| S-08 | HIGH | `da1ecc8` | `pathscope` 新增 `PROTECTED` 集合与 `check_protected`（双向前缀判定 → `PolicyDenied`）；`bootstrap::install_control_path_guards` 保护 `config.toml`、`.bak`、`instance.lock`、审计文件、`data/tls` | `protected_control_paths_are_unreachable`；MCP 读 `config.toml` → 403 `policy_denied` |

### 9.2 MEDIUM

| ID | 级别 | 提交 | 修复要点 | 验证 |
|---|---|---|---|---|
| S-09 | MEDIUM | `bb48b8d` | `/fs/read` 写 `fs.read` 审计；每会话读预算 512 MiB/min（按令牌摘要计费，`/fs/download` 同计），超限 429 + `retry_after_secs` | `file_reads_are_recorded_in_the_audit_trail` |
| S-10 | MEDIUM | `bb48b8d` | `middleware::origin_layer`：缺 `Host` → 400；Host 不在本机名/监听地址/白名单 → 403；`Origin` 必须与 Host 同源；`Sec-Fetch-Site: cross-site` → 403（DNS rebinding / CSRF 双封） | `request_host_and_origin_are_validated` |
| S-11 | MEDIUM | `bb48b8d` | `X-Forwarded-For` 只在 peer 为回环/私网/链路本地时采用，否则忽略并限流式 `warn` | `forwarded_headers_are_only_trusted_from_a_local_peer` |
| S-12 | MEDIUM | `589735f` | stdin 写入改为 spawn 后的独立 writer 线程 + 64 KiB 分片 + 与 deadline/取消联动；`READER_GRACE = 500ms` 收尾 | `large_stdin_cannot_outlive_the_deadline` |
| S-13 | MEDIUM | `589735f` | Job Object（`CreateJobObjectW` + `JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE` + `AssignProcessToJobObject`，RAII），`taskkill` 降为兜底 | `grandchildren_are_reaped_when_the_run_ends`（含「禁用 attach 即失败」反证） |
| S-14 | MEDIUM | `bb48b8d` | 凭据热重载：`AppState::credentials()` 每 1s 按配置 (mtime,len) 抽查，改配置即生效（吊销 API key 无需重启）；已签发会话不受影响 | `credential_changes_apply_without_a_restart` |
| S-15 | MEDIUM | `6ff81b7` + `3895dc5` | 新模块 `rt-core/src/acl.rs`：`SetNamedSecurityInfoW` 写 `D:P(A;;FA;;;OW)(A;;FA;;;SY)(A;;FA;;;BA)`，收敛 TLS 私钥/证书/指纹文件、`config.toml`+`.bak`、`data/`、`tls/` | `acl::tests`；`restrict_to_current_user` 后 owner 仍可读写 |
| S-16 | MEDIUM | `c9dca5f` | `ensure_capacity`：`free > incoming + 256 MiB`；流式每 64 MiB 复核，超限中止并删残留（`PayloadTooLarge`） | `capacity_check_rejects_a_payload_the_volume_cannot_hold` |
| S-17 | MEDIUM | `3fcff23` | MCP 审批门：`rt_exec`/`rt_fs_write`/`rt_fs_delete`/`rt_fs_rename`/`rt_fs_copy`/`rt_fs_upload` 需操作者租约（`mcp-approvals.json`，默认关闭 = 需要租约），`remote-terminal approve <tool> --minutes N` / `--revoke` / `--list`，`RT_REQUIRE_APPROVAL=0` 可关 | `cargo test -p rt-app --lib approval`；真机已验证「拒绝 → approve → 成功 → revoke → 再拒」 |
| S-18 | MEDIUM | `3fcff23` | `content_b64` 预检 64 MiB（按 base64 长度估算），超限提示改用 `rt_fs_upload` 流式 | `mcp::tools` 单测 |
| S-19 | MEDIUM | `3fcff23` | 下载/截屏落盘强制约束在 `RT_DOWNLOAD_DIR`/`RT_CAPTURE_DIR` 内（大小写不敏感前缀判定） | `mcp::tools` 单测 |
| S-20 | MEDIUM | `3fcff23` | `RT_INSECURE=1` 必须同时 `RT_ALLOW_PLAINTEXT=1`，否则忽略并 `warn` | `mcp::tools` 单测 |
| S-21 | MEDIUM | `22cd845` + `bb48b8d` | `/sysinfo/processes`、`/capture/windows` 提升为 Full-only；`/sysinfo`、`/sysinfo/quick`、`/exec/shells` 保持 workspace 可用 | `process_listing_requires_full_scope` |
| S-22 | MEDIUM | `bb48b8d` | 账号维度失败计数 50/h + 指数退避（1,2,4…≤900s，前 3 次免延迟）→ 429 + `Retry-After`；用户名小写归一 | `repeated_failures_back_off_per_account` |
| S-23 | MEDIUM | `683f24d` + `d9f20f1` | `AppState` 持 `Arc<Semaphore>`（64 槽）作准入，超 2s → 503 + `Retry-After: 1`；所有 `spawn_blocking` 路径统一走 `spawn_blocking_admitted`；登录的 Argon2 不占预算；rt-app 阻塞池 32 → 64 对齐 | `requests_are_shed_when_every_blocking_slot_is_taken`、`admit_sheds_the_caller_when_every_slot_is_taken` |
| S-24 | MEDIUM | `bb48b8d` | WS ticket 绑定签发方 IP、TTL 60s → 15s、仍一次性；IP 不符 403 | `websocket_tickets_are_bound_to_the_issuing_address` |
| S-25 | MEDIUM | `7bc0323` + `3895dc5` + `83d7f94` | 审计轮转保留 `audit_max_files`（默认 10）份并清理更旧；新增 `log_checked()` 与 `audit_fail_closed`（默认 false）。服务端把**破坏性**动作（`exec.start` 与 `exec.run/success`、`fs.mkdir`/`delete`/`rename`/`copy`/`write`/`upload`）改为 `record_audit_required`，fail-closed 时写不进审计即 503 + `Retry-After: 1`（命令根本不会启动）；读路径与 `capture`/`auth`/WS 连接事件保持 best-effort，命令**失败**的结果也保留自身错误码而不被 503 覆盖 | `checked_audit_answers_unavailable_when_the_write_fails`、`best_effort_audit_never_blocks_the_request`、`fail_closed_auditing_still_serves_a_working_trail`、`exec_records_the_intent_before_the_command_runs` |

### 9.3 LOW

| ID | 级别 | 提交 | 修复要点 | 验证 |
|---|---|---|---|---|
| S-26 | LOW | `7bc0323` | `panic.log` 超 1 MiB 轮转为 `panic.log.1`（只留一份） | `logging` 单测 |
| S-27 | LOW | `bb48b8d` | workspace 会话的 `/sysinfo` 把 `app.config_path`/`app.data_dir` 置空、`app.workspace_root` 置 `"\"` | `process_listing_requires_full_scope`（含路径隐藏断言） |
| S-28 | LOW | `cab0518` | `device_stem()`：去尾空格、上标数字折叠、大写比对；`RESERVED` 补 `CONIN$`/`CONOUT$`/`CLOCK$` → `CON .txt`、`COM¹` 全部拒绝 | `rejects_device_name_variants` |
| S-29 | LOW | `cab0518` | `is_hidden_format_char` 拒绝 `U+200B..200F`、`U+202A..202E`、`U+2066..2069`、`U+061C`、`U+FEFF` | `rejects_zero_width_and_bidi_characters` |
| S-30 | LOW | `cab0518` | `C:`（无尾随分隔符）改为 `InvalidPath` 并提示用 `C:\` | `rejects_residual_drive_paths` |
| S-31 | LOW | `c9dca5f` | 主路径用 `GetFinalPathNameByHandleW` 做句柄终态校验（不一致 → `PolicyDenied`）；`delete` 用「重新 resolve + 不跟随链接的句柄确认」，残余微秒窗口已写入函数文档 | `final_path_check_rejects_paths_outside_the_jail`、`a_junction_inside_the_jail_cannot_smuggle_io_outside` |
| S-32 | LOW | `bb48b8d` | 登录失败统一 401「invalid username or password」，剩余次数只进审计/tracing | `login_failure_gives_one_uniform_answer` |
| S-33 | LOW | `3895dc5` | `validate()` 对 `rate_limit_per_min == 0` 报 error、1..=9 报 warning | `config` 单测 |
| S-34 | LOW | `3895dc5` | `write_atomic_with` 用随机临时名 + `create_new(true)` + 4 次重试 | `config` 单测 |
| S-35 | LOW | `bb48b8d` | 审计尾部改为末尾 16 KiB 块倒读，只解析最后 N 条 | `tail_handles_files_larger_than_one_chunk` 等 4 条 |
| S-36 | LOW | `3a20251` | MCP 错误文本截断 2 KiB + `… (truncated)`；CLI 无 TTY 时密码从 stdin 读（不进 argv） | `mcp` 单测 |
| S-37 | LOW | `3a20251` | MCP stdin 单行 8 MiB 上限，超限回 JSON-RPC error 并跳过 | `mcp` 单测 |
| S-38 | LOW | `3a20251` | 无 TTY 时 `read_password()` 读 stdin 一行；`--password` 保留但文档标注风险 | `cli` 单测 |
| S-39 | LOW | `08ba6e5` | 统一响应层注入 `X-Content-Type-Options: nosniff`、`Referrer-Policy: no-referrer`、`X-Frame-Options: DENY`（覆盖 404/405 与错误信封） | `every_response_carries_the_hardening_headers` |
| S-40 | LOW | `3a20251` | 保留 2024→2099 的有效期（固定指纹下可接受），新增 `crypto::rotate_self_signed_tls` 与 `remote-terminal rotate-cert`（旧文件留 `.old`，提示重新 pin） | `remote-terminal rotate-cert` |
| S-41 | LOW | `fc8e332` | exec 审计 detail 改 `cmd=<前 200 字符>[…] sha256=<完整命令摘要>` | `command_audit_keeps_a_head_and_a_digest` |
| S-42 | LOW | `d262414` + `0dccacf` | `taskkill` 三级解析：`GetSystemDirectoryW`（内核锚点）→ `%SystemRoot%\System32` → 裸名；Job Object 仍是主杀路径 | `taskkill_is_invoked_through_its_absolute_system_path` |

### 9.4 保留的取舍（已评估、不修）

| 条目 | 决定 | 理由 |
|---|---|---|
| `/capture/screens` 对 workspace 开放 | 保留 | 只返回显示器分辨率/缩放，不含像素内容；前端选屏需要 |
| 证书 75 年有效期（S-40） | 保留 + 提供轮换 | 指纹固定模型下有效期不构成信任依据；需要时 `rotate-cert` |
| `X-Forwarded-For` 默认不信任 | 保留 | 默认 `false`；开启后也只采信本地 peer |
| Full 作用域 = 完全信任 | 保留 | 这是设计：Full 会话等价于在该机器上以服务账户身份操作，审计与审批门是主要约束手段 |
| `delete` 的微秒级 TOCTOU 窗口（S-31） | 保留并文档化 | 远端无法在监狱内创建 junction；本地低权进程不在威胁模型内 |

### 9.5 回归命令

```powershell
cargo test --workspace --all-targets          # 全量（core/server/app/client）
cargo test -p rt-core --lib pathscope          # 路径监狱
cargo test -p rt-core --test pathscope_adversarial   # 51 条越狱对抗用例
cargo test -p rt-server --all-targets          # 鉴权/作用域/Host/Origin/准入
cargo test -p rt-app --lib approval            # MCP 审批门
cargo test -p rt-app --test e2e                # 真实 TLS 端到端 + 作用域边界
```
