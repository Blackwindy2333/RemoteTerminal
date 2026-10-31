# RemoteTerminal

A single-file Windows application (Rust) that lets you drive another Windows
machine over your LAN: run `cmd`/`pwsh` commands, browse and transfer files under
a mandatory path jail, read system status, grab screenshots of screens and
windows — from a native GUI, from the command line, over REST/WebSocket, or from
an agent harness through MCP.

The same executable is client and server: turn the server on (or leave it off) on
every machine, pair them with a password or API key, and control them from one
window.

```
┌─────────────────────── remote-terminal.exe ───────────────────────┐
│  GUI (egui)   CLI   REST + WebSocket server   MCP bridge (stdio)  │
└───────────────────────────────────────────────────────────────────┘
          rt-app
             ├── rt-client  ── typed API client (used by GUI + MCP)
             ├── rt-server  ── axum app, TLS 1.3, auth, WS streams
             └── rt-core    ── config, logging, crypto, path jail,
                              file ops, exec, sysinfo, screen capture
                                  └── rt-protocol ── shared DTOs
```

## Features

| Area | What you get |
| --- | --- |
| Command execution | `cmd`, `powershell`, `pwsh` (or a custom shell); cwd, env, stdin, timeout, output cap, live streaming over WebSocket, process-tree kill on timeout |
| Files | list / stat / mkdir / delete / rename / copy / ranged read / streaming upload+download with SHA-256; **workspace jail** or **full access** per session |
| System info | CPU, memory, disks, network interfaces, displays, battery, uptime, process list, app/server state |
| Screen | monitor and window enumeration, single-frame PNG/JPEG capture (primary / one monitor / all monitors / one window), optional low-fps live preview |
| Interfaces | REST + WebSocket + `openapi.json` + MCP stdio bridge with 17 tools |
| Safety | TLS 1.3 with pinned self-signed certificate, argon2id passwords, hashed session tokens, API keys, login lockout + rate limit + IP allowlist, audit log, path jail |
| Ops | config in `config.toml` (created on first run), rotating logs, JSON audit trail, single-instance guard |

## Build

Requirements: Rust 1.85+ (tested with 1.98.1), **MSVC toolchain** (Visual Studio
Build Tools with the Windows SDK). No C++ runtime is needed on target machines:
the binary links the static CRT.

```powershell
# from the repository root
cargo build --release
# → target\release\remote-terminal.exe   (single file, no DLL dependencies)
```

Dependencies are fetched through the rsproxy mirror configured in
`.cargo/config.toml` (`rustflags = ["-C", "target-feature=+crt-static"]` makes
the exe self-contained). To use crates.io instead, delete `.cargo/config.toml`.

`[profile.release]` uses `lto = "fat"`, `codegen-units = 1` and `strip = "symbols"`,
so the first release build takes a few minutes; the resulting exe is roughly
10–15 MB.

### Development builds

```powershell
cargo check --workspace --all-targets      # fast feedback
cargo test  --workspace                    # unit + integration tests
cargo run   --release -- --help            # CLI help
cargo run   --release                      # desktop UI
```

## First run

```powershell
.\remote-terminal.exe            # GUI; creates config.toml next to the exe
.\remote-terminal.exe config     # print the resolved paths
```

`config.toml` is created with sane defaults and **the server disabled**. Logs go
to `logs/`, the path jail root is `workspace/` next to the exe (created on
demand). Neither the config file nor the logs are tracked by git.

### Turn a machine into a server

```powershell
.\remote-terminal.exe hash-password       # paste the printed [[server.users]] block
notepad .\config.toml                     # set server.enabled = true
.\remote-terminal.exe serve               # prints URL + certificate fingerprint
```

Or do the same from the GUI: **设置 → 服务端 → 启用服务端**, add a user, save.
The GUI can run the server in-process, so one machine can serve and connect at
the same time.

### Connect from another machine

1. `.\remote-terminal.exe fingerprint 192.168.1.10:46666` — prints the server
   certificate fingerprint.
2. In the GUI **总览** page: host, port, user, password, paste the fingerprint,
   connect. Without a fingerprint the client falls back to trust-on-first-use and
   shows you what it saw before you pin it.

## CLI

```
remote-terminal [--config PATH] [-v] <command>

gui                       desktop UI (default)
serve                     headless REST/WebSocket server, Ctrl+C to stop
mcp                       MCP bridge on stdin/stdout (for harness tools)
config                    show resolved config/dir paths
hash-password [PW]        argon2id hash for config.toml
gen-key [NAME] [--scope] [--write]
                          generate an API key (prints the digest to store)
fingerprint <host[:port]> fetch the TLS certificate fingerprint of a server
exec <command...>         run a remote command through a server
info                      print a remote server's identity
```

Example:

```powershell
.\remote-terminal.exe exec --host 192.168.1.10:46666 --password secret `
    --fingerprint "AB:CD:…" "Get-Service | Where-Object Status -eq 'Running'"
```

## Integrations

* **REST/WebSocket:** see [`docs/API.md`](docs/API.md) and the live
  `https://host:46666/api/v1/openapi.json`.
* **MCP (harness):** register the executable as a stdio server:

```json
{
  "version": 1,
  "servers": {
    "remote-terminal": {
      "transport": "stdio",
      "enabled": true,
      "command": "D:\\Tools\\RemoteTerminal\\remote-terminal.exe",
      "args": ["mcp"],
      "env": { "RT_HOST": "192.168.1.10:46666", "RT_PASSWORD": "…" }
    }
  }
}
```

## Security notes

* Defaults are conservative: server off, TLS on, 720-minute sessions, 5 login
  attempts, 240 requests/minute/IP.
* Prefer the **workspace** scope for automation: the session can only touch
  `server.workspace.root`. `full` scope is root-equivalent over the network —
  hand it out deliberately.
* `server.allow_insecure_lan` disables TLS; only use it on loopback while
  debugging.
* Exposing the port to the internet is **not** recommended. If you must, put it
  behind a VPN or a reverse proxy and keep the fingerprint pinned.
* The audit trail (`logs/audit.jsonl`) records every mutating call.

## Repository layout

```
crates/rt-protocol   shared DTOs and constants (no async, no I/O)
crates/rt-core       config, logging, crypto, path scope, fs/exec/sysinfo/capture
crates/rt-server     axum HTTP + WebSocket server, auth middleware, TLS
crates/rt-client     typed client used by the GUI and the MCP bridge
crates/rt-app        binary: CLI, bootstrapping, GUI, MCP bridge
docs/                ARCHITECTURE.md, API.md
```

## Tests

```powershell
cargo test --workspace
```

Covers path-jail escapes, config validation/migration, password/token handling,
log ring buffer, filesystem operations against temporary directories, exec
timeouts and output caps, and client URL/error handling.
