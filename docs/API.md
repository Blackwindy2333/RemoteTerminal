# RemoteTerminal — API reference

Everything the GUI can do is also available to scripts, because the UI is just
another client of the HTTP API. Three entry points exist:

| Interface | Endpoint | Use |
| --- | --- | --- |
| REST | `https://<host>:46666/api/v1/...` | scripts, CI, other apps |
| WebSocket | `wss://<host>:46666/api/v1/ws` | streaming exec output, live capture, log/status tail |
| MCP (stdio) | `remote-terminal.exe mcp` | harness tool integration (DSH, Claude Desktop, …) |

`GET /api/v1/openapi.json` returns a machine readable description of the REST
surface; `GET /healthz` needs no authentication and is safe for probes.

---

## 1. Security model in one page

* **Transport** — TLS 1.3 only, self-signed certificate generated on first
  server start (`<data>/tls/server.crt.pem`, `server.key.pem`,
  `fingerprint.txt`). Clients pin the SHA-256 fingerprint of that certificate;
  plain HTTP is refused unless `server.allow_insecure_lan` is enabled (loopback
  debugging only).
* **Passwords** — argon2id PHC strings in `config.toml`. `GET /api/v1/info` and
  logs never expose them.
* **Tokens** — `POST /api/v1/auth/login` returns an opaque bearer token. The
  server stores only its SHA-256, so a memory dump or log leak does not yield
  usable credentials. Default lifetime: `server.session_ttl_minutes` (720).
* **API keys** — `rt_…` keys for machine clients. Only the digest lives in the
  config (`server.api_keys[].key_sha256`). Generate with
  `remote-terminal.exe gen-key <name> --write`.
* **Brute force** — `server.login_max_attempts` failures lock an IP for
  `server.login_lockout_secs`; all other calls are token-bucket limited by
  `server.rate_limit_per_min`; `server.ip_allowlist` restricts source addresses.
* **Path jail** — every filesystem path goes through `rt_core::pathscope`: for
  `workspace` scope the session can only touch `server.workspace.root` (default
  `<exe dir>/workspace`); for `full` scope the whole machine is reachable.
  Escape attempts (`..\..`, UNC paths, NTFS alternate data streams, device
  names, `\\?\GLOBALROOT`, symlink/reparse traversal) are rejected with
  `403 scope_violation`.
* **Auditing** — every mutating call appends a JSON line to
  `<logs dir>/audit.jsonl` with user, scope, source address, target and result.
* **Default posture** — `server.enabled = false`; nothing listens until the user
  turns the server on and adds at least one user with a password.

## 2. Running a server

```powershell
# first run creates config.toml next to the exe
.\remote-terminal.exe config
# add a user (writes a ready-to-paste [[server.users]] block)
.\remote-terminal.exe hash-password
# start
.\remote-terminal.exe serve
```

`serve` prints the URL, the TLS status and the certificate fingerprint.

## 3. Authentication

```powershell
$body = @{ username = "admin"; password = "secret" } | ConvertTo-Json
$login = Invoke-RestMethod -Uri "https://192.168.1.10:46666/api/v1/auth/login" `
    -Method Post -Body $body -ContentType "application/json" `
    -SkipCertificateCheck
$headers = @{ Authorization = "Bearer $($login.access_token)" }
```

* `POST /api/v1/auth/login` → `LoginResponse`
  (`access_token`, `expires_in_secs`, `scope`, `server`)
* `GET /api/v1/auth/me` → `SessionInfo`
* `POST /api/v1/auth/logout` → revokes the token
* `POST /api/v1/auth/ws-ticket` → single-use ticket for the WebSocket
* API-key clients skip login: send `Authorization: Bearer rt_…` directly.

Fingerprint pinning from PowerShell:

```powershell
# prints the fingerprint the server presents (trust on first use)
.\remote-terminal.exe fingerprint 192.168.1.10:46666
# then store it in config.toml under [[client.hosts]] fingerprint = "..."
```

## 4. Command execution

```powershell
$exec = @{
  shell    = "pwsh"
  command  = "Get-Process | Sort-Object CPU -Descending | Select-Object -First 5"
  cwd      = "\\src"          # workspace-relative (or absolute with full scope)
  timeout_ms = 30000
} | ConvertTo-Json
Invoke-RestMethod -Uri "$base/api/v1/exec" -Method Post -Headers $headers -Body $exec `
    -ContentType "application/json" -SkipCertificateCheck
```

`ExecResult` carries `exit_code`, `stdout`, `stderr`, `timed_out`, `truncated`,
`duration_ms`, `effective_cwd`, `encoding`, `pid`. Output is decoded as UTF-8
and falls back to GBK/`server` locale when the bytes are not valid UTF-8
(`encoding = "auto"`).

`GET /api/v1/exec/shells` lists the shells available on the server
(`pwsh`, `powershell`, `cmd`, custom).

For live output use the WebSocket instead (§7).

## 5. Files

All paths are scope-checked. Query strings carry the path (`?path=\src\main.rs`).

| Method & path | Purpose |
| --- | --- |
| `GET /api/v1/fs/roots` | drives + quick paths + workspace root |
| `GET /api/v1/fs/list?path=` | directory listing |
| `GET /api/v1/fs/stat?path=` | metadata + volume free/total |
| `POST /api/v1/fs/mkdir` | create directory |
| `POST /api/v1/fs/delete` | delete files/directories (batch) |
| `POST /api/v1/fs/rename` | rename/move |
| `POST /api/v1/fs/copy` | copy file or tree |
| `GET /api/v1/fs/read?path=&offset=&length=` | head/range read (text + base64) |
| `GET /api/v1/fs/download?path=` | streaming download, supports `Range` (206) |
| `POST /api/v1/fs/write?path=&overwrite=&create_parents=` | streaming upload, raw body |
| `POST /api/v1/fs/upload` | same, `multipart/form-data` |

Uploads are written to a temporary file in the destination directory and
atomically renamed, so a broken transfer never leaves a half-written file. The
response (`WriteResult`) includes the SHA-256 of what landed on disk.

## 6. System information and screen capture

* `GET /api/v1/sysinfo` → `SysInfoSnapshot` (CPU, memory, disks, network,
  displays, battery, uptime, app/server info)
* `GET /api/v1/sysinfo/quick` → `QuickStatus` (cheap polling)
* `GET /api/v1/sysinfo/processes?limit=&query=&sort=cpu|memory|name|pid` →
  `ProcessListResponse`
* `GET /api/v1/capture/screens` → monitors
* `GET /api/v1/capture/windows` → top-level windows
* `POST /api/v1/capture` → `CaptureResponse` (base64 payload + metadata)
* `GET /api/v1/capture/raw?target=primary|all|screen:1|window:12345&format=png|jpeg&quality=75`
  → image bytes with the proper `Content-Type`

```powershell
Invoke-WebRequest -Uri "$base/api/v1/capture/raw?target=primary&format=png" `
    -Headers $headers -OutFile screen.png -SkipCertificateCheck
```

## 7. WebSocket

1. `POST /api/v1/auth/ws-ticket` → `{ ticket, expires_in_secs, ws_path }`
   (tickets are single use and bound to your session).
2. Connect to `wss://host:port/api/v1/ws?ticket=…`.
3. Client → server (`WsClientMessage`, tagged by `type`):
   `ping`, `exec`, `cancel`, `capture_stream`, `subscribe_logs`,
   `subscribe_status`, `unsubscribe`.
4. Server → client: `pong`, `accepted`, `exec_started`, `exec_output`,
   `exec_finished`, `capture_frame`, `capture_stopped`, `log`, `status`,
   `unsubscribed`, `error`.

```jsonc
// run a command with live output
{"type":"exec","id":1,"request":{"shell":"pwsh","command":"ping -t 127.0.0.1"}}
// … stream
{"type":"exec_output","id":1,"stream":"stdout","data":"Reply from 127.0.0.1…","seq":1}
{"type":"exec_finished","id":1,"summary":{"exit_code":0,"duration_ms":1200,"cancelled":false}}
// subscribe to the log tail
{"type":"subscribe_logs","id":2,"level":"info","backlog":200}
```

`GET /api/v1/ws/info` reports message-size limits and the maximum frame rate.

## 8. MCP bridge (recommended for harness tools)

`remote-terminal.exe mcp` speaks JSON-RPC 2.0 over stdin/stdout (one JSON
message per line) and exposes 17 tools:

`rt_info`, `rt_exec`, `rt_fs_list`, `rt_fs_stat`, `rt_fs_read`, `rt_fs_write`,
`rt_fs_mkdir`, `rt_fs_delete`, `rt_fs_rename`, `rt_fs_copy`, `rt_fs_download`,
`rt_fs_upload`, `rt_sysinfo`, `rt_processes`, `rt_screens`, `rt_windows`,
`rt_capture`.

Configuration is entirely through environment variables (no secrets in files):

| Variable | Meaning |
| --- | --- |
| `RT_HOST` | `host` or `host:port` |
| `RT_PORT` | port when `RT_HOST` has none |
| `RT_USER` / `RT_PASSWORD` | password login |
| `RT_TOKEN` | API key, instead of a password |
| `RT_FINGERPRINT` | pinned certificate fingerprint |
| `RT_INSECURE` | `1` to allow plaintext HTTP |
| `RT_DOWNLOAD_DIR` / `RT_CAPTURE_DIR` | where downloads / captures land |

DSH (`dsh-mcp.json`):

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
        "RT_PASSWORD": "……",
        "RT_FINGERPRINT": "AB:CD:…"
      }
    }
  }
}
```

Claude Desktop uses the same shape under `mcpServers`.

## 9. Error format

Every failure returns the same envelope with a matching HTTP status:

```json
{
  "error": {
    "code": "scope_violation",
    "message": "path escapes the workspace root",
    "detail": "requested \\..\\..\\windows\\system32",
    "request_id": "3f8c1e0a",
    "retry_after_secs": null
  }
}
```

| `code` | HTTP | Meaning |
| --- | --- | --- |
| `bad_request` | 400 | malformed body or query |
| `invalid_path` | 400 | path syntax rejected (device name, ADS, …) |
| `unauthorized` | 401 | missing/expired token, bad password |
| `forbidden` | 403 | authenticated but not allowed |
| `scope_violation` | 403 | path outside the jail |
| `policy_denied` | 403 | blocked by policy (UNC, insecure transport) |
| `not_found` | 404 | path or resource missing |
| `conflict` | 409 | exists / non-empty directory |
| `payload_too_large` | 413 | exceeds `server.max_upload_mb` / `max_json_kb` |
| `unsupported_media_type` | 415 | wrong `Content-Type` |
| `range_not_satisfiable` | 416 | bad `Range` header |
| `timeout` | 408 | command exceeded its limit |
| `rate_limited` | 429 | token bucket empty (see `retry_after_secs`) |
| `locked` | 423 | login lockout |
| `unavailable` | 503 | service not ready |
| `not_implemented` | 501 | capability not built on this server |
| `internal` | 500 | unexpected failure (check the server log) |

## 10. Client libraries

* Rust — `rt-client` (used by the GUI and the MCP bridge). `RemoteClient::new(target)`
  pins the fingerprint when `target.fingerprint` is set, otherwise trust on
  first use via `FingerprintProbe`.
* Anything else — plain REST; `GET /api/v1/openapi.json` drives code generation.
