//! Entry point: dispatch the CLI to the GUI, the headless server, the MCP
//! bridge, or one of the small maintenance commands.
//!
//! Every path starts from the same place: [`rt_app::bootstrap`] loads (and on
//! first run creates) `config.toml` next to the executable, prepares the data
//! directories and starts logging.

use std::io::{IsTerminal, Write};
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use anyhow::{bail, Context};
use clap::Parser;
use rt_app::cli::{Cli, Command, TargetArgs};

fn main() -> ExitCode {
    let cli = Cli::parse();
    match run(cli) {
        Ok(code) => code,
        Err(error) => {
            eprintln!("remote-terminal: {error:#}");
            ExitCode::from(1)
        }
    }
}

fn run(cli: Cli) -> anyhow::Result<ExitCode> {
    let command = cli.command_or_default();
    let config_path = cli.config.clone();

    match command {
        Command::Mcp => {
            let runtime = rt_app::bootstrap::runtime()?;
            let code = runtime.block_on(rt_app::mcp::run(config_path))?;
            Ok(ExitCode::from(code as u8))
        }
        Command::Fingerprint { address, timeout } => {
            let runtime = rt_app::bootstrap::runtime()?;
            let fingerprint = runtime.block_on(fingerprint(&address, timeout))?;
            println!("{fingerprint}");
            Ok(ExitCode::SUCCESS)
        }
        Command::Gui => {
            let boot = rt_app::bootstrap::bootstrap(config_path.as_deref(), cli.verbose, true)?;
            let _guard = rt_app::bootstrap::acquire_single_instance(
                &boot.paths,
                boot.config().app.single_instance,
            )?;
            if _guard.is_none() {
                tracing::warn!("another instance is already running; exiting");
                eprintln!("RemoteTerminal is already running.");
                return Ok(ExitCode::SUCCESS);
            }
            let runtime = rt_app::bootstrap::runtime()?;
            rt_app::ui::run(boot, runtime)?;
            Ok(ExitCode::SUCCESS)
        }
        Command::Serve => {
            let boot = rt_app::bootstrap::bootstrap(config_path.as_deref(), cli.verbose, true)?;
            let runtime = rt_app::bootstrap::runtime()?;
            let code = runtime.block_on(serve(boot))?;
            Ok(ExitCode::from(code as u8))
        }
        Command::Config => {
            let boot = rt_app::bootstrap::bootstrap(config_path.as_deref(), cli.verbose, false)?;
            println!("config file   : {}", boot.loaded.path.display());
            println!("base directory: {}", boot.loaded.base_dir.display());
            println!("data directory: {}", boot.paths.data_dir.display());
            println!("workspace root: {}", boot.paths.workspace_root.display());
            println!("logs directory: {}", boot.paths.logs_dir.display());
            println!("tls directory : {}", boot.paths.tls_dir.display());
            println!(
                "server        : {} (enabled: {})",
                format!("{}:{}", boot.config().server.bind, boot.config().server.port),
                boot.config().server.enabled
            );
            Ok(ExitCode::SUCCESS)
        }
        Command::HashPassword { password } => {
            let password = match password {
                Some(p) => p,
                None => read_password("Password: ")?,
            };
            let hash = rt_core::crypto::hash_password(&password)
                .map_err(|e| anyhow::anyhow!("{e}"))?;
            println!("{hash}");
            eprintln!();
            eprintln!("Add this block to config.toml:");
            eprintln!();
            eprintln!("[[server.users]]");
            eprintln!("name = \"admin\"");
            eprintln!("password_hash = \"{hash}\"");
            eprintln!("scope = \"workspace\"   # or \"full\"");
            eprintln!("enabled = true");
            Ok(ExitCode::SUCCESS)
        }
        Command::GenKey { name, scope, write } => {
            let mut boot =
                rt_app::bootstrap::bootstrap(config_path.as_deref(), cli.verbose, false)?;
            let scope = rt_protocol::Scope::parse(&scope)
                .ok_or_else(|| anyhow::anyhow!("unknown scope `{scope}` (use workspace|full)"))?;
            let (key, digest) = rt_core::config::generate_api_key();
            println!("{key}");
            eprintln!();
            eprintln!("Store this key now — only its digest is kept.");
            eprintln!("key_sha256 = \"{digest}\"");
            if write {
                boot.loaded.config.server.api_keys.push(
                    rt_core::config::ApiKeyConfig {
                        name: name.clone(),
                        key_sha256: digest.clone(),
                        scope: scope.as_str().to_string(),
                        enabled: true,
                        created_at: Some(rt_core::util::now_rfc3339()),
                    },
                );
                boot.loaded
                    .config
                    .save_with_header(&boot.loaded.path)
                    .context("cannot write the API key to the config file")?;
                eprintln!();
                eprintln!("Appended `[[server.api_keys]]` for `{name}` to {}", boot.loaded.path.display());
            } else {
                eprintln!();
                eprintln!("Re-run with --write to append it to the config file automatically.");
            }
            Ok(ExitCode::SUCCESS)
        }
        Command::Info { target } => {
            let runtime = rt_app::bootstrap::runtime()?;
            let code = runtime.block_on(client_info(config_path, target))?;
            Ok(ExitCode::from(code as u8))
        }
        Command::Exec {
            command,
            target,
            shell,
            cwd,
            timeout_ms,
        } => {
            if command.is_empty() {
                bail!("no command given (usage: remote-terminal exec <command...>)");
            }
            let runtime = rt_app::bootstrap::runtime()?;
            let code = runtime.block_on(client_exec(
                config_path,
                target,
                command.join(" "),
                shell,
                cwd,
                timeout_ms,
            ))?;
            Ok(ExitCode::from(code as u8))
        }
    }
}

/// Starts the API server and blocks until Ctrl+C.
async fn serve(boot: rt_app::Bootstrapped) -> anyhow::Result<i32> {
    if !boot.config().server.enabled {
        tracing::warn!("server.enabled is false; starting anyway because `serve` was requested");
    }

    // S-04: refuse to bind a configuration that `validate()` flags. A typo such
    // as `tls = false` would otherwise put passwords on the wire in plaintext
    // with only a log line as warning.
    let report = boot.config().validate();
    if !report.is_ok() {
        for error in &report.errors {
            tracing::error!(target: "config", "{error}");
        }
        bail!(
            "refusing to start the server: the configuration has {} error(s) — run `remote-terminal config` to inspect {}",
            report.errors.len(),
            boot.loaded.path.display()
        );
    }
    for warning in &report.warnings {
        tracing::warn!(target: "config", "{warning}");
    }

    let handle = rt_server::serve(rt_server::ServerOptions {
        config: boot.config().clone(),
        paths: boot.paths.clone(),
        sink: boot.logging.sink.clone(),
        audit: boot.logging.audit.clone(),
    })
    .await?;

    println!("RemoteTerminal server listening");
    println!("  url        : {}", handle.url);
    println!(
        "  tls        : {}",
        if handle.tls { "on" } else { "off (plaintext HTTP)" }
    );
    if let Some(fingerprint) = &handle.fingerprint {
        println!("  fingerprint: {fingerprint}");
    }
    println!("  config     : {}", boot.loaded.path.display());
    println!("Press Ctrl+C to stop.");

    tokio::signal::ctrl_c()
        .await
        .context("cannot listen for Ctrl+C")?;
    tracing::info!("shutdown requested");
    handle.stop();
    Ok(0)
}

fn target_from(boot: &rt_app::Bootstrapped, args: &TargetArgs) -> rt_client::Target {
    let cfg = boot.config();

    let saved = cfg
        .client
        .hosts
        .iter()
        .find(|h| h.auto_connect)
        .or_else(|| cfg.client.hosts.first());

    let raw_host = args
        .host
        .clone()
        .or_else(|| saved.map(|s| s.host.clone()))
        .unwrap_or_else(|| "127.0.0.1".to_string());
    let mut port = saved.map(|s| s.port).unwrap_or(cfg.server.port);
    let mut host = raw_host.clone();
    if let Some((h, p)) = raw_host.rsplit_once(':') {
        if !h.is_empty() && !h.ends_with(']') {
            if let Ok(parsed) = p.parse::<u16>() {
                host = h.to_string();
                port = parsed;
            }
        }
    }

    let fingerprint = args
        .fingerprint
        .clone()
        .or_else(|| saved.and_then(|s| s.fingerprint.clone()));
    let tls = !args.insecure && (cfg.server.tls || fingerprint.is_some());

    let mut target = rt_client::Target {
        host,
        port,
        tls,
        fingerprint: if tls { fingerprint } else { None },
    };
    if target.fingerprint.is_some() && !tls {
        target.tls = true;
    }
    target
}

fn credentials(boot: &rt_app::Bootstrapped, args: &TargetArgs) -> (String, Option<String>, Option<String>) {
    let saved = boot
        .config()
        .client
        .hosts
        .iter()
        .find(|h| h.auto_connect)
        .or_else(|| boot.config().client.hosts.first());

    let user = args
        .user
        .clone()
        .or_else(|| saved.map(|s| s.username.clone()))
        .unwrap_or_else(|| "admin".to_string());
    let token = args
        .token
        .clone()
        .or_else(|| std::env::var("RT_TOKEN").ok())
        .filter(|t| !t.is_empty());
    let password = args
        .password
        .clone()
        .or_else(|| std::env::var("RT_PASSWORD").ok())
        .filter(|p| !p.is_empty());
    (user, token, password)
}

async fn connect(
    config: &Path,
    args: &TargetArgs,
) -> anyhow::Result<rt_client::RemoteClient> {
    let boot = rt_app::bootstrap::bootstrap(Some(config), false, false)?;
    let target = target_from(&boot, args);
    let (user, token, password) = credentials(&boot, args);
    let client = rt_client::RemoteClient::new(target)?;

    // S-06: never hand a password to an unverified peer. When the certificate is
    // not pinned yet, the only request allowed over trust-on-first-use is an
    // unauthenticated health probe; its fingerprint is then either rejected (pin
    // required) or reported for the operator to pin.
    if client.target().tls && client.target().fingerprint.is_none() {
        let probe = client.health().await;
        let presented = client.presented_fingerprint();
        match (probe, presented) {
            (Ok(_), Some(presented)) => {
                eprintln!("note: server presented certificate fingerprint {presented}");
                if boot.config().client.require_pinned_fingerprint {
                    bail!(
                        "refusing to send credentials over an unpinned TLS connection\n  \
                         the server's certificate fingerprint is {presented}\n  \
                         pin it once: remote-terminal --fingerprint {presented} ...\n  \
                         or add `fingerprint = \"{presented}\"` to the matching [[client.hosts]] entry in {}\n  \
                         (set client.require_pinned_fingerprint = false to allow trust-on-first-use)",
                        boot.loaded.path.display()
                    );
                }
                eprintln!("      pin it with --fingerprint {presented} to prevent MITM on later runs");
            }
            (Err(err), _) => {
                return Err(anyhow::anyhow!("cannot reach {}: {}", client.target().base_url(), err.message()));
            }
            (Ok(_), None) => {}
        }
    }

    match (token, password) {
        (Some(token), _) => client.use_api_key(&token),
        (None, Some(password)) => {
            client
                .login(&user, &password, "cli")
                .await
                .map_err(|e| anyhow::anyhow!("login failed: {}", e.message()))?;
        }
        (None, None) => bail!(
            "no credentials: pass --token <api key> or --password <password> (or set RT_TOKEN / RT_PASSWORD)"
        ),
    }

    Ok(client)
}

async fn client_info(config: Option<PathBuf>, args: TargetArgs) -> anyhow::Result<i32> {
    let config = resolve_config_arg(config)?;
    let client = connect(&config, &args).await?;
    let info = client.info().await.map_err(|e| anyhow::anyhow!("{}", e.message()))?;
    println!("{}", serde_json::to_string_pretty(&info)?);
    Ok(0)
}

async fn client_exec(
    config: Option<PathBuf>,
    args: TargetArgs,
    command: String,
    shell: String,
    cwd: Option<String>,
    timeout_ms: Option<u64>,
) -> anyhow::Result<i32> {
    let config = resolve_config_arg(config)?;
    let client = connect(&config, &args).await?;

    let shell = rt_protocol::ShellKind::parse_name(&shell)
        .ok_or_else(|| anyhow::anyhow!("unknown shell `{shell}`"))?;
    let mut request = rt_protocol::ExecRequest::new(shell, command);
    request.cwd = cwd;
    request.timeout_ms = timeout_ms;

    let result = client
        .exec(&request)
        .await
        .map_err(|e| anyhow::anyhow!("{}", e.message()))?;

    print!("{}", result.stdout);
    eprint!("{}", result.stderr);
    let _ = std::io::stdout().flush();
    if result.timed_out {
        eprintln!("(timed out after {} ms)", result.duration_ms);
    }
    Ok(result.exit_code)
}

fn resolve_config_arg(config: Option<PathBuf>) -> anyhow::Result<PathBuf> {
    match config {
        Some(path) => Ok(path),
        None => rt_core::config::resolve_config_path(None)
            .ok_or_else(|| anyhow::anyhow!("cannot determine the configuration path")),
    }
}

/// Connects with a throwaway TLS probe and reports the certificate fingerprint.
async fn fingerprint(address: &str, timeout_secs: u64) -> anyhow::Result<String> {
    use std::sync::Arc;

    let (host, port) = match address.rsplit_once(':') {
        Some((h, p)) if !h.is_empty() && !h.ends_with(']') => (
            h.to_string(),
            p.parse::<u16>()
                .with_context(|| format!("invalid port in `{address}`"))?,
        ),
        _ => (address.to_string(), 46666),
    };

    let probe = rt_core::crypto::FingerprintProbe::new();
    let tls_config = rt_core::crypto::client_config_tofu(probe.clone());
    let connector = tokio_rustls::TlsConnector::from(Arc::new(tls_config));

    let server_name = rustls::pki_types::ServerName::try_from(host.clone())
        .map_err(|_| anyhow::anyhow!("`{host}` is not a valid server name"))?;

    let tcp = tokio::time::timeout(
        std::time::Duration::from_secs(timeout_secs.max(1)),
        tokio::net::TcpStream::connect((host.as_str(), port)),
    )
    .await
    .with_context(|| format!("timed out connecting to {host}:{port}"))?
    .with_context(|| format!("cannot connect to {host}:{port}"))?;
    let _ = tcp.set_nodelay(true);

    tokio::time::timeout(
        std::time::Duration::from_secs(timeout_secs.max(1)),
        connector.connect(server_name, tcp),
    )
    .await
    .with_context(|| format!("TLS handshake with {host}:{port} timed out"))?
    .with_context(|| format!("TLS handshake with {host}:{port} failed"))?;

    probe
        .get()
        .ok_or_else(|| anyhow::anyhow!("the server did not present a certificate"))
}

fn read_password(prompt: &str) -> anyhow::Result<String> {
    if std::io::stdin().is_terminal() {
        eprint!("{prompt}");
        let _ = std::io::stderr().flush();
    }
    let mut line = String::new();
    std::io::stdin()
        .read_line(&mut line)
        .context("cannot read the password")?;
    let password = line.trim_end_matches(['\r', '\n']).to_string();
    if password.is_empty() {
        bail!("the password cannot be empty");
    }
    Ok(password)
}
