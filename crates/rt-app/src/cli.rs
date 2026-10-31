//! Command line surface.
//!
//! ```text
//! remote-terminal                     # start the desktop UI (default)
//! remote-terminal gui                 # same, explicit
//! remote-terminal serve               # headless: REST + WebSocket server
//! remote-terminal mcp                 # MCP stdio bridge for harness tools
//! remote-terminal config              # print the resolved config path
//! remote-terminal hash-password       # argon2 hash for server.users[]
//! remote-terminal gen-key <name>      # one-off API key + digest
//! remote-terminal fingerprint <addr>  # TLS certificate fingerprint of a server
//! remote-terminal exec <cmd...>       # run a remote command (client smoke test)
//! remote-terminal info                # remote server identity
//! ```

use std::path::PathBuf;

use clap::{Args, Parser, Subcommand};

/// RemoteTerminal — control a Windows machine over your LAN.
#[derive(Debug, Parser)]
#[command(
    name = "remote-terminal",
    version = rt_protocol::APP_VERSION,
    about = "RemoteTerminal: desktop UI, REST/WebSocket server and MCP bridge for one Windows machine",
    long_about = None,
    disable_help_subcommand = true,
)]
pub struct Cli {
    /// Configuration file to use (defaults to ./config.toml, created on first run).
    #[arg(long, global = true, value_name = "PATH")]
    pub config: Option<PathBuf>,

    /// Log at debug level (overrides logging.level from the config file).
    #[arg(long, short, global = true)]
    pub verbose: bool,

    #[command(subcommand)]
    pub command: Option<Command>,
}

#[derive(Debug, Subcommand, Clone)]
pub enum Command {
    /// Start the desktop application (default when no subcommand is given).
    Gui,

    /// Run headless: start the API server and stay in the foreground.
    Serve,

    /// Run the MCP bridge on stdin/stdout so harness tools can call this machine.
    Mcp,

    /// Show which configuration file would be used, creating it when missing.
    Config,

    /// Hash a password (argon2id) for `server.users[].password_hash`.
    #[command(name = "hash-password")]
    HashPassword {
        /// Password to hash; omit to be prompted on stdin.
        password: Option<String>,
    },

    /// Generate an API key. The key is printed once; only its digest is stored.
    #[command(name = "gen-key")]
    GenKey {
        /// Label for the key (used in `server.api_keys[].name`).
        #[arg(default_value = "default")]
        name: String,
        /// Scope granted to the key: `workspace` or `full`.
        #[arg(long, default_value = "workspace")]
        scope: String,
        /// Append the entry to the config file instead of only printing it.
        #[arg(long)]
        write: bool,
    },

    /// Fetch the TLS certificate fingerprint of a running server.
    Fingerprint {
        /// `host` or `host:port`.
        address: String,
        /// Seconds to wait for the TLS handshake.
        #[arg(long, default_value_t = 10)]
        timeout: u64,
    },

    /// Run a command on a remote server (uses the CLI credentials).
    Exec {
        /// Command to execute; joined with spaces unless `--raw` is used.
        #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
        command: Vec<String>,
        #[command(flatten)]
        target: TargetArgs,
        /// Shell to use on the remote side.
        #[arg(long, default_value = "pwsh")]
        shell: String,
        /// Working directory on the remote side.
        #[arg(long)]
        cwd: Option<String>,
        /// Timeout in milliseconds.
        #[arg(long)]
        timeout_ms: Option<u64>,
    },

    /// Print the identity and capabilities of a remote server.
    Info {
        #[command(flatten)]
        target: TargetArgs,
    },
}

#[derive(Debug, Args, Clone, Default)]
pub struct TargetArgs {
    /// `host` or `host:port` of the remote server.
    #[arg(long)]
    pub host: Option<String>,
    /// API key (`rt_...`) used instead of a password.
    #[arg(long)]
    pub token: Option<String>,
    /// Username for password login.
    #[arg(long)]
    pub user: Option<String>,
    /// Password for password login.
    #[arg(long)]
    pub password: Option<String>,
    /// Pinned certificate fingerprint (recommended).
    #[arg(long)]
    pub fingerprint: Option<String>,
    /// Connect without TLS (only for loopback debugging).
    #[arg(long)]
    pub insecure: bool,
}

impl Cli {
    pub fn command_or_default(&self) -> Command {
        self.command.clone().unwrap_or(Command::Gui)
    }
}

impl Command {
    /// Short label used in logs.
    pub fn label(&self) -> &'static str {
        match self {
            Command::Gui => "gui",
            Command::Serve => "serve",
            Command::Mcp => "mcp",
            Command::Config => "config",
            Command::HashPassword { .. } => "hash-password",
            Command::GenKey { .. } => "gen-key",
            Command::Fingerprint { .. } => "fingerprint",
            Command::Exec { .. } => "exec",
            Command::Info { .. } => "info",
        }
    }

    /// Commands that must not initialise console logging (stdout is a protocol).
    pub fn wants_console_log(&self) -> bool {
        !matches!(self, Command::Mcp)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::CommandFactory;

    #[test]
    fn cli_definition_is_valid() {
        Cli::command().debug_assert();
    }

    #[test]
    fn defaults_to_gui() {
        let cli = Cli::parse_from(["remote-terminal"]);
        assert!(matches!(cli.command_or_default(), Command::Gui));
        assert!(cli.config.is_none());
    }

    #[test]
    fn global_config_flag_is_accepted_before_and_after_command() {
        let a = Cli::parse_from(["remote-terminal", "--config", "x.toml", "serve"]);
        assert_eq!(a.config.as_deref(), Some(std::path::Path::new("x.toml")));
        let b = Cli::parse_from(["remote-terminal", "serve", "--config", "y.toml"]);
        assert_eq!(b.config.as_deref(), Some(std::path::Path::new("y.toml")));
    }

    #[test]
    fn exec_collects_trailing_arguments() {
        let cli = Cli::parse_from(["remote-terminal", "exec", "Get-Date", "-Format", "o"]);
        match cli.command.unwrap() {
            Command::Exec { command, shell, .. } => {
                assert_eq!(command, vec!["Get-Date", "-Format", "o"]);
                assert_eq!(shell, "pwsh");
            }
            other => panic!("unexpected: {other:?}"),
        }
    }

    #[test]
    fn mcp_suppresses_console_logging() {
        assert!(!Command::Mcp.wants_console_log());
        assert!(Command::Gui.wants_console_log());
    }
}
