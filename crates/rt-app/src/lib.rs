//! `rt-app` — the single deployable binary: GUI, CLI, server host, MCP bridge.
//!
//! Module ownership (see `docs/ARCHITECTURE.md`):
//! * `cli` / `bootstrap` / `main` — command surface, config + logging bootstrap
//! * `mcp` — stdio JSON-RPC bridge for harness/tool integration
//! * `ui` — the egui desktop application
//!
//! Everything here is glue: behaviour lives in `rt-core`, `rt-server` and
//! `rt-client`, so the same capability is reachable from the GUI, the CLI, the
//! REST API and the MCP bridge.

pub mod bootstrap;
pub mod cli;
pub mod mcp;
pub mod ui;

pub use bootstrap::{bootstrap, Bootstrapped};

/// Product name shown in window titles, `--version` and logs.
pub const DISPLAY_NAME: &str = "RemoteTerminal";
