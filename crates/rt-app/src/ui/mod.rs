//! Desktop UI for RemoteTerminal.
//!
//! Layout: `theme` (design tokens + motion), `widgets` (reusable controls),
//! `app` (shell, connection state, navigation) and `pages` (one module per
//! view). The only entry point `main.rs` needs is [`run`].

pub mod app;
pub mod pages;
pub mod theme;
pub mod widgets;

use anyhow::Context as _;

/// Runs the desktop UI until the user closes the window.
///
/// Takes ownership of the already-built tokio runtime: the UI keeps it alive
/// for background tasks and drops it when the window closes.
pub fn run(boot: crate::Bootstrapped, runtime: tokio::runtime::Runtime) -> anyhow::Result<()> {
    let window = boot.loaded.config.app.window.clone();
    let width = if window.width >= 900.0 { window.width } else { 1180.0 };
    let height = if window.height >= 620.0 { window.height } else { 780.0 };
    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_title(crate::DISPLAY_NAME)
            .with_app_id("remote-terminal")
            .with_inner_size([width, height])
            .with_min_inner_size([900.0, 620.0])
            .with_maximized(window.maximized),
        ..Default::default()
    };

    eframe::run_native(
        crate::DISPLAY_NAME,
        options,
        Box::new(move |cc| Ok(Box::new(app::App::new(cc, boot, runtime)) as Box<dyn eframe::App>)),
    )
    .map_err(|err| anyhow::anyhow!("cannot start the desktop UI: {err}"))
    .context("eframe event loop")
}
