# egui / eframe 0.37 — API differences that bite

We pin `egui 0.37`, `eframe 0.37`, `egui_extras 0.37` (see the root `Cargo.toml`).
0.37 is a **breaking release** compared to the 0.2x/0.3x API that most examples
and blog posts still show. Everything below was verified against the sources in
`C:\Users\BlackBee\.cargo\registry\src\rsproxy.cn-e3de039b2554c837\{eframe,egui,ecolor}-0.37.0\src\`
— read those files instead of guessing; they are the ground truth.

## 1. `eframe::App` is now `ui`-based, not `update`-based

`eframe-0.37.0/src/epi.rs:152-186`:

```rust
pub trait App {
    /// optional; called before each `ui`, and also while the window is hidden
    fn logic(&mut self, ctx: &egui::Context, frame: &mut Frame) {}

    /// REQUIRED — no margin, no background
    fn ui(&mut self, ui: &mut egui::Ui, frame: &mut Frame);
    // save(), on_exit(), clear_color(), persist_egui_memory(), …
}
```

Migration:

```rust
// was: fn update(&mut self, ctx: &egui::Context, frame: &mut eframe::Frame)
fn ui(&mut self, ui: &mut egui::Ui, frame: &mut eframe::Frame) {
    let ctx = ui.ctx().clone();          // `Ui::ctx(&self) -> &Context`
    // network polling / timers can stay here, or move to `fn logic(..)`
    egui::Panel::left("nav").exact_size(224.0).show(ui, |ui| { … });
    egui::CentralPanel::default().show(ui, |ui| { … });
}
```

`run_native(app_name, NativeOptions, AppCreator) -> Result` is unchanged
(`eframe-0.37.0/src/lib.rs:288`). `AppCreator::new(Box::new(|cc| …))` still gets
`&CreationContext`.

## 2. `TopBottomPanel` / `SidePanel` are gone — one unified `Panel`

`egui-0.37.0/src/containers/panel.rs`:

| old (≤0.36) | 0.37 |
| --- | --- |
| `egui::SidePanel::left("x")` | `egui::Panel::left("x")` |
| `egui::SidePanel::right("x")` | `egui::Panel::right("x")` |
| `egui::TopBottomPanel::top("x")` | `egui::Panel::top("x")` |
| `egui::TopBottomPanel::bottom("x")` | `egui::Panel::bottom("x")` |
| `.default_width(w)` / `.default_height(h)` | `.default_size(w_or_h)` |
| `.min_width/.max_width/.min_height/.max_height` | `.min_size(..)` / `.max_size(..)` / `.size_range(Rangef)` / `.exact_size(..)` |
| `.show(ctx, |ui| …)` | `.show(ui, |ui| …)` ← **takes `&mut Ui`** |
| — | `.resizable(bool)`, `.show_separator_line(bool)`, `.drag_to_open(bool)`, `.frame(Frame)` |
| — | `.show_inside(ui, ..)`, `.show_collapsible(..)`, `.show_animated_inside(..)` |

`egui::CentralPanel` still exists (`panel.rs:1352`) but also takes `ui`:
`CentralPanel::default().show(ui, |ui| …)`; `CentralPanel::no_frame()`,
`CentralPanel::default_margins()`. `egui::Frame::central_panel(..)` exists for
custom styling.

## 3. Styling: `Context::style()` is gone

`egui-0.37.0/src/context.rs` offers:

* `ctx.all_styles_mut(|style: &mut Style| …)` ← use this instead of `ctx.style_mut()` / `set_style(style.clone())`
* `ctx.set_visuals(visuals)`, `ctx.set_theme(egui::ThemePreference::{Dark,Light,System})`, `ctx.theme()`
* `ctx.options_mut(|o| …)`, `ctx.set_zoom_factor(f32)`
* `ctx.request_repaint()` (unchanged — keep using it when a background task finishes)

Per-widget styling is unchanged: `ui.style()`, `ui.style_mut()` (`egui-0.37.0/src/ui.rs`).

## 4. `Color32` const constructors

`ecolor-0.37.0/src/`: `from_rgb`, `from_rgba_premultiplied`, `from_black_alpha`,
`from_white_alpha` are `const fn`; **`from_rgba_unmultiplied` is not** — for a
`const`/`static` theme table use `Color32::from_rgba_unmultiplied_const(r, g, b, a)`
(the const counterpart) or `from_rgba_premultiplied`.

## 5. `id_salt` parameters need `Hash + Debug`

`egui-0.37.0/src/id_salt.rs:7-9`:

```rust
pub trait AsIdSalt: core::hash::Hash + core::fmt::Debug {}
impl<T: core::hash::Hash + core::fmt::Debug> AsIdSalt for T {}
```

So a generic helper must be written

```rust
pub fn card(ui: &mut egui::Ui, id_salt: impl std::hash::Hash + std::fmt::Debug, …)
```

`impl Hash` alone fails with `impl Hash doesn't implement Debug` / `AsIdSalt is not satisfied`.

## 6. `NativeOptions` has no `vsync` field

`eframe-0.37.0/src/epi.rs:299+`: `viewport: egui::ViewportBuilder`,
`multisampling: u16`, `depth_buffer`, `stencil_buffer`, `renderer: Renderer`
(glow/wgpu), `run_and_return: bool`, `event_loop_builder`, `window_builder`,
`centered: bool`, `persist_window`, `persistence_path`, …

```rust
let options = eframe::NativeOptions {
    viewport: egui::ViewportBuilder::default()
        .with_inner_size([1180.0, 780.0])
        .with_min_inner_size([920.0, 620.0])
        .with_title("RemoteTerminal"),
    ..Default::default()
};
eframe::run_native("RemoteTerminal", options, Box::new(|cc| Ok(Box::new(App::new(cc, …)))))
```

## 7. Misc that showed up in our build log

* `egui::ServerInfo` is ours — `rt_protocol::ServerInfo` has `os` (a string like
  `"Windows 11 …"`), **not** `os_version`; version/build live in `SysInfoSnapshot`.
* `Ui::show` variants that used to take `&Context` now take `&mut Ui`; when you
  have only a `Context` (e.g. inside `logic`), pass `ui` down instead of
  re-entering `ctx`.
* Keep the "no allocation in the hot loop" advice: `ui.ctx().request_repaint_after(Duration)`
  for 1–5 Hz status/capture polling, `request_repaint()` only when a task lands.

## 8. Verifying GUI code quickly

```powershell
cargo check -p rt-app --message-format short 2>&1 | Select-String 'rt-app'
```

`eframe`/`egui`/`glow` take a few minutes to compile the first time; after that a
check is seconds. If you need to inspect an API, grep the registry:

```powershell
$reg = "C:\Users\BlackBee\.cargo\registry\src\rsproxy.cn-e3de039b2554c837"
Select-String -Path "$reg\egui-0.37.0\src\containers\panel.rs" -Pattern '^\s{4}pub fn '
```
