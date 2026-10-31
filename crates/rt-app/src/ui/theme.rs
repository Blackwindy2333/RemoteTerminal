//! Design system for the RemoteTerminal desktop UI.
//!
//! Implements the visual contract from `docs/ARCHITECTURE.md` §6/§9 and the
//! translation table in `UIDevelopInstructions.md`:
//!
//! * one palette (dark is canonical, light is derived),
//! * one type scale (title 20/600, body 14/400, caption 12/400, line height
//!   `size × 1.45`),
//! * one spacing scale (4/8/12/16/24) and one radius scale (6/10/14),
//! * one motion model: critically damped springs with a 0.32 s response that can
//!   be turned off through the "reduce motion" preference.
//!
//! egui has no `backdrop-filter`, so the guide's frosted materials degrade to
//! translucent layered fills plus 1 px hairline borders (see [`Palette`] and
//! `widgets::glass_panel`).

use std::collections::{BTreeMap, HashMap};
use std::path::PathBuf;

use egui::{
    Color32, Context, CornerRadius, FontData, FontDefinitions, FontFamily, FontId, Id, Margin,
    Shadow, Stroke, Style, TextStyle, ThemePreference, Visuals,
};

use rt_core::config::Theme as ConfigTheme;

// ---------------------------------------------------------------------------
// Palette
// ---------------------------------------------------------------------------

/// Every colour the UI is allowed to use.
///
/// Values mirror `ARCHITECTURE.md` §6. Translucent entries (`hairline`, `veil`,
/// `accent_soft`) are what replaces real blur: stacked translucency conveys
/// depth where a WebView would have used `backdrop-filter`.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct Palette {
    /// Window / app background.
    pub bg: Color32,
    /// Cards and panels sitting on [`Self::bg`].
    pub surface: Color32,
    /// Inputs, table stripes and other raised elements.
    pub raised: Color32,
    /// Translucent overlay for layered ("glass") panels.
    pub veil: Color32,
    /// 1 px separators.
    pub hairline: Color32,
    /// Slightly stronger hairline for hovered / focused surfaces.
    pub hairline_strong: Color32,
    /// Composite of [`Self::bg`] over translucency, for panel interiors.
    pub sunken: Color32,
    /// Primary text.
    pub text: Color32,
    /// Secondary text (captions, labels).
    pub text_muted: Color32,
    /// Tertiary text (hints, disabled).
    pub text_faint: Color32,
    /// Accent (interactive).
    pub accent: Color32,
    /// Accent hover state.
    pub accent_hover: Color32,
    /// Accent used as a translucent wash.
    pub accent_soft: Color32,
    /// Positive / healthy.
    pub success: Color32,
    /// Warning / degraded.
    pub warning: Color32,
    /// Error / destructive.
    pub danger: Color32,
    /// Drop shadow colour.
    pub shadow: Color32,
    /// Text drawn on top of a saturated accent fill.
    pub on_accent: Color32,
    /// True for the dark variant.
    pub dark: bool,
}

impl Palette {
    /// Canonical dark palette (from the architecture contract).
    pub const DARK: Self = Self {
        bg: Color32::from_rgb(0x0F, 0x11, 0x15),
        surface: Color32::from_rgb(0x16, 0x1A, 0x20),
        raised: Color32::from_rgb(0x1D, 0x22, 0x29),
        veil: Color32::from_rgba_unmultiplied_const(0x16, 0x1A, 0x20, 0xD9),
        hairline: Color32::from_rgba_unmultiplied_const(0xFF, 0xFF, 0xFF, 0x14),
        hairline_strong: Color32::from_rgba_unmultiplied_const(0xFF, 0xFF, 0xFF, 0x26),
        sunken: Color32::from_rgb(0x0B, 0x0D, 0x11),
        text: Color32::from_rgb(0xE6, 0xE8, 0xEB),
        text_muted: Color32::from_rgb(0x9B, 0xA3, 0xAF),
        text_faint: Color32::from_rgb(0x6B, 0x72, 0x80),
        accent: Color32::from_rgb(0x3B, 0x82, 0xF6),
        accent_hover: Color32::from_rgb(0x60, 0x9C, 0xFA),
        accent_soft: Color32::from_rgba_unmultiplied_const(0x3B, 0x82, 0xF6, 0x33),
        success: Color32::from_rgb(0x10, 0xB9, 0x81),
        warning: Color32::from_rgb(0xF5, 0x9E, 0x0B),
        danger: Color32::from_rgb(0xEF, 0x44, 0x44),
        shadow: Color32::from_rgba_unmultiplied_const(0x00, 0x00, 0x00, 0x66),
        on_accent: Color32::from_rgb(0xFF, 0xFF, 0xFF),
        dark: true,
    };

    /// Light variant: same roles, inverted materials.
    pub const LIGHT: Self = Self {
        bg: Color32::from_rgb(0xF6, 0xF7, 0xF9),
        surface: Color32::from_rgb(0xFF, 0xFF, 0xFF),
        raised: Color32::from_rgb(0xEF, 0xF1, 0xF5),
        veil: Color32::from_rgba_unmultiplied_const(0xFF, 0xFF, 0xFF, 0xE6),
        hairline: Color32::from_rgba_unmultiplied_const(0x0F, 0x11, 0x15, 0x14),
        hairline_strong: Color32::from_rgba_unmultiplied_const(0x0F, 0x11, 0x15, 0x26),
        sunken: Color32::from_rgb(0xEC, 0xEE, 0xF2),
        text: Color32::from_rgb(0x10, 0x13, 0x1A),
        text_muted: Color32::from_rgb(0x5B, 0x64, 0x72),
        text_faint: Color32::from_rgb(0x8A, 0x92, 0x9E),
        accent: Color32::from_rgb(0x25, 0x63, 0xEB),
        accent_hover: Color32::from_rgb(0x3B, 0x82, 0xF6),
        accent_soft: Color32::from_rgba_unmultiplied_const(0x25, 0x63, 0xEB, 0x24),
        success: Color32::from_rgb(0x05, 0x96, 0x69),
        warning: Color32::from_rgb(0xD9, 0x77, 0x06),
        danger: Color32::from_rgb(0xDC, 0x26, 0x26),
        shadow: Color32::from_rgba_unmultiplied_const(0x64, 0x6E, 0x7B, 0x33),
        on_accent: Color32::from_rgb(0xFF, 0xFF, 0xFF),
        dark: false,
    };

    /// Colour for a semantic tone.
    pub fn tone(&self, tone: Tone) -> Color32 {
        match tone {
            Tone::Neutral => self.text_muted,
            Tone::Accent => self.accent,
            Tone::Success => self.success,
            Tone::Warning => self.warning,
            Tone::Danger => self.danger,
        }
    }
}

/// Semantic tone used by badges, bars and toasts.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Tone {
    /// Muted / informational.
    Neutral,
    /// Brand accent.
    Accent,
    /// Healthy.
    Success,
    /// Degraded.
    Warning,
    /// Broken / destructive.
    Danger,
}

// ---------------------------------------------------------------------------
// Accents
// ---------------------------------------------------------------------------

/// Accent colour for a `config.app.accent` name.
pub fn accent_color(name: &str) -> Color32 {
    match name.trim().to_ascii_lowercase().as_str() {
        "violet" | "purple" => Color32::from_rgb(0x8B, 0x5C, 0xF6),
        "green" => Color32::from_rgb(0x10, 0xB9, 0x81),
        "amber" | "orange" => Color32::from_rgb(0xF5, 0x9E, 0x0B),
        "red" => Color32::from_rgb(0xEF, 0x44, 0x44),
        "teal" | "cyan" => Color32::from_rgb(0x14, 0xB8, 0xA6),
        "pink" | "rose" => Color32::from_rgb(0xEC, 0x48, 0x99),
        _ => Color32::from_rgb(0x3B, 0x82, 0xF6),
    }
}

/// Accent names offered by the settings page, with Chinese labels.
pub const ACCENTS: &[(&str, &str)] = &[
    ("blue", "蓝"),
    ("violet", "紫"),
    ("green", "绿"),
    ("amber", "琥珀"),
    ("teal", "青"),
    ("pink", "粉"),
    ("red", "红"),
];

// ---------------------------------------------------------------------------
// Type scale, spacing and radii
// ---------------------------------------------------------------------------

/// Type scale. Sizes are points; line height is derived (`× 1.45`).
pub struct Type;

impl Type {
    /// Page title (20 pt, weight 600).
    pub const TITLE: f32 = 20.0;
    /// Hero number on the dashboard.
    pub const HERO: f32 = 28.0;
    /// Section heading (16 pt).
    pub const HEADING: f32 = 16.0;
    /// Body copy (14 pt, weight 400).
    pub const BODY: f32 = 14.0;
    /// Caption / label (12 pt).
    pub const CAPTION: f32 = 12.0;
    /// Monospace body.
    pub const MONO: f32 = 13.0;
    /// Line-height multiplier from the guide.
    pub const LEADING: f32 = 1.45;

    /// Line height for a font size.
    pub fn leading(size: f32) -> f32 {
        size * Self::LEADING
    }

    /// `FontId` for body text.
    pub fn body() -> FontId {
        FontId::proportional(Self::BODY)
    }

    /// `FontId` for captions.
    pub fn caption() -> FontId {
        FontId::proportional(Self::CAPTION)
    }

    /// `FontId` for page titles.
    pub fn title() -> FontId {
        FontId::proportional(Self::TITLE)
    }

    /// `FontId` for monospace output.
    pub fn mono() -> FontId {
        FontId::monospace(Self::MONO)
    }

    /// The guide asks for size-specific tracking. egui cannot do negative
    /// tracking, so only upper-case labels get positive tracking, approximated
    /// with thin spaces.
    pub fn track(text: &str) -> String {
        let mut out = String::with_capacity(text.len() * 2);
        for (i, ch) in text.chars().enumerate() {
            if i > 0 {
                out.push('\u{2009}');
            }
            out.push(ch);
        }
        out
    }
}

/// Spacing scale (4/8/12/16/24).
pub struct Space;

impl Space {
    /// 4 px.
    pub const XS: f32 = 4.0;
    /// 8 px.
    pub const SM: f32 = 8.0;
    /// 12 px.
    pub const MD: f32 = 12.0;
    /// 16 px.
    pub const LG: f32 = 16.0;
    /// 24 px.
    pub const XL: f32 = 24.0;
}

/// Corner radii (6/10/14).
pub struct Radius;

impl Radius {
    /// 6 px — inputs, chips.
    pub const SM: CornerRadius = CornerRadius::same(6);
    /// 10 px — buttons, rows.
    pub const MD: CornerRadius = CornerRadius::same(10);
    /// 14 px — cards and panels.
    pub const LG: CornerRadius = CornerRadius::same(14);
}

/// Soft drop shadow for cards, tuned per theme.
pub fn card_shadow(dark: bool) -> Shadow {
    Shadow {
        offset: [0, 8],
        blur: 26,
        spread: 0,
        color: if dark {
            Color32::from_rgba_unmultiplied_const(0, 0, 0, 0x66)
        } else {
            Color32::from_rgba_unmultiplied_const(0x64, 0x6E, 0x7B, 0x2E)
        },
    }
}

/// Lighter shadow for raised leaves (buttons, chips, popovers).
pub fn soft_shadow(dark: bool) -> Shadow {
    Shadow {
        offset: [0, 2],
        blur: 10,
        spread: 0,
        color: if dark {
            Color32::from_rgba_unmultiplied_const(0, 0, 0, 0x4D)
        } else {
            Color32::from_rgba_unmultiplied_const(0x64, 0x6E, 0x7B, 0x24)
        },
    }
}

// ---------------------------------------------------------------------------
// Motion
// ---------------------------------------------------------------------------

/// Response of the default spring (guide: 0.3–0.4 s at damping ratio 1.0).
pub const RESPONSE_DEFAULT: f32 = 0.32;
/// Response for hover/press feedback (contract: feedback inside 100 ms).
pub const RESPONSE_FAST: f32 = 0.16;
/// Response for large travel such as sidebar collapse.
pub const RESPONSE_SLOW: f32 = 0.44;

/// Critically damped spring integrator (`value` + `velocity`).
///
/// The guide requires animation that is *interruptible*: every call re-reads the
/// current value and velocity, so a new target mid-flight continues from where
/// the motion currently is instead of snapping. Integrating the damped harmonic
/// equation (damping ratio ζ = 1, ω = 2π / response) gives exactly that.
#[derive(Clone, Copy, Debug, Default, PartialEq)]
pub struct Spring {
    /// Current value.
    pub value: f32,
    /// Current velocity (units per second).
    pub velocity: f32,
}

impl Spring {
    /// A spring parked at `value`.
    pub const fn new(value: f32) -> Self {
        Self {
            value,
            velocity: 0.0,
        }
    }

    /// Jump to `value` without motion.
    pub fn reset(&mut self, value: f32) {
        self.value = value;
        self.velocity = 0.0;
    }

    /// Advances towards `target` by `dt` seconds and returns the new value.
    ///
    /// `response` is the approximate settle time in seconds; the step is
    /// sub-divided so long frames stay stable.
    pub fn update(&mut self, target: f32, dt: f32, response: f32) -> f32 {
        let dt = dt.clamp(0.0, 0.1);
        if dt <= f32::EPSILON {
            return self.value;
        }
        let omega = std::f32::consts::TAU / response.max(0.05);
        let steps = ((dt / 0.004).ceil() as usize).clamp(1, 16);
        let h = dt / steps as f32;
        for _ in 0..steps {
            // Damping ratio 1.0 (critically damped): a = ω²(target − x) − 2ω·v.
            let accel = omega * omega * (target - self.value) - 2.0 * omega * self.velocity;
            self.velocity += accel * h;
            self.value += self.velocity * h;
        }
        if (target - self.value).abs() < 0.0015 && self.velocity.abs() < 0.02 {
            self.value = target;
            self.velocity = 0.0;
        }
        self.value
    }

    /// True once the spring has effectively reached `target`.
    pub fn settled(&self, target: f32) -> bool {
        (target - self.value).abs() < 0.0015 && self.velocity.abs() < 0.02
    }
}

const MOTION_KEY: &str = "rt.ui.motion";
const PALETTE_KEY: &str = "rt.ui.palette";
const SPRINGS_KEY: &str = "rt.ui.springs";
const RESPONSE_KEY: &str = "rt.ui.spring.responses";

/// Motion preferences resolved from the config.
#[derive(Clone, Copy, Debug, Default)]
struct MotionCfg {
    reduce: bool,
}

/// Enables or disables spring motion (the guide's "reduce motion" case).
pub fn set_reduce_motion(ctx: &Context, reduce: bool) {
    ctx.data_mut(|d| d.insert_temp(Id::unique(MOTION_KEY), MotionCfg { reduce }));
}

/// True when motion should be skipped (reduced motion or egui animations off).
pub fn prefers_reduced(ctx: &Context) -> bool {
    let cfg = ctx
        .data(|d| d.get_temp::<MotionCfg>(Id::unique(MOTION_KEY)))
        .unwrap_or_default();
    cfg.reduce || ctx.style_of(ctx.theme()).animation_time <= 0.0
}

/// Declares the response time used by the spring behind `id` this frame.
pub fn set_spring_response(ctx: &Context, id: Id, response: f32) {
    ctx.data_mut(|d| {
        let map = d.get_temp_mut_or_default::<HashMap<Id, f32>>(Id::unique(RESPONSE_KEY));
        map.insert(id, response);
    });
}

/// One global spring per `id`, animated towards `target`.
///
/// Returns the current (animating) value and schedules a repaint while the
/// spring is still in flight. With reduced motion the target is returned
/// immediately (a cross-fade, never a slide).
pub fn spring_value(ctx: &Context, id: Id, target: f32) -> f32 {
    if prefers_reduced(ctx) {
        return target;
    }
    let response = ctx
        .data(|d| {
            d.get_temp::<HashMap<Id, f32>>(Id::unique(RESPONSE_KEY))
                .and_then(|m| m.get(&id).copied())
        })
        .unwrap_or(RESPONSE_DEFAULT);
    let dt = ctx.input(|i| i.stable_dt);
    let value = ctx.data_mut(|d| {
        let springs = d.get_temp_mut_or_default::<HashMap<Id, Spring>>(Id::unique(SPRINGS_KEY));
        springs
            .entry(id)
            .or_insert_with(|| Spring::new(target))
            .update(target, dt, response)
    });
    if (target - value).abs() > 0.0005 {
        ctx.request_repaint();
    }
    value
}

/// Animates `on`/`off` to 0..1 using a spring of the given response.
pub fn spring_bool(ctx: &Context, id: Id, on: bool, response: f32) -> f32 {
    set_spring_response(ctx, id, response);
    spring_value(ctx, id, if on { 1.0 } else { 0.0 })
}

// ---------------------------------------------------------------------------
// Fonts
// ---------------------------------------------------------------------------

/// Candidate system fonts that cover CJK (needed for every Chinese label).
const CJK_FONT_CANDIDATES: &[&str] = &[
    "msyh.ttc",
    "msyh.ttf",
    "simhei.ttf",
    "Deng.ttf",
    "simsun.ttc",
    "NotoSansSC-Regular.otf",
    "SourceHanSansCN-Regular.otf",
];

/// Installs a CJK-capable fallback font so Chinese labels do not render as boxes.
///
/// egui ships Latin-only fonts, so a Windows system font is read from
/// `%WINDIR%\Fonts` and appended *after* the built-in fonts: Latin text keeps the
/// crisp Ubuntu/Hack shapes while CJK falls through to Microsoft YaHei (or the
/// first candidate that exists). Returns the loaded font file name, if any.
pub fn install_fonts(ctx: &Context) -> Option<String> {
    let dir = std::env::var_os("WINDIR")
        .map(PathBuf::from)
        .map(|p| p.join("Fonts"))
        .unwrap_or_else(|| PathBuf::from(r"C:\Windows\Fonts"));

    let mut loaded: Option<(String, Vec<u8>)> = None;
    for name in CJK_FONT_CANDIDATES {
        match std::fs::read(dir.join(name)) {
            Ok(bytes) if bytes.len() > 1024 => {
                loaded = Some(((*name).to_string(), bytes));
                break;
            }
            _ => continue,
        }
    }
    let (name, bytes) = loaded?;

    let mut fonts = FontDefinitions::default();
    fonts
        .font_data
        .insert(name.clone(), std::sync::Arc::new(FontData::from_owned(bytes)));
    for family in [FontFamily::Proportional, FontFamily::Monospace] {
        fonts.families.entry(family).or_default().push(name.clone());
    }
    ctx.set_fonts(fonts);
    Some(name)
}

// ---------------------------------------------------------------------------
// Applying the theme
// ---------------------------------------------------------------------------

/// Current palette (defaults to the dark palette before [`apply`] ran).
pub fn palette(ctx: &Context) -> Palette {
    ctx.data(|d| d.get_temp::<Palette>(Id::unique(PALETTE_KEY)))
        .unwrap_or(Palette::DARK)
}

/// Applies theme, accent and motion settings to the whole context.
///
/// Cheap enough to call whenever the config changes (not every frame): it only
/// rebuilds two [`Style`] values and refreshes the cached palette.
pub fn apply(ctx: &Context, theme: ConfigTheme, accent: &str, reduce_motion: bool) {
    ctx.set_theme(match theme {
        ConfigTheme::Light => ThemePreference::Light,
        ConfigTheme::Dark => ThemePreference::Dark,
        ConfigTheme::System => ThemePreference::System,
    });
    // `ctx.theme()` resolves System against the OS preference eframe reported.
    let dark = ctx.theme() == egui::Theme::Dark;
    let p = if dark { Palette::DARK } else { Palette::LIGHT };
    let accent = accent_color(accent);

    ctx.data_mut(|d| d.insert_temp(Id::unique(PALETTE_KEY), p));
    set_reduce_motion(ctx, reduce_motion);

    ctx.set_style_of(
        egui::Theme::Dark,
        build_style(Palette::DARK, accent, false, reduce_motion),
    );
    ctx.set_style_of(
        egui::Theme::Light,
        build_style(Palette::LIGHT, accent, true, reduce_motion),
    );
}

/// Builds an egui [`Style`] for one palette variant.
fn build_style(p: Palette, accent: Color32, light: bool, reduce_motion: bool) -> Style {
    let mut visuals = if light {
        Visuals::light()
    } else {
        Visuals::dark()
    };

    visuals.dark_mode = !light;
    visuals.override_text_color = Some(p.text);
    visuals.panel_fill = p.bg;
    visuals.window_fill = p.surface;
    visuals.window_stroke = Stroke::new(1.0, p.hairline_strong);
    visuals.window_corner_radius = Radius::LG;
    visuals.window_shadow = card_shadow(!light);
    visuals.menu_corner_radius = Radius::MD;
    visuals.popup_shadow = card_shadow(!light);
    visuals.faint_bg_color = p.raised;
    visuals.extreme_bg_color = p.sunken;
    visuals.code_bg_color = p.raised;
    visuals.text_edit_bg_color = Some(p.raised);
    visuals.hyperlink_color = accent;
    visuals.warn_fg_color = p.warning;
    visuals.error_fg_color = p.danger;
    visuals.striped = true;
    visuals.slider_trailing_fill = true;
    visuals.window_highlight_topmost = true;
    visuals.selection.bg_fill = wash(accent, 0x59);
    visuals.selection.stroke = Stroke::new(1.0, accent);

    visuals.widgets.noninteractive.bg_fill = p.raised;
    visuals.widgets.noninteractive.weak_bg_fill = p.surface;
    visuals.widgets.noninteractive.bg_stroke = Stroke::new(1.0, p.hairline);
    visuals.widgets.noninteractive.corner_radius = Radius::SM;
    visuals.widgets.noninteractive.fg_stroke = Stroke::new(1.0, p.text);

    visuals.widgets.inactive.bg_fill = p.raised;
    visuals.widgets.inactive.weak_bg_fill = p.raised;
    visuals.widgets.inactive.bg_stroke = Stroke::new(1.0, p.hairline);
    visuals.widgets.inactive.corner_radius = Radius::SM;
    visuals.widgets.inactive.fg_stroke = Stroke::new(1.0, p.text);

    visuals.widgets.hovered.bg_fill = p.raised;
    visuals.widgets.hovered.weak_bg_fill = p.raised;
    visuals.widgets.hovered.bg_stroke = Stroke::new(1.0, p.hairline_strong);
    visuals.widgets.hovered.corner_radius = Radius::SM;
    visuals.widgets.hovered.fg_stroke = Stroke::new(1.0, p.text);
    visuals.widgets.hovered.expansion = 0.0;

    visuals.widgets.active.bg_fill = p.accent_soft;
    visuals.widgets.active.weak_bg_fill = p.accent_soft;
    visuals.widgets.active.bg_stroke = Stroke::new(1.0, accent);
    visuals.widgets.active.corner_radius = Radius::SM;
    visuals.widgets.active.fg_stroke = Stroke::new(1.0, p.text);
    visuals.widgets.active.expansion = 0.0;

    visuals.widgets.open.bg_fill = p.raised;
    visuals.widgets.open.weak_bg_fill = p.raised;
    visuals.widgets.open.bg_stroke = Stroke::new(1.0, p.hairline_strong);
    visuals.widgets.open.corner_radius = Radius::MD;
    visuals.widgets.open.fg_stroke = Stroke::new(1.0, p.text);

    let mut style = Style {
        visuals,
        ..Default::default()
    };

    // Typography: one scale shared by both themes.
    let mut text_styles = BTreeMap::new();
    text_styles.insert(TextStyle::Heading, FontId::proportional(Type::HEADING));
    text_styles.insert(TextStyle::Body, FontId::proportional(Type::BODY));
    text_styles.insert(TextStyle::Button, FontId::proportional(Type::BODY));
    text_styles.insert(TextStyle::Small, FontId::proportional(Type::CAPTION));
    text_styles.insert(TextStyle::Monospace, FontId::monospace(Type::MONO));
    style.text_styles = text_styles;

    style.spacing.item_spacing = egui::vec2(Space::SM, Space::SM);
    style.spacing.button_padding = egui::vec2(Space::MD, 6.0);
    style.spacing.window_margin = Margin::same(Space::LG as i8);
    style.spacing.menu_margin = Margin::same(Space::SM as i8);
    style.spacing.interact_size = egui::vec2(40.0, 28.0);
    style.spacing.slider_width = 180.0;
    style.spacing.combo_width = 160.0;
    style.spacing.icon_width = 16.0;
    style.spacing.icon_width_inner = 12.0;
    style.spacing.icon_spacing = Space::SM;
    style.spacing.indent = Space::LG;
    style.spacing.extra_text_line_spacing = 2.0;
    style.spacing.tooltip_width = 320.0;
    style.spacing.scroll.bar_width = 8.0;
    style.spacing.scroll.floating = false;
    style.spacing.scroll.bar_inner_margin = 2.0;
    style.spacing.scroll.bar_outer_margin = 0.0;
    // Feedback must land inside 100 ms; zero when the user asked for less motion.
    style.animation_time = if reduce_motion { 0.0 } else { 0.09 };
    style
}

/// Mixes two colours (`t` = 0 → `a`, 1 → `b`).
pub fn mix(a: Color32, b: Color32, t: f32) -> Color32 {
    let t = t.clamp(0.0, 1.0);
    let f = |x: u8, y: u8| -> u8 {
        (x as f32 + (y as f32 - x as f32) * t)
            .round()
            .clamp(0.0, 255.0) as u8
    };
    Color32::from_rgba_unmultiplied_const(
        f(a.r(), b.r()),
        f(a.g(), b.g()),
        f(a.b(), b.b()),
        f(a.a(), b.a()),
    )
}

/// Builds a translucent colour from an opaque one.
pub fn wash(color: Color32, alpha: u8) -> Color32 {
    Color32::from_rgba_unmultiplied_const(color.r(), color.g(), color.b(), alpha)
}

/// Multiplies the alpha of a colour.
pub fn fade(color: Color32, factor: f32) -> Color32 {
    let a = (color.a() as f32 * factor.clamp(0.0, 1.0)).round() as u8;
    Color32::from_rgba_unmultiplied_const(color.r(), color.g(), color.b(), a)
}

// ---------------------------------------------------------------------------
// Small shared helpers
// ---------------------------------------------------------------------------

/// A large numeric readout above a caption (guide: hierarchy through size and
/// weight, not colour alone).
pub fn hero_number(ui: &mut egui::Ui, value: &str, caption: &str, tone: Color32) {
    let p = palette(ui.ctx());
    ui.vertical(|ui| {
        ui.label(
            egui::RichText::new(value)
                .size(Type::HERO)
                .strong()
                .color(tone),
        );
        ui.label(
            egui::RichText::new(caption)
                .size(Type::CAPTION)
                .color(p.text_muted),
        );
    });
}
