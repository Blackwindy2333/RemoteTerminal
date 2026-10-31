//! Reusable widget layer built on top of egui.
//!
//! Everything here follows the design system in [`super::theme`]: rounded
//! surfaces, hairline borders, spring-driven motion and one type scale. Widgets
//! take explicit ids so their animation state survives layout changes and so two
//! buttons with the same label never share a spring.
//!
//! Every interactive widget accepts a tooltip string; the guide requires that no
//! control is a mystery ("specific labels beat generic").

use std::time::Instant;

use egui::{
    Align, Align2, Color32, CornerRadius, CursorIcon, FontId, Frame, Id, Layout, Margin, Pos2,
    Rect, Response, RichText, ScrollArea, Sense, Stroke, StrokeKind, Ui, Vec2,
};

use super::theme::{self, palette, Palette, Radius, Space, Tone, Type};

// ---------------------------------------------------------------------------
// Surfaces
// ---------------------------------------------------------------------------

/// Opaque card: the standard container for a group of related controls.
pub fn card<R>(ui: &mut Ui, add: impl FnOnce(&mut Ui) -> R) -> R {
    let p = palette(ui.ctx());
    Frame::default()
        .fill(p.surface)
        .stroke(Stroke::new(1.0, p.hairline))
        .corner_radius(Radius::LG)
        .inner_margin(Margin::same(Space::LG as i8))
        .shadow(theme::card_shadow(!p.dark))
        .show(ui, add)
        .inner
}

/// Card with a title row and an optional trailing action.
pub fn card_titled<R>(
    ui: &mut Ui,
    title: &str,
    action: Option<&str>,
    add: impl FnOnce(&mut Ui, &mut bool) -> R,
) -> (R, bool) {
    let p = palette(ui.ctx());
    let mut clicked = false;
    let inner = card(ui, |ui| {
        ui.horizontal(|ui| {
            ui.label(RichText::new(title).size(Type::HEADING).strong().color(p.text));
            if let Some(label) = action {
                ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                    clicked = ui
                        .add(
                            egui::Button::new(RichText::new(label).size(Type::CAPTION).color(p.accent))
                                .fill(Color32::TRANSPARENT)
                                .stroke(Stroke::NONE),
                        )
                        .on_hover_text(label)
                        .clicked();
                });
            }
        });
        ui.add_space(Space::XS);
        add(ui, &mut clicked)
    });
    (inner, clicked)
}

/// Translucent layered surface — the egui stand-in for `backdrop-filter` blur.
///
/// Three stacked translucent layers plus a 1 px top highlight read as a raised
/// material without any real blur (per the architecture's degradation rule).
pub fn glass_panel<R>(ui: &mut Ui, add: impl FnOnce(&mut Ui) -> R) -> R {
    let p = palette(ui.ctx());
    let inner = Frame::default()
        .fill(p.veil)
        .stroke(Stroke::new(1.0, p.hairline_strong))
        .corner_radius(Radius::LG)
        .inner_margin(Margin::same(Space::MD as i8))
        .shadow(theme::card_shadow(!p.dark))
        .show(ui, add);
    let rect = inner.response.rect;
    if rect.width() > 8.0 {
        // Top 1 px gradient highlight: the material "edge" the guide asks for.
        let strip = Rect::from_min_max(rect.min, Pos2::new(rect.max.x, rect.min.y + 1.0));
        ui.painter().rect_filled(
            strip,
            CornerRadius {
                nw: Radius::LG.nw,
                ne: Radius::LG.ne,
                sw: 0,
                se: 0,
            },
            theme::fade(Color32::WHITE, if p.dark { 0.07 } else { 0.55 }),
        );
    }
    inner.inner
}

/// Flat inset area (darker than the card) for console output and tables.
pub fn inset<R>(ui: &mut Ui, add: impl FnOnce(&mut Ui) -> R) -> R {
    let p = palette(ui.ctx());
    Frame::default()
        .fill(p.sunken)
        .stroke(Stroke::new(1.0, p.hairline))
        .corner_radius(Radius::MD)
        .inner_margin(Margin::same(Space::MD as i8))
        .show(ui, add)
        .inner
}

/// Horizontal 1 px rule that fades at both ends (guide: no hard dividers).
pub fn divider(ui: &mut Ui) {
    let p = palette(ui.ctx());
    let width = ui.available_width();
    let (rect, _) = ui.allocate_exact_size(Vec2::new(width, 9.0), Sense::hover());
    let y = rect.center().y;
    let stroke = Stroke::new(1.0, p.hairline);
    let left = rect.left() + 1.0;
    let right = rect.right() - 1.0;
    ui.painter().line_segment(
        [Pos2::new(left, y), Pos2::new(left + (right - left) * 0.15, y)],
        stroke,
    );
    ui.painter().line_segment(
        [Pos2::new(left + (right - left) * 0.15, y), Pos2::new(right - (right - left) * 0.15, y)],
        stroke,
    );
    ui.painter().line_segment(
        [Pos2::new(right - (right - left) * 0.15, y), Pos2::new(right, y)],
        stroke,
    );
}

// ---------------------------------------------------------------------------
// Text helpers
// ---------------------------------------------------------------------------

/// Page title block: 20/600 title, muted caption underneath.
pub fn page_header(ui: &mut Ui, title: &str, subtitle: &str) {
    let p = palette(ui.ctx());
    ui.label(RichText::new(title).size(Type::TITLE).strong().color(p.text));
    if !subtitle.is_empty() {
        ui.add_space(2.0);
        ui.label(RichText::new(subtitle).size(Type::CAPTION).color(p.text_muted));
    }
    ui.add_space(Space::MD);
}

/// Uppercase section label with tracking, used inside cards.
pub fn section_label(ui: &mut Ui, text: &str) {
    let p = palette(ui.ctx());
    ui.label(
        RichText::new(Type::track(&text.to_uppercase()))
            .size(Type::CAPTION)
            .color(p.text_faint),
    );
}

/// One "key: value" line used by the identity and metadata cards.
pub fn key_value_row(ui: &mut Ui, key: &str, value: &str, mono: bool) {
    let p = palette(ui.ctx());
    ui.horizontal(|ui| {
        ui.add_sized(
            [96.0, Type::leading(Type::BODY)],
            egui::Label::new(
                RichText::new(key)
                    .size(Type::CAPTION)
                    .color(p.text_muted),
            )
            .halign(Align::LEFT),
        );
        let mut text = RichText::new(value).size(Type::BODY).color(p.text);
        if mono {
            text = text.monospace().size(Type::MONO);
        }
        ui.label(text);
    });
}

/// Muted caption line.
pub fn caption(ui: &mut Ui, text: &str) {
    let p = palette(ui.ctx());
    ui.label(RichText::new(text).size(Type::CAPTION).color(p.text_muted));
}

/// Small pill badge, e.g. the connection scope (`工作区` / `完全访问`).
pub fn badge(ui: &mut Ui, text: &str, tone: Tone) -> Response {
    let p = palette(ui.ctx());
    let color = p.tone(tone);
    let galley = ui.painter().layout_no_wrap(
        text.to_string(),
        FontId::proportional(Type::CAPTION),
        color,
    );
    let size = Vec2::new(galley.size().x + Space::MD, galley.size().y + 6.0);
    let (rect, resp) = ui.allocate_exact_size(size, Sense::hover());
    ui.painter().rect_filled(rect, Radius::SM, theme::wash(color, if p.dark { 0x2E } else { 0x1F }));
    ui.painter().rect_stroke(
        rect,
        Radius::SM,
        Stroke::new(1.0, theme::wash(color, if p.dark { 0x66 } else { 0x40 })),
        StrokeKind::Inside,
    );
    ui.painter()
        .galley(rect.center() - galley.size() / 2.0, galley, color);
    resp
}

/// Filter chip with a selected state.
pub fn chip(ui: &mut Ui, id: impl std::hash::Hash + std::fmt::Debug, label: &str, active: &mut bool) -> Response {
    let p = palette(ui.ctx());
    let id = ui.make_persistent_id((id, label));
    let resp = ui
        .add(
            egui::Button::new(
                RichText::new(label)
                    .size(Type::CAPTION)
                    .color(if *active { p.on_accent } else { p.text_muted }),
            )
            .fill(if *active { p.accent } else { p.raised })
            .stroke(Stroke::new(
                1.0,
                if *active { p.accent } else { p.hairline },
            ))
            .corner_radius(Radius::SM)
            .min_size(Vec2::new(0.0, 22.0)),
        )
        .on_hover_text(label);
    if resp.clicked() {
        *active = !*active;
    }
    ui.ctx().check_for_id_clash(id, resp.rect, "chip");
    resp
}

/// Status dot; `pulse` animates the alpha for the "live" states.
pub fn status_dot(ui: &mut Ui, color: Color32, pulse: bool) -> Response {
    let size = Vec2::splat(10.0);
    let (rect, resp) = ui.allocate_exact_size(size, Sense::hover());
    let t = ui.ctx().input(|i| i.time) as f32;
    let alpha = if pulse {
        0.45 + 0.55 * (0.5 + 0.5 * (t * 3.2).sin())
    } else {
        1.0
    };
    let center = rect.center();
    if pulse {
        ui.painter().circle_filled(
            center,
            5.0,
            theme::fade(color, 0.18 * alpha),
        );
        ui.ctx().request_repaint();
    }
    ui.painter().circle_filled(center, 3.5, theme::fade(color, alpha));
    resp
}

/// Spinner plus label, used wherever a background job is in flight.
pub fn spinner_row(ui: &mut Ui, label: &str) {
    let p = palette(ui.ctx());
    ui.horizontal(|ui| {
        ui.add(egui::Spinner::new().size(14.0));
        ui.label(RichText::new(label).size(Type::CAPTION).color(p.text_muted));
    });
}

/// Inline error surface showing the *raw* error text (never swallowed).
pub fn error_banner(ui: &mut Ui, text: &str) {
    let p = palette(ui.ctx());
    Frame::default()
        .fill(theme::wash(p.danger, if p.dark { 0x24 } else { 0x14 }))
        .stroke(Stroke::new(1.0, theme::wash(p.danger, 0x59)))
        .corner_radius(Radius::MD)
        .inner_margin(Margin::symmetric(Space::MD as i8, Space::SM as i8))
        .show(ui, |ui| {
            ui.horizontal(|ui| {
                ui.label(RichText::new("⚠").size(Type::BODY).color(p.danger));
                ui.add(
                    egui::Label::new(
                        RichText::new(text)
                            .size(Type::CAPTION)
                            .color(if p.dark { p.text } else { p.danger }),
                    )
                    .wrap(),
                );
            });
        });
    ui.add_space(Space::SM);
}

/// Inline warning / hint surface.
pub fn note_banner(ui: &mut Ui, text: &str) {
    let p = palette(ui.ctx());
    Frame::default()
        .fill(theme::wash(p.warning, if p.dark { 0x1C } else { 0x12 }))
        .stroke(Stroke::new(1.0, theme::wash(p.warning, 0x40)))
        .corner_radius(Radius::MD)
        .inner_margin(Margin::symmetric(Space::MD as i8, Space::SM as i8))
        .show(ui, |ui| {
            ui.add(
                egui::Label::new(
                    RichText::new(text)
                        .size(Type::CAPTION)
                        .color(if p.dark { p.text } else { p.text_muted }),
                )
                .wrap(),
            );
        });
    ui.add_space(Space::SM);
}

// ---------------------------------------------------------------------------
// Buttons
// ---------------------------------------------------------------------------

/// Visual weight of a [`Btn`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BtnKind {
    /// Saturated accent fill — one per view at most.
    Primary,
    /// Surface fill with hairline border.
    Secondary,
    /// Text only, for low-emphasis actions.
    Ghost,
    /// Destructive action.
    Danger,
}

/// Description of a button: label, tooltip, weight and enabled state.
#[derive(Clone, Debug)]
pub struct Btn<'a> {
    id: Id,
    label: &'a str,
    tip: &'a str,
    kind: BtnKind,
    enabled: bool,
    min_width: f32,
    small: bool,
}

impl<'a> Btn<'a> {
    /// Secondary button with a required tooltip.
    pub fn new(id: impl std::hash::Hash + std::fmt::Debug, label: &'a str, tip: &'a str) -> Self {
        Self {
            id: Id::unique(id),
            label,
            tip,
            kind: BtnKind::Secondary,
            enabled: true,
            min_width: 0.0,
            small: false,
        }
    }

    /// Saturated accent button.
    pub fn primary(mut self) -> Self {
        self.kind = BtnKind::Primary;
        self
    }

    /// Text-only button.
    pub fn ghost(mut self) -> Self {
        self.kind = BtnKind::Ghost;
        self
    }

    /// Destructive button.
    pub fn danger(mut self) -> Self {
        self.kind = BtnKind::Danger;
        self
    }

    /// Enables or disables the button (disabled buttons keep their tooltip).
    pub fn enabled(mut self, on: bool) -> Self {
        self.enabled = on;
        self
    }

    /// Minimum width for aligned toolbars.
    pub fn min_width(mut self, w: f32) -> Self {
        self.min_width = w;
        self
    }

    /// Compact variant for dense rows.
    pub fn small(mut self) -> Self {
        self.small = true;
        self
    }
}

/// Springy button: hover lifts it 1 %, press returns it, colours interpolate.
///
/// Motion comes from [`theme::spring_bool`], which is interruptible and respects
/// reduced motion. Feedback starts on pointer-down (guide: respond on press).
pub fn button(ui: &mut Ui, btn: Btn<'_>) -> Response {
    let p = palette(ui.ctx());
    let font = FontId::proportional(if btn.small {
        Type::CAPTION
    } else {
        Type::BODY
    });

    let (base_fill, text_color, border) = match btn.kind {
        BtnKind::Primary => (p.accent, p.on_accent, p.accent),
        BtnKind::Secondary => (p.raised, p.text, p.hairline_strong),
        BtnKind::Ghost => (Color32::TRANSPARENT, p.text_muted, Color32::TRANSPARENT),
        BtnKind::Danger => (
            theme::wash(p.danger, if p.dark { 0x1F } else { 0x12 }),
            p.danger,
            theme::wash(p.danger, 0x40),
        ),
    };

    let galley = ui
        .painter()
        .layout_no_wrap(btn.label.to_string(), font.clone(), text_color);
    let pad = if btn.small {
        Vec2::new(Space::MD, 4.0)
    } else {
        Vec2::new(Space::LG, 6.0)
    };
    let size = Vec2::new(
        (galley.size().x + pad.x * 2.0).max(btn.min_width),
        galley.size().y + pad.y * 2.0,
    )
    .max(Vec2::new(0.0, if btn.small { 24.0 } else { 30.0 }));

    let sense = if btn.enabled {
        Sense::click()
    } else {
        Sense::hover()
    };
    let (rect, resp) = ui.allocate_exact_size(size, sense);
    let resp = resp.on_hover_text(btn.tip);

    let hover = if btn.enabled {
        theme::spring_bool(ui.ctx(), btn.id.with("hover"), resp.hovered(), theme::RESPONSE_FAST)
    } else {
        0.0
    };
    let press = if btn.enabled {
        theme::spring_bool(
            ui.ctx(),
            btn.id.with("press"),
            resp.is_pointer_button_down_on(),
            theme::RESPONSE_FAST,
        )
    } else {
        0.0
    };

    // Pressed state scales down 2 %; hovered lifts 1 % (guide: tactile feedback).
    let scale = 1.0 + 0.010 * hover - 0.020 * press;
    let fill = match btn.kind {
        BtnKind::Primary => theme::mix(p.accent, p.accent_hover, hover),
        BtnKind::Secondary => {
            let h = if p.dark {
                Color32::from_rgb(0x25, 0x2B, 0x34)
            } else {
                Color32::from_rgb(0xF6, 0xF8, 0xFB)
            };
            theme::mix(p.raised, h, hover)
        }
        BtnKind::Ghost => {
            let h = theme::wash(p.text, if p.dark { 0x12 } else { 0x0A });
            theme::mix(Color32::TRANSPARENT, h, hover)
        }
        BtnKind::Danger => theme::mix(base_fill, theme::wash(p.danger, 0x38), hover),
    };
    let fill = theme::mix(fill, theme::wash(p.text, 0x1A), press * 0.5);
    let text_color = if !btn.enabled {
        theme::fade(text_color, 0.45)
    } else {
        text_color
    };

    if resp.hovered() && btn.enabled {
        ui.ctx().set_cursor_icon(CursorIcon::PointingHand);
    }

    let paint_rect = Rect::from_center_size(rect.center(), rect.size() * scale);
    let painter = ui.painter();
    let radius = if btn.small { Radius::SM } else { Radius::MD };
    if resp.hovered() && btn.enabled && btn.kind != BtnKind::Ghost {
        painter.add(theme::soft_shadow(!p.dark).as_shape(paint_rect, radius));
    }
    if fill.a() > 0 {
        painter.rect_filled(paint_rect, radius, fill);
    }
    if border.a() > 0 {
        painter.rect_stroke(
            paint_rect,
            radius,
            Stroke::new(1.0, theme::fade(border, if btn.enabled { 1.0 } else { 0.5 })),
            StrokeKind::Inside,
        );
    }
    let galley = ui
        .painter()
        .layout_no_wrap(btn.label.to_string(), font, text_color);
    painter.galley(paint_rect.center() - galley.size() / 2.0, galley, text_color);
    resp
}

/// Compact text button used inside table rows and toolbars.
pub fn link_button(ui: &mut Ui, label: &str, tip: &str) -> Response {
    let p = palette(ui.ctx());
    ui.add(
        egui::Button::new(RichText::new(label).size(Type::CAPTION).color(p.accent))
            .fill(Color32::TRANSPARENT)
            .stroke(Stroke::NONE)
            .corner_radius(Radius::SM),
    )
    .on_hover_text(tip)
    .on_hover_cursor(CursorIcon::PointingHand)
}

// ---------------------------------------------------------------------------
// Toggle switch
// ---------------------------------------------------------------------------

/// Animated on/off switch. Returns the response; the click flips `on`.
pub fn toggle_switch(ui: &mut Ui, id: impl std::hash::Hash + std::fmt::Debug, on: &mut bool, tip: &str) -> Response {
    let p = palette(ui.ctx());
    let id = Id::unique(id);
    let size = Vec2::new(38.0, 22.0);
    let (rect, resp) = ui.allocate_exact_size(size, Sense::click());
    let resp = resp.on_hover_text(tip);
    if resp.clicked() {
        *on = !*on;
    }
    if resp.hovered() {
        ui.ctx().set_cursor_icon(CursorIcon::PointingHand);
    }

    // Knob travel uses the default spring so it feels like a physical control.
    theme::set_spring_response(ui.ctx(), id, theme::RESPONSE_DEFAULT);
    let t = theme::spring_bool(ui.ctx(), id, *on, theme::RESPONSE_DEFAULT);
    let track = theme::mix(p.raised, p.accent, t);
    let painter = ui.painter();
    painter.rect_filled(rect, CornerRadius::same(11), track);
    painter.rect_stroke(
        rect,
        CornerRadius::same(11),
        Stroke::new(
            1.0,
            if *on { p.accent } else { p.hairline_strong },
        ),
        StrokeKind::Inside,
    );
    let knob_x = rect.left() + 11.0 + t * (rect.width() - 22.0);
    let knob_center = Pos2::new(knob_x, rect.center().y);
    painter.circle_filled(knob_center, 8.0, if p.dark { p.text } else { Color32::WHITE });
    painter.circle_stroke(
        knob_center,
        8.0,
        Stroke::new(1.0, theme::fade(Color32::BLACK, 0.10)),
    );
    resp
}

/// Labelled switch row: title, optional description, switch on the right.
pub fn switch_row(
    ui: &mut Ui,
    id: impl std::hash::Hash + std::fmt::Debug,
    on: &mut bool,
    title: &str,
    desc: &str,
) -> Response {
    let p = palette(ui.ctx());
    let mut changed = None;
    ui.horizontal(|ui| {
        ui.vertical(|ui| {
            ui.label(RichText::new(title).size(Type::BODY).color(p.text));
            if !desc.is_empty() {
                ui.label(RichText::new(desc).size(Type::CAPTION).color(p.text_muted));
            }
        });
        ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
            changed = Some(toggle_switch(ui, id, on, title));
        });
    });
    changed.unwrap_or_else(|| ui.allocate_response(Vec2::ZERO, Sense::hover()))
}

// ---------------------------------------------------------------------------
// Stat bar
// ---------------------------------------------------------------------------

/// Animated usage bar with a label and a right-aligned detail string.
///
/// The fill chases the value with a spring so periodic refreshes read as motion
/// instead of jumping.
pub fn stat_bar(ui: &mut Ui, id: impl std::hash::Hash + std::fmt::Debug, label: &str, ratio: f32, detail: &str, tone: Tone) {
    let p = palette(ui.ctx());
    let id = Id::unique(id);
    let ratio = ratio.clamp(0.0, 1.0);
    theme::set_spring_response(ui.ctx(), id, theme::RESPONSE_SLOW);
    let animated = theme::spring_bool(ui.ctx(), id, ratio > 0.5, theme::RESPONSE_SLOW);
    // Use a real spring on the value itself (not a threshold) so the bar
    // interpolates smoothly between arbitrary percentages.
    let value = theme::spring_value(ui.ctx(), id.with("value"), ratio);
    let _ = animated;
    let color = p.tone(tone);

    ui.horizontal(|ui| {
        ui.label(RichText::new(label).size(Type::CAPTION).color(p.text_muted));
        ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
            ui.label(RichText::new(detail).size(Type::CAPTION).color(p.text));
        });
    });
    let (rect, resp) = ui.allocate_exact_size(Vec2::new(ui.available_width(), 6.0), Sense::hover());
    let painter = ui.painter();
    painter.rect_filled(rect, CornerRadius::same(3), p.raised);
    let w = (rect.width() * value).max(0.0);
    if w > 0.5 {
        let fill = Rect::from_min_size(rect.min, Vec2::new(w, rect.height()));
        painter.rect_filled(fill, CornerRadius::same(3), color);
    }
    // Hairline on the track keeps the bar visible even at 0 %.
    painter.rect_stroke(
        rect,
        CornerRadius::same(3),
        Stroke::new(1.0, p.hairline),
        StrokeKind::Inside,
    );
    let _ = resp;
}

// ---------------------------------------------------------------------------
// Empty state and breadcrumb
// ---------------------------------------------------------------------------

/// Centred empty/placeholder state with an optional action button.
pub fn empty_state(
    ui: &mut Ui,
    glyph: &str,
    title: &str,
    body: &str,
    action: Option<(&str, &str)>,
) -> Option<Response> {
    let p = palette(ui.ctx());
    let mut clicked = None;
    ui.vertical_centered(|ui| {
        ui.add_space(Space::XL);
        let (rect, _) = ui.allocate_exact_size(Vec2::splat(56.0), Sense::hover());
        ui.painter()
            .circle_filled(rect.center(), 28.0, theme::wash(p.accent, if p.dark { 0x1F } else { 0x12 }));
        ui.painter().text(
            rect.center(),
            Align2::CENTER_CENTER,
            glyph,
            FontId::proportional(22.0),
            p.accent,
        );
        ui.add_space(Space::MD);
        ui.label(RichText::new(title).size(Type::HEADING).strong().color(p.text));
        ui.add_space(Space::XS);
        ui.add(
            egui::Label::new(RichText::new(body).size(Type::CAPTION).color(p.text_muted)).wrap(),
        );
        if let Some((label, tip)) = action {
            ui.add_space(Space::MD);
            clicked = Some(button(ui, Btn::new(("empty", label), label, tip).primary()));
        }
        ui.add_space(Space::XL);
    });
    clicked
}

/// Clickable path breadcrumb. Returns the prefix that was clicked.
pub fn path_breadcrumb(ui: &mut Ui, path: &str) -> Option<String> {
    let p = palette(ui.ctx());
    let sep = if path.contains('\\') { '\\' } else { '/' };
    let mut clicked = None;
    let mut acc = String::new();
    ScrollArea::horizontal()
        .id_salt("breadcrumb")
        .show(ui, |ui| {
            ui.horizontal(|ui| {
                ui.spacing_mut().item_spacing.x = 2.0;
                // Root marker.
                let root_label = if sep == '\\' { "磁盘" } else { "/" };
                let root_resp = ui
                    .add(
                        egui::Button::new(
                            RichText::new(root_label).size(Type::CAPTION).color(p.text_muted),
                        )
                        .fill(Color32::TRANSPARENT)
                        .stroke(Stroke::NONE)
                        .corner_radius(Radius::SM),
                    )
                    .on_hover_text("回到根目录");
                if root_resp.clicked() {
                    clicked = Some(path.chars().next().map(|c| c.to_string()).unwrap_or_default());
                }
                for segment in path.split(sep).filter(|s| !s.is_empty()) {
                    if !acc.is_empty() {
                        acc.push(sep);
                    }
                    acc.push_str(segment);
                    ui.label(RichText::new("›").size(Type::CAPTION).color(p.text_faint));
                    let resp = ui
                        .add(
                            egui::Button::new(
                                RichText::new(segment).size(Type::CAPTION).color(p.text),
                            )
                            .fill(Color32::TRANSPARENT)
                            .stroke(Stroke::NONE)
                            .corner_radius(Radius::SM),
                        )
                        .on_hover_text(segment);
                    if resp.clicked() {
                        clicked = Some(acc.clone());
                    }
                }
            });
        });
    clicked
}

// ---------------------------------------------------------------------------
// Code / output panel
// ---------------------------------------------------------------------------

/// What the code panel reported this frame.
#[derive(Clone, Copy, Debug, Default)]
pub struct CodePanelResponse {
    /// The panel was clicked (useful to focus).
    pub response: bool,
    /// The copy button was pressed.
    pub copy: bool,
}

/// Monospace, selectable, scrollable output with a copy button.
///
/// `follow` keeps the view pinned to the bottom (live console behaviour); the
/// caller decides when to stop following (the user scrolling up).
pub fn code_panel(
    ui: &mut Ui,
    id_salt: impl std::hash::Hash + std::fmt::Debug,
    lines: &[OutputLine],
    height: f32,
    follow: bool,
) -> CodePanelResponse {
    let p = palette(ui.ctx());
    let mut out = CodePanelResponse::default();
    Frame::default()
        .fill(p.sunken)
        .stroke(Stroke::new(1.0, p.hairline))
        .corner_radius(Radius::MD)
        .inner_margin(Margin::same(Space::MD as i8))
        .show(ui, |ui| {
            ui.horizontal(|ui| {
                ui.label(
                    RichText::new("输出")
                        .size(Type::CAPTION)
                        .color(p.text_faint),
                );
                ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                    if ui
                        .add(
                            egui::Button::new(
                                RichText::new("复制全部").size(Type::CAPTION).color(p.accent),
                            )
                            .fill(Color32::TRANSPARENT)
                            .stroke(Stroke::NONE)
                            .corner_radius(Radius::SM),
                        )
                        .on_hover_text("把当前全部输出复制到剪贴板")
                        .clicked()
                    {
                        out.copy = true;
                    }
                });
            });
            ScrollArea::vertical()
                .id_salt(id_salt)
                .max_height(height)
                .auto_shrink([false, false])
                .stick_to_bottom(follow)
                .show(ui, |ui| {
                    ui.spacing_mut().item_spacing.y = 1.0;
                    for line in lines {
                        let color = match line.stream {
                            OutputKind::Stdout => p.text,
                            OutputKind::Stderr => p.danger,
                            OutputKind::Notice => p.warning,
                        };
                        ui.add(
                            egui::Label::new(
                                RichText::new(&line.text)
                                    .font(Type::mono())
                                    .color(color),
                            )
                            .selectable(true)
                            .wrap(),
                        );
                    }
                    if lines.is_empty() {
                        ui.label(
                            RichText::new("（暂无输出）")
                                .size(Type::CAPTION)
                                .color(p.text_faint),
                        );
                    }
                });
        });
    out.response = true;
    out
}

/// Which stream an output line came from.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum OutputKind {
    /// Standard output.
    Stdout,
    /// Standard error.
    Stderr,
    /// UI notice injected into the console (fallback, cancellation, …).
    Notice,
}

/// One console line.
#[derive(Clone, Debug)]
pub struct OutputLine {
    /// Stream the line belongs to.
    pub stream: OutputKind,
    /// Line text without trailing newline.
    pub text: String,
}

/// Splits a chunk of streamed text into display lines.
pub fn push_output(lines: &mut Vec<OutputLine>, stream: OutputKind, chunk: &str, limit: usize) {
    for raw in chunk.split_inclusive('\n') {
        let text = raw.strip_suffix('\n').unwrap_or(raw);
        let text = text.strip_suffix('\r').unwrap_or(text);
        lines.push(OutputLine {
            stream,
            text: text.to_string(),
        });
    }
    if lines.len() > limit {
        let excess = lines.len() - limit;
        lines.drain(0..excess);
    }
}

/// Joins console lines back into plain text for the clipboard.
pub fn output_text(lines: &[OutputLine]) -> String {
    let mut out = String::new();
    for line in lines {
        out.push_str(&line.text);
        out.push('\n');
    }
    out
}

// ---------------------------------------------------------------------------
// Toasts
// ---------------------------------------------------------------------------

/// Severity of a toast message (the guide's four feedback kinds).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ToastKind {
    /// Informational.
    Info,
    /// Operation completed.
    Success,
    /// Actionable warning.
    Warn,
    /// Error with the raw message.
    Error,
}

/// One queued toast.
#[derive(Clone, Debug)]
pub struct Toast {
    id: u64,
    kind: ToastKind,
    text: String,
    born: Instant,
    ttl: f32,
}

/// Auto-dismissing toast stack rendered as a foreground overlay.
#[derive(Default)]
pub struct Toasts {
    items: Vec<Toast>,
    next_id: u64,
}

impl Toasts {
    /// Queues a toast; keeping the stack short is the caller's job.
    pub fn push(&mut self, kind: ToastKind, text: impl Into<String>) {
        let text = text.into();
        if let Some(existing) = self
            .items
            .iter_mut()
            .find(|t| t.kind == kind && t.text == text)
        {
            existing.born = Instant::now();
            return;
        }
        self.next_id = self.next_id.wrapping_add(1);
        self.items.push(Toast {
            id: self.next_id,
            kind,
            text,
            born: Instant::now(),
            ttl: if kind == ToastKind::Error { 8.0 } else { 4.5 },
        });
        if self.items.len() > 4 {
            self.items.remove(0);
        }
    }

    /// Convenience: success toast.
    pub fn success(&mut self, text: impl Into<String>) {
        self.push(ToastKind::Success, text);
    }

    /// Convenience: warning toast.
    pub fn warn(&mut self, text: impl Into<String>) {
        self.push(ToastKind::Warn, text);
    }

    /// Convenience: error toast (raw `ClientError::message()` text).
    pub fn error(&mut self, text: impl Into<String>) {
        self.push(ToastKind::Error, text);
    }

    /// Convenience: info toast.
    pub fn info(&mut self, text: impl Into<String>) {
        self.push(ToastKind::Info, text);
    }

    /// Renders the stack bottom-right, above the status line.
    pub fn show(&mut self, ctx: &egui::Context) {
        if self.items.is_empty() {
            return;
        }
        let now = Instant::now();
        self.items
            .retain(|t| now.duration_since(t.born).as_secs_f32() < t.ttl);
        if self.items.is_empty() {
            return;
        }
        let p = palette(ctx);
        let mut dismissed: Option<u64> = None;
        egui::Area::new(Id::unique("rt.toasts"))
            .order(egui::Order::Foreground)
            .anchor(Align2::RIGHT_BOTTOM, Vec2::new(-Space::LG, -48.0))
            .show(ctx, |ui| {
                ui.with_layout(Layout::top_down(Align::RIGHT), |ui| {
                    for toast in self.items.iter().rev() {
                        let color = match toast.kind {
                            ToastKind::Info => p.text,
                            ToastKind::Success => p.success,
                            ToastKind::Warn => p.warning,
                            ToastKind::Error => p.danger,
                        };
                        let glyph = match toast.kind {
                            ToastKind::Info => "ℹ",
                            ToastKind::Success => "✓",
                            ToastKind::Warn => "⚠",
                            ToastKind::Error => "✕",
                        };
                        let age = now.duration_since(toast.born).as_secs_f32();
                        let enter = theme::spring_bool(
                            ctx,
                            Id::unique(("toast.enter", toast.id)),
                            true,
                            theme::RESPONSE_FAST,
                        );
                        // Cross-fade out over the last 0.4 s (never a slide).
                        let fade = ((toast.ttl - age) / 0.4).clamp(0.0, 1.0);
                        let alpha = enter.min(fade);
                        let frame = Frame::default()
                            .fill(theme::fade(p.surface, alpha))
                            .stroke(Stroke::new(1.0, theme::fade(color, alpha)))
                            .corner_radius(Radius::MD)
                            .inner_margin(Margin::symmetric(Space::MD as i8, Space::SM as i8))
                            .shadow(theme::card_shadow(!p.dark));
                        let resp = frame
                            .show(ui, |ui| {
                                ui.horizontal(|ui| {
                                    ui.label(
                                        RichText::new(glyph)
                                            .size(Type::BODY)
                                            .color(theme::fade(color, alpha)),
                                    );
                                    ui.add(
                                        egui::Label::new(
                                            RichText::new(&toast.text)
                                                .size(Type::CAPTION)
                                                .color(theme::fade(p.text, alpha)),
                                        )
                                        .wrap(),
                                    );
                                });
                            })
                            .response;
                        if resp.interact(Sense::click()).clicked() {
                            dismissed = Some(toast.id);
                        }
                    }
                });
            });
        if let Some(id) = dismissed {
            self.items.retain(|t| t.id != id);
        }
        ctx.request_repaint_after(std::time::Duration::from_millis(120));
    }
}

// ---------------------------------------------------------------------------
// Confirmation modal
// ---------------------------------------------------------------------------

/// Modal confirmation dialog with an explicit destructive styling.
pub struct Confirm<'a> {
    /// Dialog id (must be stable per dialog).
    pub id: &'a str,
    /// Title.
    pub title: &'a str,
    /// Body text, may contain the target path.
    pub body: &'a str,
    /// Confirm button label.
    pub confirm: &'a str,
    /// Whether the action is destructive.
    pub danger: bool,
}

/// Result of [`confirm_modal`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ConfirmOutcome {
    /// Still open.
    Pending,
    /// The user accepted.
    Accepted,
    /// The user cancelled (or pressed Esc / clicked the scrim).
    Cancelled,
}

/// Renders a confirmation modal and reports what happened.
pub fn confirm_modal(ctx: &egui::Context, dialog: Confirm<'_>) -> ConfirmOutcome {
    let p = palette(ctx);
    let mut outcome = ConfirmOutcome::Pending;
    let modal = egui::Modal::new(Id::unique(dialog.id))
        .frame(
            Frame::default()
                .fill(p.surface)
                .stroke(Stroke::new(1.0, p.hairline_strong))
                .corner_radius(Radius::LG)
                .inner_margin(Margin::same(Space::LG as i8))
                .shadow(theme::card_shadow(!p.dark)),
        )
        .backdrop_color(theme::fade(Color32::BLACK, if p.dark { 0.55 } else { 0.28 }));

    let resp = modal.show(ctx, |ui| {
        ui.set_width(380.0);
        ui.label(RichText::new(dialog.title).size(Type::TITLE).strong().color(p.text));
        ui.add_space(Space::SM);
        ui.add(
            egui::Label::new(RichText::new(dialog.body).size(Type::BODY).color(p.text_muted)).wrap(),
        );
        ui.add_space(Space::LG);
        ui.horizontal(|ui| {
            ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                let ok = if dialog.danger {
                    button(ui, Btn::new("confirm.ok", dialog.confirm, dialog.confirm).danger())
                } else {
                    button(ui, Btn::new("confirm.ok", dialog.confirm, dialog.confirm).primary())
                };
                if ok.clicked() {
                    outcome = ConfirmOutcome::Accepted;
                }
                if button(
                    ui,
                    Btn::new("confirm.cancel", "取消", "关闭对话框，不做任何修改").ghost(),
                )
                .clicked()
                {
                    outcome = ConfirmOutcome::Cancelled;
                }
            });
        });
    });

    if resp.should_close() && outcome == ConfirmOutcome::Pending {
        outcome = ConfirmOutcome::Cancelled;
    }
    outcome
}

// ---------------------------------------------------------------------------
// Misc helpers
// ---------------------------------------------------------------------------

/// Small label used for table headers.
pub fn table_header_label(ui: &mut Ui, text: &str) {
    let p = palette(ui.ctx());
    ui.label(RichText::new(text).size(Type::CAPTION).color(p.text_faint));
}

/// Renders a row of chips as a single-selection group.
pub fn segmented<'a>(
    ui: &mut Ui,
    id: &str,
    options: &[(&'a str, &'a str)],
    current: &mut String,
) {
    ui.horizontal_wrapped(|ui| {
        for (value, label) in options {
            let mut active = current == value;
            let resp = chip(ui, (id, *value), label, &mut active);
            if resp.clicked() {
                *current = (*value).to_string();
            }
        }
    });
}

/// Applies a colour tint behind a widget group (used for scope highlighting).
pub fn scope_tint(p: &Palette, scope: &str) -> Color32 {
    if scope == "workspace" {
        p.warning
    } else {
        p.success
    }
}

/// Formats an `i64` unix-millis timestamp for display.
pub fn format_ms(ms: i64) -> String {
    match chrono::DateTime::from_timestamp_millis(ms) {
        Some(dt) => dt
            .with_timezone(&chrono::Local)
            .format("%Y-%m-%d %H:%M:%S")
            .to_string(),
        None => "—".to_string(),
    }
}

/// Formats a duration in seconds as `1h 02m 03s`.
pub fn format_secs(secs: u64) -> String {
    rt_core::util::format_uptime(secs)
}
