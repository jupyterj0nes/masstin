//! Where a host's name goes and how big things are: inside the circle, as
//! a band across it, under it or over it, with or without a box behind,
//! the font and the host size; globally in the style, per host as a style
//! rule on that host's name.

use super::*;
use crate::view::icons as ic;
use crate::view::theme;
use crate::view::views::LabelPos;

/// A host's rule being edited in its window (a working copy; writes go to
/// the style on every change so the canvas shows them).
pub(super) struct HostEdit {
    pub name: String,
}

/// The default box behind a name when a box is asked for and no colour is.
pub(super) const LABEL_BOX: [u8; 3] = [20, 25, 36];

/// Dark text on a light box, light text on a dark one.
pub(super) fn ink_for(bg: Color32) -> Color32 {
    let lum = 0.299 * bg.r() as f32 + 0.587 * bg.g() as f32 + 0.114 * bg.b() as f32;
    if lum > 150.0 { Color32::from_rgb(14, 18, 26) } else { TEXT }
}

/// Paint a host's name. `r` is the drawn radius, `base_px` the font size
/// the zoom and the scales ask for; returns whether something was drawn.
#[allow(clippy::too_many_arguments)]
pub(super) fn paint_host_label(painter: &egui::Painter, name: &str, p: Pos2, r: f32, pos: LabelPos, base_px: f32, bg: Option<Color32>, ring: Color32, alpha: f32, lit: bool, crowd: bool) -> bool {
    let chars = name.chars().count().max(1) as f32;
    let fits = (r * 1.8) / (chars * 0.56);
    let inside_ok = r > 9.0 && fits >= (base_px * 0.75).max(8.5);
    let pos = match pos {
        LabelPos::Auto => {
            if inside_ok {
                LabelPos::Inside
            } else {
                LabelPos::Below
            }
        }
        p => p,
    };
    // a crowd shows only the names that fit inside big hosts, and the lit ones
    if crowd && !lit && !(pos == LabelPos::Inside && r > 14.0) {
        return false;
    }
    match pos {
        LabelPos::Inside | LabelPos::Auto => {
            if r <= 7.0 {
                return false;
            }
            let font = base_px.min(fits).max(6.5);
            let max_chars = ((r * 1.8) / (font * 0.56)).floor().max(3.0) as usize;
            let text: String = if name.chars().count() > max_chars { format!("{}…", name.chars().take(max_chars.saturating_sub(1)).collect::<String>()) } else { name.to_string() };
            painter.text(p, Align2::CENTER_CENTER, text, FontId::proportional(font), draw::fade(Color32::from_rgb(14, 18, 26), alpha));
            true
        }
        LabelPos::Band => {
            let font = base_px.clamp(7.0, 22.0);
            let galley = painter.layout_no_wrap(name.to_string(), FontId::proportional(font), TEXT);
            let w = (galley.size().x + 18.0).max(r * 2.4);
            let h = galley.size().y + 6.0;
            let rect = Rect::from_center_size(p, Vec2::new(w, h));
            let fill = bg.unwrap_or_else(|| draw::darken(ring, 0.45));
            painter.rect_filled(rect, CornerRadius::same((h / 2.0) as u8), draw::fade(fill, 0.96 * alpha));
            painter.rect_stroke(rect, CornerRadius::same((h / 2.0) as u8), Stroke::new(1.0, draw::fade(draw::lighten(ring, 0.3), 0.9 * alpha)), egui::StrokeKind::Inside);
            let ink = ink_for(fill);
            painter.galley(Pos2::new(p.x - galley.size().x / 2.0, p.y - galley.size().y / 2.0), galley, draw::fade(ink, alpha));
            true
        }
        LabelPos::Below | LabelPos::Above => {
            let font = base_px.clamp(7.0, 22.0);
            let galley = painter.layout_no_wrap(name.to_string(), FontId::proportional(font), TEXT);
            let h = galley.size().y;
            let y = if pos == LabelPos::Below { p.y + r + 8.0 + h / 2.0 } else { p.y - r - 8.0 - h / 2.0 };
            match bg {
                Some(c) => {
                    draw::pill(painter, Pos2::new(p.x, y), galley, draw::fade(c, 0.96 * alpha), Some(draw::fade(draw::lighten(c, 0.3), 0.6 * alpha)), draw::fade(ink_for(c), alpha));
                }
                None => {
                    draw::pill(painter, Pos2::new(p.x, y), galley, draw::fade(CAPTION_BG, alpha), None, draw::fade(TEXT, alpha));
                }
            }
            true
        }
    }
}

impl Viewer {
    /// The style rule that holds one host's own settings (made if missing).
    pub(super) fn host_rule_mut(&mut self, name: &str) -> &mut Rule {
        let exact = format!("={}", name);
        let at = match self.style.rules.iter().position(|r| r.field == Field::Host && (r.pattern.eq_ignore_ascii_case(&exact) || r.pattern.eq_ignore_ascii_case(name)) && !r.hide) {
            Some(i) => i,
            None => {
                self.style.rules.insert(0, Rule { enabled: true, field: Field::Host, pattern: exact, color: None, ..Rule::default() });
                0
            }
        };
        &mut self.style.rules[at]
    }

    fn host_rule(&self, name: &str) -> Option<&Rule> {
        let exact = format!("={}", name);
        self.style.rules.iter().find(|r| r.field == Field::Host && (r.pattern.eq_ignore_ascii_case(&exact) || r.pattern.eq_ignore_ascii_case(name)) && !r.hide)
    }

    /// View › Labels and sizes: the global settings.
    pub(super) fn labels_window(&mut self, ctx: &egui::Context) {
        if !self.show_labels {
            return;
        }
        let mut open = true;
        let mut changed = false;
        let mut resize = false;
        egui::Window::new(format!("{}  Labels and sizes", ic::TAG)).open(&mut open).collapsible(false).resizable(false).default_width(420.0).anchor(egui::Align2::RIGHT_TOP, Vec2::new(-20.0, 120.0)).show(ctx, |ui| {
            theme::section(ui, "Where the name goes");
            ui.horizontal_wrapped(|ui| {
                for pos in LabelPos::ALL {
                    if theme::pill(ui, self.style.label_pos == pos, pos.label(), theme::ACCENT).on_hover_text(pos.help()).clicked() {
                        self.style.label_pos = pos;
                        changed = true;
                    }
                }
            });
            theme::section(ui, "Text");
            ui.horizontal(|ui| {
                ui.label("size");
                changed |= ui.add(egui::Slider::new(&mut self.style.font_scale, 0.6..=2.4).fixed_decimals(1)).changed();
            });
            ui.horizontal(|ui| {
                changed |= ui.checkbox(&mut self.style.label_bg, "a box behind the name").changed();
                let mut c = Color32::from_rgb(self.style.label_bg_color[0], self.style.label_bg_color[1], self.style.label_bg_color[2]);
                if egui::color_picker::color_edit_button_srgba(ui, &mut c, egui::color_picker::Alpha::Opaque).changed() {
                    self.style.label_bg_color = [c.r(), c.g(), c.b()];
                    self.style.label_bg = true;
                    changed = true;
                }
                ui.label(egui::RichText::new("its colour").color(theme::MUTED));
            });
            theme::section(ui, "Hosts");
            if ui.checkbox(&mut self.style.size_by_traffic, "size by traffic (events in and out of the view, log scale)").changed() {
                changed = true;
                resize = true;
            }
            ui.horizontal(|ui| {
                ui.label("size");
                changed |= ui.add(egui::Slider::new(&mut self.style.node_scale, 0.4..=2.5).fixed_decimals(1)).changed();
            });
            ui.horizontal(|ui| {
                ui.label("edges");
                changed |= ui.add(egui::Slider::new(&mut self.style.edge_scale, 0.3..=3.0).fixed_decimals(1)).changed();
            });
            ui.add_space(6.0);
            ui.label(egui::RichText::new("Right-click a host for its own name position, text size, box and size; those are kept as style rules on its name and win over these.").color(theme::DIM).small());
        });
        if changed {
            self.persist();
        }
        if resize {
            let f = self.draft.clone();
            self.draft = f;
            self.requery(false);
        }
        self.show_labels = open;
    }

    /// Right-click › Label and size of this host: its own settings.
    pub(super) fn host_window(&mut self, ctx: &egui::Context) {
        let Some(edit) = self.host_edit.as_ref() else { return };
        let name = edit.name.clone();
        let mut open = true;
        let mut changed = false;
        let mut reset = false;
        let current = self.host_rule(&name).cloned();
        let mut pos = current.as_ref().and_then(|r| r.label_pos);
        let mut size_mul = current.as_ref().map(|r| r.size).unwrap_or(1.0);
        let mut text_mul = current.as_ref().and_then(|r| r.label_size).unwrap_or(1.0);
        let mut bg = current.as_ref().and_then(|r| r.label_bg);
        let mut color = current.as_ref().and_then(|r| r.color);
        egui::Window::new(format!("{}  {}", ic::DESKTOP, name)).open(&mut open).collapsible(false).resizable(false).default_width(420.0).anchor(egui::Align2::RIGHT_TOP, Vec2::new(-20.0, 120.0)).show(ctx, |ui| {
            theme::section(ui, "Name");
            ui.horizontal_wrapped(|ui| {
                if theme::pill(ui, pos.is_none(), "as the global setting", theme::MUTED).clicked() {
                    pos = None;
                    changed = true;
                }
                for p in LabelPos::ALL {
                    if p == LabelPos::Auto {
                        continue;
                    }
                    if theme::pill(ui, pos == Some(p), p.label(), theme::ACCENT).on_hover_text(p.help()).clicked() {
                        pos = Some(p);
                        changed = true;
                    }
                }
            });
            ui.horizontal(|ui| {
                ui.label("text size ×");
                changed |= ui.add(egui::Slider::new(&mut text_mul, 0.5..=3.0).fixed_decimals(1)).changed();
            });
            ui.horizontal(|ui| {
                let mut has_bg = bg.is_some();
                if ui.checkbox(&mut has_bg, "a box behind the name").changed() {
                    bg = if has_bg { Some(LABEL_BOX) } else { None };
                    changed = true;
                }
                if let Some(b) = bg.as_mut() {
                    let mut c = Color32::from_rgb(b[0], b[1], b[2]);
                    if egui::color_picker::color_edit_button_srgba(ui, &mut c, egui::color_picker::Alpha::Opaque).changed() {
                        *b = [c.r(), c.g(), c.b()];
                        changed = true;
                    }
                }
            });
            theme::section(ui, "Host");
            ui.horizontal(|ui| {
                ui.label("size ×");
                changed |= ui.add(egui::Slider::new(&mut size_mul, 0.4..=3.0).fixed_decimals(1)).changed();
            });
            ui.horizontal(|ui| {
                let mut has_color = color.is_some();
                if ui.checkbox(&mut has_color, "its own colour").changed() {
                    color = if has_color { Some([HOST_FILL.r(), HOST_FILL.g(), HOST_FILL.b()]) } else { None };
                    changed = true;
                }
                if let Some(c3) = color.as_mut() {
                    let mut c = Color32::from_rgb(c3[0], c3[1], c3[2]);
                    if egui::color_picker::color_edit_button_srgba(ui, &mut c, egui::color_picker::Alpha::Opaque).changed() {
                        *c3 = [c.r(), c.g(), c.b()];
                        changed = true;
                    }
                }
            });
            ui.add_space(6.0);
            if ui.button(format!("{}  Back to the global settings", ic::ARROW_CLOCKWISE)).clicked() {
                reset = true;
            }
        });
        if reset {
            let exact = format!("={}", name);
            self.style.rules.retain(|r| !(r.field == Field::Host && (r.pattern.eq_ignore_ascii_case(&exact) || r.pattern.eq_ignore_ascii_case(&name)) && !r.hide));
            self.persist();
        } else if changed {
            let rule = self.host_rule_mut(&name);
            rule.label_pos = pos;
            rule.size = size_mul;
            rule.label_size = if (text_mul - 1.0).abs() < 1e-3 { None } else { Some(text_mul) };
            rule.label_bg = bg;
            rule.color = color;
            self.persist();
        }
        if !open {
            self.host_edit = None;
        }
    }
}
