//! Right-click a connection › Style: the look of every connection of that
//! account (colour, width, dashes, glow, hidden), kept as a style rule on
//! the account's exact name.

use super::*;
use crate::view::icons as ic;
use crate::view::theme;

/// A connection's style being edited.
pub(super) struct EdgeEdit {
    pub user: String,
    /// the accounts of a folded edge, to pick one
    pub choices: Vec<String>,
}

impl Viewer {
    fn user_rule(&self, user: &str) -> Option<&Rule> {
        let exact = format!("={}", user);
        self.style.rules.iter().find(|r| r.field == Field::User && r.pattern.eq_ignore_ascii_case(&exact) && !r.hide)
    }

    fn user_rule_mut(&mut self, user: &str) -> &mut Rule {
        let exact = format!("={}", user);
        let at = match self.style.rules.iter().position(|r| r.field == Field::User && r.pattern.eq_ignore_ascii_case(&exact) && !r.hide) {
            Some(i) => i,
            None => {
                self.style.rules.insert(0, Rule { enabled: true, field: Field::User, pattern: exact, color: None, ..Rule::default() });
                0
            }
        };
        &mut self.style.rules[at]
    }

    pub(super) fn edge_window(&mut self, ctx: &egui::Context) {
        let Some(edit) = self.edge_edit.as_ref() else { return };
        let choices = edit.choices.clone();
        let mut user = edit.user.clone();
        let mut open = true;
        let mut changed = false;
        let mut reset = false;
        let current = self.user_rule(&user).cloned();
        let mut color = current.as_ref().and_then(|r| r.color);
        let mut width = current.as_ref().map(|r| r.width).unwrap_or(1.0);
        let mut dashed = current.as_ref().map(|r| r.dashed).unwrap_or(false);
        let mut glow = current.as_ref().map(|r| r.glow).unwrap_or(false);
        let exact_now = format!("={}", user);
        let hidden = self.style.rules.iter().any(|r| r.field == Field::User && r.hide && r.pattern.eq_ignore_ascii_case(&exact_now));
        let mut hide = hidden;
        egui::Window::new(format!("{}  Style of the connections of {}", ic::LINK, user)).open(&mut open).collapsible(false).resizable(false).default_width(440.0).anchor(egui::Align2::RIGHT_TOP, Vec2::new(-20.0, 120.0)).show(ctx, |ui| {
            if choices.len() > 1 {
                theme::section(ui, "Account");
                egui::ComboBox::from_id_salt("edge-style-user").selected_text(&user).width(260.0).show_ui(ui, |ui| {
                    for c in &choices {
                        ui.selectable_value(&mut user, c.clone(), c);
                    }
                });
            }
            ui.label(egui::RichText::new("Every connection this account makes, wherever it is drawn.").color(theme::DIM).small());
            theme::section(ui, "Line");
            ui.horizontal(|ui| {
                let mut has_color = color.is_some();
                if ui.checkbox(&mut has_color, "its own colour").changed() {
                    color = if has_color { Some([theme::ACCENT.r(), theme::ACCENT.g(), theme::ACCENT.b()]) } else { None };
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
            ui.horizontal(|ui| {
                ui.label("width x");
                changed |= ui.add(egui::Slider::new(&mut width, 0.3..=4.0).fixed_decimals(1)).changed();
            });
            changed |= ui.checkbox(&mut dashed, "dashed").changed();
            changed |= ui.checkbox(&mut glow, "a glow along it (and dots travelling, with motion on)").changed();
            changed |= ui.checkbox(&mut hide, "hidden").changed();
            ui.add_space(6.0);
            if ui.button(format!("{}  Back to the default look", ic::ARROW_CLOCKWISE)).clicked() {
                reset = true;
            }
        });
        let exact = format!("={}", user);
        if reset {
            self.style.rules.retain(|r| !(r.field == Field::User && r.pattern.eq_ignore_ascii_case(&exact)));
            self.persist();
        } else if changed {
            if hide != hidden {
                self.style.rules.retain(|r| !(r.field == Field::User && r.pattern.eq_ignore_ascii_case(&exact) && r.hide));
                if hide {
                    self.style.rules.insert(0, Rule { enabled: true, field: Field::User, pattern: exact.clone(), color: None, hide: true, ..Rule::default() });
                }
            }
            if !hide {
                let rule = self.user_rule_mut(&user);
                rule.color = color;
                rule.width = width;
                rule.dashed = dashed;
                rule.glow = glow;
            }
            self.persist();
        }
        if let Some(e) = self.edge_edit.as_mut() {
            e.user = user;
        }
        if !open {
            self.edge_edit = None;
        }
    }
}
