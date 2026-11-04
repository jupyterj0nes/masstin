//! The viewer's own look: Inter for the text, Phosphor for the icons, and
//! an egui style that is not egui's (rounded, quiet borders, one accent).
//! Small widgets the chrome is built from live here too: section titles,
//! pill toggles, icon buttons, chips.

use std::sync::Arc;

use egui::{Color32, CornerRadius, FontData, FontDefinitions, FontFamily, FontId, RichText, Stroke, Vec2};

pub const PANEL: Color32 = Color32::from_rgb(15, 19, 28);
pub const PANEL_2: Color32 = Color32::from_rgb(20, 25, 36);
pub const FIELD: Color32 = Color32::from_rgb(26, 32, 45);
pub const BORDER: Color32 = Color32::from_rgb(38, 45, 60);
pub const BORDER_2: Color32 = Color32::from_rgb(56, 65, 84);
pub const TEXT: Color32 = Color32::from_rgb(228, 232, 240);
pub const MUTED: Color32 = Color32::from_rgb(132, 142, 160);
pub const DIM: Color32 = Color32::from_rgb(88, 97, 114);
pub const ACCENT: Color32 = Color32::from_rgb(255, 198, 88);
pub const ACCENT_INK: Color32 = Color32::from_rgb(34, 26, 8);

/// The named families the chrome uses besides the default proportional one.
pub const SEMIBOLD: &str = "semibold";
pub const MEDIUM: &str = "medium";

pub fn install(ctx: &egui::Context) {
    let mut fonts = FontDefinitions::default();
    fonts.font_data.insert("inter".into(), Arc::new(FontData::from_static(include_bytes!("fonts/Inter-Regular.ttf"))));
    fonts.font_data.insert("inter-medium".into(), Arc::new(FontData::from_static(include_bytes!("fonts/Inter-Medium.ttf"))));
    fonts.font_data.insert("inter-semibold".into(), Arc::new(FontData::from_static(include_bytes!("fonts/Inter-SemiBold.ttf"))));
    let mut phosphor = FontData::from_static(include_bytes!("fonts/Phosphor.ttf"));
    phosphor.tweak.y_offset_factor = 0.0;
    phosphor.tweak.scale = 1.08;
    fonts.font_data.insert("phosphor".into(), Arc::new(phosphor));
    // egui's own fallbacks (whatever this build has) stay behind ours
    let base: Vec<String> = fonts.families.get(&FontFamily::Proportional).cloned().unwrap_or_default();
    // Inter is subset to the text ranges (its private-use alternates would
    // shadow the icons), so the icon font can follow it
    let chain = |first: &str| -> Vec<String> {
        let mut v = vec![first.to_string(), "phosphor".to_string()];
        v.extend(base.iter().cloned());
        v
    };
    fonts.families.insert(FontFamily::Proportional, chain("inter"));
    fonts.families.insert(FontFamily::Name(MEDIUM.into()), chain("inter-medium"));
    fonts.families.insert(FontFamily::Name(SEMIBOLD.into()), chain("inter-semibold"));
    fonts.families.entry(FontFamily::Monospace).or_default().push("phosphor".into());
    ctx.set_fonts(fonts);

    let mut visuals = egui::Visuals::dark();
    visuals.panel_fill = PANEL;
    visuals.window_fill = PANEL_2;
    visuals.window_stroke = Stroke::new(1.0, BORDER_2);
    visuals.window_corner_radius = CornerRadius::same(10);
    visuals.window_shadow = egui::epaint::Shadow { offset: [0, 8], blur: 24, spread: 0, color: Color32::from_black_alpha(140) };
    visuals.popup_shadow = egui::epaint::Shadow { offset: [0, 6], blur: 16, spread: 0, color: Color32::from_black_alpha(120) };
    visuals.menu_corner_radius = CornerRadius::same(8);
    visuals.extreme_bg_color = FIELD;
    visuals.faint_bg_color = PANEL_2;
    visuals.code_bg_color = FIELD;
    visuals.hyperlink_color = ACCENT;
    visuals.override_text_color = Some(TEXT);
    visuals.weak_text_color = Some(MUTED);
    visuals.selection.bg_fill = Color32::from_rgb(74, 58, 22);
    visuals.selection.stroke = Stroke::new(1.0, ACCENT);
    let r = CornerRadius::same(7);
    visuals.widgets.noninteractive.bg_fill = PANEL;
    visuals.widgets.noninteractive.weak_bg_fill = PANEL;
    visuals.widgets.noninteractive.bg_stroke = Stroke::new(1.0, BORDER);
    visuals.widgets.noninteractive.fg_stroke = Stroke::new(1.0, TEXT);
    visuals.widgets.noninteractive.corner_radius = r;
    visuals.widgets.inactive.bg_fill = FIELD;
    visuals.widgets.inactive.weak_bg_fill = Color32::from_rgb(24, 30, 42);
    visuals.widgets.inactive.bg_stroke = Stroke::new(1.0, BORDER);
    visuals.widgets.inactive.fg_stroke = Stroke::new(1.0, TEXT);
    visuals.widgets.inactive.corner_radius = r;
    visuals.widgets.hovered.bg_fill = Color32::from_rgb(36, 44, 60);
    visuals.widgets.hovered.weak_bg_fill = Color32::from_rgb(32, 39, 54);
    visuals.widgets.hovered.bg_stroke = Stroke::new(1.0, BORDER_2);
    visuals.widgets.hovered.fg_stroke = Stroke::new(1.0, Color32::WHITE);
    visuals.widgets.hovered.corner_radius = r;
    visuals.widgets.hovered.expansion = 0.0;
    visuals.widgets.active.bg_fill = Color32::from_rgb(46, 56, 76);
    visuals.widgets.active.weak_bg_fill = Color32::from_rgb(40, 49, 66);
    visuals.widgets.active.bg_stroke = Stroke::new(1.0, ACCENT);
    visuals.widgets.active.fg_stroke = Stroke::new(1.0, Color32::WHITE);
    visuals.widgets.active.corner_radius = r;
    visuals.widgets.open.bg_fill = Color32::from_rgb(36, 44, 60);
    visuals.widgets.open.weak_bg_fill = Color32::from_rgb(36, 44, 60);
    visuals.widgets.open.bg_stroke = Stroke::new(1.0, BORDER_2);
    visuals.widgets.open.corner_radius = r;
    visuals.slider_trailing_fill = true;
    visuals.handle_shape = egui::style::HandleShape::Circle;
    visuals.striped = true;
    ctx.set_visuals(visuals);

    ctx.all_styles_mut(|style| {
        style.spacing.item_spacing = Vec2::new(8.0, 7.0);
        style.spacing.button_padding = Vec2::new(10.0, 5.0);
        style.spacing.interact_size = Vec2::new(40.0, 24.0);
        style.spacing.menu_margin = egui::Margin::same(8);
        style.spacing.window_margin = egui::Margin::same(14);
        style.spacing.combo_width = 120.0;
        style.spacing.slider_width = 160.0;
        style.spacing.indent = 14.0;
        style.text_styles.insert(egui::TextStyle::Body, FontId::proportional(13.5));
        style.text_styles.insert(egui::TextStyle::Button, FontId::proportional(13.5));
        style.text_styles.insert(egui::TextStyle::Small, FontId::proportional(11.0));
        style.text_styles.insert(egui::TextStyle::Monospace, FontId::monospace(12.0));
        style.text_styles.insert(egui::TextStyle::Heading, FontId::new(17.0, FontFamily::Name(SEMIBOLD.into())));
        style.visuals.menu_corner_radius = CornerRadius::same(8);
        style.interaction.tooltip_delay = 0.35;
        style.interaction.show_tooltips_only_when_still = true;
    });
}

pub fn semibold(text: impl Into<String>, size: f32) -> RichText {
    RichText::new(text).font(FontId::new(size, FontFamily::Name(SEMIBOLD.into())))
}

pub fn medium(text: impl Into<String>, size: f32) -> RichText {
    RichText::new(text).font(FontId::new(size, FontFamily::Name(MEDIUM.into())))
}

/// A small upper-case section title, the way a settings pane labels its groups.
pub fn section(ui: &mut egui::Ui, title: &str) {
    ui.add_space(6.0);
    ui.label(medium(title.to_ascii_uppercase(), 10.5).color(DIM));
    ui.add_space(1.0);
}

/// An on/off pill with the category's colour when on.
pub fn pill(ui: &mut egui::Ui, on: bool, text: &str, color: Color32) -> egui::Response {
    let fill = if on { Color32::from_rgba_unmultiplied(color.r(), color.g(), color.b(), 34) } else { Color32::TRANSPARENT };
    let stroke = if on { Stroke::new(1.0, color) } else { Stroke::new(1.0, BORDER) };
    let txt = RichText::new(text).color(if on { color } else { MUTED });
    let b = egui::Button::new(txt).fill(fill).stroke(stroke).corner_radius(CornerRadius::same(12)).min_size(Vec2::new(0.0, 22.0));
    ui.add(b)
}

/// A button with an icon before its text.
pub fn icon_button(ui: &mut egui::Ui, icon: &str, text: &str) -> egui::Response {
    ui.add(egui::Button::new(format!("{icon}  {text}")).min_size(Vec2::new(0.0, 26.0)))
}

/// A square icon-only button for the toolbar.
pub fn tool(ui: &mut egui::Ui, icon: &str, tip: &str, on: bool) -> egui::Response {
    let fill = if on { Color32::from_rgba_unmultiplied(ACCENT.r(), ACCENT.g(), ACCENT.b(), 40) } else { Color32::TRANSPARENT };
    let stroke = if on { Stroke::new(1.0, ACCENT) } else { Stroke::NONE };
    let txt = RichText::new(icon).size(16.0).color(if on { ACCENT } else { TEXT });
    ui.add(egui::Button::new(txt).fill(fill).stroke(stroke).min_size(Vec2::new(30.0, 28.0)).corner_radius(CornerRadius::same(7))).on_hover_text(tip)
}

/// The accent button: the one action of a pane.
pub fn primary(ui: &mut egui::Ui, text: &str) -> egui::Response {
    ui.add(egui::Button::new(semibold(text, 13.5).color(ACCENT_INK)).fill(ACCENT).stroke(Stroke::NONE).min_size(Vec2::new(ui.available_width(), 32.0)).corner_radius(CornerRadius::same(8)))
}

/// A removable chip: `text ×`. Returns true when the × was clicked.
pub fn chip(ui: &mut egui::Ui, text: &str, color: Color32) -> bool {
    let mut remove = false;
    egui::Frame::new().fill(Color32::from_rgba_unmultiplied(color.r(), color.g(), color.b(), 26)).stroke(Stroke::new(1.0, Color32::from_rgba_unmultiplied(color.r(), color.g(), color.b(), 140))).corner_radius(CornerRadius::same(12)).inner_margin(egui::Margin::symmetric(9, 3)).show(ui, |ui| {
        ui.spacing_mut().item_spacing.x = 6.0;
        ui.label(RichText::new(text).color(TEXT).size(12.5));
        if ui.add(egui::Button::new(RichText::new(super::icons::X).size(11.0).color(MUTED)).frame(false).min_size(Vec2::new(14.0, 14.0))).on_hover_text("Remove this filter").clicked() {
            remove = true;
        }
    });
    remove
}

/// A quiet separator line inside a pane.
pub fn hairline(ui: &mut egui::Ui) {
    let r = ui.available_rect_before_wrap();
    let y = ui.cursor().top() + 4.0;
    ui.painter().hline(r.left()..=r.right(), y, Stroke::new(1.0, BORDER));
    ui.add_space(9.0);
}

/// Text in a field-coloured box, for the hints the panes show.
pub fn hint(ui: &mut egui::Ui, text: &str) {
    egui::Frame::new().fill(PANEL_2).stroke(Stroke::new(1.0, BORDER)).corner_radius(CornerRadius::same(8)).inner_margin(egui::Margin::same(10)).show(ui, |ui| {
        ui.label(RichText::new(text).color(MUTED).size(12.5));
    });
}
