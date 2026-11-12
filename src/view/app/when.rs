//! The time window to the second: From and To typed or pasted, or picked
//! on a month calendar that shades the days by their activity, with the
//! hour, minute and second set apart. The time strip's handles move with
//! them and they with the handles. Times are the timeline's (UTC).

use super::*;
use crate::view::theme;
use chrono::{Datelike, NaiveDate};

const CALENDAR: &str = "\u{E108}";
const CARET_LEFT: &str = "\u{E138}";
const CARET_RIGHT: &str = "\u{E13A}";

/// What the fields did this frame: a bound changed, Enter asked to apply.
#[derive(Default)]
pub(super) struct WhenEdit {
    pub changed: bool,
    pub commit: bool,
}

/// A typed bound to the second. A date alone is the whole day (From its
/// first second, To its last), `HH:MM` the whole minute. `Some(None)` no
/// bound, `None` text that does not read as a time.
pub(super) fn normalise(text: &str, end: bool) -> Option<Option<String>> {
    let s = text.trim();
    if s.is_empty() {
        return Some(None);
    }
    let t = parse_time(s)?;
    let pad = match s.len() {
        10 => 86_399,
        16 => 59,
        _ => 0,
    };
    Some(Some(fmt_time(if end { t + pad } else { t })))
}

fn day_of(t: i64) -> NaiveDate {
    chrono::DateTime::from_timestamp(t, 0).map(|d| d.date_naive()).unwrap_or_default()
}

fn midnight(d: NaiveDate) -> i64 {
    d.and_hms_opt(0, 0, 0).map(|n| n.and_utc().timestamp()).unwrap_or(0)
}

fn two(v: f64, _: std::ops::RangeInclusive<usize>) -> String {
    format!("{:02}", v as i64)
}

impl Viewer {
    /// Events per day over the whole timeline, counted once per load.
    fn when_days(&mut self) -> &HashMap<NaiveDate, u32> {
        let n = self.store.edges.len();
        if self.when_days.as_ref().map_or(true, |d| d.0 != n) {
            let mut m: HashMap<NaiveDate, u32> = HashMap::new();
            for e in &self.store.edges {
                *m.entry(day_of(e.t)).or_insert(0) += 1;
            }
            self.when_days = Some((n, m));
        }
        &self.when_days.as_ref().unwrap().1
    }

    fn set_bound(&mut self, end: bool, value: String) {
        if end {
            self.draft.to = value;
        } else {
            self.draft.from = value;
        }
    }

    /// From and To, each a field and a calendar. Typing applies on Enter or
    /// when the field is left; a text that does not read stays red and the
    /// window keeps its value.
    pub(super) fn time_window_fields(&mut self, ui: &mut egui::Ui, salt: &str) -> WhenEdit {
        let mut out = WhenEdit::default();
        for k in 0..2 {
            let end = k == 1;
            ui.horizontal(|ui| {
                ui.spacing_mut().item_spacing.x = 4.0;
                ui.add_sized([34.0, 22.0], egui::Label::new(egui::RichText::new(if end { "to" } else { "from" }).color(MUTED)));
                let id = ui.make_persistent_id((salt, "when-text", k));
                let current = if end { self.draft.to.clone() } else { self.draft.from.clone() };
                if !ui.memory(|m| m.has_focus(id)) {
                    self.when_text[k] = current.clone();
                }
                let ok = normalise(&self.when_text[k], end).is_some();
                let r = ui
                    .add(egui::TextEdit::singleline(&mut self.when_text[k]).id(id).font(egui::TextStyle::Monospace).hint_text(if end { "end of the timeline" } else { "start of the timeline" }).text_color(if ok { TEXT } else { SIGNIFICANT }).desired_width(166.0))
                    .on_hover_text("YYYY-MM-DD HH:MM:SS, the timeline's time (UTC). A date alone takes the whole day, HH:MM the whole minute; empty: no bound. Enter applies.");
                if r.lost_focus() {
                    if let Some(v) = normalise(&self.when_text[k], end) {
                        let v = v.unwrap_or_default();
                        if v != current {
                            self.set_bound(end, v.clone());
                            out.changed = true;
                        }
                        self.when_text[k] = v;
                        if ui.input(|i| i.key_pressed(egui::Key::Enter)) {
                            out.commit = true;
                        }
                    }
                }
                let b = ui.add(egui::Button::new(egui::RichText::new(CALENDAR).size(14.0)).min_size(Vec2::new(24.0, 22.0))).on_hover_text("Pick the day on a calendar and the time to the second");
                if self.when_open_cal.as_deref() == Some(&format!("{salt}:{k}")) {
                    self.when_open_cal = None;
                    egui::Popup::open_id(ui.ctx(), egui::Popup::default_response_id(&b));
                }
                egui::Popup::from_toggle_button_response(&b).close_behavior(egui::PopupCloseBehavior::CloseOnClickOutside).show(|ui| {
                    out.changed |= self.calendar(ui, salt, k);
                });
            });
        }
        if let (Some(f), Some(t)) = (parse_time(&self.draft.from), parse_time(&self.draft.to)) {
            if f > t {
                ui.label(egui::RichText::new("From is after To: nothing falls in between.").small().color(SIGNIFICANT));
            }
        }
        out
    }

    /// The month of bound `k`: a day picked keeps the time of the bound,
    /// the hour, minute and second under it, the day's first and last event.
    fn calendar(&mut self, ui: &mut egui::Ui, salt: &str, k: usize) -> bool {
        let end = k == 1;
        let (t0, t1) = (self.store.t_min, self.store.t_max);
        let bound = parse_time(if end { &self.draft.to } else { &self.draft.from });
        let month_id = ui.make_persistent_id((salt, "when-month", k));
        let first_of = |d: NaiveDate| d.with_day(1).unwrap_or(d);
        let mut month: NaiveDate = ui.data(|d| d.get_temp(month_id)).unwrap_or_else(|| first_of(day_of(bound.unwrap_or(if end { t1 } else { t0 }))));
        let mut set: Option<Option<i64>> = None;
        ui.set_min_width(250.0);
        ui.horizontal(|ui| {
            if ui.small_button(CARET_LEFT).on_hover_text("previous month").clicked() {
                month = first_of(month.pred_opt().unwrap_or(month));
            }
            ui.add_sized([180.0, 20.0], egui::Label::new(theme::semibold(month.format("%B %Y").to_string(), 13.5)));
            if ui.small_button(CARET_RIGHT).on_hover_text("next month").clicked() {
                month = month.checked_add_months(chrono::Months::new(1)).unwrap_or(month);
            }
        });
        let counts = self.when_days().clone();
        let max = counts.values().copied().max().unwrap_or(1).max(1) as f32;
        let (d0, d1) = (day_of(t0), day_of(t1));
        egui::Grid::new(ui.make_persistent_id((salt, "when-grid", k))).spacing([2.0, 2.0]).show(ui, |ui| {
            for h in ["Mo", "Tu", "We", "Th", "Fr", "Sa", "Su"] {
                ui.label(egui::RichText::new(h).small().color(theme::DIM));
            }
            ui.end_row();
            let lead = month.weekday().num_days_from_monday();
            for _ in 0..lead {
                ui.label("");
            }
            let mut col = lead;
            let mut d = month;
            while d.month() == month.month() {
                let n = counts.get(&d).copied().unwrap_or(0);
                let picked = bound.map(day_of) == Some(d);
                let fill = if picked {
                    theme::ACCENT
                } else if n > 0 {
                    theme::ACCENT.gamma_multiply(0.12 + 0.45 * (n as f32).ln_1p() / max.ln_1p())
                } else {
                    Color32::TRANSPARENT
                };
                let color = if picked { theme::ACCENT_INK } else if d >= d0 && d <= d1 { TEXT } else { theme::DIM };
                let r = ui.add(egui::Button::new(egui::RichText::new(d.day().to_string()).color(color)).fill(fill).min_size(Vec2::new(30.0, 24.0))).on_hover_text(format!("{}: {} event(s)", d, n));
                if r.clicked() {
                    let tod = bound.map(|b| b.rem_euclid(86_400)).unwrap_or(if end { 86_399 } else { 0 });
                    set = Some(Some(midnight(d) + tod));
                }
                col += 1;
                if col == 7 {
                    ui.end_row();
                    col = 0;
                }
                match d.succ_opt() {
                    Some(n) => d = n,
                    None => break,
                }
            }
        });
        ui.data_mut(|m| m.insert_temp(month_id, month));
        ui.add_space(4.0);
        if let Some(b) = set.flatten().or(bound) {
            let tod = b.rem_euclid(86_400);
            let day = b - tod;
            let (mut h, mut m, mut s) = (tod / 3600, tod % 3600 / 60, tod % 60);
            let mut moved = false;
            ui.horizontal(|ui| {
                ui.spacing_mut().item_spacing.x = 2.0;
                ui.label(egui::RichText::new("time  ").color(MUTED));
                moved |= ui.add(egui::DragValue::new(&mut h).range(0..=23).speed(0.1).custom_formatter(two)).changed();
                ui.label(":");
                moved |= ui.add(egui::DragValue::new(&mut m).range(0..=59).speed(0.2).custom_formatter(two)).changed();
                ui.label(":");
                moved |= ui.add(egui::DragValue::new(&mut s).range(0..=59).speed(0.2).custom_formatter(two)).changed();
                ui.label(egui::RichText::new("  UTC").small().color(theme::DIM));
            });
            if moved {
                set = Some(Some(day + h * 3600 + m * 60 + s));
            }
            ui.horizontal_wrapped(|ui| {
                if ui.small_button("00:00:00").clicked() {
                    set = Some(Some(day));
                }
                if ui.small_button("23:59:59").clicked() {
                    set = Some(Some(day + 86_399));
                }
                let of_day = self.store.in_window(Some(day), Some(day + 86_399));
                if let (Some(&a), Some(&z)) = (of_day.first(), of_day.last()) {
                    let (ta, tz) = (self.store.edges[a as usize].t, self.store.edges[z as usize].t);
                    if ui.small_button("first event").on_hover_text(fmt_time(ta)).clicked() {
                        set = Some(Some(ta));
                    }
                    if ui.small_button("last event").on_hover_text(fmt_time(tz)).clicked() {
                        set = Some(Some(tz));
                    }
                }
            });
        }
        ui.horizontal(|ui| {
            if ui.small_button(if end { "end of the timeline" } else { "start of the timeline" }).on_hover_text("No bound on this side").clicked() {
                set = Some(None);
            }
        });
        match set {
            Some(v) => {
                let text = v.map(fmt_time).unwrap_or_default();
                let before = if end { &self.draft.to } else { &self.draft.from };
                let changed = *before != text;
                self.set_bound(end, text);
                changed
            }
            None => false,
        }
    }

    /// The time window on its own, opened from the time strip; applies as it changes.
    pub(super) fn when_window(&mut self, ctx: &egui::Context) {
        if !self.show_when {
            return;
        }
        let mut open = true;
        let mut apply = false;
        egui::Window::new(format!("{CALENDAR}  Time window")).open(&mut open).collapsible(false).resizable(false).default_width(360.0).anchor(egui::Align2::CENTER_BOTTOM, Vec2::new(0.0, -110.0)).show(ctx, |ui| {
            let w = self.time_window_fields(ui, "strip");
            apply = w.changed || w.commit;
            ui.label(egui::RichText::new("Applies as you change it. The handles on the strip follow; double-click the strip to free the window.").small().color(theme::DIM));
        });
        if apply {
            self.requery(false);
        }
        self.show_when = open;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_typed_bound_covers_what_it_names() {
        assert_eq!(normalise("", false), Some(None));
        assert_eq!(normalise("  ", true), Some(None));
        assert_eq!(normalise("2026-11-03", false), Some(Some("2026-11-03 00:00:00".into())));
        assert_eq!(normalise("2026-11-03", true), Some(Some("2026-11-03 23:59:59".into())));
        assert_eq!(normalise("2026-11-03 10:43", false), Some(Some("2026-11-03 10:43:00".into())));
        assert_eq!(normalise("2026-11-03 10:43", true), Some(Some("2026-11-03 10:43:59".into())));
        assert_eq!(normalise("2026-11-03 10:43:17", true), Some(Some("2026-11-03 10:43:17".into())));
        assert_eq!(normalise("2026-11-03T10:43:17", false), Some(Some("2026-11-03 10:43:17".into())));
        assert_eq!(normalise("2026-13-03", false), None);
        assert_eq!(normalise("yesterday", false), None);
    }

    #[test]
    fn days_and_midnights_agree() {
        let t = parse_time("2026-11-03 10:43:17").unwrap();
        let d = day_of(t);
        assert_eq!(d, NaiveDate::from_ymd_opt(2026, 11, 3).unwrap());
        assert_eq!(fmt_time(midnight(d)), "2026-11-03 00:00:00");
        assert_eq!(t - t.rem_euclid(86_400), midnight(d));
    }
}
