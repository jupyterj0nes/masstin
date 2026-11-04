//! What the hunt found, once the findings have lit up: the counts by
//! state, the rarest connections, the spread of scores, and the score
//! threshold to filter by, right there.

use super::*;
use crate::view::icons as ic;
use crate::view::theme;

pub(super) struct HuntReport {
    /// rows per hunt state, in `HUNT_NAMES` order
    pub counts: [usize; 6],
    /// (origin, destination, account, score, state) of the rarest connections
    pub top: Vec<(String, String, String, u8, u8)>,
    /// rows per ten points of score
    pub hist: [usize; 11],
    pub connections: usize,
}

impl Viewer {
    pub(super) fn build_report(&self) -> HuntReport {
        let mut counts = [0usize; 6];
        let mut hist = [0usize; 11];
        let mut best: HashMap<(u32, u32, u32), (f32, u8)> = HashMap::new();
        for e in &self.store.edges {
            counts[e.hunt as usize] += 1;
            if !e.score.is_nan() {
                hist[((e.score / 10.0).floor() as usize).min(10)] += 1;
            }
            if matches!(e.hunt, super::super::store::H_SIGNIFICANT | super::super::store::H_CANDIDATE) {
                let k = (e.src, e.dst, e.user);
                let s = if e.score.is_nan() { 0.0 } else { e.score };
                let cur = best.entry(k).or_insert((s, e.hunt));
                if s > cur.0 {
                    *cur = (s, e.hunt);
                }
            }
        }
        let connections = best.len();
        let mut top: Vec<((u32, u32, u32), (f32, u8))> = best.into_iter().collect();
        top.sort_by(|a, b| hunt_rank(a.1 .1).cmp(&hunt_rank(b.1 .1)).then(b.1 .0.partial_cmp(&a.1 .0).unwrap()));
        let top = top.into_iter().take(8).map(|((s, d, u), (sc, h))| (self.store.hosts.name(s).to_string(), self.store.hosts.name(d).to_string(), self.store.users.name(u).to_string(), sc.round() as u8, h)).collect();
        HuntReport { counts, top, hist, connections }
    }

    pub(super) fn report_window(&mut self, ctx: &egui::Context) {
        let Some(rep) = self.hunt_report.as_ref() else { return };
        let mut open = true;
        let mut apply: Option<u8> = None;
        let mut close = false;
        let sig = rep.counts[super::super::store::H_SIGNIFICANT as usize];
        let cand = rep.counts[super::super::store::H_CANDIDATE as usize];
        let hab = rep.counts[super::super::store::H_HABITUAL as usize];
        let ne = rep.counts[super::super::store::H_NOT_EVALUATED as usize];
        let base = rep.counts[super::super::store::H_BASELINE as usize];
        egui::Window::new(format!("{}  The hunt is done", ic::DETECTIVE)).open(&mut open).collapsible(false).resizable(false).default_width(560.0).anchor(egui::Align2::CENTER_CENTER, Vec2::new(0.0, -20.0)).show(ctx, |ui| {
            ui.horizontal(|ui| {
                if let Some(t) = &self.logo_small {
                    ui.image((t.id(), Vec2::new(64.0, 40.0)));
                }
                ui.vertical(|ui| {
                    ui.label(theme::semibold(format!("{} connection(s) worth a look", rep.connections), 15.0));
                    ui.label(egui::RichText::new("Every new connection after the start was tested against what the network did before it. What stands out is below, and in the graph in red and orange.").color(theme::MUTED).size(12.5));
                });
            });
            theme::section(ui, "Rows by state");
            ui.horizontal_wrapped(|ui| {
                let _ = theme::pill(ui, sig > 0, &format!("{} significant", sig), SIGNIFICANT);
                let _ = theme::pill(ui, cand > 0, &format!("{} candidate", cand), CANDIDATE);
                let _ = theme::pill(ui, false, &format!("{} habitual", hab), theme::MUTED);
                let _ = theme::pill(ui, false, &format!("{} not evaluated", ne), theme::MUTED);
                let _ = theme::pill(ui, false, &format!("{} baseline", base), theme::MUTED);
            });
            ui.label(egui::RichText::new("significant: rarer than chance at the alpha asked · candidate: new and tested, not below alpha · habitual: seen before · baseline: before the start").color(theme::DIM).size(11.0));
            if !rep.top.is_empty() {
                theme::section(ui, "The rarest");
                egui::Grid::new("report-top").num_columns(4).spacing([14.0, 4.0]).striped(true).show(ui, |ui| {
                    for (s, d, u, sc, h) in &rep.top {
                        ui.label(egui::RichText::new(format!("{}  {}  {}", s, ic::ARROW_RIGHT, d)).size(12.5));
                        ui.label(egui::RichText::new(if u.is_empty() { "(no account)" } else { u }).color(theme::MUTED).size(12.5));
                        ui.label(egui::RichText::new(HUNT_NAMES[*h as usize]).color(hunt_color(*h).unwrap_or(theme::MUTED)).size(12.5));
                        ui.label(theme::medium(format!("{}", sc), 12.5).color(TEXT));
                        ui.end_row();
                    }
                });
            }
            theme::section(ui, "Scores");
            ui.horizontal(|ui| {
                let (r, p) = ui.allocate_painter(Vec2::new(ui.available_width() - 8.0, 48.0), Sense::hover());
                let max = rep.hist.iter().copied().max().unwrap_or(1).max(1) as f32;
                let w = r.rect.width() / 11.0;
                for (i, n) in rep.hist.iter().enumerate() {
                    let x = r.rect.left() + i as f32 * w;
                    let h = ((*n as f32).ln_1p() / max.ln_1p()) * 34.0;
                    let col = if i >= 3 { SIGNIFICANT } else if i >= 1 { CANDIDATE } else { theme::MUTED };
                    p.rect_filled(Rect::from_min_max(Pos2::new(x + 2.0, r.rect.bottom() - 12.0 - h.max(1.0)), Pos2::new(x + w - 2.0, r.rect.bottom() - 12.0)), CornerRadius::same(2), draw::fade(col, 0.8));
                    p.text(Pos2::new(x + w / 2.0, r.rect.bottom() - 2.0), Align2::CENTER_BOTTOM, format!("{}", i * 10), FontId::proportional(9.5), theme::DIM);
                }
            });
            ui.label(egui::RichText::new("hunt_score is how rare a connection is, 0 to 100: 13 is one in twenty (alpha 0.05), 30 one in a thousand, 60 one in a million.").color(theme::DIM).size(11.0));
            theme::section(ui, "Now raise the bar");
            ui.horizontal(|ui| {
                ui.label(egui::RichText::new("score ≥").color(theme::MUTED));
                ui.spacing_mut().slider_width = 220.0;
                ui.add(egui::Slider::new(&mut self.draft.min_score, 0..=100).show_value(true));
                ui.label(egui::RichText::new(if self.draft.min_score == 0 { "any score".to_string() } else { crate::csv_out::score_words(self.draft.min_score).to_string() }).color(theme::DIM).size(11.5));
            });
            ui.horizontal(|ui| {
                for (label, v) in [("one in twenty", 13u8), ("one in a hundred", 20), ("one in a thousand", 30)] {
                    if ui.add(egui::Button::new(egui::RichText::new(format!("≥ {}  {}", v, label)).size(12.0))).clicked() {
                        apply = Some(v);
                    }
                }
            });
            ui.add_space(6.0);
            ui.horizontal(|ui| {
                if ui.add(egui::Button::new(theme::semibold(format!("{}  Show the findings with this score", ic::FIRE), 13.0).color(theme::ACCENT_INK)).fill(theme::ACCENT).stroke(Stroke::NONE).min_size(Vec2::new(0.0, 30.0))).clicked() {
                    apply = Some(self.draft.min_score);
                }
                if ui.button("Close").clicked() {
                    close = true;
                }
                ui.label(egui::RichText::new("The slider in the filter pane does the same at any time.").color(theme::DIM).size(11.0));
            });
        });
        if let Some(v) = apply {
            self.draft.min_score = v;
            self.draft.view = View::Findings;
            self.requery(false);
            self.show_filters = true;
            self.hunt_report = None;
        } else if close || !open {
            self.hunt_report = None;
        }
    }
}
