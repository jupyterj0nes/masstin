//! What the hunt found, once the findings have lit up: the findings as a
//! list the analyst scrolls (time, origin, account, destination, state,
//! score, the hunt's explanation), a click selecting one in the graph;
//! the spread of scores and the threshold to filter by, right there.

use super::*;
use crate::view::icons as ic;
use crate::view::theme;

pub(super) struct Finding {
    pub src: u32,
    pub dst: u32,
    pub user: u32,
    pub first: i64,
    pub last: i64,
    pub count: u64,
    pub hunt: u8,
    pub score: f32,
    pub why: String,
}

pub(super) struct HuntReport {
    /// rows per hunt state, in `HUNT_NAMES` order
    pub counts: [usize; 6],
    /// the connections the hunt flagged, rarest first
    pub findings: Vec<Finding>,
    /// rows per ten points of score
    pub hist: [usize; 11],
}

impl Viewer {
    pub(super) fn build_report(&self) -> HuntReport {
        let mut counts = [0usize; 6];
        let mut hist = [0usize; 11];
        let mut agg: HashMap<(u32, u32, u32), Finding> = HashMap::new();
        for e in &self.store.edges {
            counts[e.hunt as usize] += 1;
            if !e.score.is_nan() {
                hist[((e.score / 10.0).floor() as usize).min(10)] += 1;
            }
            if !matches!(e.hunt, super::super::store::H_SIGNIFICANT | super::super::store::H_CANDIDATE) {
                continue;
            }
            let s = if e.score.is_nan() { 0.0 } else { e.score };
            let f = agg.entry((e.src, e.dst, e.user)).or_insert(Finding { src: e.src, dst: e.dst, user: e.user, first: e.t, last: e.t, count: 0, hunt: e.hunt, score: s, why: self.store.whys.name(e.why).to_string() });
            f.count += 1;
            f.first = f.first.min(e.t);
            f.last = f.last.max(e.t);
            if hunt_rank(e.hunt) < hunt_rank(f.hunt) || (e.hunt == f.hunt && s > f.score) {
                f.hunt = e.hunt;
                f.score = s;
                f.why = self.store.whys.name(e.why).to_string();
            }
        }
        let mut findings: Vec<Finding> = agg.into_values().collect();
        findings.sort_by(|a, b| hunt_rank(a.hunt).cmp(&hunt_rank(b.hunt)).then(b.score.partial_cmp(&a.score).unwrap()).then(a.first.cmp(&b.first)));
        HuntReport { counts, findings, hist }
    }

    /// Select this finding's edge in the graph (widening the view to the
    /// findings if it is not drawn) and bring the camera to it.
    fn go_to_finding(&mut self, src: u32, dst: u32, user: u32) {
        let find = |g: &GraphView| g.edges.iter().position(|e| e.src == src && e.dst == dst && (e.user == Some(user) || e.users.contains(&user)));
        let mut k = find(&self.graph);
        if k.is_none() {
            self.draft.view = View::Findings;
            self.draft.min_score = 0;
            self.requery(false);
            k = find(&self.graph);
        }
        let Some(k) = k else {
            self.status = "That connection is outside the current filters.".into();
            return;
        };
        self.selected = Some(Sel::Edge(k));
        self.tab = chrome::Tab::Selection;
        self.show_inspector = true;
        self.load_rows(k);
        let (a, b) = (self.scene.edges.get(k).map(|l| (l.a as usize, l.b as usize))).unwrap_or((0, 0));
        if a < self.layout.pos.len() && b < self.layout.pos.len() {
            let pa = self.layout.pos[a];
            let pb = self.layout.pos[b];
            self.cam_t = V2::new((pa.x + pb.x) / 2.0, (pa.y + pb.y) / 2.0);
            self.zoom_t = self.zoom_t.max(0.9);
        }
    }

    pub(super) fn report_window(&mut self, ctx: &egui::Context) {
        if self.hunt_report.is_none() {
            return;
        }
        let mut open = true;
        let mut apply: Option<u8> = None;
        let mut close = false;
        let mut go: Option<(u32, u32, u32)> = None;
        let canvas = self.canvas_rect;
        let (counts, hist, n_findings) = {
            let rep = self.hunt_report.as_ref().unwrap();
            (rep.counts, rep.hist, rep.findings.len())
        };
        let sig = counts[super::super::store::H_SIGNIFICANT as usize];
        let cand = counts[super::super::store::H_CANDIDATE as usize];
        let hab = counts[super::super::store::H_HABITUAL as usize];
        let ne = counts[super::super::store::H_NOT_EVALUATED as usize];
        let base = counts[super::super::store::H_BASELINE as usize];
        let mut top_n = self.report_top;
        let mut needle = std::mem::take(&mut self.report_find);
        egui::Window::new(format!("{}  The hunt is done", ic::DETECTIVE)).id(egui::Id::unique("hunt-report")).open(&mut open).collapsible(true).resizable(true).default_pos(Pos2::new(canvas.left() + 16.0, canvas.top() + 16.0)).default_size(Vec2::new(760.0, 640.0)).show(ctx, |ui| {
            ui.horizontal(|ui| {
                if let Some(t) = &self.logo_small {
                    ui.image((t.id(), Vec2::new(64.0, 40.0)));
                }
                ui.vertical(|ui| {
                    ui.label(theme::semibold(format!("{} connection(s) worth a look", n_findings), 15.0));
                    ui.label(egui::RichText::new("Every new connection after the start was tested against what the network did before it. Click a finding to see it in the graph and in the inspector.").color(theme::MUTED).size(12.5));
                });
            });
            ui.horizontal_wrapped(|ui| {
                let _ = theme::pill(ui, sig > 0, &format!("{} significant", sig), SIGNIFICANT);
                let _ = theme::pill(ui, cand > 0, &format!("{} candidate", cand), CANDIDATE);
                let _ = theme::pill(ui, false, &format!("{} habitual", hab), theme::MUTED);
                let _ = theme::pill(ui, false, &format!("{} not evaluated", ne), theme::MUTED);
                let _ = theme::pill(ui, false, &format!("{} baseline", base), theme::MUTED);
            });

            // ── the findings ──
            ui.horizontal(|ui| {
                theme::section(ui, "Findings");
                ui.add_space(8.0);
                for n in [10usize, 25, 50, usize::MAX] {
                    let label = if n == usize::MAX { "all".to_string() } else { format!("top {}", n) };
                    if theme::pill(ui, top_n == n, &label, theme::CYAN).clicked() {
                        top_n = n;
                    }
                }
                ui.add(egui::TextEdit::singleline(&mut needle).hint_text(format!("{}  host or account", ic::MAGNIFYING_GLASS)).desired_width(180.0));
            });
            let needle_u = needle.trim().to_uppercase();
            let rows: Vec<(u32, u32, u32, String, String, String, String, u64, u8, u8, String)> = {
                let rep = self.hunt_report.as_ref().unwrap();
                rep.findings
                    .iter()
                    .filter(|f| {
                        if needle_u.is_empty() {
                            return true;
                        }
                        self.store.hosts.name(f.src).to_uppercase().contains(&needle_u) || self.store.hosts.name(f.dst).to_uppercase().contains(&needle_u) || self.store.users.name(f.user).to_uppercase().contains(&needle_u)
                    })
                    .take(top_n)
                    .map(|f| (f.src, f.dst, f.user, fmt_time(f.first), self.store.hosts.name(f.src).to_string(), self.store.hosts.name(f.dst).to_string(), self.store.users.name(f.user).to_string(), f.count, f.hunt, f.score.round() as u8, f.why.clone()))
                    .collect()
            };
            let list_h = (ui.available_height() - 250.0).max(160.0);
            egui::ScrollArea::vertical().max_height(list_h).auto_shrink([false, true]).show(ui, |ui| {
                egui::Grid::new("report-findings").num_columns(6).spacing([12.0, 3.0]).striped(true).min_col_width(40.0).show(ui, |ui| {
                    for h in ["first seen", "origin  →  destination", "account", "state", "score", "why"] {
                        ui.label(egui::RichText::new(h).small().color(theme::DIM));
                    }
                    ui.end_row();
                    for (src, dst, user, t, sname, dname, uname, count, hunt, score, why) in &rows {
                        let selected = matches!(self.selected, Some(Sel::Edge(k)) if self.graph.edges.get(k).map_or(false, |e| e.src == *src && e.dst == *dst && (e.user == Some(*user) || e.users.contains(user))));
                        let c = hunt_color(*hunt).unwrap_or(theme::MUTED);
                        let link = |ui: &mut egui::Ui, text: egui::RichText| -> bool { ui.add(egui::Button::new(text).frame(false).fill(if selected { draw::fade(theme::CYAN, 0.18) } else { Color32::TRANSPARENT })).clicked() };
                        let mut clicked = false;
                        clicked |= link(ui, egui::RichText::new(&t[..16]).monospace().size(11.5).color(theme::MUTED));
                        clicked |= link(ui, egui::RichText::new(format!("{}  {}  {}", sname, ic::ARROW_RIGHT, dname)).size(12.5).color(TEXT));
                        clicked |= link(ui, egui::RichText::new(if uname.is_empty() { "(no account)".to_string() } else { uname.clone() }).size(12.5).color(theme::MUTED));
                        clicked |= link(ui, egui::RichText::new(format!("{}{}", HUNT_NAMES[*hunt as usize], if *count > 1 { format!(" ×{}", count) } else { String::new() })).size(12.0).color(c));
                        clicked |= link(ui, theme::medium(format!("{}", score), 12.5).color(TEXT));
                        let short: String = if why.chars().count() > 70 { format!("{}…", why.chars().take(69).collect::<String>()) } else { why.clone() };
                        let r = ui.add(egui::Button::new(egui::RichText::new(short).size(11.5).color(theme::MUTED)).frame(false).fill(if selected { draw::fade(theme::CYAN, 0.18) } else { Color32::TRANSPARENT }));
                        if !why.is_empty() {
                            let r = r.on_hover_text(why);
                            clicked |= r.clicked();
                        } else {
                            clicked |= r.clicked();
                        }
                        if clicked {
                            go = Some((*src, *dst, *user));
                        }
                        ui.end_row();
                    }
                });
                if rows.is_empty() {
                    ui.label(egui::RichText::new("Nothing flagged. The baseline before the start may be too short, or the network really was quiet.").color(theme::MUTED));
                }
            });

            // ── the scores and the bar ──
            theme::section(ui, "Scores, and where to set the bar");
            ui.horizontal(|ui| {
                let (r, p) = ui.allocate_painter(Vec2::new(ui.available_width() - 8.0, 44.0), Sense::hover());
                let max = hist.iter().copied().max().unwrap_or(1).max(1) as f32;
                let w = r.rect.width() / 11.0;
                for (i, n) in hist.iter().enumerate() {
                    let x = r.rect.left() + i as f32 * w;
                    let h = ((*n as f32).ln_1p() / max.ln_1p()) * 30.0;
                    let col = if i >= 3 { SIGNIFICANT } else if i >= 1 { CANDIDATE } else { theme::MUTED };
                    let on = (i * 10) as u8 >= self.draft.min_score || self.draft.min_score == 0;
                    p.rect_filled(Rect::from_min_max(Pos2::new(x + 2.0, r.rect.bottom() - 12.0 - h.max(1.0)), Pos2::new(x + w - 2.0, r.rect.bottom() - 12.0)), CornerRadius::same(2), draw::fade(col, if on { 0.85 } else { 0.25 }));
                    p.text(Pos2::new(x + w / 2.0, r.rect.bottom() - 2.0), Align2::CENTER_BOTTOM, format!("{}", i * 10), FontId::proportional(9.5), theme::DIM);
                }
            });
            ui.horizontal(|ui| {
                ui.label(egui::RichText::new("score ≥").color(theme::MUTED));
                ui.spacing_mut().slider_width = 200.0;
                ui.add(egui::Slider::new(&mut self.draft.min_score, 0..=100).show_value(true));
                ui.label(egui::RichText::new(if self.draft.min_score == 0 { "any score".to_string() } else { crate::csv_out::score_words(self.draft.min_score).to_string() }).color(theme::DIM).size(11.5));
                for (label, v) in [("1 in 20", 13u8), ("1 in 100", 20), ("1 in 1000", 30)] {
                    if ui.add(egui::Button::new(egui::RichText::new(format!("≥ {}  {}", v, label)).size(11.5))).clicked() {
                        apply = Some(v);
                    }
                }
            });
            ui.horizontal(|ui| {
                if ui.add(egui::Button::new(theme::semibold(format!("{}  Show the findings with this score", ic::FIRE), 13.0).color(theme::ACCENT_INK)).fill(theme::ACCENT).stroke(Stroke::NONE).min_size(Vec2::new(0.0, 30.0))).clicked() {
                    apply = Some(self.draft.min_score);
                }
                if ui.button("Close").clicked() {
                    close = true;
                }
                ui.label(egui::RichText::new("13 is one in twenty (alpha 0.05), 30 one in a thousand, 60 one in a million. The slider in the filter pane does the same at any time.").color(theme::DIM).size(11.0));
            });
        });
        self.report_top = top_n;
        self.report_find = needle;
        if let Some((s, d, u)) = go {
            self.go_to_finding(s, d, u);
        }
        if let Some(v) = apply {
            self.draft.min_score = v;
            self.draft.view = View::Findings;
            self.requery(false);
            self.show_filters = true;
        }
        if close || !open {
            self.hunt_report = None;
        }
    }
}
