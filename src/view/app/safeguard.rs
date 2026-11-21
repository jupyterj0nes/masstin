//! The safeguard: when the window takes too long to draw, for long enough
//! (a view of every host of a big case, over remote desktop), the costly
//! parts of the drawing go off on their own and the status line says so,
//! with a button that brings them back. The light mode does the same on the
//! first frames of a software renderer; this one watches all the time, on
//! any renderer, and also draws the connections plain.

use super::*;
use crate::view::views::{CaptionShow, Style};

/// A frame this slow (what masstin and the renderer spend on it) is slow.
pub(super) const SLOW_FRAME_MS: f32 = 150.0;
/// For this long, frame after frame, before the drawing is reduced.
pub(super) const SLOW_FOR: std::time::Duration = std::time::Duration::from_secs(2);

/// The drawing reduced, and what it was before.
pub(super) struct Safeguard {
    /// the style before: what Restore brings back, and what is saved meanwhile
    pub saved: Style,
    pub why: String,
    /// the graph it was reduced on: another graph, small, brings it back
    pub graph: u64,
}

/// What the safeguard turns off: the motion along the connections, their
/// glow, their curves (a straight line is a quarter of the triangles), the
/// captions but on the connection pointed at, the dot grid and the
/// spotlight. The rest of the style (colours, sizes, rules) is kept.
pub(super) fn reduced(style: &Style) -> Style {
    let mut s = style.clone();
    s.motion = false;
    s.edge_glow = false;
    s.curves = false;
    s.caption_show = CaptionShow::Hover;
    s.grid = false;
    s.vignette = false;
    s
}

/// The decision, frame by frame: `Some(true)` reduce now, `None` nothing to
/// do. `slow_since` is when the frames started being slow, kept across
/// frames; a fast frame clears it.
pub(super) fn should_reduce(cost_ms: f32, now: std::time::Instant, slow_since: &mut Option<std::time::Instant>, declined: bool) -> bool {
    if declined || cost_ms <= SLOW_FRAME_MS {
        *slow_since = None;
        return false;
    }
    let since = *slow_since.get_or_insert(now);
    now.duration_since(since) >= SLOW_FOR
}

/// A reduced drawing comes back by itself when the view is another one and
/// small: the reduction was for the big one.
pub(super) fn may_restore(reduced_on: u64, graph_now: u64, hosts: usize, edges: usize) -> bool {
    reduced_on != graph_now && hosts < super::super::layout::BIG_GRAPH && edges < 2500
}

impl Viewer {
    /// Each frame: reduce the drawing when it has been slow long enough, or
    /// bring it back when the view became a small one.
    pub(super) fn watch_safeguard(&mut self) {
        let now = std::time::Instant::now();
        if let Some(sg) = &self.safeguard {
            if may_restore(sg.graph, self.graph_id, self.graph.nodes.len(), self.graph.edges.len()) {
                self.restore_drawing(false);
            }
            return;
        }
        let cost = self.inside_ms + self.outside_ms;
        let declined = self.safeguard_declined == Some(self.graph_id);
        if should_reduce(cost, now, &mut self.slow_since, declined) {
            self.slow_since = None;
            let why = format!("{:.0} ms a frame with {} hosts and {} connections", cost, group_digits(self.graph.nodes.len()), group_digits(self.graph.edges.len()));
            let saved = self.style.clone();
            self.style = reduced(&saved);
            self.requery(false);
            self.safeguard = Some(Safeguard { saved, why: why.clone(), graph: self.graph_id });
            self.status = format!("Drawing reduced to stay responsive ({:.0} ms a frame)", cost);
        }
    }

    /// Restore: the style as it was. Asked by hand, the safeguard leaves
    /// this view alone from then on.
    pub(super) fn restore_drawing(&mut self, by_hand: bool) {
        let Some(sg) = self.safeguard.take() else { return };
        self.style = sg.saved;
        if by_hand {
            self.safeguard_declined = Some(self.graph_id);
            self.status = "Drawing restored: the safeguard leaves this view alone".to_string();
        }
        self.requery(false);
        if by_hand {
            // the requery made the view anew: it is still the one declined
            self.safeguard_declined = Some(self.graph_id);
        }
    }

    /// The style to save: the analyst's, not the reduced one.
    pub(super) fn style_to_save(&self) -> Style {
        self.safeguard.as_ref().map(|s| s.saved.clone()).unwrap_or_else(|| self.style.clone())
    }

    /// The status line's notice of a reduced drawing, with its button.
    pub(super) fn safeguard_chip(&mut self, ui: &mut egui::Ui) {
        let Some(sg) = &self.safeguard else { return };
        let why = sg.why.clone();
        ui.label(egui::RichText::new(format!("{}  Drawing reduced", crate::view::icons::WARNING)).color(CANDIDATE).size(12.0)).on_hover_text(format!(
            "The window took too long to draw ({}), so motion, glow, curves, captions (but on the connection pointed at), the grid and the spotlight are off and the connections are plain lines. Nothing of the case changed.",
            why
        ));
        if ui.small_button("Restore").on_hover_text("The drawing as it was; the safeguard leaves this view alone").clicked() {
            self.restore_drawing(true);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{Duration, Instant};

    /// Slow frames reduce the drawing after two seconds of them, not one
    /// slow frame; a fast frame starts the count again; declined, never.
    #[test]
    fn slow_for_long_enough_reduces() {
        let t0 = Instant::now();
        let mut since = None;
        assert!(!should_reduce(400.0, t0, &mut since, false), "the first slow frame starts the count");
        assert!(!should_reduce(400.0, t0 + Duration::from_millis(1500), &mut since, false));
        assert!(should_reduce(400.0, t0 + Duration::from_millis(2100), &mut since, false), "two seconds of slow frames");
        let mut since = None;
        should_reduce(400.0, t0, &mut since, false);
        assert!(!should_reduce(40.0, t0 + Duration::from_millis(1000), &mut since, false), "a fast frame");
        assert!(since.is_none(), "and the count starts again");
        assert!(!should_reduce(400.0, t0 + Duration::from_millis(2500), &mut since, false));
        let mut since = None;
        should_reduce(400.0, t0, &mut since, true);
        assert!(!should_reduce(400.0, t0 + Duration::from_secs(60), &mut since, true), "declined for this view");
        assert!(!should_reduce(SLOW_FRAME_MS, t0 + Duration::from_secs(60), &mut None, false), "at the limit is not slow");
    }

    /// What is turned off, and what is kept.
    #[test]
    fn the_reduced_style_keeps_the_analysts_choices() {
        let mut s = Style::default();
        s.motion = true;
        s.edge_glow = true;
        s.curves = true;
        s.grid = true;
        s.vignette = true;
        s.node_scale = 1.7;
        s.caption_show = CaptionShow::Always;
        let r = reduced(&s);
        assert!(!r.motion && !r.edge_glow && !r.curves && !r.grid && !r.vignette);
        assert_eq!(r.caption_show, CaptionShow::Hover);
        assert_eq!(r.node_scale, 1.7, "sizes, colours and rules are the analyst's");
        assert_eq!(r.color_by, s.color_by);
        assert_eq!(r.rules.len(), s.rules.len());
    }

    /// It comes back by itself on another, small view; not on the same one
    /// nor on another big one.
    #[test]
    fn a_small_view_brings_the_drawing_back() {
        assert!(may_restore(1, 2, 300, 900));
        assert!(!may_restore(1, 1, 300, 900), "the same view");
        assert!(!may_restore(1, 2, 8000, 900), "another big one");
        assert!(!may_restore(1, 2, 300, 40_000), "many connections");
    }
}
