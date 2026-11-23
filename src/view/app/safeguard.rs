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

/// A part of the drawing that costs: the motion (lights and dots along the
/// connections, the sheen, pulses: the window is drawn again all the time)
/// and every host with its figure and its name (hundreds of figures and
/// texts a frame). They are two things: a window that had its motion
/// turned off keeps its names, and the other way round.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(super) enum Costly {
    Motion,
    Names,
}

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
        let declined = self.keep_as_asked || self.safeguard_declined == Some(self.graph_id);
        if should_reduce(cost, now, &mut self.slow_since, declined) {
            self.slow_since = None;
            let why = format!("{:.0} ms a frame with {} hosts and {} connections", cost, group_digits(self.graph.nodes.len()), group_digits(self.graph.edges.len()));
            let saved = self.style.clone();
            // the scene is drawn anew from the style by itself; a requery would
            // lay the graph out again and set thousands of hosts moving
            self.style = reduced(&saved);
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
    }

    /// Why turning `what` on may slow this window now, if it may: the
    /// renderer, the size of the view, what a frame costs already.
    pub(super) fn cost_of(&self, what: Costly) -> Option<String> {
        let hosts = self.graph.nodes.len();
        let mut why: Vec<String> = Vec::new();
        if self.light_mode {
            why.push("this window is drawn by the CPU (a remote desktop, or no graphics driver), where each frame costs many times what it costs a graphics card".to_string());
        }
        if self.safeguard.is_some() {
            why.push("the safeguard turned the drawing of this view down because its frames were slow".to_string());
        }
        match what {
            Costly::Motion => {
                if hosts >= 300 {
                    why.push(format!("the view has {} hosts and {} connections, and with motion the window is drawn again all the time instead of when something changes", group_digits(hosts), group_digits(self.graph.edges.len())));
                }
            }
            Costly::Names => {
                if hosts >= 150 {
                    why.push(format!("the view has {} hosts: that many figures and names are drawn at every frame, where a plain disc costs a hundredth", group_digits(hosts)));
                }
            }
        }
        let frame = self.inside_ms + self.outside_ms;
        if !why.is_empty() && frame > 1.0 {
            why.push(format!("a frame takes {:.0} ms now", frame));
        }
        if why.is_empty() { None } else { Some(why.join("; ")) }
    }

    /// Turn `what` on: at once where it costs nothing to speak of, after
    /// the analyst has read what it may cost where it may.
    pub(super) fn ask_costly(&mut self, what: Costly) {
        if self.cost_of(what).is_some() {
            self.confirm_cost = Some(what);
        } else {
            self.turn_on(what);
        }
    }

    /// `what` on, as asked: it stays on, and the safeguard no longer turns
    /// the drawing down by itself in this window (it was told).
    pub(super) fn turn_on(&mut self, what: Costly) {
        let warned = self.cost_of(what).is_some();
        // the style under a reduced drawing is the analyst's: both take it
        match what {
            Costly::Motion => {
                self.style.motion = true;
                if let Some(sg) = self.safeguard.as_mut() {
                    sg.saved.motion = true;
                }
            }
            Costly::Names => {
                self.style.names_always = true;
                if let Some(sg) = self.safeguard.as_mut() {
                    sg.saved.names_always = true;
                }
            }
        }
        self.confirm_cost = None;
        // the first frames' own check of the renderer does not undo it either
        self.light_checked = true;
        if warned {
            self.keep_as_asked = true;
            self.status = match what {
                Costly::Motion => "Motion on, as asked: it stays on. The toolbar's motion button turns it off if the window drags.".to_string(),
                Costly::Names => "Every host with its figure and its name, as asked. The chip over the graph (or View > Names and figures always) turns it off if the window drags.".to_string(),
            };
        }
        self.persist();
    }

    /// What it may cost, said before it is turned on; the analyst decides.
    pub(super) fn confirm_cost_window(&mut self, ctx: &egui::Context) {
        let Some(what) = self.confirm_cost else { return };
        let why = self.cost_of(what).unwrap_or_default();
        let (title, does, gives) = match what {
            Costly::Motion => (
                "Turn the motion on?",
                "Motion is the lights and dots that travel along the connections, the sheen on the hosts and the pulses.",
                "The window may answer late to the pointer and to the keys while it is on. Nothing is lost: the motion button of the toolbar turns it off again.",
            ),
            Costly::Names => (
                "Show every host's figure and name?",
                "Every host is drawn with its figure and its name, whatever the zoom and how many there are, instead of plain discs with no name when they are small or many.",
                "Panning and zooming may get slow, and names may sit on one another. Nothing is lost: the chip over the graph, or View > Names and figures always, turns it off again.",
            ),
        };
        let mut open = true;
        let mut done = false;
        egui::Window::new(format!("{}  {}", crate::view::icons::WARNING, title)).id(egui::Id::new("confirm-cost")).open(&mut open).collapsible(false).resizable(false).default_width(460.0).anchor(Align2::CENTER_CENTER, Vec2::ZERO).show(ctx, |ui| {
            ui.set_max_width(460.0);
            ui.label(egui::RichText::new(does).color(TEXT).size(12.5));
            ui.add_space(4.0);
            ui.label(egui::RichText::new(format!("It may slow this window: {}.", why)).color(CANDIDATE).size(12.5));
            ui.add_space(4.0);
            ui.label(egui::RichText::new(gives).color(crate::view::theme::MUTED).size(12.0));
            ui.label(egui::RichText::new("Once you turn it on masstin leaves it on: it will not turn the drawing down by itself in this window.").color(crate::view::theme::DIM).size(11.5));
            ui.add_space(8.0);
            ui.horizontal(|ui| {
                if ui.add(egui::Button::new(crate::view::theme::semibold("Turn it on", 13.0).color(TEXT)).min_size(Vec2::new(110.0, 30.0))).clicked() {
                    self.turn_on(what);
                    done = true;
                }
                if ui.add(egui::Button::new("Leave it off").min_size(Vec2::new(110.0, 30.0))).clicked() {
                    done = true;
                }
            });
        });
        if done || !open {
            self.confirm_cost = None;
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
