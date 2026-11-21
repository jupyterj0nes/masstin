//! Timelines read away from the window. Reading 330,000 rows takes seconds,
//! and read on the thread that draws, the window stopped answering for as
//! long (Windows greys it and shows the busy wheel; over remote desktop it
//! looks hung). Every opener (a timeline, a case, the end of an ingest, a
//! merge of hosts, Reload) now hands the reading to a thread and carries on
//! drawing; what comes after the reading runs when it is done.

use std::sync::mpsc::{channel, Receiver, TryRecvError};

use super::*;
use crate::view::theme;

/// What is done with the timelines once read: the rest of the opener.
pub(super) type ThenFn = Box<dyn FnOnce(&mut Viewer, Result<Store, String>)>;

/// A reading under way.
pub(super) struct PendingLoad {
    pub rx: Receiver<Result<Store, String>>,
    pub then: Option<ThenFn>,
    /// what is being read, for the window: "12 timelines", "the case X"
    pub what: String,
    pub started: std::time::Instant,
}

/// Reads the timelines on a thread of its own; `then` gets what came of it.
pub(super) fn spawn_load(files: Vec<String>, alpha: f64, merges: Vec<(String, String)>) -> Receiver<Result<Store, String>> {
    let (tx, rx) = channel();
    std::thread::Builder::new()
        .name("masstin-load".into())
        .spawn(move || {
            let r = Store::load_with(&files, alpha, &merges).map_err(|e| e.to_string());
            let _ = tx.send(r);
        })
        .map_err(|e| {
            // no thread to be had: the reading says so instead of hanging
            let (tx2, rx2) = channel();
            let _ = tx2.send(Err(format!("cannot start the reading: {}", e)));
            rx2
        })
        .map(|_| rx)
        .unwrap_or_else(|rx2| rx2)
}

impl Viewer {
    /// Read `files` (with these merges) away from the window, then `then`.
    /// A reading asked for while another is under way replaces it: the one
    /// asked last is the one wanted.
    pub(super) fn load_then(&mut self, files: Vec<String>, merges: Vec<(String, String)>, what: String, then: ThenFn) {
        let rx = spawn_load(files, self.alpha, merges);
        self.status = format!("Reading {}…", what);
        self.pending_load = Some(PendingLoad { rx, then: Some(then), what, started: std::time::Instant::now() });
    }

    /// The timelines open, read again with the current merges, then `then`
    /// with whether it worked (the store is replaced when it did).
    pub(super) fn reload_store_then(&mut self, then: Box<dyn FnOnce(&mut Viewer, Result<(), String>)>) {
        let (files, merges) = (self.files.clone(), self.merges.clone());
        let what = if files.len() == 1 { "the timeline again".to_string() } else { format!("the {} timelines again", files.len()) };
        self.load_then(
            files,
            merges,
            what,
            Box::new(move |v: &mut Viewer, r: Result<Store, String>| match r {
                Ok(s) => {
                    v.store = s;
                    v.table_raw_cache.clear();
                    then(v, Ok(()))
                }
                Err(e) => then(v, Err(e)),
            }),
        );
    }

    /// Is a reading under way? The autopilot and the openers wait for it.
    pub(super) fn loading(&self) -> bool {
        self.pending_load.is_some()
    }

    /// Each frame: has the reading ended? Then the rest of the opener runs.
    pub(super) fn poll_pending_load(&mut self, ctx: &egui::Context) {
        let Some(p) = self.pending_load.as_mut() else { return };
        let r = match p.rx.try_recv() {
            Ok(r) => r,
            Err(TryRecvError::Empty) => {
                ctx.request_repaint_after(std::time::Duration::from_millis(100));
                return;
            }
            Err(TryRecvError::Disconnected) => Err("the reading stopped before it ended".to_string()),
        };
        let mut p = self.pending_load.take().unwrap();
        if let Some(then) = p.then.take() {
            then(self, r);
        }
        ctx.request_repaint();
    }

    /// While a reading is under way: what is read and for how long, over the
    /// canvas, so the window says it is working rather than looking stuck.
    pub(super) fn loading_overlay(&mut self, ctx: &egui::Context) {
        let Some(p) = self.pending_load.as_ref() else { return };
        let secs = p.started.elapsed().as_secs_f32();
        // a quick reading flashes nothing
        if secs < 0.25 {
            return;
        }
        let text = format!("Reading {}…  {:.0} s", p.what, secs);
        egui::Area::new(egui::Id::new("loading-overlay")).anchor(egui::Align2::CENTER_TOP, Vec2::new(0.0, 64.0)).order(egui::Order::Foreground).interactable(false).show(ctx, |ui| {
            egui::Frame::new().fill(theme::PANEL).stroke(egui::Stroke::new(1.0, theme::BORDER)).corner_radius(egui::CornerRadius::same(8)).inner_margin(egui::Margin::symmetric(14, 8)).show(ui, |ui| {
                ui.horizontal(|ui| {
                    ui.add(egui::Spinner::new().size(14.0).color(theme::ACCENT));
                    ui.label(egui::RichText::new(text).color(theme::TEXT));
                });
                ui.label(egui::RichText::new("the window stays usable while the timelines are read").small().color(theme::DIM));
            });
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn timeline(name: &str, rows: usize) -> String {
        let p = std::env::temp_dir().join(format!("masstin_loading_{}_{}", std::process::id(), name));
        let mut s = format!("{}\n", crate::csv_out::HEADER);
        for i in 0..rows {
            s.push_str(&format!("2026-01-01T08:{:02}:00+00:00,SRV{:02},SUCCESSFUL_LOGON,4624,3,user{},CORP,WS{:02},10.0.0.{},,,0x1,,Security.evtx,,,,,\n", i % 60, i % 7, i % 5, i % 9, i % 200));
        }
        std::fs::write(&p, s).unwrap();
        p.to_string_lossy().to_string()
    }

    /// The reading runs on another thread and gives the same store as a
    /// reading on this one; a file that is not there comes back as an error,
    /// not a hang.
    #[test]
    fn a_timeline_is_read_on_another_thread() {
        let f = timeline("bg.csv", 500);
        let rx = spawn_load(vec![f.clone()], 0.05, Vec::new());
        let bg = rx.recv_timeout(std::time::Duration::from_secs(30)).expect("an answer").expect("read");
        let here = Store::load_with(&[f.clone()], 0.05, &[]).unwrap();
        assert_eq!(bg.rows_total, here.rows_total);
        assert_eq!(bg.edges.len(), here.edges.len());
        assert_eq!(bg.hosts.len(), here.hosts.len());
        let rx = spawn_load(vec![format!("{}.missing", f)], 0.05, Vec::new());
        assert!(rx.recv_timeout(std::time::Duration::from_secs(30)).expect("an answer").is_err());
        let _ = std::fs::remove_file(f);
    }

    /// The merges go with the reading: two hosts merged are one in the store
    /// read away from the window.
    #[test]
    fn the_merges_go_with_the_reading() {
        let f = timeline("merge.csv", 200);
        let plain = spawn_load(vec![f.clone()], 0.05, Vec::new()).recv().unwrap().unwrap();
        let merged = spawn_load(vec![f.clone()], 0.05, vec![("SRV01".into(), "SRV02".into())]).recv().unwrap().unwrap();
        assert_eq!(merged.hosts.len() + 1, plain.hosts.len(), "SRV01 is SRV02 now");
        let _ = std::fs::remove_file(f);
    }
}
