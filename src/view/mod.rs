//! `-a view`: the graph viewer, a window of masstin's own.
//!
//! One timeline (or several) is read into memory (`store`), the analyst's
//! filter selects a graph from it (`query`), a force simulation lays it
//! out (`layout`) and `app` draws it the way Neo4j Browser draws a graph:
//! coloured circles with the host name inside, thin edges carrying the
//! account, a details pane for what is selected. Marks (verdict, notes)
//! go straight into the CSV. No server, no browser.

mod app;
mod layout;
mod paths;
mod present;
mod query;
mod store;
mod views;

pub struct Options {
    pub files: Vec<String>,
    pub alpha: f64,
    /// open on this host's neighbourhood instead of the findings
    pub focus: Option<String>,
    pub start: Option<String>,
    pub end: Option<String>,
}

/// Open the window; returns when it is closed.
pub fn run(opts: Options) -> Result<(), Box<dyn std::error::Error>> {
    let clock = std::time::Instant::now();
    crate::banner::print_phase("1", "2", "Reading the timeline...");
    for f in &opts.files {
        crate::banner::print_phase_detail("File:", f);
    }
    let store = store::Store::load(&opts.files, opts.alpha)?;
    crate::banner::print_phase_result(&format!(
        "{} rows: {} edges between {} hosts, {} accounts; {} row(s) without an origin, {} with an unreadable time ({:.1}s)",
        store.rows_total,
        store.edges.len(),
        store.hosts.len(),
        store.users.len(),
        store.rows_without_origin,
        store.rows_bad_time,
        clock.elapsed().as_secs_f64()
    ));
    crate::banner::print_phase("2", "2", "Opening the viewer (close the window to end)");
    let title = format!("masstin — {}", opts.files.iter().map(|f| std::path::Path::new(f).file_name().map(|n| n.to_string_lossy().to_string()).unwrap_or_else(|| f.clone())).collect::<Vec<_>>().join(", "));
    let native = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default().with_title(&title).with_inner_size([1460.0, 900.0]).with_min_inner_size([900.0, 600.0]),
        ..Default::default()
    };
    let app_opts = opts;
    eframe::run_native("masstin", native, Box::new(move |cc| Ok(Box::new(app::Viewer::new(cc, store, app_opts))))).map_err(|e| Box::<dyn std::error::Error>::from(e.to_string()))?;
    Ok(())
}
