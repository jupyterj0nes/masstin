//! Timeline mode: the open CSVs row by row, in the file's own 19 columns,
//! as written. The other face of the graph: a connection or a host of the
//! graph shows its rows here, a row here shows its connection there, and
//! the rows on screen open in a spreadsheet or an editor. Rows are drawn
//! on demand, so a million of them scroll as fast as fifteen.

use super::viewers::{self, ViewerApp};
use super::*;
use crate::view::icons as ic;
use crate::view::theme;
use crate::view::theme::icon_button;

/// The file's own columns, as `csv_out::HEADER` names them, and their widths.
const RAW_WIDTHS: [f32; 19] = [210.0, 170.0, 140.0, 64.0, 74.0, 150.0, 130.0, 150.0, 120.0, 140.0, 130.0, 100.0, 260.0, 320.0, 92.0, 76.0, 280.0, 80.0, 200.0];
/// The margin with the row's line in its file: the window's, not a column.
const GUTTER: f32 = 62.0;

fn raw_columns() -> Vec<&'static str> {
    crate::csv_out::HEADER.split(',').collect()
}

/// A column of the file by its name, in any case.
pub(super) fn column_named(name: &str) -> Option<usize> {
    raw_columns().iter().position(|c| c.eq_ignore_ascii_case(name.trim()))
}

/// How the analyst left the timeline: the size of its text, the width of
/// each column, the columns hidden. The analyst's, not the case's: kept in
/// the viewer's own settings, for every timeline.
#[derive(Clone, Debug, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(default)]
pub(super) struct TableLook {
    pub font: f32,
    pub widths: [f32; 19],
    pub hidden: [bool; 19],
}

impl Default for TableLook {
    fn default() -> Self {
        TableLook { font: 12.0, widths: RAW_WIDTHS, hidden: [false; 19] }
    }
}

impl TableLook {
    pub const FONT: (f32, f32) = (8.0, 24.0);
    pub const WIDTH: (f32, f32) = (36.0, 1200.0);

    fn path() -> Option<std::path::PathBuf> {
        super::ingest::config_file("timeline.json")
    }

    pub fn load() -> TableLook {
        let mut l: TableLook = Self::path().and_then(|p| std::fs::read_to_string(p).ok()).and_then(|s| serde_json::from_str(&s).ok()).unwrap_or_default();
        l.font = l.font.clamp(Self::FONT.0, Self::FONT.1);
        for w in l.widths.iter_mut() {
            *w = w.clamp(Self::WIDTH.0, Self::WIDTH.1);
        }
        // a timeline with every column hidden shows nothing to bring one back from
        if l.hidden.iter().all(|h| *h) {
            l.hidden = [false; 19];
        }
        l
    }

    pub fn save(&self) {
        if let Some(p) = Self::path() {
            if let Some(dir) = p.parent() {
                let _ = std::fs::create_dir_all(dir);
            }
            if let Ok(s) = serde_json::to_string_pretty(self) {
                let _ = std::fs::write(p, s);
            }
        }
    }

    pub fn set_font(&mut self, size: f32) {
        self.font = (size * 2.0).round() / 2.0;
        self.font = self.font.clamp(Self::FONT.0, Self::FONT.1);
    }

    pub fn set_width(&mut self, col: usize, width: f32) {
        if let Some(w) = self.widths.get_mut(col) {
            *w = width.clamp(Self::WIDTH.0, Self::WIDTH.1);
        }
    }

    /// The height of a row at this size of text.
    pub fn row_height(&self) -> f32 {
        (self.font + 8.0).round()
    }

    /// The columns shown, in the file's order.
    pub fn shown(&self) -> Vec<usize> {
        (0..19).filter(|c| !self.hidden[*c]).collect()
    }

    /// The column at a horizontal position, `x` measured from where the
    /// first column starts (each column is its width and the gap after it).
    pub fn column_at(&self, x: f32) -> Option<usize> {
        let mut left = 0.0;
        for c in self.shown() {
            let right = left + self.widths[c] + COL_GAP;
            if x >= left && x < right {
                return Some(c);
            }
            left = right;
        }
        None
    }
}

/// The gap between two columns: in the header it is the handle that
/// drags the width of the column before it.
const COL_GAP: f32 = 8.0;

/// One filter of the timeline: the rows whose column (or any column) holds
/// the text, or the ones that do not. Any case; an empty text is "the
/// column is empty". Filters add up: a row is shown when it passes all.
#[derive(Clone, Debug, PartialEq)]
pub(super) struct RowFilter {
    /// the column, in the file's order; None: any column
    pub col: Option<usize>,
    /// lower case
    pub text: String,
    /// true: the rows that do NOT hold it
    pub negate: bool,
}

impl RowFilter {
    pub fn new(col: Option<usize>, text: &str, negate: bool) -> RowFilter {
        RowFilter { col, text: text.trim().to_lowercase(), negate }
    }

    /// `+user:alice`, `-event_type:logoff`, `+10.0.0.5`: the sign (none is
    /// `+`), a column by its name in the file or any column, the text.
    pub fn parse(s: &str) -> Option<RowFilter> {
        let s = s.trim();
        let (negate, rest) = match s.strip_prefix('-') {
            Some(r) => (true, r),
            None => (false, s.strip_prefix('+').unwrap_or(s)),
        };
        if rest.is_empty() {
            return None;
        }
        let cols = raw_columns();
        match rest.split_once(':').and_then(|(c, t)| cols.iter().position(|n| n.eq_ignore_ascii_case(c.trim())).map(|i| (i, t))) {
            Some((i, t)) => Some(RowFilter::new(Some(i), t, negate)),
            None => Some(RowFilter::new(None, rest, negate)),
        }
    }

    /// The filter in words, for its chip.
    pub fn label(&self) -> String {
        let cols = raw_columns();
        let what = match (self.col.and_then(|c| cols.get(c)), self.text.is_empty()) {
            (Some(c), true) => format!("{} is empty", c),
            (Some(c), false) => format!("{}: {}", c, self.text),
            (None, _) => self.text.clone(),
        };
        format!("{} {}", if self.negate { "−" } else { "+" }, what)
    }

    /// Whether a row passes: `lower` is its text in lower case, `fields`
    /// its columns (lower case too).
    fn passes(&self, lower: &str, fields: &[std::borrow::Cow<str>]) -> bool {
        let hit = match self.col {
            Some(c) => {
                let v = fields.get(c).map(|v| v.trim()).unwrap_or("");
                if self.text.is_empty() { v.is_empty() } else { v.contains(&self.text) }
            }
            None => lower.contains(&self.text),
        };
        hit != self.negate
    }
}

/// Whether a row (its text as the file has it) holds the find box and
/// passes every filter.
pub(super) fn row_passes(text: &str, find: &str, filters: &[RowFilter]) -> bool {
    let lower = text.to_lowercase();
    if !find.is_empty() && !lower.contains(find) {
        return false;
    }
    if filters.is_empty() {
        return true;
    }
    let mut fields: Vec<std::borrow::Cow<str>> = Vec::with_capacity(20);
    crate::graph_hunt_common::engine::split_csv_into(&lower, &mut fields);
    filters.iter().all(|f| f.passes(&lower, &fields))
}

/// The rows the table is narrowed to: those of a connection or of a host.
pub(super) struct TableScope {
    pub label: String,
    pub rows: Vec<(u16, u32)>,
}

enum RowAct {
    Select((u16, u32)),
    /// Ctrl + click: one more row, or one fewer
    Toggle((u16, u32)),
    /// Shift + click: every row from the one picked to this one
    Range((u16, u32)),
    /// exactly the rows picked (or this one), in the graph
    Exact((u16, u32)),
    /// the rows picked (or this one), in agentc00pr's viewer
    Agent((u16, u32)),
    Graph((u16, u32)),
    Copy((u16, u32)),
    Connection((u16, u32)),
}

/// One field as CSV writes it.
fn csv_field(s: &str) -> String {
    if s.contains([',', '"', '\n', '\r']) {
        format!("\"{}\"", s.replace('"', "\"\""))
    } else {
        s.to_string()
    }
}

/// A name for a file out of a label.
fn file_label(label: &str) -> String {
    let s: String = label.chars().map(|c| if c.is_alphanumeric() || c == '-' || c == '.' { c } else { '_' }).collect();
    let s = s.trim_matches('_').to_string();
    let cut: String = s.chars().take(60).collect();
    if cut.is_empty() { "rows".to_string() } else { cut }
}

/// Write these rows to `path` as a timeline of their own: the header and
/// each record exactly as the file has them when the rows come from files
/// with one header; else in the 19 columns every layout is read as.
/// Nothing is added: the copy has the columns of the timeline and no other.
pub(super) fn write_rows(store: &Store, rows: &[(u16, u32)], path: &std::path::Path) -> std::io::Result<usize> {
    use std::io::Write;
    let mut files: Vec<u16> = rows.iter().map(|r| r.0).collect();
    files.sort_unstable();
    files.dedup();
    let headers: Vec<String> = files.iter().map(|f| store.header_text(*f)).collect::<std::io::Result<Vec<String>>>()?;
    let bare = |h: &str| h.trim_start_matches('\u{feff}').to_string();
    let same = headers.windows(2).all(|w| bare(&w[0]) == bare(&w[1]));
    let mut out = std::io::BufWriter::new(std::fs::File::create(path)?);
    if same && !headers.is_empty() {
        writeln!(out, "{}", headers[0])?;
        let mut k = 0usize;
        while k < rows.len() {
            let f = rows[k].0;
            let mut j = k;
            while j < rows.len() && rows[j].0 == f {
                j += 1;
            }
            let lines: Vec<u32> = rows[k..j].iter().map(|r| r.1).collect();
            for text in store.raw_texts(f, &lines)? {
                writeln!(out, "{}", text)?;
            }
            k = j;
        }
    } else {
        writeln!(out, "{}", crate::csv_out::HEADER)?;
        for (f, l) in rows {
            let fields = store.raw_row(*f, *l)?;
            writeln!(out, "{}", fields.iter().map(|s| csv_field(s)).collect::<Vec<_>>().join(","))?;
        }
    }
    out.flush()?;
    Ok(rows.len())
}

impl Viewer {
    /// The programs a timeline opens in: found once, on first use.
    /// A copy of these rows (the timeline's own columns), opened in a
    /// program of the list, or in the system's CSV application.
    pub(super) fn rows_in_program(&mut self, rows: &[(u16, u32)], label: &str, viewer: Option<usize>) {
        let path = match self.write_rows_copy(rows, label) {
            Ok(p) => p,
            Err(e) => {
                self.status = format!("Cannot write the copy of the rows: {}", e);
                return;
            }
        };
        let apps = self.viewer_list();
        let (name, r) = match viewer.and_then(|i| apps.get(i)) {
            Some(a) => (a.name.clone(), viewers::launch(a, &path, None)),
            None => ("the system's application".to_string(), super::ingest::open_external(&path)),
        };
        self.status = match r {
            Ok(()) => format!("Opened {} row(s) of {} in {} ({})", rows.len(), label, name, path),
            Err(e) => format!("Cannot open {} in {}: {}", path, name, e),
        };
    }

    pub(super) fn viewer_list(&mut self) -> Vec<ViewerApp> {
        if self.viewer_apps.is_none() {
            self.viewer_apps = Some(viewers::all());
        }
        self.viewer_apps.clone().unwrap_or_default()
    }

    /// The rows shown (file, row): every row of the open files, or the
    /// rows the table is narrowed to, that hold the find box; cached.
    fn table_raw_rows(&mut self) -> &[(u16, u32)] {
        let key = (self.table_find.trim().to_lowercase(), self.store.files.len(), self.store.rows_total, self.table_scope_gen);
        if self.table_raw_key != key {
            let mut out = Vec::new();
            let filters = self.table_filters.clone();
            let plain = key.0.is_empty() && filters.is_empty();
            match &self.table_scope {
                Some(sc) if plain => out = sc.rows.clone(),
                Some(sc) => {
                    let mut k = 0usize;
                    while k < sc.rows.len() {
                        let f = sc.rows[k].0;
                        let mut j = k;
                        while j < sc.rows.len() && sc.rows[j].0 == f {
                            j += 1;
                        }
                        let lines: Vec<u32> = sc.rows[k..j].iter().map(|r| r.1).collect();
                        match self.store.raw_texts(f, &lines) {
                            Ok(texts) => out.extend(lines.iter().zip(texts).filter(|(_, t)| row_passes(t, &key.0, &filters)).map(|(l, _)| (f, *l))),
                            Err(e) => self.status = format!("Cannot read {}: {}", self.store.files[f as usize].path, e),
                        }
                        k = j;
                    }
                }
                None => {
                    for f in 0..self.store.files.len() as u16 {
                        if plain {
                            out.extend((0..self.store.file_rows(f) as u32).map(|l| (f, l)));
                        } else {
                            match self.store.file_rows_where(f, &|t| row_passes(t, &key.0, &filters)) {
                                Ok(v) => out.extend(v.into_iter().map(|l| (f, l))),
                                Err(e) => self.status = format!("Cannot read {}: {}", self.store.files[f as usize].path, e),
                            }
                        }
                    }
                }
            }
            self.table_raw_rows = out;
            self.table_raw_cache.clear();
            self.table_raw_key = key;
        }
        &self.table_raw_rows
    }

    /// One more filter on the timeline (the same one twice is once).
    pub(super) fn add_table_filter(&mut self, f: RowFilter) {
        if !self.table_filters.contains(&f) {
            self.table_filters.push(f);
            self.table_scope_gen += 1;
            self.table_sel = None;
            self.table_multi.clear();
        }
    }

    /// Timeline mode on these rows only.
    pub(super) fn show_rows_in_timeline(&mut self, label: String, mut rows: Vec<(u16, u32)>) {
        rows.sort_unstable();
        rows.dedup();
        self.status = format!("Timeline: {} row(s) of {}", rows.len(), label);
        self.table_scope = Some(TableScope { label, rows });
        self.table_scope_gen += 1;
        self.table_find.clear();
        self.table_sel = None;
        self.table_multi.clear();
        self.show_table = true;
    }

    pub(super) fn rows_of_graph_edge(&self, k: usize) -> Vec<(u16, u32)> {
        self.graph.edges[k].rows.iter().map(|&ei| (self.store.edges[ei as usize].file, self.store.edges[ei as usize].line)).collect()
    }

    pub(super) fn graph_edge_label(&self, k: usize) -> String {
        let e = &self.graph.edges[k];
        let who = match e.user {
            Some(u) => format!(" as {}", self.store.users.name(u)),
            None => String::new(),
        };
        format!("{} -> {}{}", self.store.hosts.name(e.src), self.store.hosts.name(e.dst), who)
    }

    /// The rows of a connection of the graph, in the timeline.
    pub(super) fn timeline_of_edge(&mut self, k: usize) {
        if k >= self.graph.edges.len() {
            return;
        }
        let (label, rows) = (self.graph_edge_label(k), self.rows_of_graph_edge(k));
        self.show_rows_in_timeline(label, rows);
    }

    /// The rows of every connection of a host that the graph shows, in the
    /// timeline.
    pub(super) fn timeline_of_node(&mut self, i: usize) {
        let Some(n) = self.graph.nodes.get(i) else { return };
        let host = n.host;
        let rows: Vec<(u16, u32)> = (0..self.graph.edges.len()).filter(|&k| self.graph.edges[k].src == host || self.graph.edges[k].dst == host).flat_map(|k| self.rows_of_graph_edge(k)).collect();
        let label = self.store.hosts.name(host).to_string();
        self.show_rows_in_timeline(label, rows);
    }

    /// The connection of the graph a row belongs to, if the graph shows it.
    fn graph_edge_of_row(&self, row: (u16, u32)) -> Result<usize, &'static str> {
        let ei = self.store.edge_at(row.0, row.1).ok_or("this row has no origin: the graph does not draw it")? as u32;
        self.graph.edges.iter().position(|g| g.rows.contains(&ei)).ok_or("the connection of this row is not in the graph as it is filtered now (try Everything, or clear the filters)")
    }

    /// A row picked in the timeline: its connection in the inspector, when
    /// the graph has it.
    pub(super) fn pick_row(&mut self, row: (u16, u32)) {
        self.table_sel = Some(row);
        if let Ok(k) = self.graph_edge_of_row(row) {
            self.selected = Some(Sel::Edge(k));
            self.tab = Tab::Selection;
            self.load_rows(k);
        }
    }

    /// Exactly these rows in the graph: one edge per row (ungrouped), the
    /// hosts they name and nothing else, whatever the filters say. Rows
    /// without an origin have no edge to draw.
    pub(super) fn rows_to_graph_view(&mut self, rows: &[(u16, u32)]) {
        let mut edges: Vec<u32> = rows.iter().filter_map(|r| self.store.edge_at(r.0, r.1)).map(|e| e as u32).collect();
        edges.sort_unstable();
        edges.dedup();
        let asked = rows.len();
        if edges.is_empty() {
            self.status = format!("Of the {} row(s) selected none names an origin other than its destination: the graph has nothing to draw of them", asked);
            return;
        }
        let n = edges.len();
        self.overlay = Some(Overlay { title: format!("{} row(s) selected in the timeline", n), edges, labels: HashMap::new(), hops: HashMap::new(), exact: true });
        self.selected = None;
        self.show_table = false;
        self.fit_pending = true;
        self.requery(true);
        let left = if asked > n { format!(" ({} of the {} selected have no origin and are not drawn)", asked - n, asked) } else { String::new() };
        self.status = format!("Graph: exactly the {} row(s) selected, one edge per row{}", n, left);
    }

    /// Exactly the events these conditions name (`--event`), in the graph:
    /// the events of any of them, one edge each.
    pub(super) fn events_to_graph_view(&mut self, conds: &[String]) {
        let mut parsed: Vec<EventCond> = Vec::new();
        for c in conds {
            match parse_event(c) {
                Ok(p) => parsed.push(p),
                Err(e) => {
                    self.status = e;
                    return;
                }
            }
        }
        let mut hit = vec![0usize; parsed.len()];
        let mut edges: Vec<u32> = Vec::new();
        for (ei, e) in self.store.edges.iter().enumerate() {
            let mut any = false;
            for (k, c) in parsed.iter().enumerate() {
                if c.t.is_some_and(|t| t != e.t) {
                    continue;
                }
                // the account asked for, by its name (the row's domain is not asked
                // about unless the name carries one: `alice@DEV`)
                if !c.user.is_empty() {
                    let have = self.store.users.name(e.user);
                    let asked = crate::graph_hunt_common::account::account_shown(&c.user, "", "");
                    let same = if asked.contains('@') { have.eq_ignore_ascii_case(&asked) } else { have.split('@').next().unwrap_or(have).eq_ignore_ascii_case(&asked) };
                    if !same {
                        continue;
                    }
                }
                if !c.origin.is_empty() && !host_answers(&self.store.aliases[e.src as usize], &c.origin) {
                    continue;
                }
                if !c.destination.is_empty() && !host_answers(&self.store.aliases[e.dst as usize], &c.destination) {
                    continue;
                }
                // the instant itself, when it was given: read off the row
                if !c.fraction.is_empty() {
                    let raw = self.store.raw_row(e.file, e.line).ok().and_then(|r| r.into_iter().next()).unwrap_or_default();
                    let got: String = raw.get(19..).and_then(|r| r.strip_prefix('.')).map(|r| r.chars().take_while(|ch| ch.is_ascii_digit()).collect::<String>()).unwrap_or_default();
                    if got.trim_end_matches('0') != c.fraction {
                        continue;
                    }
                }
                hit[k] += 1;
                any = true;
            }
            if any {
                edges.push(ei as u32);
            }
        }
        let unanswered = hit.iter().filter(|h| **h == 0).count();
        if edges.is_empty() {
            self.status = format!("None of the {} event(s) asked for is in the graph of this timeline: no row with an origin answers (the time is UTC; an event from a host to itself has no edge)", parsed.len());
            return;
        }
        let n = edges.len();
        self.overlay = Some(Overlay { title: format!("{} event(s) asked for", n), edges, labels: HashMap::new(), hops: HashMap::new(), exact: true });
        self.selected = None;
        self.show_table = false;
        self.fit_pending = true;
        self.requery(true);
        let left = if unanswered > 0 { format!(" ({} of the {} asked for have no event with an origin here)", unanswered, parsed.len()) } else { String::new() };
        self.status = format!("Graph: exactly the {} event(s) that answer to the {} asked for, one edge per event{}", n, parsed.len(), left);
    }

    /// From a row to its connection in the graph. A connection the graph
    /// does not show as it is filtered now is brought in with the
    /// neighbourhood of its origin.
    pub(super) fn row_to_graph(&mut self, row: (u16, u32)) {
        self.table_sel = Some(row);
        let mut found = self.graph_edge_of_row(row);
        let mut widened = false;
        if found.is_err() {
            if let Some(ei) = self.store.edge_at(row.0, row.1) {
                let origin = self.store.hosts.name(self.store.edges[ei].src).to_string();
                self.draft.view = View::Around;
                self.draft.around = origin;
                self.requery(false);
                found = self.graph_edge_of_row(row);
                widened = found.is_ok();
            }
        }
        match found {
            Ok(k) if widened => {
                self.selected = Some(Sel::Edge(k));
                self.tab = Tab::Selection;
                self.show_inspector = true;
                self.load_rows(k);
                self.show_table = false;
                self.status = format!("Graph: {} (the view was not showing it: now the neighbourhood of its origin)", self.graph_edge_label(k));
            }
            Ok(k) => {
                self.selected = Some(Sel::Edge(k));
                self.tab = Tab::Selection;
                self.show_inspector = true;
                self.load_rows(k);
                self.show_table = false;
                self.status = format!("Graph: {}", self.graph_edge_label(k));
            }
            // still not drawn (its kind of event is filtered out): the
            // graph on its origin, which is where the row happens
            Err(_) if self.store.edge_at(row.0, row.1).is_some() => {
                let ei = self.store.edge_at(row.0, row.1).unwrap();
                let src = self.store.edges[ei].src;
                if let Some(i) = self.graph.nodes.iter().position(|n| n.host == src) {
                    self.selected = Some(Sel::Node(i));
                    self.tab = Tab::Selection;
                    self.show_inspector = true;
                }
                self.show_table = false;
                self.status = format!("Line {}: the filters hide this row; the graph shows the neighbourhood of its origin, {}", row.1 + 2, self.store.hosts.name(src));
            }
            Err(why) => self.status = format!("Line {}: {}", row.1 + 2, why),
        }
    }

    /// Open what the timeline shows in a program: the rows on screen as a
    /// copy when the table is narrowed, else (or when asked) the file.
    pub(super) fn open_rows_in(&mut self, viewer: Option<usize>, whole: bool) {
        let narrowed = self.table_scope.is_some() || !self.table_find.trim().is_empty() || !self.table_filters.is_empty();
        let (path, line) = if whole || !narrowed {
            let f = self.table_sel.map(|s| s.0).unwrap_or(0);
            let Some(info) = self.store.files.get(f as usize) else { return };
            // line 1 of the file is the header
            (info.path.clone(), self.table_sel.filter(|s| s.0 == f).map(|s| s.1 + 2))
        } else {
            let rows: Vec<(u16, u32)> = self.table_raw_rows().to_vec();
            let label = match (&self.table_scope, self.table_find.trim()) {
                (Some(sc), "") => sc.label.clone(),
                (Some(sc), f) => format!("{} {}", sc.label, f),
                (None, f) => f.to_string(),
            };
            match self.write_rows_copy(&rows, &label) {
                Ok(p) => (p, None),
                Err(e) => {
                    self.status = format!("Cannot write the copy of the rows: {}", e);
                    return;
                }
            }
        };
        let apps = self.viewer_list();
        let (name, r) = match viewer.and_then(|i| apps.get(i)) {
            Some(a) => (a.name.clone(), viewers::launch(a, &path, line)),
            None => ("the system's application".to_string(), super::ingest::open_external(&path)),
        };
        self.status = match r {
            Ok(()) => format!("Opened {} in {}", path, name),
            Err(e) => format!("Cannot open {} in {}: {}", path, name, e),
        };
    }

    /// The copy of these rows, next to nothing of the case: in the
    /// system's temporary folder, named after the timeline and the rows.
    pub(super) fn write_rows_copy(&mut self, rows: &[(u16, u32)], label: &str) -> std::io::Result<String> {
        let dir = std::env::temp_dir().join(format!("masstin_view_{}", std::process::id()));
        std::fs::create_dir_all(&dir)?;
        let stem = self.store.files.first().and_then(|f| std::path::Path::new(&f.path).file_stem().map(|s| s.to_string_lossy().to_string())).unwrap_or_else(|| "timeline".to_string());
        let path = dir.join(format!("{}.{}.csv", stem, file_label(label)));
        write_rows(&self.store, rows, &path)?;
        Ok(path.to_string_lossy().to_string())
    }

    /// Timeline mode: the whole centre of the window.
    pub(super) fn timeline_view(&mut self, ui: &mut egui::Ui) {
        if self.store.files.is_empty() {
            ui.centered_and_justified(|ui| {
                ui.label(egui::RichText::new("No timeline open: Evidence > Open timeline…, or drop a CSV on the window").color(theme::MUTED));
            });
            return;
        }
        let ctx = ui.ctx().clone();
        let shown = self.table_raw_rows().len();
        let total = self.store.rows_total;
        let narrowed = self.table_scope.is_some() || !self.table_find.trim().is_empty() || !self.table_filters.is_empty();
        let apps = self.viewer_list();
        let mut clear_scope = false;
        let mut new_filter: Option<RowFilter> = None;
        let mut drop_filter: Option<usize> = None;
        let mut clear_filters = false;
        let mut open_req: Option<(Option<usize>, bool)> = None;
        let mut add_program = false;
        let mut to_agent = false;
        let mut forget: Option<String> = None;
        let mut reveal = false;
        egui::Frame::new().inner_margin(egui::Margin::symmetric(12, 8)).show(ui, |ui| {
            ui.horizontal(|ui| {
                ui.spacing_mut().item_spacing.x = 8.0;
                if let Some(sc) = &self.table_scope {
                    let chip = egui::Button::new(egui::RichText::new(format!("{}  {}   {}", ic::FUNNEL, sc.label, ic::X)).color(theme::ACCENT_INK)).fill(theme::ACCENT).corner_radius(CornerRadius::same(8)).min_size(Vec2::new(0.0, 26.0));
                    if ui.add(chip).on_hover_text("The timeline shows the rows of this only. Click to go back to every row").clicked() {
                        clear_scope = true;
                    }
                }
                ui.add(egui::TextEdit::singleline(&mut self.table_find).desired_width(240.0).hint_text(format!("{}  find in the rows", ic::MAGNIFYING_GLASS)));
                // what is typed can be kept as a filter that adds up, or turned round
                let typed = !self.table_find.trim().is_empty();
                if ui.add_enabled(typed, egui::Button::new(egui::RichText::new("+ keep").color(theme::ACCENT)).min_size(Vec2::new(0.0, 24.0))).on_hover_text("Keep it as a filter: only the rows that hold this text, in any column. It adds to the filters there, and the box is free for another").clicked() {
                    new_filter = Some(RowFilter::new(None, &self.table_find, false));
                }
                if ui.add_enabled(typed, egui::Button::new(egui::RichText::new("− exclude").color(EDGE_FAIL)).min_size(Vec2::new(0.0, 24.0))).on_hover_text("Leave out the rows that hold this text, in any column. It adds to the filters there").clicked() {
                    new_filter = Some(RowFilter::new(None, &self.table_find, true));
                }
                let label = if narrowed { format!("{} of {} rows", shown, total) } else { format!("{} rows, all of the file(s)", shown) };
                ui.label(egui::RichText::new(label).color(theme::MUTED).size(12.5));
                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    ui.spacing_mut().item_spacing.x = 6.0;
                    if ui.add(egui::Button::new(egui::RichText::new(ic::FOLDER_OPEN).size(14.0)).min_size(Vec2::new(30.0, 26.0))).on_hover_text("Show the timeline's file in its folder").clicked() {
                        reveal = true;
                    }
                    // the columns shown, and their widths as they came
                    let n_hidden = self.table_look.hidden.iter().filter(|h| **h).count();
                    ui.menu_button(if n_hidden > 0 { format!("{}  Columns ({} hidden)", ic::TABLE, n_hidden) } else { format!("{}  Columns", ic::TABLE) }, |ui| {
                        ui.set_min_width(230.0);
                        ui.label(egui::RichText::new("The columns of the file to show. Nothing changes in the file").color(theme::MUTED).small());
                        for (ci, name) in raw_columns().iter().enumerate() {
                            let mut on = !self.table_look.hidden[ci];
                            if ui.checkbox(&mut on, *name).changed() {
                                // the last one shown stays
                                if on || self.table_look.hidden.iter().filter(|h| !**h).count() > 1 {
                                    self.table_look.hidden[ci] = !on;
                                    self.table_look_dirty = true;
                                }
                            }
                        }
                        ui.separator();
                        if ui.button("Show every column").clicked() {
                            self.table_look.hidden = [false; 19];
                            self.table_look_dirty = true;
                        }
                        if ui.button("Widths as they came").clicked() {
                            self.table_look.widths = RAW_WIDTHS;
                            self.table_look_dirty = true;
                        }
                    });
                    // the size of the text
                    if ui.add(egui::Button::new("A+").min_size(Vec2::new(30.0, 26.0))).on_hover_text("Larger text").clicked() {
                        self.table_look.set_font(self.table_look.font + 1.0);
                        self.table_look_dirty = true;
                    }
                    ui.label(egui::RichText::new(format!("{} pt", self.table_look.font)).color(theme::MUTED).size(12.0)).on_hover_text("The size of the timeline's text");
                    if ui.add(egui::Button::new("A-").min_size(Vec2::new(30.0, 26.0))).on_hover_text("Smaller text").clicked() {
                        self.table_look.set_font(self.table_look.font - 1.0);
                        self.table_look_dirty = true;
                    }
                    ui.menu_button(format!("{}  Open in…", ic::APP_WINDOW), |ui| {
                        ui.set_min_width(300.0);
                        if narrowed {
                            ui.label(egui::RichText::new(format!("The {} row(s) shown, as a copy with the timeline's own columns", shown)).color(theme::MUTED).small());
                            ui.checkbox(&mut self.table_open_whole, "The whole file instead").on_hover_text("Open the timeline itself, not a copy of the rows shown. A program that can go to a line (Visual Studio Code, Notepad++) opens it at the selected row");
                            ui.separator();
                        }
                        let whole = self.table_open_whole || !narrowed;
                        if icon_button(ui, ic::APP_WINDOW, "The system's CSV application").clicked() {
                            ui.close();
                            open_req = Some((None, whole));
                        }
                        for (i, a) in apps.iter().enumerate() {
                            ui.horizontal(|ui| {
                                if icon_button(ui, ic::APP_WINDOW, &a.name).on_hover_text(a.args.last().unwrap_or(&a.program)).clicked() {
                                    ui.close();
                                    open_req = Some((Some(i), whole));
                                }
                                if a.custom && ui.small_button(ic::X).on_hover_text("Take this program off the list").clicked() {
                                    forget = Some(a.args.last().cloned().unwrap_or_else(|| a.program.clone()));
                                }
                            });
                        }
                        ui.separator();
                        if icon_button(ui, ic::APP_WINDOW, "agentc00pr: into a case…").on_hover_text("The case workbench of the family. The timelines open here go into a case of agentc00pr, with the evidence they were read from").clicked() {
                            ui.close();
                            to_agent = true;
                        }
                        if icon_button(ui, ic::PLUS, "Add a program…").on_hover_text("Any program that opens a CSV: it stays on this list").clicked() {
                            ui.close();
                            add_program = true;
                        }
                    });
                });
            });
        });
        // the filters that add up, each a chip that takes it off
        if !self.table_filters.is_empty() {
            egui::Frame::new().inner_margin(egui::Margin { left: 12, right: 12, top: 0, bottom: 8 }).show(ui, |ui| {
                ui.horizontal_wrapped(|ui| {
                    ui.spacing_mut().item_spacing = Vec2::new(6.0, 4.0);
                    ui.label(egui::RichText::new(format!("{}  filters", ic::FUNNEL)).color(theme::MUTED).size(12.0));
                    for (i, f) in self.table_filters.iter().enumerate() {
                        let color = if f.negate { EDGE_FAIL } else { theme::ACCENT };
                        let chip = egui::Button::new(egui::RichText::new(format!("{}   {}", f.label(), ic::X)).color(color).size(12.0)).fill(draw::fade(color, 0.14)).stroke(Stroke::new(1.0, draw::fade(color, 0.5))).corner_radius(CornerRadius::same(8));
                        if ui.add(chip).on_hover_text(if f.negate { "Rows that hold this are left out. Click to take the filter off" } else { "Only rows that hold this are shown. Click to take the filter off" }).clicked() {
                            drop_filter = Some(i);
                        }
                    }
                    if ui.add(egui::Button::new(egui::RichText::new("clear all").color(theme::MUTED).size(12.0)).frame(false)).clicked() {
                        clear_filters = true;
                    }
                });
            });
        }
        theme::hairline(ui);
        let (act, from_rows) = self.timeline_rows(ui);
        // the look is kept once it is settled (not at every step of a drag)
        if self.table_look_dirty && !ui.input(|i| i.pointer.any_down()) {
            self.table_look.save();
            self.table_look_dirty = false;
        }
        if from_rows.is_some() {
            new_filter = from_rows;
        }
        if let Some(f) = new_filter {
            if f.col.is_none() {
                self.table_find.clear();
            }
            self.add_table_filter(f);
        }
        if let Some(i) = drop_filter {
            self.table_filters.remove(i);
            self.table_scope_gen += 1;
        }
        if clear_filters {
            self.table_filters.clear();
            self.table_scope_gen += 1;
        }

        if clear_scope {
            self.table_scope = None;
            self.table_scope_gen += 1;
            self.table_sel = None;
            self.table_multi.clear();
        }
        match act {
            Some(RowAct::Select(row)) => {
                self.table_multi.clear();
                self.pick_row(row)
            }
            Some(RowAct::Toggle(row)) => {
                // the row picked before is the first of the selection
                if self.table_multi.is_empty() {
                    if let Some(prev) = self.table_sel {
                        self.table_multi.insert(prev);
                    }
                }
                if !self.table_multi.remove(&row) {
                    self.table_multi.insert(row);
                }
                self.table_sel = Some(row);
                self.status = format!("Timeline: {} row(s) selected (right-click: show exactly them in the graph)", self.table_multi.len());
            }
            Some(RowAct::Range(row)) => {
                let shown: Vec<(u16, u32)> = self.table_raw_rows().to_vec();
                let anchor = self.table_sel.unwrap_or(row);
                if let (Some(a), Some(b)) = (shown.iter().position(|r| *r == anchor), shown.iter().position(|r| *r == row)) {
                    self.table_multi.extend(shown[a.min(b)..=a.max(b)].iter().copied());
                }
                self.status = format!("Timeline: {} row(s) selected (right-click: show exactly them in the graph)", self.table_multi.len());
            }
            Some(RowAct::Exact(row)) => {
                let rows: Vec<(u16, u32)> = if self.table_multi.contains(&row) { self.table_multi.iter().copied().collect() } else { vec![row] };
                self.rows_to_graph_view(&rows);
            }
            Some(RowAct::Agent(row)) => {
                let rows: Vec<(u16, u32)> = if self.table_multi.contains(&row) { self.table_multi.iter().copied().collect() } else { vec![row] };
                let what = if rows.len() > 1 { format!("the {} rows picked", rows.len()) } else { format!("line {}", row.1 + 2) };
                self.rows_to_agentc00pr(&rows, &what);
            }
            Some(RowAct::Graph(row)) => self.row_to_graph(row),
            Some(RowAct::Copy(row)) => match self.store.raw_texts(row.0, &[row.1]) {
                Ok(t) => {
                    ctx.copy_text(t.into_iter().next().unwrap_or_default());
                    self.status = format!("Line {} copied", row.1 + 2);
                }
                Err(e) => self.status = format!("Cannot read the row: {}", e),
            },
            Some(RowAct::Connection(row)) => match self.graph_edge_of_row(row) {
                Ok(k) => self.timeline_of_edge(k),
                Err(why) => self.status = format!("Line {}: {}", row.1 + 2, why),
            },
            None => {}
        }
        if let Some((viewer, whole)) = open_req {
            self.open_rows_in(viewer, whole);
        }
        if to_agent {
            self.open_agentc00pr();
        }
        if add_program {
            if let Some(p) = rfd::FileDialog::new().set_title("A program to open timelines with").pick_file() {
                let p = p.to_string_lossy().to_string();
                let mut list = viewers::load_custom();
                if !list.contains(&p) {
                    list.push(p);
                }
                match viewers::save_custom(&list) {
                    Ok(()) => self.viewer_apps = None,
                    Err(e) => self.status = format!("Cannot keep the program: {}", e),
                }
            }
        }
        if let Some(p) = forget {
            let list: Vec<String> = viewers::load_custom().into_iter().filter(|x| x != &p).collect();
            if viewers::save_custom(&list).is_ok() {
                self.viewer_apps = None;
            }
        }
        if reveal {
            let f = self.table_sel.map(|s| s.0 as usize).unwrap_or(0);
            if let Some(info) = self.store.files.get(f) {
                if let Err(e) = super::ingest::reveal_in_folder(&info.path) {
                    self.status = format!("Cannot show {}: {}", info.path, e);
                }
            }
        }
    }

    /// The rows, in the file's 19 columns, read from the file as they
    /// scroll into view. The margin on the left is the row's line in its
    /// file (1 is the header), the number an editor shows.
    fn timeline_rows(&mut self, ui: &mut egui::Ui) -> (Option<RowAct>, Option<RowFilter>) {
        let look = self.table_look.clone();
        let row_h = look.row_height();
        let cols = raw_columns();
        let shown = look.shown();
        let width: f32 = GUTTER + COL_GAP + shown.iter().map(|c| look.widths[*c] + COL_GAP).sum::<f32>();
        let mut resize: Option<(usize, f32)> = None;
        let mut hide: Option<usize> = None;
        let rows: Vec<(u16, u32)> = self.table_raw_rows().to_vec();
        if self.table_raw_cache.len() > 4000 {
            self.table_raw_cache.clear();
        }
        let several = self.store.files.len() > 1;
        let mut act: Option<RowAct> = None;
        let mut filter: Option<RowFilter> = None;
        egui::ScrollArea::both().id_salt("table-raw").auto_shrink([false, false]).show(ui, |ui| {
            ui.set_min_width(width);
            ui.horizontal(|ui| {
                ui.spacing_mut().item_spacing.x = 0.0;
                ui.add_sized([GUTTER, row_h], egui::Label::new(egui::RichText::new("line").size(look.font - 1.5).color(theme::DIM))).on_hover_text("The row's line in its file (1 is the header). It is not a column of the timeline");
                ui.add_space(COL_GAP);
                // A column's name: a right click (or a click) opens what can be
                // done with the column: filter by a text it contains or does
                // not, hide it. The gap after it drags its width.
                for &ci in &shown {
                    let (name, w) = (cols[ci], look.widths[ci]);
                    let on = self.table_filters.iter().any(|f| f.col == Some(ci));
                    let head = egui::Button::new(egui::RichText::new(name).size(look.font - 1.5).monospace().color(if on { theme::ACCENT } else { theme::MUTED })).frame(false).truncate().min_size(Vec2::new(w, row_h));
                    let resp = ui.add_sized([w, row_h], head).on_hover_text(format!("{}: right click (or click) to filter by a text it contains or does not, or to hide the column. Drag its right edge for its width", name));
                    let mut menu = |ui: &mut egui::Ui| {
                        ui.set_min_width(260.0);
                        if self.table_filter_draft.0 != ci {
                            self.table_filter_draft = (ci, String::new());
                        }
                        ui.label(theme::semibold(name, 12.5).color(TEXT));
                        ui.label(egui::RichText::new("the rows whose column…").color(theme::MUTED).small());
                        let edit = ui.add(egui::TextEdit::singleline(&mut self.table_filter_draft.1).desired_width(240.0).hint_text("text, in any case (empty: the column is empty)"));
                        let enter = edit.lost_focus() && ui.input(|i| i.key_pressed(egui::Key::Enter));
                        ui.horizontal(|ui| {
                            if ui.button(egui::RichText::new("+ contains").color(theme::ACCENT)).on_hover_text("Include: only the rows whose column contains the text (Enter does this). It adds to the filters there").clicked() || enter {
                                filter = Some(RowFilter::new(Some(ci), &self.table_filter_draft.1, false));
                                self.table_filter_draft.1.clear();
                                ui.close();
                            }
                            if ui.button(egui::RichText::new("− does not contain").color(EDGE_FAIL)).on_hover_text("Exclude: leave out the rows whose column contains the text. It adds to the filters there").clicked() {
                                filter = Some(RowFilter::new(Some(ci), &self.table_filter_draft.1, true));
                                self.table_filter_draft.1.clear();
                                ui.close();
                            }
                        });
                        ui.separator();
                        if icon_button(ui, ic::EYE_SLASH, "Hide this column").on_hover_text("Columns, on the bar above, brings it back").clicked() {
                            hide = Some(ci);
                            ui.close();
                        }
                        if icon_button(ui, ic::CORNERS_OUT, "Its width as it came").clicked() {
                            resize = Some((ci, RAW_WIDTHS[ci]));
                            ui.close();
                        }
                    };
                    // one menu, opened by either button of the mouse
                    let open = (resp.clicked() || resp.secondary_clicked()).then_some(egui::SetOpenCommand::Toggle);
                    egui::Popup::menu(&resp).open_memory(open).show(&mut menu);
                    // the handle of its width
                    let (grip, grip_resp) = ui.allocate_exact_size(Vec2::new(COL_GAP, row_h), Sense::drag());
                    let hot = grip_resp.hovered() || grip_resp.dragged();
                    if hot {
                        ui.ctx().set_cursor_icon(egui::CursorIcon::ResizeHorizontal);
                    }
                    ui.painter().vline(grip.center().x, grip.y_range().shrink(3.0), Stroke::new(if hot { 2.0 } else { 1.0 }, if hot { theme::ACCENT } else { theme::BORDER }));
                    if grip_resp.dragged() {
                        resize = Some((ci, w + grip_resp.drag_delta().x));
                    }
                }
            });
            theme::hairline(ui);
            egui::ScrollArea::vertical().id_salt("table-raw-rows").auto_shrink([false, false]).show_rows(ui, row_h, rows.len(), |ui, range| {
                ui.spacing_mut().item_spacing.y = 0.0;
                for i in range {
                    let key = rows[i];
                    if !self.table_raw_cache.contains_key(&key) {
                        let fields = self.store.raw_row(key.0, key.1).unwrap_or_else(|e| vec![format!("cannot read the row: {}", e)]);
                        self.table_raw_cache.insert(key, fields);
                    }
                    let fields = &self.table_raw_cache[&key];
                    let r = ui.horizontal(|ui| {
                        ui.spacing_mut().item_spacing.x = COL_GAP;
                        let num = if several { format!("{}:{}", key.0 + 1, key.1 + 2) } else { (key.1 + 2).to_string() };
                        ui.add_sized([GUTTER, row_h], egui::Label::new(egui::RichText::new(num).size(look.font - 1.0).monospace().color(theme::DIM)).selectable(false));
                        for &k in &shown {
                            let w = &look.widths[k];
                            let text = fields.get(k).map(|s| s.as_str()).unwrap_or("");
                            let color = match k {
                                0 | 3 | 4 | 11 => theme::MUTED,
                                13 | 16 => theme::DIM,
                                14 => match text {
                                    "significant" => SIGNIFICANT,
                                    "candidate" => CANDIDATE,
                                    _ => theme::MUTED,
                                },
                                2 if text == "FAILED_LOGON" => EDGE_FAIL,
                                _ => TEXT,
                            };
                            ui.add_sized([*w, row_h], egui::Label::new(egui::RichText::new(text).size(look.font).color(color)).truncate().selectable(false));
                        }
                    });
                    let rect = r.response.rect.expand2(Vec2::new(4.0, 0.0));
                    let resp = ui.interact(rect, ui.scope_id().with(("timeline-row", key.0, key.1)), Sense::click());
                    let picked = self.table_sel == Some(key) || self.table_multi.contains(&key);
                    if picked {
                        ui.painter().rect_filled(rect, CornerRadius::ZERO, Color32::from_rgba_unmultiplied(theme::ACCENT.r(), theme::ACCENT.g(), theme::ACCENT.b(), 46));
                    } else if resp.hovered() {
                        ui.painter().rect_filled(rect, CornerRadius::ZERO, Color32::from_rgba_unmultiplied(255, 255, 255, 12));
                    } else if i % 2 == 1 {
                        ui.painter().rect_filled(rect, CornerRadius::ZERO, Color32::from_rgba_unmultiplied(255, 255, 255, 4));
                    }
                    if resp.clicked() {
                        let mods = ui.input(|i| i.modifiers);
                        act = Some(if mods.command { RowAct::Toggle(key) } else if mods.shift { RowAct::Range(key) } else { RowAct::Select(key) });
                    } else if resp.secondary_clicked() && !self.table_multi.contains(&key) {
                        // a right click on a row outside the selection is about that row
                        act = Some(RowAct::Select(key));
                    }
                    if resp.secondary_clicked() {
                        // the cell under the click: its column by where the pointer is
                        self.table_ctx_cell = resp.interact_pointer_pos().and_then(|p| look.column_at(p.x - (r.response.rect.left() + GUTTER + COL_GAP))).map(|ci| (ci, fields.get(ci).cloned().unwrap_or_default()));
                    }
                    resp.context_menu(|ui| {
                        ui.set_min_width(250.0);
                        ui.label(egui::RichText::new(format!("line {}", key.1 + 2)).color(theme::MUTED).small());
                        // the cell clicked: keep only its value, or leave it out
                        if let Some((ci, value)) = self.table_ctx_cell.clone() {
                            let name = cols.get(ci).copied().unwrap_or("");
                            let v = value.trim();
                            let short: String = v.chars().take(40).collect();
                            let shown = if v.is_empty() { "(empty)".to_string() } else if v.chars().count() > 40 { format!("{}…", short) } else { short };
                            if ui.add(egui::Button::new(egui::RichText::new(format!("+  Keep only {} = {}", name, shown)).color(theme::ACCENT)).frame(false)).on_hover_text("Only the rows whose column holds this (contains). It adds to the filters there").clicked() {
                                ui.close();
                                filter = Some(RowFilter::new(Some(ci), v, false));
                            }
                            if ui.add(egui::Button::new(egui::RichText::new(format!("−  Exclude {} = {}", name, shown)).color(EDGE_FAIL)).frame(false)).on_hover_text("Leave out the rows whose column holds this. It adds to the filters there").clicked() {
                                ui.close();
                                filter = Some(RowFilter::new(Some(ci), v, true));
                            }
                            ui.separator();
                        }
                        if icon_button(ui, ic::GRAPH, "Show its connection in the graph").on_hover_text("Graph mode, with the connection of this row selected").clicked() {
                            ui.close();
                            act = Some(RowAct::Graph(key));
                        }
                        let n_sel = if self.table_multi.contains(&key) { self.table_multi.len() } else { 1 };
                        let label = if n_sel > 1 { format!("Show exactly these {} rows in the graph", n_sel) } else { "Show exactly this row in the graph".to_string() };
                        if icon_button(ui, ic::CROSSHAIR, &label).on_hover_text("A graph of the selection alone: one edge per row, ungrouped, and only the hosts they name. Ctrl + click and Shift + click pick several rows").clicked() {
                            ui.close();
                            act = Some(RowAct::Exact(key));
                        }
                        let label = if n_sel > 1 { format!("Show these {} rows in agentc00pr", n_sel) } else { "Show this row in agentc00pr".to_string() };
                        if icon_button(ui, ic::APP_WINDOW, &label).on_hover_text("agentc00pr's viewer on the case this timeline is in, showing only these rows: its filters, its notables, the other tools' rows of the same moment. A timeline that is in no case yet is taken to one first").clicked() {
                            ui.close();
                            act = Some(RowAct::Agent(key));
                        }
                        if icon_button(ui, ic::FUNNEL, "Only the rows of its connection").clicked() {
                            ui.close();
                            act = Some(RowAct::Connection(key));
                        }
                        ui.separator();
                        if icon_button(ui, ic::LINK, "Copy the row").on_hover_text("The row as the file has it").clicked() {
                            ui.close();
                            act = Some(RowAct::Copy(key));
                        }
                    });
                }
            });
        });
        if let Some((ci, w)) = resize {
            self.table_look.set_width(ci, w);
            self.table_look_dirty = true;
        }
        if let Some(ci) = hide {
            // the last column shown stays
            if self.table_look.hidden.iter().filter(|h| !**h).count() > 1 {
                self.table_look.hidden[ci] = true;
                self.table_look_dirty = true;
            }
        }
        (act, filter)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The look of the timeline: text size, widths and hidden columns, within
    /// bounds, and which column a click falls on.
    #[test]
    fn the_look_of_the_timeline_stays_usable() {
        let mut l = TableLook::default();
        assert_eq!((l.font, l.shown().len(), l.row_height()), (12.0, 19, 20.0));
        l.set_font(14.3);
        assert_eq!(l.font, 14.5);
        l.set_font(100.0);
        assert_eq!(l.font, TableLook::FONT.1);
        l.set_font(1.0);
        assert_eq!(l.font, TableLook::FONT.0);
        l.set_width(0, 5.0);
        assert_eq!(l.widths[0], TableLook::WIDTH.0);
        l.set_width(0, 300.0);
        l.set_width(99, 300.0);
        assert_eq!(l.widths[0], 300.0);
        // a click by where it falls: column 0 is 300 wide and the gap after it
        assert_eq!(l.column_at(0.0), Some(0));
        assert_eq!(l.column_at(307.0), Some(0));
        assert_eq!(l.column_at(308.0), Some(1));
        assert_eq!(l.column_at(-1.0), None);
        // hidden columns take no room
        l.hidden[0] = true;
        l.hidden[1] = true;
        assert_eq!(l.shown()[0], 2);
        assert_eq!(l.column_at(0.0), Some(2));
        assert_eq!(l.column_at(1.0e6), None);
        // by its name in the file
        assert_eq!((column_named("TARGET_USER_NAME"), column_named(" hunt_score "), column_named("line")), (Some(5), Some(15), None));
        // what was kept reads back; what does not read is the defaults
        let back: TableLook = serde_json::from_str(&serde_json::to_string(&l).unwrap()).unwrap();
        assert_eq!(back, l);
        assert_eq!(serde_json::from_str::<TableLook>("{\"font\": 15.0}").unwrap().widths, RAW_WIDTHS);
    }

    /// Filters of the timeline: contains by default, one way or the other,
    /// by a column or by any, and they add up.
    #[test]
    fn filters_add_up_and_go_both_ways() {
        let row = "2026-11-03T08:00:00+00:00,SRV01.corp.test,SUCCESSFUL_LOGON,4624,3,Alice,CORP,WS01,10.0.0.5,,,0x1,,Security.evtx,significant,42,new,,";
        let f = |s: &str| RowFilter::parse(s).unwrap();
        // the sign, the column by its name in the file, any case
        assert_eq!(f("+target_user_name:ALI"), RowFilter { col: Some(5), text: "ali".into(), negate: false });
        assert_eq!(f("-event_type:logoff"), RowFilter { col: Some(2), text: "logoff".into(), negate: true });
        assert_eq!(f("10.0.0.5"), RowFilter { col: None, text: "10.0.0.5".into(), negate: false });
        assert_eq!(f("-nosuchcolumn:x"), RowFilter { col: None, text: "nosuchcolumn:x".into(), negate: true });
        assert_eq!(RowFilter::parse(""), None);
        assert_eq!((f("+target_user_name:ali").label(), f("-10.0").label(), RowFilter::new(Some(7), "", false).label()), ("+ target_user_name: ali".to_string(), "− 10.0".to_string(), "+ src_computer is empty".to_string()));
        let pass = |find: &str, fs: &[&str]| row_passes(row, find, &fs.iter().map(|s| f(s)).collect::<Vec<_>>());
        assert!(pass("", &[]));
        assert!(pass("alice", &[]) && !pass("bob", &[]));
        // contains, in its column only
        assert!(pass("", &["+target_user_name:ali"]) && !pass("", &["+src_computer:ali"]));
        assert!(pass("", &["-target_user_name:bob"]) && !pass("", &["-target_user_name:ali"]));
        // any column
        assert!(pass("", &["+10.0.0"]) && !pass("", &["-10.0.0"]));
        // they add up: every one must hold
        assert!(pass("", &["+target_user_name:alice", "+event_id:4624", "-event_type:failed"]));
        assert!(!pass("", &["+target_user_name:alice", "-event_id:4624"]));
        assert!(!pass("srv01", &["+target_user_name:bob"]));
        // an empty text is "the column is empty"
        assert!(row_passes(row, "", &[RowFilter::new(Some(9), "", false)]) && !row_passes(row, "", &[RowFilter::new(Some(7), "", false)]));
        assert!(row_passes(row, "", &[RowFilter::new(Some(7), "", true)]));
    }

    fn timeline(name: &str, rows: &[&str]) -> std::path::PathBuf {
        let p = std::env::temp_dir().join(format!("masstin_table_{}_{}", std::process::id(), name));
        let mut s = format!("{}\n", crate::csv_out::HEADER);
        for r in rows {
            s.push_str(r);
            s.push('\n');
        }
        std::fs::write(&p, s).unwrap();
        p
    }

    fn row(t: &str, dst: &str, user: &str, src: &str, detail: &str) -> String {
        format!("{t},{dst},SUCCESSFUL_LOGON,4624,3,{user},CORP,{src},10.0.0.5,,,0x1,{detail},Security.evtx,,,,,")
    }

    /// The copy of some rows is a timeline of its own with the file's own
    /// header and the records as written: 19 columns, nothing added.
    #[test]
    fn the_copy_of_rows_has_the_files_columns_and_text() {
        let rows = [
            row("2026-01-01T08:00:00+00:00", "SRV01", "alice", "WS01", "plain"),
            row("2026-01-01T09:00:00+00:00", "SRV02", "bob", "WS02", "\"a, quoted \"\"detail\"\"\""),
            row("2026-01-01T10:00:00+00:00", "SRV01", "carol", "WS03", "\"two\nlines\""),
            row("2026-01-01T11:00:00+00:00", "SRV03", "dave", "WS04", "last"),
        ];
        let refs: Vec<&str> = rows.iter().map(|s| s.as_str()).collect();
        let path = timeline("copy.csv", &refs);
        let store = Store::load(&[path.to_string_lossy().to_string()], 0.05).unwrap();
        assert_eq!(store.file_rows(0), 4);
        let out = path.with_extension("out.csv");
        assert_eq!(write_rows(&store, &[(0, 1), (0, 2)], &out).unwrap(), 2);
        let text = std::fs::read_to_string(&out).unwrap();
        assert_eq!(text, format!("{}\n{}\n{}\n", crate::csv_out::HEADER, rows[1], rows[2]), "the header and the two records, byte for byte");
        // it reads back as a timeline of two rows of 19 columns
        let again = Store::load(&[out.to_string_lossy().to_string()], 0.05).unwrap();
        assert_eq!(again.file_rows(0), 2);
        assert_eq!(again.raw_row(0, 0).unwrap().len(), 19);
        assert_eq!(again.raw_row(0, 1).unwrap()[12], "two\nlines");
        assert_eq!(store.raw_texts(0, &[3]).unwrap(), vec![rows[3].clone()]);
        assert_eq!(store.header_text(0).unwrap(), crate::csv_out::HEADER);
        let _ = std::fs::remove_file(&path);
        let _ = std::fs::remove_file(&out);
    }

    #[test]
    fn a_label_makes_a_file_name() {
        assert_eq!(file_label("WS01 -> SRV01 as CORP\\alice"), "WS01_-__SRV01_as_CORP_alice");
        assert_eq!(file_label("../../x"), ".._.._x");
        assert_eq!(file_label("///"), "rows");
        assert_eq!(csv_field("a,b"), "\"a,b\"");
        assert_eq!(csv_field("say \"hi\""), "\"say \"\"hi\"\"\"");
        assert_eq!(csv_field("plain"), "plain");
    }
}
