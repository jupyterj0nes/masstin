//! Saved views and style: what the analyst keeps between sessions.
//!
//! A view is a filter plus a style. The style says what colours the
//! edges (result, account, logon type, hunt state, verdict), what is
//! written on them, whether hosts take a shape by role, the scales, and
//! an ordered list of rules (`condition -> look`) that override the rest,
//! first match wins. Built-in views cover the usual questions; the
//! analyst's own are saved next to the timeline in
//! `<timeline>.views.json`, together with the last style used.

use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

use super::query::{Filter, View};

#[derive(Clone, Copy, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub enum ColorBy {
    Result,
    User,
    LogonType,
    Hunt,
    Verdict,
}

impl ColorBy {
    pub const ALL: [ColorBy; 5] = [ColorBy::Result, ColorBy::User, ColorBy::LogonType, ColorBy::Hunt, ColorBy::Verdict];
    pub fn label(self) -> &'static str {
        match self {
            ColorBy::Result => "result",
            ColorBy::User => "account",
            ColorBy::LogonType => "logon type",
            ColorBy::Hunt => "hunt state",
            ColorBy::Verdict => "verdict",
        }
    }
}

#[derive(Clone, Copy, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub enum Caption {
    None,
    User,
    Time,
    LogonType,
    UserTime,
    Count,
}

impl Caption {
    pub const ALL: [Caption; 6] = [Caption::User, Caption::UserTime, Caption::Time, Caption::LogonType, Caption::Count, Caption::None];
    pub fn label(self) -> &'static str {
        match self {
            Caption::None => "nothing",
            Caption::User => "account",
            Caption::Time => "first time",
            Caption::LogonType => "logon type",
            Caption::UserTime => "account + time",
            Caption::Count => "events",
        }
    }
}

#[derive(Clone, Copy, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub enum Field {
    Host,
    User,
    LogonType,
    EventId,
    Result,
    Hunt,
    Verdict,
}

impl Field {
    pub const ALL: [Field; 7] = [Field::Host, Field::User, Field::LogonType, Field::EventId, Field::Result, Field::Hunt, Field::Verdict];
    pub fn label(self) -> &'static str {
        match self {
            Field::Host => "host",
            Field::User => "account",
            Field::LogonType => "logon type",
            Field::EventId => "event id",
            Field::Result => "result",
            Field::Hunt => "hunt",
            Field::Verdict => "verdict",
        }
    }
    /// A rule on this field applies to hosts (as well as to edges).
    pub fn on_nodes(self) -> bool {
        matches!(self, Field::Host | Field::Hunt)
    }
}

#[derive(Clone, Copy, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub enum Shape {
    Circle,
    Square,
    Diamond,
    Hexagon,
}

impl Shape {
    pub const ALL: [Shape; 4] = [Shape::Circle, Shape::Square, Shape::Diamond, Shape::Hexagon];
    pub fn label(self) -> &'static str {
        match self {
            Shape::Circle => "circle",
            Shape::Square => "square",
            Shape::Diamond => "diamond",
            Shape::Hexagon => "hexagon",
        }
    }
}

/// How a host is drawn.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default, Serialize, Deserialize)]
pub enum NodeStyle {
    /// the machine itself, shaded: a monitor, a rack, a laptop, an antenna…
    #[default]
    #[serde(alias = "Device")]
    Realistic,
    /// a clean tile with a glyph for what the host is, like a network diagram
    Icon,
    /// neon outlines, scanlines, a line grid: the cabinet of the eighties
    Arcade,
    /// a piece of glass: gradient, shadow, highlight, thin rim
    Glass,
    /// a small dot inside a thin ring
    Minimal,
}

impl NodeStyle {
    pub const ALL: [NodeStyle; 5] = [NodeStyle::Realistic, NodeStyle::Icon, NodeStyle::Arcade, NodeStyle::Glass, NodeStyle::Minimal];
    pub fn label(self) -> &'static str {
        match self {
            NodeStyle::Realistic => "realistic",
            NodeStyle::Icon => "icons",
            NodeStyle::Arcade => "arcade",
            NodeStyle::Glass => "glass",
            NodeStyle::Minimal => "minimal",
        }
    }
    pub fn help(self) -> &'static str {
        match self {
            NodeStyle::Realistic => "The machines drawn as they are, with shading, a shadow and their lights: a monitor, a laptop, a rack, a domain controller with its badge, an antenna for an address, a globe for the outside.",
            NodeStyle::Icon => "Clean tiles with a glyph for what each host is, the name under it: the look of a network diagram.",
            NodeStyle::Arcade => "A video game: the machines as pixel sprites with blinking lights, names in an 8-bit face, a starfield with depth, scanlines, square bullets along the connections.",
            NodeStyle::Glass => "Glossy orbs with a highlight and a bright rim.",
            NodeStyle::Minimal => "A dot in a thin ring; the quietest.",
        }
    }
    /// The modes that draw the machines.
    pub fn draws_devices(self) -> bool {
        matches!(self, NodeStyle::Realistic | NodeStyle::Arcade)
    }
}

/// Where a host's name is drawn.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default, Serialize, Deserialize)]
pub enum LabelPos {
    /// inside when it stays readable there, under the host otherwise
    #[default]
    Auto,
    Inside,
    /// a band across the host, wider than it, like a road sign
    Band,
    Below,
    Above,
}

impl LabelPos {
    pub const ALL: [LabelPos; 5] = [LabelPos::Auto, LabelPos::Inside, LabelPos::Band, LabelPos::Below, LabelPos::Above];
    pub fn label(self) -> &'static str {
        match self {
            LabelPos::Auto => "auto",
            LabelPos::Inside => "inside",
            LabelPos::Band => "band",
            LabelPos::Below => "below",
            LabelPos::Above => "above",
        }
    }
    pub fn help(self) -> &'static str {
        match self {
            LabelPos::Auto => "inside the host when the name fits readably, under it otherwise",
            LabelPos::Inside => "inside the host, shrunk to fit",
            LabelPos::Band => "a band across the host, wider than it, the name on it",
            LabelPos::Below => "under the host",
            LabelPos::Above => "over the host",
        }
    }
}

/// `condition -> look`. Empty `pattern` matches everything.
#[derive(Clone, PartialEq, Debug, Serialize, Deserialize)]
pub struct Rule {
    pub enabled: bool,
    pub field: Field,
    pub pattern: String,
    pub color: Option<[u8; 3]>,
    /// edge width multiplier
    pub width: f32,
    /// host size multiplier
    pub size: f32,
    pub dashed: bool,
    pub hide: bool,
    pub shape: Option<Shape>,
    /// a glow around the edge / the host
    pub glow: bool,
    /// a host's own name position, text size multiplier and box colour
    #[serde(default)]
    pub label_pos: Option<LabelPos>,
    #[serde(default)]
    pub label_size: Option<f32>,
    #[serde(default)]
    pub label_bg: Option<[u8; 3]>,
    /// a host's own icon (a key of the catalogue), shown whatever the node style
    #[serde(default)]
    pub icon: Option<String>,
}

impl Default for Rule {
    fn default() -> Self {
        Rule { enabled: true, field: Field::User, pattern: String::new(), color: Some([255, 196, 84]), width: 1.0, size: 1.0, dashed: false, hide: false, shape: None, glow: false, label_pos: None, label_size: None, label_bg: None, icon: None }
    }
}

#[derive(Clone, PartialEq, Debug, Serialize, Deserialize)]
pub struct Style {
    pub color_by: ColorBy,
    pub caption: Caption,
    pub shapes_by_role: bool,
    pub node_scale: f32,
    pub edge_scale: f32,
    pub font_scale: f32,
    pub rules: Vec<Rule>,
    /// the dots travelling along the edges that matter, the pulse of a
    /// significant host, the hover ring
    #[serde(default = "yes")]
    pub motion: bool,
    /// a host's size grows with its traffic in the view; off, every host is the same
    #[serde(default = "yes")]
    pub size_by_traffic: bool,
    #[serde(default)]
    pub label_pos: LabelPos,
    /// a box behind every name, in `label_bg_color`
    #[serde(default)]
    pub label_bg: bool,
    #[serde(default = "label_box")]
    pub label_bg_color: [u8; 3],
    #[serde(default)]
    pub node_style: NodeStyle,
    /// subnet regions behind the hosts
    #[serde(default)]
    pub show_subnets: bool,
    /// a group per /24 besides the named CIDRs
    #[serde(default = "yes")]
    pub subnets_auto: bool,
    /// how much of a connection's colour shows, 0.2 to 1
    #[serde(default = "edge_opacity")]
    pub edge_opacity: f32,
    /// the account on an edge only when the edge is hovered or selected
    #[serde(default)]
    pub caption_hover: bool,
    /// curved connections; off: straight, except the fan of a busy pair
    #[serde(default = "yes")]
    pub curves: bool,
    /// an arrowhead at the destination
    #[serde(default = "yes")]
    pub arrows: bool,
    /// a soft glow under the findings and the lit connections
    #[serde(default = "yes")]
    pub edge_glow: bool,
    /// the dot grid behind the canvas
    #[serde(default = "yes")]
    pub grid: bool,
    /// the spotlight in the middle of the canvas
    #[serde(default = "yes")]
    pub vignette: bool,
    /// hosts drawn bigger when there are few of them
    #[serde(default = "yes")]
    pub auto_size: bool,
}

fn edge_opacity() -> f32 {
    0.8
}

fn label_box() -> [u8; 3] {
    [20, 25, 36]
}

fn yes() -> bool {
    true
}

impl Default for Style {
    fn default() -> Self {
        Style { color_by: ColorBy::Result, caption: Caption::User, shapes_by_role: false, node_scale: 1.0, edge_scale: 0.8, font_scale: 1.0, rules: Vec::new(), motion: true, size_by_traffic: true, label_pos: LabelPos::Auto, label_bg: false, label_bg_color: label_box(), node_style: NodeStyle::Realistic, show_subnets: false, subnets_auto: true, edge_opacity: edge_opacity(), caption_hover: false, curves: true, arrows: true, edge_glow: true, grid: true, vignette: true, auto_size: true }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SavedView {
    pub name: String,
    pub filter: Filter,
    pub style: Style,
    /// where the hosts were on the canvas when the view was saved:
    /// `(host, x, y)`; empty when the analyst did not keep the arrangement
    #[serde(default)]
    pub places: Vec<(String, f32, f32)>,
}

#[derive(Default, Serialize, Deserialize)]
pub struct ViewsFile {
    #[serde(default)]
    pub views: Vec<SavedView>,
    /// the style in use when the window was last closed or a view saved
    #[serde(default)]
    pub last_style: Option<Style>,
    /// hosts the analyst merged: `(from, into)`
    #[serde(default)]
    pub merges: Vec<(String, String)>,
    /// named subnets: `(cidr, name)`
    #[serde(default)]
    pub subnets: Vec<(String, String)>,
}

impl ViewsFile {
    /// `timeline.csv` -> `timeline.views.json`, next to the first timeline.
    pub fn path_for(first_csv: &str) -> PathBuf {
        let p = Path::new(first_csv);
        let stem = p.file_stem().map(|s| s.to_string_lossy().to_string()).unwrap_or_else(|| "timeline".into());
        p.with_file_name(format!("{}.views.json", stem))
    }

    pub fn load(path: &Path) -> ViewsFile {
        std::fs::read_to_string(path).ok().and_then(|s| serde_json::from_str(&s).ok()).unwrap_or_default()
    }

    pub fn save(&self, path: &Path) -> std::io::Result<()> {
        let text = serde_json::to_string_pretty(self).map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))?;
        std::fs::write(path, text)
    }
}

/// The views every timeline starts with.
pub fn builtin_views(t_max: i64) -> Vec<SavedView> {
    let base = Filter::default();
    let mut v = Vec::new();
    let mut push = |name: &str, f: Filter| v.push(SavedView { name: name.to_string(), filter: f, style: Style::default(), places: Vec::new() });
    push("Findings", base.clone());
    let mut all = base.clone();
    all.view = View::All;
    all.results = [true, true, true, true];
    push("Everything", all.clone());
    let mut rdp = all.clone();
    rdp.logon_type = "10".into();
    push("RDP only (type 10)", rdp);
    let mut net = all.clone();
    net.logon_type = "3".into();
    push("Network logons (type 3: SMB, PsExec, WMI)", net);
    let mut ssh = all.clone();
    ssh.logon_type = "SSH".into();
    push("SSH", ssh);
    let mut adm = all.clone();
    adm.user = "*adm*,*administrator*,*root*".into();
    push("Admin accounts", adm);
    let mut svc = all.clone();
    svc.user = "svc*,*svc*,*service*".into();
    push("Service accounts", svc);
    let mut nomachine = all.clone();
    nomachine.user = "!*$".into();
    push("Without machine accounts", nomachine);
    let mut failed = all.clone();
    failed.results = [false, true, false, true];
    push("Failures and touches", failed);
    let mut marked = all.clone();
    marked.verdict = [false, true, true, true];
    push("Marked by the analyst", marked);
    let mut last_day = all.clone();
    last_day.from = super::query::fmt_time(t_max - 86_400);
    push("Last 24 hours of the timeline", last_day);
    v
}

/// Neo4j Browser's node palette, for the "colour by account / logon type" modes.
pub const PALETTE: [[u8; 3]; 12] = [
    [87, 199, 227],
    [241, 102, 103],
    [141, 204, 147],
    [255, 196, 84],
    [201, 144, 192],
    [247, 151, 103],
    [76, 142, 218],
    [236, 181, 201],
    [217, 200, 174],
    [86, 148, 128],
    [218, 113, 148],
    [132, 132, 132],
];

pub fn palette_color(i: u32) -> [u8; 3] {
    PALETTE[(i as usize) % PALETTE.len()]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn views_round_trip_through_json() {
        let mut f = ViewsFile::default();
        let mut sv = builtin_views(0).remove(2);
        sv.style.rules.push(Rule { field: Field::User, pattern: "adm*".into(), color: Some([1, 2, 3]), glow: true, ..Default::default() });
        f.views.push(sv.clone());
        f.last_style = Some(sv.style.clone());
        let p = std::env::temp_dir().join(format!("masstin-views-{}.json", std::process::id()));
        f.save(&p).unwrap();
        let back = ViewsFile::load(&p);
        assert_eq!(back.views.len(), 1);
        assert_eq!(back.views[0].filter.logon_type, "10");
        assert_eq!(back.views[0].style.rules[0].pattern, "adm*");
        assert!(back.last_style.unwrap().rules[0].glow);
        assert_eq!(ViewsFile::path_for("D:/x/timeline.csv").file_name().unwrap().to_string_lossy(), "timeline.views.json");
        let _ = std::fs::remove_file(p);
    }
}
