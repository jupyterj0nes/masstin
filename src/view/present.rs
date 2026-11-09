//! Presentation: the view replayed in time order as a story, and the
//! story recorded as a video.
//!
//! A step is one row of the view, or a burst of rows close in time. Each
//! step lasts a chosen time (the same for all, or the real gap compressed)
//! and may pause after itself; the analyst can override any step's
//! duration, pause and caption, skip it or emphasise it. The story is
//! saved next to the timeline as `<timeline>.story.json`.
//!
//! Recording asks the window for a screenshot of every frame at a fixed
//! rate, so what is written is exactly what was shown: GIF (animated),
//! PNG frames, and MP4 through ffmpeg when it is on the PATH.

use std::collections::HashMap;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

#[derive(Clone, Copy, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub enum Timing {
    /// every step takes `step_secs`
    Fixed,
    /// the real gap between rows, divided by `compress`, clamped
    Compressed,
}

#[derive(Clone, PartialEq, Debug, Serialize, Deserialize)]
#[serde(default)]
pub struct StepOverride {
    pub secs: Option<f32>,
    pub pause_after: f32,
    pub caption: Option<String>,
    pub skip: bool,
    pub emphasis: bool,
}

impl Default for StepOverride {
    fn default() -> Self {
        StepOverride { secs: None, pause_after: 0.0, caption: None, skip: false, emphasis: false }
    }
}

/// A stretch of the timeline with a speed of its own: steps whose time
/// falls in `[from, to)` take this timing instead of the story's. Times
/// are `YYYY-MM-DD HH:MM[:SS]`; empty means open on that side.
#[derive(Clone, PartialEq, Debug, Serialize, Deserialize)]
#[serde(default)]
pub struct Stretch {
    pub from: String,
    pub to: String,
    pub timing: Timing,
    pub step_secs: f32,
    /// timeline seconds a second when by the clock
    pub compress: f32,
}

impl Default for Stretch {
    fn default() -> Self {
        Stretch { from: String::new(), to: String::new(), timing: Timing::Fixed, step_secs: 0.8, compress: 600.0 }
    }
}

impl Stretch {
    pub fn contains(&self, t: i64) -> bool {
        let from = super::query::parse_time(&self.from);
        let to = super::query::parse_time(&self.to);
        from.map_or(true, |f| t >= f) && to.map_or(true, |x| t < x)
    }
}

/// Where a logo goes on the recording.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub enum LogoPos {
    TopLeft,
    TopCentre,
    TopRight,
    BottomLeft,
    BottomCentre,
    BottomRight,
}

impl LogoPos {
    pub const ALL: [LogoPos; 6] = [LogoPos::TopLeft, LogoPos::TopCentre, LogoPos::TopRight, LogoPos::BottomLeft, LogoPos::BottomCentre, LogoPos::BottomRight];
    pub fn label(self) -> &'static str {
        match self {
            LogoPos::TopLeft => "top left",
            LogoPos::TopCentre => "top centre",
            LogoPos::TopRight => "top right",
            LogoPos::BottomLeft => "bottom left",
            LogoPos::BottomCentre => "bottom centre",
            LogoPos::BottomRight => "bottom right",
        }
    }
}

/// A clock speed as people say it: "10 min/s", "1.5 h/s", "2 day/s".
pub fn clock_label(secs_per_sec: f32) -> String {
    let tidy = |x: f32| if (x - x.round()).abs() < 0.05 { format!("{:.0}", x) } else { format!("{:.1}", x) };
    if secs_per_sec < 60.0 {
        format!("{} s/s", tidy(secs_per_sec))
    } else if secs_per_sec < 3600.0 {
        format!("{} min/s", tidy(secs_per_sec / 60.0))
    } else if secs_per_sec < 86_400.0 {
        format!("{} h/s", tidy(secs_per_sec / 3600.0))
    } else if secs_per_sec < 7.0 * 86_400.0 {
        format!("{} day/s", tidy(secs_per_sec / 86_400.0))
    } else {
        format!("{} week/s", tidy(secs_per_sec / (7.0 * 86_400.0)))
    }
}

#[derive(Clone, PartialEq, Debug, Serialize, Deserialize)]
#[serde(default)]
pub struct Story {
    pub title: String,
    pub timing: Timing,
    pub step_secs: f32,
    pub compress: f32,
    pub min_gap: f32,
    pub max_gap: f32,
    /// rows within this many seconds of each other form one step
    pub group_secs: f32,
    pub pause_significant: f32,
    pub fade_old: bool,
    pub show_clock: bool,
    pub show_caption: bool,
    pub show_counter: bool,
    pub anonymise: bool,
    pub hold_end: f32,
    /// per step, keyed by `file:line` of its first row
    pub steps: HashMap<String, StepOverride>,
    /// stretches of the timeline with a speed of their own; the first that
    /// contains a step wins
    pub stretches: Vec<Stretch>,
    /// a logo (PNG, JPEG, WebP, BMP, GIF: the path) on the presentation and
    /// the recording, where, how wide (a fraction of the width), how opaque,
    /// and whether it also stays on the window outside the presentation
    pub logo: String,
    pub logo_pos: LogoPos,
    pub logo_width: f32,
    pub logo_opacity: f32,
    pub logo_always: bool,
    /// what the Record dialog last used
    pub recording: Recording,
    /// the cinematic look, for the presentation and the recording alike
    pub cinematic: bool,
    pub look: Look,
}

impl Story {
    /// Seconds before the first step: the title card, when there is one.
    pub fn lead_in(&self) -> f32 {
        if self.cinematic && self.look.cards { CARD_IN } else { 0.0 }
    }

    /// Seconds after the hold at the end: the summary card, when there is one.
    pub fn lead_out(&self) -> f32 {
        if self.cinematic && self.look.cards { CARD_OUT } else { 0.0 }
    }
}

/// The look of a presentation and its recording when `Story::cinematic` is
/// on: the hop under way is what the eye goes to, the time is legible and
/// its pace felt, the picture is one a client keeps. Each piece can go.
#[derive(Clone, PartialEq, Debug, Serialize, Deserialize)]
#[serde(default)]
pub struct Look {
    /// the rest of the picture dims while a hop draws; its two hosts and
    /// its line stay lit, a ring runs out of the destination as the line arrives
    pub focus: bool,
    /// the hosts already reached keep a warm trace: the spread, visible
    pub footprint: bool,
    /// the clock card: the date, the time rolling at the story's pace, the
    /// speed and when it changes, a jump in the timeline named
    pub time: bool,
    /// the caption as a lower third sliding in, with the hunt's word and
    /// the analyst's note on the connection
    pub lower_third: bool,
    /// the incident's span along the bottom, the significant hops marked,
    /// the head where the story is
    pub bar: bool,
    /// a title card before the story and a summary after it
    pub cards: bool,
    /// the client's colour for the overlays, instead of masstin's amber
    pub accent: Option<[u8; 3]>,
}

impl Default for Look {
    fn default() -> Self {
        Look { focus: true, footprint: true, time: true, lower_third: true, bar: true, cards: true, accent: None }
    }
}

/// Seconds of the title card before the story, and of the summary after it.
pub const CARD_IN: f32 = 3.5;
pub const CARD_OUT: f32 = 7.0;
/// A gap in the timeline this long or longer is a jump the clock card names.
pub const JUMP_SECS: i64 = 3 * 3600;

/// A gap worth naming on the picture: three hours, or three times the
/// story's usual gap when its hops are hours apart anyway (else every hop
/// of a sparse month would be "10 h later").
pub fn jump_threshold(steps: &[Step]) -> i64 {
    let mut gaps: Vec<i64> = steps.iter().skip(1).map(|s| s.gap).collect();
    if gaps.is_empty() {
        return JUMP_SECS;
    }
    gaps.sort_unstable();
    JUMP_SECS.max(3 * gaps[(gaps.len() - 1) / 2])
}

/// "2 days 3 h later", "14 h later", "45 min later".
pub fn jump_label(secs: i64) -> String {
    let (d, h, m) = (secs / 86_400, (secs % 86_400) / 3600, (secs % 3600) / 60);
    let what = if d >= 1 {
        if h > 0 { format!("{} day{} {} h", d, if d == 1 { "" } else { "s" }, h) } else { format!("{} day{}", d, if d == 1 { "" } else { "s" }) }
    } else if h >= 1 {
        if m > 0 && h < 6 { format!("{} h {} min", h, m) } else { format!("{} h", h) }
    } else {
        format!("{} min", m.max(1))
    };
    format!("{} later", what)
}

/// The speed a step plays at, as the clock card says.
pub fn speed_label(step: &Step) -> String {
    match step.timing {
        Timing::Fixed => format!("a hop every {} s", if (step.step_secs - step.step_secs.round()).abs() < 0.05 { format!("{:.0}", step.step_secs) } else { format!("{:.1}", step.step_secs) }),
        Timing::Compressed => format!("time ×{:.0}  ·  {}", step.compress, clock_label(step.compress)),
    }
}

/// Whether the pace changed from `prev` to `step` (a stretch began or
/// ended): Some(true) faster, Some(false) slower, None the same settings.
pub fn speed_change(prev: &Step, step: &Step) -> Option<bool> {
    if prev.timing == step.timing && (prev.compress - step.compress).abs() < 0.5 && (prev.step_secs - step.step_secs).abs() < 0.01 {
        return None;
    }
    // timeline seconds a presentation second, either way of timing
    let rate = |s: &Step| match s.timing {
        Timing::Compressed => s.compress,
        Timing::Fixed => s.gap.max(1) as f32 / s.dur.max(0.05),
    };
    Some(rate(step) > rate(prev))
}

impl Default for Story {
    fn default() -> Self {
        Story { title: String::new(), timing: Timing::Fixed, step_secs: 0.8, compress: 600.0, min_gap: 0.3, max_gap: 3.0, group_secs: 2.0, pause_significant: 1.2, fade_old: false, show_clock: true, show_caption: true, show_counter: true, anonymise: false, hold_end: 3.0, steps: HashMap::new(), stretches: Vec::new(), logo: String::new(), logo_pos: LogoPos::BottomRight, logo_width: 0.12, logo_opacity: 0.9, logo_always: false, recording: Recording::default(), cinematic: false, look: Look::default() }
    }
}

impl Story {
    pub fn path_for(first_csv: &str) -> PathBuf {
        let p = Path::new(first_csv);
        let stem = p.file_stem().map(|s| s.to_string_lossy().to_string()).unwrap_or_else(|| "timeline".into());
        p.with_file_name(format!("{}.story.json", stem))
    }
    pub fn load(path: &Path) -> Story {
        std::fs::read_to_string(path).ok().and_then(|s| serde_json::from_str(&s).ok()).unwrap_or_default()
    }
    pub fn save(&self, path: &Path) -> std::io::Result<()> {
        let text = serde_json::to_string_pretty(self).map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))?;
        std::fs::write(path, text)
    }
}

/// One step of the presentation: a range of the view's events.
#[derive(Clone, Debug)]
pub struct Step {
    pub key: String,
    /// first event index (inclusive) and one past the last
    pub from: usize,
    pub to: usize,
    pub t: i64,
    /// seconds into the presentation when it starts, and how long it lasts
    pub start: f32,
    pub dur: f32,
    pub pause: f32,
    pub significant: bool,
    pub emphasis: bool,
    pub caption: Option<String>,
    /// timeline seconds since the step before (0 for the first)
    pub gap: i64,
    /// the pace this step was given: the stretch's, or the story's
    pub timing: Timing,
    pub step_secs: f32,
    pub compress: f32,
}

/// Build the steps of a presentation from the view's events (time,
/// first-row key, whether significant), in time order.
pub fn build_steps(events: &[(i64, String, bool)], story: &Story) -> Vec<Step> {
    let mut steps: Vec<Step> = Vec::new();
    let mut i = 0usize;
    while i < events.len() {
        let (t0, ref key, mut sig) = events[i];
        let mut j = i + 1;
        while j < events.len() && (events[j].0 - t0) as f32 <= story.group_secs {
            sig |= events[j].2;
            j += 1;
        }
        let ov = story.steps.get(key);
        if ov.map_or(false, |o| o.skip) {
            i = j;
            continue;
        }
        let prev_t = steps.last().map(|s| s.t);
        // the stretch this step falls in sets its timing; else the story's
        let (timing, step_secs, compress) = match story.stretches.iter().find(|s| s.contains(t0)) {
            Some(s) => (s.timing, s.step_secs, s.compress),
            None => (story.timing, story.step_secs, story.compress),
        };
        let base = match timing {
            Timing::Fixed => step_secs,
            Timing::Compressed => match prev_t {
                Some(p) => (((t0 - p) as f32) / compress.max(1.0)).clamp(story.min_gap, story.max_gap),
                None => step_secs,
            },
        };
        let dur = ov.and_then(|o| o.secs).unwrap_or(base).max(0.05);
        let pause = ov.map(|o| o.pause_after).unwrap_or(0.0) + if sig { story.pause_significant } else { 0.0 };
        let start = steps.last().map(|s| s.start + s.dur + s.pause).unwrap_or_else(|| story.lead_in());
        let gap = prev_t.map(|p| (t0 - p).max(0)).unwrap_or(0);
        steps.push(Step { key: key.clone(), from: i, to: j, t: t0, start, dur, pause, significant: sig, emphasis: ov.map_or(false, |o| o.emphasis), caption: ov.and_then(|o| o.caption.clone()), gap, timing, step_secs, compress });
        i = j;
    }
    steps
}

/// Total length of the presentation in seconds.
pub fn total_secs(steps: &[Step], story: &Story) -> f32 {
    steps.last().map(|s| s.start + s.dur + s.pause).unwrap_or(0.0) + story.hold_end + story.lead_out()
}

/// Where the presentation is at second `t`: the step and how far into
/// its drawing (0..1; 1 while it pauses), or None after the end.
pub fn at(steps: &[Step], t: f32) -> Option<(usize, f32)> {
    if steps.is_empty() {
        return None;
    }
    let k = steps.partition_point(|s| s.start <= t).saturating_sub(1);
    let s = &steps[k];
    if t < s.start {
        return Some((k, 0.0));
    }
    Some((k, ((t - s.start) / s.dur).clamp(0.0, 1.0)))
}

/// Consistent stand-in names for a talk: HOST-01, user-03.
pub struct Anonymiser {
    hosts: std::cell::RefCell<HashMap<u32, String>>,
    users: std::cell::RefCell<HashMap<u32, String>>,
}

impl Anonymiser {
    pub fn new() -> Anonymiser {
        Anonymiser { hosts: std::cell::RefCell::new(HashMap::new()), users: std::cell::RefCell::new(HashMap::new()) }
    }
    pub fn host(&self, id: u32, is_ip: bool) -> String {
        let mut m = self.hosts.borrow_mut();
        let n = m.len() + 1;
        m.entry(id).or_insert_with(|| if is_ip { format!("10.x.x.{}", n) } else { format!("HOST-{:02}", n) }).clone()
    }
    pub fn user(&self, id: u32) -> String {
        let mut m = self.users.borrow_mut();
        let n = m.len() + 1;
        m.entry(id).or_insert_with(|| format!("user-{:02}", n)).clone()
    }
}

// ───────────────────────────── recording ────────────────────────────────────

#[derive(Clone, Copy, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub enum Format {
    Gif,
    Png,
    Mp4,
}

impl Format {
    pub fn label(self) -> &'static str {
        match self {
            Format::Gif => "GIF",
            Format::Png => "PNG frames",
            Format::Mp4 => "MP4 (ffmpeg)",
        }
    }
}

/// How much of the picture a recording keeps: a GIF's colours and how
/// small a change it redraws, an MP4's compression.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub enum Quality {
    Small,
    Balanced,
    Best,
}

impl Quality {
    pub const ALL: [Quality; 3] = [Quality::Small, Quality::Balanced, Quality::Best];

    pub fn label(self) -> &'static str {
        match self {
            Quality::Small => "small file",
            Quality::Balanced => "balanced",
            Quality::Best => "best",
        }
    }

    pub fn hint(self) -> &'static str {
        match self {
            Quality::Small => "64 colours a frame and only clear changes redrawn; an MP4 compressed hard. For a chat or a wiki.",
            Quality::Balanced => "128 colours a frame; an MP4 as a video site keeps it. For a report or a talk.",
            Quality::Best => "256 colours a frame, every change redrawn; an MP4 near lossless. For the archive, or to edit further.",
        }
    }

    /// A GIF frame's colours (one of them stands for what did not change),
    /// NeuQuant's sample factor (1 the finest, 30 the fastest) and the
    /// change a pixel must make, per channel, to be drawn again.
    fn gif(self) -> (usize, i32, i16) {
        match self {
            Quality::Small => (64, 10, 12),
            Quality::Balanced => (128, 4, 6),
            Quality::Best => (256, 1, 2),
        }
    }

    /// x264's constant rate factor: 17 is near lossless, 28 is small.
    fn crf(self) -> u32 {
        match self {
            Quality::Small => 26,
            Quality::Balanced => 21,
            Quality::Best => 17,
        }
    }
}

/// The Record dialog's settings, saved with the story (so with the case).
#[derive(Clone, PartialEq, Debug, Serialize, Deserialize)]
#[serde(default)]
pub struct Recording {
    pub format: Format,
    pub fps: u32,
    /// 0 the window as it is, 1 1280 x 720, 2 1920 x 1080, 3 1600 x 900
    pub size: usize,
    pub quality: Quality,
    /// where it goes; empty: `<stem>-story.<ext>` next to the case or the timeline
    pub file: String,
}

impl Default for Recording {
    fn default() -> Self {
        Recording { format: Format::Gif, fps: 20, size: 1, quality: Quality::Balanced, file: String::new() }
    }
}

/// The rates a format keeps: a GIF's clock ticks in hundredths of a second,
/// so only a rate that divides a hundred plays at the speed it was recorded
/// (and players hold a frame for a tenth of a second when told less than two
/// hundredths).
pub fn fps_choices(format: Format) -> &'static [u32] {
    match format {
        Format::Gif => &[10, 20, 25, 33, 50],
        Format::Mp4 | Format::Png => &[10, 15, 24, 30, 60],
    }
}

/// The rate `format` offers nearest to `fps`.
pub fn nearest_fps(format: Format, fps: u32) -> u32 {
    fps_choices(format).iter().copied().min_by_key(|f| (*f as i64 - fps as i64).abs()).unwrap_or(fps)
}

/// About how big the file will be, bytes, low to high. The low end is a
/// lateral-movement story of seventy connections measured at these settings
/// (per frame and megapixel for a GIF and the PNG frames, per second and
/// megapixel for an MP4: 4.0 / 4.7 / 6.4 MB the GIF small / balanced / best,
/// 1.0 / 1.8 MB the MP4 small / balanced, 0.9 MB a PNG frame, at 720p); the
/// high end is for a picture where much moves: a camera glide, older edges
/// fading, motion on.
pub fn estimate_bytes(format: Format, quality: Quality, w: f32, h: f32, fps: u32, secs: f32) -> (u64, u64) {
    let mp = (w * h) as f64 / 1e6;
    let frames = (secs * fps as f32).ceil().max(1.0) as f64;
    let (lo, hi) = match format {
        Format::Gif => {
            let (lo, hi) = match quality {
                Quality::Small => (GIF_BYTES[0].0, GIF_BYTES[0].1),
                Quality::Balanced => (GIF_BYTES[1].0, GIF_BYTES[1].1),
                Quality::Best => (GIF_BYTES[2].0, GIF_BYTES[2].1),
            };
            (frames * mp * lo, frames * mp * hi)
        }
        Format::Mp4 => {
            let (lo, hi) = match quality {
                Quality::Small => (MP4_BYTES[0].0, MP4_BYTES[0].1),
                Quality::Balanced => (MP4_BYTES[1].0, MP4_BYTES[1].1),
                Quality::Best => (MP4_BYTES[2].0, MP4_BYTES[2].1),
            };
            (secs.max(1.0) as f64 * mp * lo, secs.max(1.0) as f64 * mp * hi)
        }
        Format::Png => (frames * mp * PNG_BYTES.0, frames * mp * PNG_BYTES.1),
    };
    (lo as u64, hi as u64)
}

/// Bytes per frame and megapixel of a GIF, (low, high), by quality.
const GIF_BYTES: [(f64, f64); 3] = [(3_900.0, 14_000.0), (4_600.0, 18_000.0), (6_300.0, 28_000.0)];
/// Bytes per second and megapixel of an MP4, (low, high), by quality.
const MP4_BYTES: [(f64, f64); 3] = [(18_000.0, 80_000.0), (34_000.0, 150_000.0), (70_000.0, 300_000.0)];
/// Bytes per frame and megapixel of a PNG frame.
const PNG_BYTES: (f64, f64) = (1_000_000.0, 1_600_000.0);

/// `12.3 MB`, `840 KB`.
pub fn human_bytes(b: u64) -> String {
    if b >= 1 << 30 {
        format!("{:.1} GB", b as f64 / (1u64 << 30) as f64)
    } else if b >= 1 << 20 {
        format!("{:.0} MB", b as f64 / (1u64 << 20) as f64)
    } else {
        format!("{:.0} KB", (b as f64 / 1024.0).max(1.0))
    }
}

fn size_note(path: &std::path::Path) -> String {
    std::fs::metadata(path).map(|m| format!(", {}", human_bytes(m.len()))).unwrap_or_default()
}

/// A GIF written frame by frame as a screen recorder does: a frame carries
/// only the rectangle where pixels changed, the rest of it transparent over
/// what is already shown, with a palette of its own (the region's colours as
/// they are when they fit, quantised otherwise); frames that change nothing
/// lengthen the one before. A pixel is drawn again when it moved from what
/// was last drawn by more than the quality's tolerance, so a slow fade
/// catches up and the file does not carry every breath of a glow.
struct GifSink<W: std::io::Write> {
    enc: gif::Encoder<W>,
    w: usize,
    h: usize,
    /// each pixel as it was when last drawn
    base: Vec<[u8; 3]>,
    mark: Vec<bool>,
    started: bool,
    colours: usize,
    sample: i32,
    tol: i16,
    fps: u32,
    /// hundredths of a second owed by rounding
    carry: f32,
    /// hundredths accumulated by frames that changed nothing
    pending: u16,
    frames: usize,
}

impl<W: std::io::Write> GifSink<W> {
    fn new(w: W, width: usize, height: usize, fps: u32, quality: Quality) -> Result<Self, String> {
        let mut enc = gif::Encoder::new(w, width as u16, height as u16, &[]).map_err(|e| e.to_string())?;
        enc.set_repeat(gif::Repeat::Infinite).map_err(|e| e.to_string())?;
        let (colours, sample, tol) = quality.gif();
        Ok(GifSink { enc, w: width, h: height, base: vec![[0; 3]; width * height], mark: vec![false; width * height], started: false, colours, sample, tol, fps, carry: 0.0, pending: 0, frames: 0 })
    }

    /// This frame's time in hundredths, the remainder carried so a long GIF keeps its rate.
    fn delay(&mut self) -> u16 {
        self.carry += 100.0 / self.fps.max(1) as f32;
        let d = self.carry.floor();
        self.carry -= d;
        d as u16
    }

    fn push(&mut self, img: &egui::ColorImage) -> Result<(), String> {
        if img.width() != self.w || img.height() != self.h {
            // another size (the window resized): left out
            return Ok(());
        }
        let d = self.delay();
        let px = &img.pixels;
        let (mut x0, mut y0, mut x1, mut y1) = (self.w, self.h, 0usize, 0usize);
        let mut any = false;
        for y in 0..self.h {
            for x in 0..self.w {
                let i = y * self.w + x;
                let c = px[i];
                let b = self.base[i];
                let moved = !self.started || (c.r() as i16 - b[0] as i16).abs() > self.tol || (c.g() as i16 - b[1] as i16).abs() > self.tol || (c.b() as i16 - b[2] as i16).abs() > self.tol;
                self.mark[i] = moved;
                if moved {
                    any = true;
                    x0 = x0.min(x);
                    x1 = x1.max(x + 1);
                    y0 = y0.min(y);
                    y1 = y1.max(y + 1);
                }
            }
        }
        if !any {
            self.pending = self.pending.saturating_add(d);
            return Ok(());
        }
        let (bw, bh) = (x1 - x0, y1 - y0);
        // the palette: the colours as they are when they fit, quantised otherwise
        let mut exact: HashMap<[u8; 3], u8> = HashMap::new();
        let mut rgba: Vec<u8> = Vec::new();
        let mut few = true;
        for y in y0..y1 {
            for x in x0..x1 {
                let i = y * self.w + x;
                if self.mark[i] {
                    let c = px[i];
                    let k = [c.r(), c.g(), c.b()];
                    if few && !exact.contains_key(&k) {
                        if exact.len() + 1 >= self.colours {
                            few = false;
                        } else {
                            exact.insert(k, exact.len() as u8);
                        }
                    }
                    rgba.extend_from_slice(&[k[0], k[1], k[2], 255]);
                }
            }
        }
        let (mut pal, index): (Vec<u8>, Box<dyn Fn([u8; 3]) -> u8>) = if few {
            let mut pal = vec![0u8; exact.len() * 3];
            for (c, &i) in &exact {
                pal[i as usize * 3..i as usize * 3 + 3].copy_from_slice(c);
            }
            (pal, Box::new(move |c| exact[&c]))
        } else {
            let nq = color_quant::NeuQuant::new(self.sample, self.colours - 1, &rgba);
            (nq.color_map_rgb(), Box::new(move |c| nq.index_of(&[c[0], c[1], c[2], 255]) as u8))
        };
        let transparent = (pal.len() / 3) as u8;
        pal.extend_from_slice(&[0, 0, 0]);
        while pal.len() < 6 {
            pal.extend_from_slice(&[0, 0, 0]);
        }
        let mut buf = Vec::with_capacity(bw * bh);
        for y in y0..y1 {
            for x in x0..x1 {
                let i = y * self.w + x;
                if self.mark[i] {
                    let c = px[i];
                    let k = [c.r(), c.g(), c.b()];
                    buf.push(index(k));
                    self.base[i] = k;
                } else {
                    buf.push(transparent);
                }
            }
        }
        let frame = gif::Frame {
            delay: (d + self.pending).max(2),
            dispose: gif::DisposalMethod::Keep,
            transparent: if self.started { Some(transparent) } else { None },
            needs_user_input: false,
            top: y0 as u16,
            left: x0 as u16,
            width: bw as u16,
            height: bh as u16,
            interlaced: false,
            palette: Some(pal),
            buffer: std::borrow::Cow::Owned(buf),
        };
        self.enc.write_frame(&frame).map_err(|e| e.to_string())?;
        self.pending = 0;
        self.started = true;
        self.frames += 1;
        Ok(())
    }

    /// The trailer; a last still frame carries the time of the frames that changed nothing.
    fn finish(mut self) -> Result<usize, String> {
        if self.pending > 0 && self.started {
            let frame = gif::Frame { delay: self.pending.max(2), dispose: gif::DisposalMethod::Keep, transparent: Some(1), width: 1, height: 1, palette: Some(vec![0, 0, 0, 0, 0, 0]), buffer: std::borrow::Cow::Owned(vec![1]), ..Default::default() };
            self.enc.write_frame(&frame).map_err(|e| e.to_string())?;
        }
        use std::io::Write;
        let mut w = self.enc.into_inner().map_err(|e| e.to_string())?;
        w.flush().map_err(|e| e.to_string())?;
        Ok(self.frames)
    }
}

/// Whether ffmpeg is on the PATH.
pub fn ffmpeg_available() -> bool {
    std::process::Command::new("ffmpeg").arg("-version").stdout(std::process::Stdio::null()).stderr(std::process::Stdio::null()).status().map(|s| s.success()).unwrap_or(false)
}

/// The frames of a recording, encoded as they arrive on a thread of
/// their own, so the window never holds more than the frame in flight.
pub struct Recorder {
    tx: Option<std::sync::mpsc::SyncSender<std::sync::Arc<egui::ColorImage>>>,
    done: std::sync::mpsc::Receiver<Result<String, String>>,
    pub sent: usize,
}

pub(super) fn to_rgba(img: &egui::ColorImage) -> image::RgbaImage {
    let (w, h) = (img.width() as u32, img.height() as u32);
    let mut buf = Vec::with_capacity((w * h * 4) as usize);
    for px in img.pixels.iter() {
        buf.extend_from_slice(&px.to_srgba_unmultiplied());
    }
    image::RgbaImage::from_raw(w, h, buf).expect("image size")
}

impl Recorder {
    pub fn start(fps: u32, format: Format, quality: Quality, out: std::path::PathBuf) -> Recorder {
        if format == Format::Mp4 {
            return Recorder::start_stream(fps, quality, out);
        }
        // bounded: the window waits for the encoder instead of piling frames up in memory
        let (tx, rx) = std::sync::mpsc::sync_channel::<std::sync::Arc<egui::ColorImage>>(3);
        let (dtx, drx) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            let result = (|| -> Result<String, String> {
                let mut n = 0usize;
                match format {
                    Format::Gif => {
                        let mut file = Some(std::fs::File::create(&out).map_err(|e| e.to_string())?);
                        let mut sink: Option<GifSink<std::io::BufWriter<std::fs::File>>> = None;
                        while let Ok(f) = rx.recv() {
                            let s = match sink.as_mut() {
                                Some(s) => s,
                                None => sink.insert(GifSink::new(std::io::BufWriter::with_capacity(1 << 20, file.take().ok_or("no file")?), f.width(), f.height(), fps, quality)?),
                            };
                            s.push(&f)?;
                            n += 1;
                        }
                        if let Some(s) = sink {
                            s.finish()?;
                        }
                        Ok(format!("{} ({} frames at {} fps{})", out.display(), n, fps, size_note(&out)))
                    }
                    Format::Png | Format::Mp4 => {
                        std::fs::create_dir_all(&out).map_err(|e| e.to_string())?;
                        while let Ok(f) = rx.recv() {
                            let p = out.join(format!("frame_{:05}.png", n));
                            // RGB: the window has no transparency, and the alpha would be a quarter of the file
                            image::DynamicImage::ImageRgba8(to_rgba(&f)).to_rgb8().save(&p).map_err(|e| e.to_string())?;
                            n += 1;
                        }
                        Ok(format!("{} frames in {}", n, out.display()))
                    }
                }
            })();
            let _ = dtx.send(result);
        });
        Recorder { tx: Some(tx), done: drx, sent: 0 }
    }

    /// An MP4 written as the frames come, through ffmpeg's standard input
    /// (raw RGBA, no frame files): what a film of the window needs, since
    /// it has no end known beforehand. ffmpeg starts with the first frame,
    /// which sets the size; a frame of another size is left out.
    pub fn start_stream(fps: u32, quality: Quality, out: std::path::PathBuf) -> Recorder {
        let (tx, rx) = std::sync::mpsc::sync_channel::<std::sync::Arc<egui::ColorImage>>(8);
        let (dtx, drx) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            let result = (|| -> Result<String, String> {
                use std::io::Write;
                let mut child: Option<std::process::Child> = None;
                let mut size = (0usize, 0usize);
                let mut n = 0usize;
                while let Ok(f) = rx.recv() {
                    if child.is_none() {
                        size = (f.width() & !1, f.height() & !1);
                        let mut cmd = std::process::Command::new("ffmpeg");
                        cmd.args(["-y", "-f", "rawvideo", "-pix_fmt", "rgba", "-s"])
                            .arg(format!("{}x{}", f.width(), f.height()))
                            .args(["-r", &fps.to_string(), "-i", "-", "-vf"])
                            .arg(format!("crop={}:{}:0:0", size.0, size.1))
                            .args(["-c:v", "libx264", "-preset", "veryfast", "-pix_fmt", "yuv420p", "-crf", &quality.crf().to_string(), "-movflags", "+faststart"])
                            .arg(&out)
                            .stdin(std::process::Stdio::piped())
                            .stdout(std::process::Stdio::null())
                            .stderr(std::process::Stdio::null());
                        #[cfg(windows)]
                        {
                            use std::os::windows::process::CommandExt;
                            cmd.creation_flags(0x0800_0000);
                        }
                        child = Some(cmd.spawn().map_err(|e| format!("ffmpeg: {}", e))?);
                    }
                    if (f.width() & !1, f.height() & !1) != size {
                        continue;
                    }
                    let stdin = child.as_mut().and_then(|c| c.stdin.as_mut()).ok_or("ffmpeg closed its input")?;
                    stdin.write_all(to_rgba(&f).as_raw()).map_err(|e| format!("ffmpeg: {}", e))?;
                    n += 1;
                }
                let Some(mut c) = child else { return Err("no frame was filmed".into()) };
                drop(c.stdin.take());
                let status = c.wait().map_err(|e| format!("ffmpeg: {}", e))?;
                if !status.success() {
                    return Err("ffmpeg failed".into());
                }
                Ok(format!("{} ({} frames at {} fps, {:.0} s{})", out.display(), n, fps, n as f32 / fps.max(1) as f32, size_note(&out)))
            })();
            let _ = dtx.send(result);
        });
        Recorder { tx: Some(tx), done: drx, sent: 0 }
    }

    pub fn push(&mut self, img: std::sync::Arc<egui::ColorImage>) {
        if let Some(tx) = &self.tx {
            let _ = tx.send(img);
            self.sent += 1;
        }
    }

    /// No more frames: the encoder finishes and reports.
    pub fn finish(&mut self) {
        self.tx = None;
    }

    pub fn finishing(&self) -> bool {
        self.tx.is_none()
    }

    pub fn result(&mut self) -> Option<Result<String, String>> {
        self.done.try_recv().ok()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn steps_group_bursts_and_honour_overrides() {
        let ev: Vec<(i64, String, bool)> = vec![(0, "a".into(), false), (1, "b".into(), false), (10, "c".into(), true), (100, "d".into(), false)];
        let mut story = Story::default();
        story.group_secs = 2.0;
        story.step_secs = 1.0;
        story.pause_significant = 0.5;
        story.steps.insert("d".into(), StepOverride { secs: Some(3.0), caption: Some("the end".into()), ..Default::default() });
        let steps = build_steps(&ev, &story);
        assert_eq!(steps.len(), 3);
        assert_eq!((steps[0].from, steps[0].to), (0, 2));
        assert!(steps[1].significant);
        assert!((steps[1].pause - 0.5).abs() < 1e-6);
        assert!((steps[2].dur - 3.0).abs() < 1e-6);
        assert_eq!(steps[2].caption.as_deref(), Some("the end"));
        assert!((steps[1].start - 1.0).abs() < 1e-6);
        assert!((steps[2].start - 2.5).abs() < 1e-6);
        assert_eq!(at(&steps, 0.5), Some((0, 0.5)));
        assert_eq!(at(&steps, 2.2), Some((1, 1.0)));
        assert!((total_secs(&steps, &story) - (5.5 + 3.0)).abs() < 1e-6);
        story.steps.get_mut("d").unwrap().skip = true;
        assert_eq!(build_steps(&ev, &story).len(), 2);
        story.timing = Timing::Compressed;
        story.compress = 10.0;
        let s2 = build_steps(&ev, &story);
        assert!((s2[1].dur - 1.0).abs() < 1e-6, "{:?}", s2[1]);
    }

    #[test]
    fn a_gif_carries_only_what_changed_and_keeps_its_clock() {
        let (w, h) = (64usize, 40usize);
        let mut pixels = vec![egui::Color32::from_rgb(12, 14, 20); w * h];
        let frame = |px: &Vec<egui::Color32>| egui::ColorImage { size: [w, h], source_size: egui::Vec2::new(w as f32, h as f32), pixels: px.clone() };
        let mut out: Vec<u8> = Vec::new();
        {
            let mut sink = GifSink::new(&mut out, w, h, 20, Quality::Balanced).unwrap();
            sink.push(&frame(&pixels)).unwrap();
            // four still frames, then a 10 x 10 square lights up
            for _ in 0..4 {
                sink.push(&frame(&pixels)).unwrap();
            }
            for y in 10..20 {
                for x in 30..40 {
                    pixels[y * w + x] = egui::Color32::from_rgb(0, 200, 180);
                }
            }
            sink.push(&frame(&pixels)).unwrap();
            // a breath under the tolerance changes nothing
            for p in pixels.iter_mut() {
                *p = egui::Color32::from_rgb(p.r().saturating_add(2), p.g(), p.b());
            }
            sink.push(&frame(&pixels)).unwrap();
            assert_eq!(sink.finish().unwrap(), 2);
        }
        let mut dec = gif::DecodeOptions::new();
        dec.set_color_output(gif::ColorOutput::Indexed);
        let mut r = dec.read_info(std::io::Cursor::new(out)).unwrap();
        let first = r.read_next_frame().unwrap().unwrap().clone();
        assert_eq!((first.left, first.top, first.width, first.height), (0, 0, 64, 40));
        assert_eq!(first.delay, 5);
        let second = r.read_next_frame().unwrap().unwrap().clone();
        // the square alone, after the four still frames' time (5 x 5 hundredths)
        assert_eq!((second.left, second.top, second.width, second.height), (30, 10, 10, 10));
        assert_eq!(second.delay, 25);
        assert!(second.transparent.is_some());
        let third = r.read_next_frame().unwrap().unwrap().clone();
        // the last breath's time, on a still pixel
        assert_eq!((third.width, third.height, third.delay), (1, 1, 5));
        assert!(r.read_next_frame().unwrap().is_none());
    }

    #[test]
    fn the_cards_make_room_and_the_clock_card_has_its_words() {
        let events = vec![(1_000_000i64, "a".to_string(), false), (1_000_600, "b".to_string(), true), (1_000_600 + 2 * 86_400 + 3 * 3600, "c".to_string(), false)];
        let mut story = Story::default();
        let plain = build_steps(&events, &story);
        assert_eq!(plain[0].start, 0.0);
        let plain_total = total_secs(&plain, &story);
        story.cinematic = true;
        let steps = build_steps(&events, &story);
        assert_eq!(steps[0].start, CARD_IN);
        assert_eq!(total_secs(&steps, &story), plain_total + CARD_IN + CARD_OUT);
        assert_eq!(steps[2].gap, 2 * 86_400 + 3 * 3600);
        assert!(steps[2].gap >= jump_threshold(&steps) && steps[1].gap < jump_threshold(&steps));
        // hops ten hours apart: only a much longer gap is a jump
        let sparse: Vec<(i64, String, bool)> = (0..20).map(|i| (i * 36_000 + if i == 10 { 5 * 86_400 } else { 0 }, format!("k{}", i), false)).collect();
        let sparse_steps = build_steps(&sparse, &story);
        assert_eq!(jump_threshold(&sparse_steps), 30 * 3600);
        assert_eq!(sparse_steps.iter().filter(|s| s.gap >= jump_threshold(&sparse_steps)).count(), 1);
        assert_eq!(jump_label(steps[2].gap), "2 days 3 h later");
        assert_eq!(jump_label(14 * 3600), "14 h later");
        assert_eq!(jump_label(2 * 3600 + 40 * 60), "2 h 40 min later");
        assert_eq!(jump_label(45 * 60), "45 min later");
        assert_eq!(speed_label(&steps[0]), "a hop every 0.8 s");
        assert!(speed_change(&steps[0], &steps[1]).is_none());
        // a stretch by the clock from the second event on: the pace changes there
        story.stretches.push(Stretch { from: "1970-01-12 13:50".into(), to: String::new(), timing: Timing::Compressed, step_secs: 0.8, compress: 600.0 });
        let steps = build_steps(&events, &story);
        assert_eq!(steps[1].timing, Timing::Compressed);
        assert_eq!(speed_label(&steps[1]), "time ×600  ·  10 min/s");
        assert_eq!(speed_change(&steps[0], &steps[1]), Some(true));
        assert!(speed_change(&steps[1], &steps[2]).is_none());
    }

    #[test]
    fn a_stretch_sets_its_own_speed() {
        let mut story = Story::default();
        story.group_secs = 0.0;
        story.step_secs = 1.0;
        story.stretches.push(Stretch { from: "2024-01-01 10:00".into(), to: "2024-01-01 11:00".into(), timing: Timing::Fixed, step_secs: 0.25, compress: 600.0 });
        let t = |s: &str| super::super::query::parse_time(s).unwrap();
        let events = vec![
            (t("2024-01-01 09:30"), "a:1".to_string(), false),
            (t("2024-01-01 10:15"), "a:2".to_string(), false),
            (t("2024-01-01 10:45"), "a:3".to_string(), false),
            (t("2024-01-01 11:30"), "a:4".to_string(), false),
        ];
        let steps = build_steps(&events, &story);
        let durs: Vec<f32> = steps.iter().map(|s| s.dur).collect();
        assert_eq!(durs, vec![1.0, 0.25, 0.25, 1.0]);
        assert_eq!(clock_label(600.0), "10 min/s");
        assert_eq!(clock_label(5400.0), "1.5 h/s");
        assert_eq!(clock_label(2.0 * 86_400.0), "2 day/s");
    }

    #[test]
    fn anonymiser_is_consistent() {
        let a = Anonymiser::new();
        assert_eq!(a.host(7, false), "HOST-01");
        assert_eq!(a.host(9, true), "10.x.x.2");
        assert_eq!(a.host(7, false), "HOST-01");
        assert_eq!(a.user(3), "user-01");
    }
}
