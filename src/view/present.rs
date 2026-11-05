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
}

impl Default for Story {
    fn default() -> Self {
        Story { title: String::new(), timing: Timing::Fixed, step_secs: 0.8, compress: 600.0, min_gap: 0.3, max_gap: 3.0, group_secs: 2.0, pause_significant: 1.2, fade_old: false, show_clock: true, show_caption: true, show_counter: true, anonymise: false, hold_end: 3.0, steps: HashMap::new(), stretches: Vec::new(), logo: String::new(), logo_pos: LogoPos::BottomRight, logo_width: 0.12, logo_opacity: 0.9, logo_always: false }
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
        let start = steps.last().map(|s| s.start + s.dur + s.pause).unwrap_or(0.0);
        steps.push(Step { key: key.clone(), from: i, to: j, t: t0, start, dur, pause, significant: sig, emphasis: ov.map_or(false, |o| o.emphasis), caption: ov.and_then(|o| o.caption.clone()) });
        i = j;
    }
    steps
}

/// Total length of the presentation in seconds.
pub fn total_secs(steps: &[Step], story: &Story) -> f32 {
    steps.last().map(|s| s.start + s.dur + s.pause).unwrap_or(0.0) + story.hold_end
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

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
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
    pub fn start(fps: u32, format: Format, out: std::path::PathBuf) -> Recorder {
        // bounded: the window waits for the encoder instead of piling frames up in memory
        let (tx, rx) = std::sync::mpsc::sync_channel::<std::sync::Arc<egui::ColorImage>>(3);
        let (dtx, drx) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            let result = (|| -> Result<String, String> {
                let mut n = 0usize;
                match format {
                    Format::Gif => {
                        let file = std::fs::File::create(&out).map_err(|e| e.to_string())?;
                        let mut enc = image::codecs::gif::GifEncoder::new_with_speed(std::io::BufWriter::with_capacity(1 << 20, file), 30);
                        enc.set_repeat(image::codecs::gif::Repeat::Infinite).map_err(|e| e.to_string())?;
                        let delay = image::Delay::from_numer_denom_ms(1000, fps.max(1));
                        while let Ok(f) = rx.recv() {
                            enc.encode_frame(image::Frame::from_parts(to_rgba(&f), 0, 0, delay)).map_err(|e| e.to_string())?;
                            n += 1;
                        }
                        Ok(format!("{} ({} frames at {} fps)", out.display(), n, fps))
                    }
                    Format::Png | Format::Mp4 => {
                        let dir = if format == Format::Png { out.clone() } else { out.with_extension("frames") };
                        std::fs::create_dir_all(&dir).map_err(|e| e.to_string())?;
                        while let Ok(f) = rx.recv() {
                            let p = dir.join(format!("frame_{:05}.png", n));
                            to_rgba(&f).save(&p).map_err(|e| e.to_string())?;
                            n += 1;
                        }
                        if format == Format::Png {
                            return Ok(format!("{} frames in {}", n, dir.display()));
                        }
                        let status = std::process::Command::new("ffmpeg")
                            .args(["-y", "-framerate", &fps.to_string(), "-i"])
                            .arg(dir.join("frame_%05d.png"))
                            .args(["-c:v", "libx264", "-pix_fmt", "yuv420p", "-crf", "18", "-movflags", "+faststart"])
                            .arg(&out)
                            .stdout(std::process::Stdio::null())
                            .stderr(std::process::Stdio::null())
                            .status()
                            .map_err(|e| format!("ffmpeg: {}", e))?;
                        if !status.success() {
                            return Err(format!("ffmpeg failed; the frames are in {}", dir.display()));
                        }
                        let _ = std::fs::remove_dir_all(&dir);
                        Ok(format!("{} ({} frames at {} fps)", out.display(), n, fps))
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
    pub fn start_stream(fps: u32, out: std::path::PathBuf) -> Recorder {
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
                            .args(["-c:v", "libx264", "-preset", "veryfast", "-pix_fmt", "yuv420p", "-crf", "18", "-movflags", "+faststart"])
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
                Ok(format!("{} ({} frames at {} fps, {:.0} s)", out.display(), n, fps, n as f32 / fps.max(1) as f32))
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
