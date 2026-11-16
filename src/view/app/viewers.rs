//! The programs a timeline can be opened in from the window: the ones
//! found on this machine (a spreadsheet, an editor) and the ones the
//! analyst added. The file handed to them is the timeline itself or a copy
//! of some of its rows, in the file's own columns either way.

use std::path::{Path, PathBuf};

/// How a program is told to open a file at a line, when it can be.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(super) enum Goto {
    /// the program takes the file only
    No,
    /// `--goto FILE:LINE` (Visual Studio Code)
    Code,
    /// `-nLINE FILE` (Notepad++)
    Npp,
}

#[derive(Clone, Debug)]
pub(super) struct ViewerApp {
    pub name: String,
    pub program: String,
    /// arguments before the file (`open -a "Microsoft Excel"`)
    pub args: Vec<String>,
    pub goto: Goto,
    /// added by the analyst (kept in `viewers.json`), not found here
    pub custom: bool,
}

fn first_existing(cands: &[PathBuf]) -> Option<String> {
    cands.iter().find(|p| p.is_file()).map(|p| p.to_string_lossy().to_string())
}

/// A program by name on the PATH.
fn on_path(name: &str) -> Option<String> {
    let paths = std::env::var_os("PATH")?;
    for dir in std::env::split_paths(&paths) {
        for ext in if cfg!(windows) { &["", ".exe", ".cmd", ".bat"][..] } else { &[""][..] } {
            let p = dir.join(format!("{name}{ext}"));
            if p.is_file() {
                return Some(p.to_string_lossy().to_string());
            }
        }
    }
    None
}

fn app(name: &str, program: String, args: &[&str], goto: Goto) -> ViewerApp {
    ViewerApp { name: name.to_string(), program, args: args.iter().map(|s| s.to_string()).collect(), goto, custom: false }
}

/// The programs found on this machine that open a CSV.
pub(super) fn detected() -> Vec<ViewerApp> {
    let mut out = Vec::new();
    if cfg!(windows) {
        let roots: Vec<PathBuf> = ["ProgramFiles", "ProgramFiles(x86)", "ProgramW6432"].iter().filter_map(|v| std::env::var_os(v).map(PathBuf::from)).collect();
        let under = |rel: &[&str]| -> Vec<PathBuf> { roots.iter().flat_map(|r| rel.iter().map(move |x| r.join(x))).collect() };
        if let Some(p) = first_existing(&under(&["Microsoft Office\\root\\Office16\\EXCEL.EXE", "Microsoft Office\\Office16\\EXCEL.EXE", "Microsoft Office\\root\\Office15\\EXCEL.EXE", "Microsoft Office\\Office15\\EXCEL.EXE"])) {
            out.push(app("Excel", p, &[], Goto::No));
        }
        if let Some(p) = first_existing(&under(&["LibreOffice\\program\\scalc.exe"])) {
            out.push(app("LibreOffice Calc", p, &[], Goto::No));
        }
        if let Some(p) = on_path("TimelineExplorer") {
            out.push(app("Timeline Explorer", p, &[], Goto::No));
        }
        let mut code: Vec<PathBuf> = std::env::var_os("LOCALAPPDATA").map(|l| vec![PathBuf::from(l).join("Programs\\Microsoft VS Code\\Code.exe")]).unwrap_or_default();
        code.extend(under(&["Microsoft VS Code\\Code.exe"]));
        if let Some(p) = first_existing(&code) {
            out.push(app("Visual Studio Code", p, &[], Goto::Code));
        }
        if let Some(p) = first_existing(&under(&["Notepad++\\notepad++.exe"])) {
            out.push(app("Notepad++", p, &[], Goto::Npp));
        }
        // part of Windows
        out.push(app("Notepad", "notepad.exe".to_string(), &[], Goto::No));
    } else if cfg!(target_os = "macos") {
        let has = |p: &str| Path::new(p).exists();
        for (name, bundle, goto) in [
            ("Excel", "/Applications/Microsoft Excel.app", Goto::No),
            ("Numbers", "/Applications/Numbers.app", Goto::No),
            ("LibreOffice", "/Applications/LibreOffice.app", Goto::No),
            ("Visual Studio Code", "/Applications/Visual Studio Code.app", Goto::No),
            ("TextEdit", "/System/Applications/TextEdit.app", Goto::No),
        ] {
            if has(bundle) {
                out.push(app(name, "open".to_string(), &["-a", bundle], goto));
            }
        }
    } else {
        for (name, bin, args, goto) in [
            ("LibreOffice Calc", "localc", &[][..], Goto::No),
            ("LibreOffice Calc", "libreoffice", &["--calc"][..], Goto::No),
            ("Gnumeric", "gnumeric", &[][..], Goto::No),
            ("Visual Studio Code", "code", &[][..], Goto::Code),
            ("Text Editor", "gnome-text-editor", &[][..], Goto::No),
            ("gedit", "gedit", &[][..], Goto::No),
            ("Kate", "kate", &[][..], Goto::No),
            ("Mousepad", "mousepad", &[][..], Goto::No),
        ] {
            if out.iter().any(|a: &ViewerApp| a.name == name) {
                continue;
            }
            if let Some(p) = on_path(bin) {
                out.push(app(name, p, args, goto));
            }
        }
    }
    out
}

/// A program the analyst picked, as an entry of the list.
pub(super) fn custom_app(program: &str) -> ViewerApp {
    // by hand: a Windows path is one name to `Path` anywhere else
    let file = program.trim_end_matches(['/', '\\']).rsplit(['/', '\\']).next().unwrap_or(program);
    let stem = match file.rsplit_once('.') {
        Some((s, ext)) if !s.is_empty() && ext.len() <= 4 => s.to_string(),
        _ => file.to_string(),
    };
    let lower = stem.to_lowercase();
    let goto = if lower == "code" || lower == "code-insiders" {
        Goto::Code
    } else if lower == "notepad++" {
        Goto::Npp
    } else {
        Goto::No
    };
    // a macOS application is a folder: it is opened through `open -a`
    if program.ends_with(".app") {
        return ViewerApp { name: stem, program: "open".to_string(), args: vec!["-a".to_string(), program.to_string()], goto: Goto::No, custom: true };
    }
    ViewerApp { name: stem, program: program.to_string(), args: Vec::new(), goto, custom: true }
}

fn custom_path() -> Option<PathBuf> {
    super::ingest::config_file("viewers.json")
}

/// The programs the analyst added (their paths).
pub(super) fn load_custom() -> Vec<String> {
    let Some(p) = custom_path() else { return Vec::new() };
    let Ok(s) = std::fs::read_to_string(&p) else { return Vec::new() };
    serde_json::from_str::<Vec<String>>(&s).unwrap_or_default()
}

pub(super) fn save_custom(list: &[String]) -> Result<(), String> {
    let p = custom_path().ok_or_else(|| "no configuration folder on this system".to_string())?;
    if let Some(dir) = p.parent() {
        std::fs::create_dir_all(dir).map_err(|e| e.to_string())?;
    }
    let s = serde_json::to_string_pretty(list).map_err(|e| e.to_string())?;
    std::fs::write(&p, s).map_err(|e| e.to_string())
}

/// Detected programs first, then the analyst's own.
pub(super) fn all() -> Vec<ViewerApp> {
    let mut out = detected();
    for p in load_custom() {
        if !out.iter().any(|a| a.program.eq_ignore_ascii_case(&p) || a.args.iter().any(|x| x == &p)) {
            out.push(custom_app(&p));
        }
    }
    out
}

/// The arguments a program is started with for a file, at a line of it
/// (1 is the header) when the program can go to one.
pub(super) fn arguments(app: &ViewerApp, path: &str, line: Option<u32>) -> Vec<String> {
    let mut out = app.args.clone();
    match (app.goto, line) {
        (Goto::Code, Some(n)) => {
            out.push("--goto".to_string());
            out.push(format!("{}:{}", path, n));
        }
        (Goto::Npp, Some(n)) => {
            out.push(format!("-n{}", n));
            out.push(path.to_string());
        }
        _ => out.push(path.to_string()),
    }
    out
}

pub(super) fn launch(app: &ViewerApp, path: &str, line: Option<u32>) -> Result<(), String> {
    let mut cmd = std::process::Command::new(&app.program);
    // every argument goes as one argument: no shell reads the path
    cmd.args(arguments(app, path, line));
    cmd.stdin(std::process::Stdio::null()).stdout(std::process::Stdio::null()).stderr(std::process::Stdio::null());
    cmd.spawn().map(|_| ()).map_err(|e| e.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_program_gets_the_file_and_the_line_when_it_can_go_to_one() {
        let excel = app("Excel", "EXCEL.EXE".into(), &[], Goto::No);
        assert_eq!(arguments(&excel, "C:\\case\\a b.csv", Some(40)), vec!["C:\\case\\a b.csv"]);
        let code = app("Visual Studio Code", "code".into(), &[], Goto::Code);
        assert_eq!(arguments(&code, "/case/t.csv", Some(40)), vec!["--goto", "/case/t.csv:40"]);
        assert_eq!(arguments(&code, "/case/t.csv", None), vec!["/case/t.csv"]);
        let npp = app("Notepad++", "notepad++.exe".into(), &[], Goto::Npp);
        assert_eq!(arguments(&npp, "t.csv", Some(7)), vec!["-n7", "t.csv"]);
        let numbers = app("Numbers", "open".into(), &["-a", "/Applications/Numbers.app"], Goto::No);
        assert_eq!(arguments(&numbers, "/case/t.csv", Some(3)), vec!["-a", "/Applications/Numbers.app", "/case/t.csv"]);
    }

    #[test]
    fn a_picked_program_is_named_after_its_file() {
        let a = custom_app("C:\\Tools\\TimelineExplorer\\TimelineExplorer.exe");
        assert_eq!((a.name.as_str(), a.goto, a.custom), ("TimelineExplorer", Goto::No, true));
        assert_eq!(custom_app("/usr/bin/code").goto, Goto::Code);
        assert_eq!(custom_app("D:\\npp\\notepad++.exe").goto, Goto::Npp);
        let mac = custom_app("/Applications/Table Tool.app");
        assert_eq!((mac.program.as_str(), mac.args.clone()), ("open", vec!["-a".to_string(), "/Applications/Table Tool.app".to_string()]));
    }
}
