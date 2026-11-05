//! `-a view`: the graph viewer, a window of masstin's own.
//!
//! One timeline (or several) is read into memory (`store`), the analyst's
//! filter selects a graph from it (`query`), a force simulation lays it
//! out (`layout`) and `app` draws it the way Neo4j Browser draws a graph:
//! coloured circles with the host name inside, thin edges carrying the
//! account, a details pane for what is selected. Marks (verdict, notes)
//! go straight into the CSV. No server, no browser.

mod app;
mod devices;
mod draw;
pub(crate) mod icons;
mod layout;
mod notes;
pub(crate) mod theme;
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
    /// `glow` (OpenGL) or `wgpu`; None means glow, unless `MASSTIN_VIEW_RENDERER` says
    pub renderer: Option<String>,
}

/// What draws the window when nothing is asked for: OpenGL, unless this
/// is a remote desktop session or the only display adapter is Windows'
/// basic one (a VM or a server without a GPU driver). There OpenGL has
/// only the generic 1.1 driver, the CPU pixel by pixel, while Direct3D 12
/// still has WARP, far quicker: wgpu then. Linux and macOS keep OpenGL.
fn pick_renderer() -> (eframe::Renderer, String) {
    #[cfg(windows)]
    {
        if remote_session() {
            return (eframe::Renderer::Wgpu, "a remote desktop session, where OpenGL has only the generic driver".to_string());
        }
        let adapters = display_adapters();
        if std::env::var_os("MASSTIN_VIEW_DEBUG").is_some() {
            eprintln!("[view] display adapters: {}", if adapters.is_empty() { "none".to_string() } else { adapters.join(", ") });
        }
        if basic_display_only(&adapters) {
            return (eframe::Renderer::Wgpu, "no GPU driver, only the basic display adapter: Direct3D 12 through its software rasteriser".to_string());
        }
    }
    (eframe::Renderer::Glow, String::new())
}

/// Whether this process runs in a remote desktop session (`SM_REMOTESESSION`).
#[cfg(windows)]
fn remote_session() -> bool {
    #[link(name = "user32")]
    extern "system" {
        fn GetSystemMetrics(n: i32) -> i32;
    }
    // SAFETY: a plain Win32 query with a constant argument
    unsafe { GetSystemMetrics(0x1000) != 0 }
}

/// The names of the active display adapters (`EnumDisplayDevicesW`).
#[cfg(windows)]
fn display_adapters() -> Vec<String> {
    #[repr(C)]
    struct DisplayDeviceW {
        cb: u32,
        device_name: [u16; 32],
        device_string: [u16; 128],
        state_flags: u32,
        device_id: [u16; 128],
        device_key: [u16; 128],
    }
    #[link(name = "user32")]
    extern "system" {
        fn EnumDisplayDevicesW(device: *const u16, index: u32, out: *mut DisplayDeviceW, flags: u32) -> i32;
    }
    const DISPLAY_DEVICE_ACTIVE: u32 = 0x1;
    let mut out = Vec::new();
    for i in 0..32u32 {
        let mut d = DisplayDeviceW { cb: std::mem::size_of::<DisplayDeviceW>() as u32, device_name: [0; 32], device_string: [0; 128], state_flags: 0, device_id: [0; 128], device_key: [0; 128] };
        // SAFETY: the struct is the documented layout, its size in `cb`, and outlives the call
        if unsafe { EnumDisplayDevicesW(std::ptr::null(), i, &mut d, 0) } == 0 {
            break;
        }
        if d.state_flags & DISPLAY_DEVICE_ACTIVE == 0 {
            continue;
        }
        let n = d.device_string.iter().position(|&c| c == 0).unwrap_or(d.device_string.len());
        out.push(String::from_utf16_lossy(&d.device_string[..n]));
    }
    out
}

/// No adapter, or only the ones Windows draws by itself without a GPU driver.
fn basic_display_only(adapters: &[String]) -> bool {
    adapters.is_empty()
        || adapters.iter().all(|a| {
            let l = a.to_ascii_lowercase();
            ["basic display", "basic render", "hyper-v video", "remote display", "rdp "].iter().any(|k| l.contains(k))
        })
}

#[cfg(test)]
mod renderer_pick_tests {
    use super::basic_display_only;

    #[test]
    fn basic_adapters_are_told_from_gpus() {
        let s = |v: &[&str]| v.iter().map(|x| x.to_string()).collect::<Vec<_>>();
        assert!(basic_display_only(&s(&[])));
        assert!(basic_display_only(&s(&["Microsoft Basic Display Adapter"])));
        assert!(basic_display_only(&s(&["Microsoft Hyper-V Video", "Microsoft Basic Display Adapter"])));
        assert!(!basic_display_only(&s(&["NVIDIA GeForce GTX 1050", "Intel(R) UHD Graphics 630"])));
        assert!(!basic_display_only(&s(&["Microsoft Basic Display Adapter", "AMD Radeon RX 6800"])));
        assert!(!basic_display_only(&s(&["VMware SVGA 3D"])));
    }
}

/// Open the window; returns when it is closed.
pub fn run(opts: Options) -> Result<(), Box<dyn std::error::Error>> {
    let clock = std::time::Instant::now();
    let store = if opts.files.is_empty() {
        crate::banner::print_phase("1", "2", "No timeline given: the window opens on its welcome (open one, or drop evidence on it)");
        store::Store::load_with(&[], opts.alpha, &[])?
    } else {
        crate::banner::print_phase("1", "2", "Reading the timeline...");
        for f in &opts.files {
            crate::banner::print_phase_detail("File:", f);
        }
        let merges = views::ViewsFile::load(&views::ViewsFile::path_for(&opts.files[0])).merges;
        store::Store::load_with(&opts.files, opts.alpha, &merges)?
    };
    if !opts.files.is_empty() {
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
    }
    crate::banner::print_phase("2", "2", "Opening the viewer (close the window to end)");
    let title = if opts.files.is_empty() { "masstin".to_string() } else { format!("masstin — {}", opts.files.iter().map(|f| std::path::Path::new(f).file_name().map(|n| n.to_string_lossy().to_string()).unwrap_or_else(|| f.clone())).collect::<Vec<_>>().join(", ")) };
    let icon = image::load_from_memory(include_bytes!("../../resources/masstin_icon.png")).ok().map(|img| {
        let rgba = img.to_rgba8();
        let (w, h) = (rgba.width(), rgba.height());
        std::sync::Arc::new(egui::IconData { rgba: rgba.into_raw(), width: w, height: h })
    });
    let mut viewport = egui::ViewportBuilder::default().with_title(&title).with_inner_size([1460.0, 900.0]).with_min_inner_size([900.0, 600.0]).with_app_id("masstin");
    if let Some(icon) = icon {
        viewport = viewport.with_icon(icon);
    }
    let backend = opts.renderer.clone().or_else(|| std::env::var("MASSTIN_VIEW_RENDERER").ok()).unwrap_or_default().trim().to_ascii_lowercase();
    let (renderer, why) = match backend.as_str() {
        "wgpu" => (eframe::Renderer::Wgpu, "asked for".to_string()),
        "glow" | "opengl" => (eframe::Renderer::Glow, String::new()),
        "" => pick_renderer(),
        other => return Err(Box::from(format!("unknown renderer '{}': glow (OpenGL) or wgpu", other))),
    };
    if renderer == eframe::Renderer::Wgpu {
        crate::banner::print_info(&format!("Renderer: wgpu, Direct3D 12 / Vulkan / Metal ({})", why));
    }
    let native = eframe::NativeOptions { viewport, renderer, ..Default::default() };
    let app_opts = opts;
    eframe::run_native("masstin", native, Box::new(move |cc| Ok(Box::new(app::Viewer::new(cc, store, app_opts))))).map_err(|e| Box::<dyn std::error::Error>::from(e.to_string()))?;
    Ok(())
}
