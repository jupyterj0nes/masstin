//! The window drawn without a GPU: winit for the window, egui-winit for the
//! input and the viewport commands, the CPU rasteriser in `soft` for the
//! pixels, softbuffer to hand them to the system (GDI on Windows, which a
//! remote desktop carries well).
//!
//! Over RDP or on a machine without a GPU driver, Windows draws OpenGL and
//! Direct3D in software (the generic OpenGL 1.1 driver, WARP); a frame of the
//! viewer costs 150 ms or more there. This rasteriser is made for egui's
//! meshes, keeps what it rasterised and only redraws the tiles that change:
//! measured over RDP on a 2-vCPU server, about 22 ms a frame at 1460 x 900.
//!
//! One window, no child viewports (the viewer has none). Frames are drawn on
//! demand, as egui asks, and at most `MAX_FPS` a second: a remote desktop gains
//! nothing from more, and a CPU drawing frames is a CPU not doing anything else.

use std::num::NonZeroU32;
use std::sync::Arc;
use std::time::{Duration, Instant};

use egui::{ViewportId, ViewportInfo};
use winit::application::ApplicationHandler;
use winit::event::WindowEvent;
use winit::event_loop::{ActiveEventLoop, ControlFlow, EventLoop, EventLoopProxy};
use winit::window::{Window, WindowId};

use super::soft::{BufferMutRef, ColorFieldOrder, EguiSoftwareRender};

/// Frames a second at most.
const MAX_FPS: u32 = 30;

/// What the window shows: one call per frame, as `eframe::App::ui`.
pub trait SoftApp {
    fn frame(&mut self, ui: &mut egui::Ui);
}

enum UserEvent {
    /// egui wants a frame at this time (a repaint asked from another thread too)
    RepaintAt(Instant),
}

struct Gfx {
    window: Arc<Window>,
    state: egui_winit::State,
    surface: softbuffer::Surface<Arc<Window>, Arc<Window>>,
    // kept alive with the surface
    _context: softbuffer::Context<Arc<Window>>,
}

struct Runner<A: SoftApp> {
    ctx: egui::Context,
    builder: egui::ViewportBuilder,
    app: A,
    gfx: Option<Gfx>,
    info: ViewportInfo,
    render: EguiSoftwareRender,
    /// the frame in BGRA, drawn over the background each time
    pixels: Vec<[u8; 4]>,
    background: [u8; 4],
    next_repaint: Option<Instant>,
    last_paint: Instant,
    min_gap: Duration,
    error: Option<String>,
    /// `MASSTIN_VIEW_DEBUG`: where a frame's time goes (ui, tessellate, raster, present), summed
    timing: Option<([f64; 4], u32, Instant)>,
}

/// Run `app` in a window built from `builder` until it is closed.
pub fn run<A: SoftApp + 'static>(builder: egui::ViewportBuilder, ctx: egui::Context, app: A) -> Result<(), String> {
    let event_loop = EventLoop::<UserEvent>::with_user_event().build().map_err(|e| format!("window system: {}", e))?;
    let proxy: EventLoopProxy<UserEvent> = event_loop.create_proxy();
    ctx.set_request_repaint_callback(move |info| {
        let _ = proxy.send_event(UserEvent::RepaintAt(Instant::now() + info.delay));
    });
    let fill = ctx.global_style().visuals.panel_fill;
    let mut runner = Runner {
        ctx,
        builder,
        app,
        gfx: None,
        info: ViewportInfo::default(),
        render: EguiSoftwareRender::new(ColorFieldOrder::Bgra),
        pixels: Vec::new(),
        background: [fill.b(), fill.g(), fill.r(), 255],
        next_repaint: Some(Instant::now()),
        last_paint: Instant::now() - Duration::from_secs(1),
        min_gap: Duration::from_secs_f64(1.0 / MAX_FPS as f64),
        error: None,
        timing: std::env::var_os("MASSTIN_VIEW_DEBUG").map(|_| ([0.0; 4], 0, Instant::now())),
    };
    event_loop.run_app(&mut runner).map_err(|e| format!("window system: {}", e))?;
    match runner.error {
        Some(e) => Err(e),
        None => Ok(()),
    }
}

impl<A: SoftApp> Runner<A> {
    fn create(&mut self, event_loop: &ActiveEventLoop) -> Result<(), String> {
        let window = Arc::new(egui_winit::create_window(&self.ctx, event_loop, &self.builder).map_err(|e| format!("cannot open the window: {}", e))?);
        let state = egui_winit::State::new(self.ctx.clone(), ViewportId::ROOT, event_loop, Some(window.scale_factor() as f32), window.theme(), None);
        let context = softbuffer::Context::new(window.clone()).map_err(|e| format!("software surface: {}", e))?;
        let surface = softbuffer::Surface::new(&context, window.clone()).map_err(|e| format!("software surface: {}", e))?;
        egui_winit::update_viewport_info(&mut self.info, &self.ctx, &window, true);
        self.gfx = Some(Gfx { window, state, surface, _context: context });
        self.next_repaint = Some(Instant::now());
        Ok(())
    }

    fn paint(&mut self, event_loop: &ActiveEventLoop) {
        let Some(gfx) = self.gfx.as_mut() else { return };
        // the frame cap counts from the start of a frame, not its end
        let started = Instant::now();
        let window = gfx.window.clone();
        egui_winit::update_viewport_info(&mut self.info, &self.ctx, &window, false);
        let mut raw = gfx.state.take_egui_input(&window);
        raw.viewports.insert(ViewportId::ROOT, self.info.clone());
        self.info.events.clear();
        let t_ui = Instant::now();
        let app = &mut self.app;
        let out = self.ctx.run_ui(raw, |ui| app.frame(ui));
        let ui_ms = t_ui.elapsed().as_secs_f64() * 1000.0;
        gfx.state.handle_platform_output(&window, out.platform_output);

        let mut actions = Vec::new();
        let mut delay = Duration::MAX;
        let mut viewport_output = out.viewport_output;
        if let Some(vo) = viewport_output.remove(&ViewportId::ROOT) {
            delay = vo.repaint_delay;
            egui_winit::process_viewport_commands(&self.ctx, &mut self.info, vo.commands, &window, &mut actions);
        }
        if self.info.events.iter().any(|e| matches!(e, egui::ViewportEvent::Close)) {
            event_loop.exit();
            return;
        }

        // the pixels
        let size = window.inner_size();
        if let (Some(w), Some(h)) = (NonZeroU32::new(size.width), NonZeroU32::new(size.height)) {
            let (wu, hu) = (w.get() as usize, h.get() as usize);
            let t_tess = Instant::now();
            let prims = self.ctx.tessellate(out.shapes, out.pixels_per_point);
            let tess_ms = t_tess.elapsed().as_secs_f64() * 1000.0;
            let t_raster = Instant::now();
            if self.pixels.len() != wu * hu {
                self.pixels = vec![self.background; wu * hu];
            } else {
                self.pixels.fill(self.background);
            }
            {
                let mut target = BufferMutRef::new(&mut self.pixels, wu, hu);
                self.render.render(&mut target, &prims, &out.textures_delta, out.pixels_per_point);
            }
            let raster_ms = t_raster.elapsed().as_secs_f64() * 1000.0;
            let t_present = Instant::now();
            match gfx.surface.resize(w, h).and_then(|_| gfx.surface.buffer_mut()) {
                Ok(mut buf) => {
                    for (dst, p) in buf.iter_mut().zip(self.pixels.iter()) {
                        // BGRA bytes -> 0x00RRGGBB
                        *dst = (p[2] as u32) << 16 | (p[1] as u32) << 8 | p[0] as u32;
                    }
                    if let Err(e) = buf.present() {
                        eprintln!("masstin: software window: {}", e);
                    }
                }
                Err(e) => eprintln!("masstin: software window: {}", e),
            }
            let present_ms = t_present.elapsed().as_secs_f64() * 1000.0;
            if let Some((sum, n, since)) = self.timing.as_mut() {
                for (s, v) in sum.iter_mut().zip([ui_ms, tess_ms, raster_ms, present_ms]) {
                    *s += v;
                }
                *n += 1;
                if since.elapsed().as_secs_f32() >= 2.0 {
                    let k = *n as f64;
                    eprintln!("[soft] {} frame(s): ui {:.1} ms · tessellate {:.1} · raster {:.1} · present {:.1} · {}x{} px", n, sum[0] / k, sum[1] / k, sum[2] / k, sum[3] / k, wu, hu);
                    *sum = [0.0; 4];
                    *n = 0;
                    *since = Instant::now();
                }
            }
            // what was asked of the frame: screenshots get these pixels
            let mut shot: Option<Arc<egui::ColorImage>> = None;
            for action in actions {
                match action {
                    egui_winit::ActionRequested::Screenshot(callback) => {
                        let image = shot
                            .get_or_insert_with(|| {
                                let rgba: Vec<u8> = self.pixels.iter().flat_map(|p| [p[2], p[1], p[0], 255]).collect();
                                Arc::new(egui::ColorImage::from_rgba_unmultiplied([wu, hu], &rgba))
                            })
                            .clone();
                        callback.complete(image);
                    }
                    egui_winit::ActionRequested::Cut => gfx.state.egui_input_mut().events.push(egui::Event::Cut),
                    egui_winit::ActionRequested::Copy => gfx.state.egui_input_mut().events.push(egui::Event::Copy),
                    egui_winit::ActionRequested::Paste => {
                        if let Some(text) = gfx.state.clipboard_text() {
                            let text = text.replace("\r\n", "\n");
                            if !text.is_empty() {
                                gfx.state.egui_input_mut().events.push(egui::Event::Paste(text));
                            }
                        }
                    }
                    _ => {}
                }
            }
        }
        self.last_paint = started;
        if delay < Duration::from_secs(3600) {
            self.want_repaint(self.last_paint + delay);
        }
    }

    fn want_repaint(&mut self, at: Instant) {
        self.next_repaint = Some(match self.next_repaint {
            Some(t) if t < at => t,
            _ => at,
        });
    }
}

impl<A: SoftApp> ApplicationHandler<UserEvent> for Runner<A> {
    fn resumed(&mut self, event_loop: &ActiveEventLoop) {
        if self.gfx.is_none() {
            if let Err(e) = self.create(event_loop) {
                self.error = Some(e);
                event_loop.exit();
            }
        }
    }

    fn user_event(&mut self, _event_loop: &ActiveEventLoop, event: UserEvent) {
        match event {
            UserEvent::RepaintAt(at) => self.want_repaint(at),
        }
    }

    fn window_event(&mut self, event_loop: &ActiveEventLoop, _id: WindowId, event: WindowEvent) {
        let Some(gfx) = self.gfx.as_mut() else { return };
        match &event {
            WindowEvent::CloseRequested => {
                event_loop.exit();
                return;
            }
            WindowEvent::RedrawRequested => {
                self.paint(event_loop);
                return;
            }
            _ => {}
        }
        let window = gfx.window.clone();
        let response = gfx.state.on_window_event(&window, &event);
        if response.repaint || matches!(event, WindowEvent::Resized(_) | WindowEvent::ScaleFactorChanged { .. }) {
            self.want_repaint(Instant::now());
        }
    }

    fn about_to_wait(&mut self, event_loop: &ActiveEventLoop) {
        let Some(gfx) = self.gfx.as_ref() else { return };
        match self.next_repaint {
            Some(at) => {
                // never sooner than the frame cap allows
                let at = at.max(self.last_paint + self.min_gap);
                if at <= Instant::now() {
                    self.next_repaint = None;
                    gfx.window.request_redraw();
                    event_loop.set_control_flow(ControlFlow::Wait);
                } else {
                    event_loop.set_control_flow(ControlFlow::WaitUntil(at));
                }
            }
            None => event_loop.set_control_flow(ControlFlow::Wait),
        }
    }
}
