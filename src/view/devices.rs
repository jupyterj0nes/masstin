//! Hosts drawn as the machines they are: a monitor with its screen lit,
//! a laptop, a rack server with its lights, a domain controller with its
//! badge, an antenna for an address, a globe, a database, a cloud, a
//! router, a phone. Vector, in the host's colour, on a glow that sits
//! them on the canvas; the small lights breathe when motion is on.

use egui::epaint::{EllipseShape, Mesh, Shape, Vertex, WHITE_UV};
use egui::{Color32, CornerRadius, Pos2, Rect, Stroke, Vec2};

use super::draw::{darken, fade, lighten};
use super::theme;

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Device {
    Workstation,
    Laptop,
    Server,
    DomainController,
    Address,
    Globe,
    Database,
    Cloud,
    Router,
    Phone,
}

impl Device {
    /// The catalogue key of a device, when the key names one.
    pub fn from_key(key: &str) -> Option<Device> {
        Some(match key.to_ascii_lowercase().as_str() {
            "workstation" => Device::Workstation,
            "laptop" | "tablet" => Device::Laptop,
            "server" | "tower" => Device::Server,
            "dc" => Device::DomainController,
            "ip" => Device::Address,
            "globe" | "cloud-ext" => Device::Globe,
            "database" => Device::Database,
            "cloud" => Device::Cloud,
            "router" => Device::Router,
            "phone" => Device::Phone,
            _ => return None,
        })
    }
}

/// A vertical gradient over a rounded rectangle (approximated by a quad
/// mesh; the corners are rounded by the frame drawn over it).
fn vgrad(painter: &egui::Painter, rect: Rect, top: Color32, bottom: Color32) {
    let mut m = Mesh::default();
    let i0 = 0;
    m.vertices.push(Vertex { pos: rect.left_top(), uv: WHITE_UV, color: top });
    m.vertices.push(Vertex { pos: rect.right_top(), uv: WHITE_UV, color: top });
    m.vertices.push(Vertex { pos: rect.right_bottom(), uv: WHITE_UV, color: bottom });
    m.vertices.push(Vertex { pos: rect.left_bottom(), uv: WHITE_UV, color: bottom });
    m.add_triangle(i0, i0 + 1, i0 + 2);
    m.add_triangle(i0, i0 + 2, i0 + 3);
    painter.add(Shape::mesh(m));
}

fn ellipse(painter: &egui::Painter, c: Pos2, radius: Vec2, fill: Color32, stroke: Stroke) {
    painter.add(Shape::Ellipse(EllipseShape { center: c, radius, fill, stroke, angle: 0.0 }));
}

/// The glow a machine stands on, and a faint halo so it belongs to the canvas.
fn pedestal(painter: &egui::Painter, c: Pos2, r: f32, base: Color32, alpha: f32) {
    // the shadow the machine casts, then the glow it stands in
    ellipse(painter, Pos2::new(c.x, c.y + r * 1.0), Vec2::new(r * 1.0, r * 0.2), fade(Color32::BLACK, 0.4 * alpha), Stroke::NONE);
    ellipse(painter, Pos2::new(c.x, c.y + r * 0.95), Vec2::new(r * 1.15, r * 0.22), fade(base, 0.22 * alpha), Stroke::NONE);
    ellipse(painter, Pos2::new(c.x, c.y + r * 0.95), Vec2::new(r * 0.8, r * 0.12), fade(lighten(base, 0.3), 0.18 * alpha), Stroke::NONE);
    painter.circle_filled(c, r * 1.25, fade(base, 0.05 * alpha));
}

/// A small light: a dot with a halo; `on` from 0 to 1.
fn led(painter: &egui::Painter, c: Pos2, r: f32, color: Color32, on: f32, alpha: f32) {
    painter.circle_filled(c, r * 2.2, fade(color, 0.22 * on * alpha));
    painter.circle_filled(c, r, fade(lighten(color, 0.2 * on), (0.45 + 0.55 * on) * alpha));
}

/// A lit screen: bezel, gradient, a tiny graph line and a scanline.
fn screen(painter: &egui::Painter, rect: Rect, base: Color32, ring: Color32, alpha: f32, t: f32, motion: bool, corner: f32) {
    let cr = CornerRadius::same(corner.clamp(1.0, 40.0) as u8);
    painter.rect_filled(rect, cr, fade(darken(base, 0.62), alpha));
    let inner = rect.shrink(rect.width() * 0.06);
    vgrad(painter, inner, fade(lighten(base, 0.22), alpha), fade(darken(base, 0.18), alpha));
    // a graph on the screen, in the brand's cyan
    let w = inner.width();
    let h = inner.height();
    let pts: Vec<Pos2> = [(0.08, 0.72), (0.28, 0.5), (0.46, 0.6), (0.64, 0.3), (0.82, 0.42), (0.94, 0.25)].iter().map(|(x, y)| Pos2::new(inner.left() + w * x, inner.top() + h * y)).collect();
    painter.add(Shape::line(pts.clone(), Stroke::new((h * 0.08).max(1.0), fade(theme::CYAN, 0.9 * alpha))));
    painter.add(Shape::line(pts.clone(), Stroke::new((h * 0.2).max(2.0), fade(theme::CYAN, 0.18 * alpha))));
    for p in &pts {
        painter.circle_filled(*p, (h * 0.06).max(1.0), fade(Color32::WHITE, 0.9 * alpha));
    }
    if motion {
        let y = inner.top() + h * (t * 0.35).fract();
        painter.rect_filled(Rect::from_min_max(Pos2::new(inner.left(), y), Pos2::new(inner.right(), y + (h * 0.06).max(1.0))), CornerRadius::ZERO, fade(Color32::WHITE, 0.12 * alpha));
    }
    // glass reflection
    painter.add(Shape::convex_polygon(vec![inner.left_top(), Pos2::new(inner.left() + w * 0.45, inner.top()), Pos2::new(inner.left(), inner.top() + h * 0.55)], fade(Color32::WHITE, 0.07 * alpha), Stroke::NONE));
    painter.rect_stroke(rect, cr, Stroke::new(1.0, fade(lighten(ring, 0.1), 0.8 * alpha)), egui::StrokeKind::Inside);
}

/// Draw `device` centred on `c`, fitting a circle of radius `r`.
#[allow(clippy::too_many_arguments)]
pub fn draw(painter: &egui::Painter, device: Device, c: Pos2, r: f32, base: Color32, ring: Color32, alpha: f32, t: f32, motion: bool) {
    pedestal(painter, c, r, base, alpha);
    let edge = Stroke::new(1.0, fade(lighten(ring, 0.1), 0.8 * alpha));
    let body_top = fade(darken(base, 0.25), alpha);
    let body_bottom = fade(darken(base, 0.55), alpha);
    let rr = |x0: f32, y0: f32, x1: f32, y1: f32| Rect::from_min_max(Pos2::new(c.x + r * x0, c.y + r * y0), Pos2::new(c.x + r * x1, c.y + r * y1));
    match device {
        Device::Workstation => {
            // stand and base first, the monitor over them
            painter.rect_filled(rr(-0.5, 0.62, 0.5, 0.74), CornerRadius::same((r * 0.06) as u8), fade(darken(base, 0.5), alpha));
            painter.line_segment([Pos2::new(c.x - r * 0.45, c.y + r * 0.63), Pos2::new(c.x + r * 0.45, c.y + r * 0.63)], Stroke::new(1.0, fade(lighten(ring, 0.2), 0.5 * alpha)));
            painter.rect_filled(rr(-0.12, 0.34, 0.12, 0.64), CornerRadius::same(2), fade(darken(base, 0.45), alpha));
            screen(painter, rr(-1.05, -0.95, 1.05, 0.36), base, ring, alpha, t, motion, r * 0.1);
        }
        Device::Laptop => {
            screen(painter, rr(-0.9, -0.88, 0.9, 0.18), base, ring, alpha, t, motion, r * 0.08);
            let base_r = rr(-1.12, 0.18, 1.12, 0.46);
            painter.rect_filled(base_r, CornerRadius::same((r * 0.08) as u8), fade(darken(base, 0.45), alpha));
            vgrad(painter, base_r.shrink2(Vec2::new(r * 0.02, r * 0.02)), fade(darken(base, 0.3), alpha), fade(darken(base, 0.55), alpha));
            for row in 0..2 {
                for k in 0..9 {
                    let x = c.x - r * 0.8 + k as f32 * r * 0.2;
                    let y = c.y + r * (0.24 + row as f32 * 0.09);
                    painter.rect_filled(Rect::from_min_size(Pos2::new(x, y), Vec2::new(r * 0.14, r * 0.06)), CornerRadius::same(1), fade(lighten(base, 0.1), 0.35 * alpha));
                }
            }
            painter.rect_filled(rr(-0.2, 0.36, 0.2, 0.44), CornerRadius::same(1), fade(lighten(base, 0.1), 0.25 * alpha));
            painter.rect_stroke(base_r, CornerRadius::same((r * 0.08) as u8), edge, egui::StrokeKind::Inside);
        }
        Device::Server | Device::DomainController => {
            let units = if device == Device::DomainController { 4 } else { 3 };
            let body = rr(-0.78, -0.98, 0.78, 0.98);
            painter.rect_filled(body, CornerRadius::same((r * 0.08) as u8), body_bottom);
            vgrad(painter, body.shrink(r * 0.03), body_top, body_bottom);
            let pitch = 1.86 / units as f32;
            for k in 0..units {
                let y0 = -0.9 + k as f32 * pitch;
                let unit = rr(-0.68, y0, 0.68, y0 + pitch * 0.82);
                painter.rect_filled(unit, CornerRadius::same((r * 0.05) as u8), fade(darken(base, 0.15), alpha));
                painter.line_segment([Pos2::new(unit.left() + 2.0, unit.top() + 1.0), Pos2::new(unit.right() - 2.0, unit.top() + 1.0)], Stroke::new(1.0, fade(lighten(base, 0.35), 0.45 * alpha)));
                // the handle, the vents, the lights
                painter.rect_filled(Rect::from_min_max(Pos2::new(unit.left() + r * 0.08, unit.center().y - r * 0.05), Pos2::new(unit.left() + r * 0.4, unit.center().y + r * 0.05)), CornerRadius::same(2), fade(lighten(base, 0.25), 0.5 * alpha));
                for v in 0..3 {
                    let y = unit.top() + unit.height() * (0.3 + 0.2 * v as f32);
                    painter.line_segment([Pos2::new(unit.left() + r * 0.5, y), Pos2::new(unit.left() + r * 0.95, y)], Stroke::new(1.0, fade(Color32::BLACK, 0.35 * alpha)));
                }
                let blink = if motion { 0.55 + 0.45 * (t * 2.6 + k as f32 * 1.7).sin() } else { 0.85 };
                led(painter, Pos2::new(unit.right() - r * 0.14, unit.center().y), (r * 0.045).max(1.0), theme::CYAN, blink, alpha);
                led(painter, Pos2::new(unit.right() - r * 0.28, unit.center().y), (r * 0.045).max(1.0), if k == 1 { theme::MAGENTA } else { theme::CYAN }, if motion { 0.5 + 0.5 * (t * 1.3 + k as f32).cos() } else { 0.7 }, alpha);
            }
            painter.rect_stroke(body, CornerRadius::same((r * 0.08) as u8), edge, egui::StrokeKind::Inside);
            if device == Device::DomainController {
                // the badge: the keeper of the keys
                let bc = Pos2::new(c.x + r * 0.72, c.y - r * 0.92);
                painter.circle_filled(bc, r * 0.36, fade(theme::MAGENTA, 0.25 * alpha));
                painter.circle_filled(bc, r * 0.27, fade(theme::MAGENTA, 0.95 * alpha));
                painter.circle_stroke(bc, r * 0.27, Stroke::new(1.0, fade(Color32::WHITE, 0.7 * alpha)));
                painter.text(bc, egui::Align2::CENTER_CENTER, super::icons::KEY, egui::FontId::proportional((r * 0.34).max(7.0)), fade(Color32::WHITE, 0.96 * alpha));
            }
        }
        Device::Address => {
            // a mast with a beacon and ripples
            painter.rect_filled(rr(-0.35, 0.78, 0.35, 0.9), CornerRadius::same(3), fade(darken(base, 0.4), alpha));
            painter.line_segment([Pos2::new(c.x, c.y + r * 0.8), Pos2::new(c.x, c.y - r * 0.1)], Stroke::new((r * 0.08).max(1.5), fade(lighten(base, 0.15), 0.9 * alpha)));
            painter.line_segment([Pos2::new(c.x - r * 0.28, c.y + r * 0.8), Pos2::new(c.x, c.y + r * 0.25)], Stroke::new(1.0, fade(lighten(base, 0.15), 0.6 * alpha)));
            painter.line_segment([Pos2::new(c.x + r * 0.28, c.y + r * 0.8), Pos2::new(c.x, c.y + r * 0.25)], Stroke::new(1.0, fade(lighten(base, 0.15), 0.6 * alpha)));
            let tip = Pos2::new(c.x, c.y - r * 0.12);
            led(painter, tip, (r * 0.09).max(1.5), theme::CYAN, if motion { 0.6 + 0.4 * (t * 3.0).sin() } else { 0.9 }, alpha);
            for k in 0..3 {
                let phase = if motion { ((t * 0.6 + k as f32 / 3.0).fract()) } else { (k as f32 + 0.5) / 3.0 };
                let rad = r * (0.25 + 0.65 * phase);
                let a = (1.0 - phase) * 0.7;
                let n = 18;
                let pts: Vec<Pos2> = (0..=n).map(|i| {
                    let ang = -std::f32::consts::FRAC_PI_2 - 1.1 + 2.2 * i as f32 / n as f32;
                    Pos2::new(tip.x + ang.cos() * rad, tip.y + ang.sin() * rad)
                }).collect();
                painter.add(Shape::line(pts, Stroke::new((r * 0.06).max(1.0), fade(lighten(base, 0.35), a * alpha))));
            }
        }
        Device::Globe => {
            let gr = r * 0.9;
            painter.circle_filled(c, gr, fade(darken(base, 0.3), alpha));
            let mut m = Mesh::default();
            let n = 40;
            m.vertices.push(Vertex { pos: Pos2::new(c.x - gr * 0.25, c.y - gr * 0.3), uv: WHITE_UV, color: fade(lighten(base, 0.3), alpha) });
            for k in 0..=n {
                let a = k as f32 / n as f32 * std::f32::consts::TAU;
                m.vertices.push(Vertex { pos: Pos2::new(c.x + a.cos() * gr, c.y + a.sin() * gr), uv: WHITE_UV, color: fade(darken(base, 0.35), alpha) });
            }
            for k in 0..n as u32 {
                m.add_triangle(0, 1 + k, 2 + k);
            }
            painter.add(Shape::mesh(m));
            let line = Stroke::new(1.0, fade(lighten(ring, 0.1), 0.55 * alpha));
            ellipse(painter, c, Vec2::new(gr * 0.38, gr), Color32::TRANSPARENT, line);
            ellipse(painter, c, Vec2::new(gr * 0.72, gr), Color32::TRANSPARENT, line);
            painter.line_segment([Pos2::new(c.x, c.y - gr), Pos2::new(c.x, c.y + gr)], line);
            painter.line_segment([Pos2::new(c.x - gr, c.y), Pos2::new(c.x + gr, c.y)], line);
            ellipse(painter, Pos2::new(c.x, c.y - gr * 0.5), Vec2::new(gr * 0.86, gr * 0.16), Color32::TRANSPARENT, line);
            ellipse(painter, Pos2::new(c.x, c.y + gr * 0.5), Vec2::new(gr * 0.86, gr * 0.16), Color32::TRANSPARENT, line);
            painter.circle_stroke(c, gr, Stroke::new(1.2, fade(lighten(ring, 0.1), 0.85 * alpha)));
        }
        Device::Database => {
            let body = rr(-0.72, -0.55, 0.72, 0.62);
            vgrad(painter, body, fade(darken(base, 0.2), alpha), fade(darken(base, 0.5), alpha));
            painter.line_segment([body.left_top(), body.left_bottom()], edge);
            painter.line_segment([body.right_top(), body.right_bottom()], edge);
            let ry = r * 0.24;
            ellipse(painter, Pos2::new(c.x, c.y + r * 0.62), Vec2::new(r * 0.72, ry), fade(darken(base, 0.5), alpha), edge);
            for y in [0.22, -0.18] {
                ellipse(painter, Pos2::new(c.x, c.y + r * y), Vec2::new(r * 0.72, ry), Color32::TRANSPARENT, Stroke::new(1.0, fade(lighten(ring, 0.1), 0.35 * alpha)));
            }
            ellipse(painter, Pos2::new(c.x, c.y - r * 0.55), Vec2::new(r * 0.72, ry), fade(lighten(base, 0.2), alpha), edge);
            ellipse(painter, Pos2::new(c.x - r * 0.15, c.y - r * 0.6), Vec2::new(r * 0.35, ry * 0.4), fade(Color32::WHITE, 0.1 * alpha), Stroke::NONE);
            led(painter, Pos2::new(c.x + r * 0.5, c.y + r * 0.45), (r * 0.05).max(1.0), theme::CYAN, if motion { 0.6 + 0.4 * (t * 2.0).sin() } else { 0.9 }, alpha);
        }
        Device::Cloud => {
            let fill = fade(lighten(base, 0.05), alpha);
            let parts: [(f32, f32, f32); 3] = [(-0.45, 0.12, 0.46), (0.05, -0.2, 0.6), (0.55, 0.15, 0.42)];
            for (x, y, rad) in parts {
                painter.circle_filled(Pos2::new(c.x + r * x, c.y + r * y), r * rad, fill);
            }
            painter.rect_filled(rr(-0.9, 0.08, 0.95, 0.58), CornerRadius::same((r * 0.25) as u8), fill);
            for (x, y, rad) in parts {
                painter.circle_filled(Pos2::new(c.x + r * (x - 0.1), c.y + r * (y - 0.15)), r * rad * 0.45, fade(Color32::WHITE, 0.08 * alpha));
            }
            for (x, y, rad) in parts {
                painter.circle_stroke(Pos2::new(c.x + r * x, c.y + r * y), r * rad, Stroke::new(1.0, fade(lighten(ring, 0.1), 0.35 * alpha)));
            }
            painter.line_segment([Pos2::new(c.x - r * 0.9, c.y + r * 0.58), Pos2::new(c.x + r * 0.95, c.y + r * 0.58)], edge);
        }
        Device::Router => {
            for (x0, x1) in [(-0.5, -0.72), (0.5, 0.72)] {
                painter.line_segment([Pos2::new(c.x + r * x0, c.y + r * 0.15), Pos2::new(c.x + r * x1, c.y - r * 0.85)], Stroke::new((r * 0.07).max(1.5), fade(lighten(base, 0.1), 0.9 * alpha)));
                led(painter, Pos2::new(c.x + r * x1, c.y - r * 0.85), (r * 0.07).max(1.0), theme::CYAN, if motion { 0.6 + 0.4 * (t * 2.2).sin() } else { 0.9 }, alpha);
            }
            let body = rr(-0.98, 0.12, 0.98, 0.62);
            painter.rect_filled(body, CornerRadius::same((r * 0.1) as u8), body_bottom);
            vgrad(painter, body.shrink(r * 0.03), body_top, body_bottom);
            for k in 0..5 {
                let on = if motion { 0.3 + 0.7 * ((t * 3.0 + k as f32 * 0.9).sin() * 0.5 + 0.5) } else { 0.8 };
                led(painter, Pos2::new(c.x - r * 0.6 + k as f32 * r * 0.3, c.y + r * 0.37), (r * 0.045).max(1.0), if k == 4 { theme::MAGENTA } else { theme::CYAN }, on, alpha);
            }
            painter.rect_stroke(body, CornerRadius::same((r * 0.1) as u8), edge, egui::StrokeKind::Inside);
        }
        Device::Phone => {
            let body = rr(-0.46, -0.98, 0.46, 0.98);
            painter.rect_filled(body, CornerRadius::same((r * 0.16) as u8), fade(darken(base, 0.6), alpha));
            screen(painter, rr(-0.38, -0.82, 0.38, 0.78), base, ring, alpha, t, motion, r * 0.06);
            painter.rect_filled(rr(-0.12, -0.92, 0.12, -0.88), CornerRadius::same(2), fade(lighten(base, 0.2), 0.5 * alpha));
            painter.circle_filled(Pos2::new(c.x, c.y + r * 0.88), r * 0.05, fade(lighten(base, 0.2), 0.5 * alpha));
            painter.rect_stroke(body, CornerRadius::same((r * 0.16) as u8), edge, egui::StrokeKind::Inside);
        }
    }
}

// ───────────────────────── the arcade ─────────────────────────

/// A neon stroke: a wide faint glow, a narrower one, the bright line.
fn neon(painter: &egui::Painter, pts: Vec<Pos2>, closed: bool, color: Color32, w: f32, alpha: f32) {
    let bright = lighten(color, 0.45);
    let passes = [(w * 5.0, 0.10), (w * 2.4, 0.28), (w, 0.98)];
    for (k, (width, a)) in passes.iter().enumerate() {
        let col = if k == 2 { bright } else { color };
        let stroke = Stroke::new(width.max(0.8), fade(col, a * alpha));
        if closed {
            painter.add(Shape::closed_line(pts.clone(), stroke));
        } else {
            painter.add(Shape::line(pts.clone(), stroke));
        }
    }
}

fn neon_rect(painter: &egui::Painter, rect: Rect, color: Color32, w: f32, alpha: f32) {
    neon(painter, vec![rect.left_top(), rect.right_top(), rect.right_bottom(), rect.left_bottom()], true, color, w, alpha);
}

fn neon_circle(painter: &egui::Painter, c: Pos2, r: f32, color: Color32, w: f32, alpha: f32) {
    let n = 40;
    let pts: Vec<Pos2> = (0..n).map(|i| {
        let a = i as f32 / n as f32 * std::f32::consts::TAU;
        Pos2::new(c.x + a.cos() * r, c.y + a.sin() * r)
    }).collect();
    neon(painter, pts, true, color, w, alpha);
}

/// Black inside a body so the beams behind do not show through, and the
/// scanlines of a tube.
fn cabinet_fill(painter: &egui::Painter, rect: Rect, alpha: f32) {
    painter.rect_filled(rect, CornerRadius::ZERO, fade(Color32::from_rgb(4, 3, 10), 0.92 * alpha));
    let step = 3.0;
    let mut y = rect.top() + 1.0;
    let mut m = Mesh::default();
    while y < rect.bottom() {
        let i0 = m.vertices.len() as u32;
        let col = fade(Color32::WHITE, 0.045 * alpha);
        m.vertices.push(Vertex { pos: Pos2::new(rect.left(), y), uv: WHITE_UV, color: col });
        m.vertices.push(Vertex { pos: Pos2::new(rect.right(), y), uv: WHITE_UV, color: col });
        m.vertices.push(Vertex { pos: Pos2::new(rect.right(), y + 1.0), uv: WHITE_UV, color: col });
        m.vertices.push(Vertex { pos: Pos2::new(rect.left(), y + 1.0), uv: WHITE_UV, color: col });
        m.add_triangle(i0, i0 + 1, i0 + 2);
        m.add_triangle(i0, i0 + 2, i0 + 3);
        y += step;
    }
    painter.add(Shape::mesh(m));
}

/// A pixel light: a small square, bright or dim.
fn pixel(painter: &egui::Painter, c: Pos2, s: f32, color: Color32, on: f32, alpha: f32) {
    let r = Rect::from_center_size(c, Vec2::splat(s.max(1.5)));
    painter.rect_filled(r.expand(s * 0.8), CornerRadius::ZERO, fade(color, 0.18 * on * alpha));
    painter.rect_filled(r, CornerRadius::ZERO, fade(lighten(color, 0.3 * on), (0.35 + 0.65 * on) * alpha));
}

/// Draw `device` the arcade way: neon outlines on black, centred on `c`,
/// fitting a circle of radius `r`.
#[allow(clippy::too_many_arguments)]
pub fn draw_arcade(painter: &egui::Painter, device: Device, c: Pos2, r: f32, base: Color32, _ring: Color32, alpha: f32, t: f32, motion: bool) {
    let w = (r * 0.07).clamp(1.0, 2.6);
    let col = lighten(base, 0.2);
    let rr = |x0: f32, y0: f32, x1: f32, y1: f32| Rect::from_min_max(Pos2::new(c.x + r * x0, c.y + r * y0), Pos2::new(c.x + r * x1, c.y + r * y1));
    let at = |x: f32, y: f32| Pos2::new(c.x + r * x, c.y + r * y);
    // the floor line the cabinet stands on
    neon(painter, vec![at(-1.1, 1.0), at(1.1, 1.0)], false, theme::MAGENTA, w * 0.8, 0.55 * alpha);
    let blink = |k: f32| if motion { 0.5 + 0.5 * (t * 2.4 + k * 1.9).sin() } else { 0.85 };
    match device {
        Device::Workstation => {
            let screen = rr(-1.0, -0.92, 1.0, 0.36);
            cabinet_fill(painter, screen, alpha);
            // bars on the screen, a pixel chart
            for k in 0..6 {
                let h = [0.35, 0.6, 0.45, 0.8, 0.55, 0.9][k];
                let h = if motion { h * (0.85 + 0.15 * (t * 1.7 + k as f32).sin()) } else { h };
                let x0 = screen.left() + screen.width() * (0.1 + 0.14 * k as f32);
                let bar = Rect::from_min_max(Pos2::new(x0, screen.bottom() - screen.height() * (0.1 + 0.75 * h)), Pos2::new(x0 + screen.width() * 0.09, screen.bottom() - screen.height() * 0.1));
                painter.rect_filled(bar, CornerRadius::ZERO, fade(if k % 2 == 0 { theme::CYAN } else { theme::MAGENTA }, 0.8 * alpha));
            }
            neon_rect(painter, screen, col, w, alpha);
            neon(painter, vec![at(0.0, 0.36), at(0.0, 0.66)], false, col, w, alpha);
            neon(painter, vec![at(-0.5, 0.66), at(0.5, 0.66)], false, col, w, alpha);
        }
        Device::Laptop => {
            let screen = rr(-0.85, -0.85, 0.85, 0.2);
            cabinet_fill(painter, screen, alpha);
            for k in 0..3 {
                let y = screen.top() + screen.height() * (0.3 + 0.2 * k as f32);
                painter.line_segment([Pos2::new(screen.left() + screen.width() * 0.12, y), Pos2::new(screen.left() + screen.width() * (0.4 + 0.18 * k as f32), y)], Stroke::new(w, fade(theme::CYAN, 0.8 * alpha)));
            }
            neon_rect(painter, screen, col, w, alpha);
            neon(painter, vec![at(-1.1, 0.2), at(1.1, 0.2), at(1.2, 0.5), at(-1.2, 0.5)], true, col, w, alpha);
        }
        Device::Server | Device::DomainController => {
            let body = rr(-0.75, -0.95, 0.75, 0.95);
            cabinet_fill(painter, body, alpha);
            let units = if device == Device::DomainController { 4 } else { 3 };
            let pitch = body.height() / units as f32;
            for k in 0..units {
                let y = body.top() + pitch * k as f32;
                if k > 0 {
                    painter.line_segment([Pos2::new(body.left(), y), Pos2::new(body.right(), y)], Stroke::new(w * 0.8, fade(col, 0.7 * alpha)));
                }
                let cy = y + pitch * 0.5;
                pixel(painter, Pos2::new(body.right() - r * 0.16, cy), r * 0.09, theme::CYAN, blink(k as f32), alpha);
                pixel(painter, Pos2::new(body.right() - r * 0.32, cy), r * 0.09, if k == 1 { theme::MAGENTA } else { theme::CYAN }, blink(k as f32 + 0.7), alpha);
                painter.line_segment([Pos2::new(body.left() + r * 0.12, cy), Pos2::new(body.left() + r * 0.7, cy)], Stroke::new(w * 0.9, fade(col, 0.5 * alpha)));
            }
            neon_rect(painter, body, col, w, alpha);
            if device == Device::DomainController {
                let bc = Pos2::new(c.x + r * 0.72, c.y - r * 0.9);
                painter.circle_filled(bc, r * 0.3, fade(Color32::BLACK, 0.9 * alpha));
                neon_circle(painter, bc, r * 0.3, theme::MAGENTA, w * 0.8, alpha);
                painter.text(bc, egui::Align2::CENTER_CENTER, super::icons::KEY, egui::FontId::proportional((r * 0.34).max(7.0)), fade(lighten(theme::MAGENTA, 0.5), 0.96 * alpha));
            }
        }
        Device::Address => {
            neon(painter, vec![at(-0.35, 0.9), at(0.0, -0.1), at(0.35, 0.9)], false, col, w, alpha);
            neon(painter, vec![at(-0.2, 0.5), at(0.2, 0.5)], false, col, w * 0.8, alpha);
            let tip = at(0.0, -0.15);
            pixel(painter, tip, r * 0.12, theme::MAGENTA, blink(0.0), alpha);
            for k in 0..3 {
                let phase = if motion { (t * 0.6 + k as f32 / 3.0).fract() } else { (k as f32 + 0.5) / 3.0 };
                let rad = r * (0.25 + 0.65 * phase);
                let n = 14;
                let pts: Vec<Pos2> = (0..=n).map(|i| {
                    let ang = -std::f32::consts::FRAC_PI_2 - 1.1 + 2.2 * i as f32 / n as f32;
                    Pos2::new(tip.x + ang.cos() * rad, tip.y + ang.sin() * rad)
                }).collect();
                painter.add(Shape::line(pts, Stroke::new(w, fade(theme::CYAN, (1.0 - phase) * 0.8 * alpha))));
            }
        }
        Device::Globe => {
            let gr = r * 0.9;
            painter.circle_filled(c, gr, fade(Color32::from_rgb(4, 3, 10), 0.92 * alpha));
            let line = Stroke::new(w * 0.7, fade(col, 0.55 * alpha));
            ellipse(painter, c, Vec2::new(gr * 0.4, gr), Color32::TRANSPARENT, line);
            ellipse(painter, c, Vec2::new(gr * 0.75, gr), Color32::TRANSPARENT, line);
            painter.line_segment([Pos2::new(c.x - gr, c.y), Pos2::new(c.x + gr, c.y)], line);
            ellipse(painter, Pos2::new(c.x, c.y - gr * 0.5), Vec2::new(gr * 0.86, gr * 0.16), Color32::TRANSPARENT, line);
            ellipse(painter, Pos2::new(c.x, c.y + gr * 0.5), Vec2::new(gr * 0.86, gr * 0.16), Color32::TRANSPARENT, line);
            neon_circle(painter, c, gr, col, w, alpha);
        }
        Device::Database => {
            let body = rr(-0.72, -0.55, 0.72, 0.62);
            cabinet_fill(painter, body, alpha);
            let ry = r * 0.24;
            for y in [0.62, 0.22, -0.18] {
                ellipse(painter, Pos2::new(c.x, c.y + r * y), Vec2::new(r * 0.72, ry), Color32::TRANSPARENT, Stroke::new(w * 0.8, fade(col, 0.6 * alpha)));
            }
            neon(painter, vec![body.left_top(), body.left_bottom()], false, col, w, alpha);
            neon(painter, vec![body.right_top(), body.right_bottom()], false, col, w, alpha);
            painter.add(Shape::Ellipse(EllipseShape { center: Pos2::new(c.x, c.y - r * 0.55), radius: Vec2::new(r * 0.72, ry), fill: fade(Color32::from_rgb(4, 3, 10), 0.92 * alpha), stroke: Stroke::NONE, angle: 0.0 }));
            for (k, pass) in [(w * 5.0, 0.10), (w * 2.4, 0.28), (w, 0.98)].iter().enumerate() {
                let cc = if k == 2 { lighten(col, 0.45) } else { col };
                ellipse(painter, Pos2::new(c.x, c.y - r * 0.55), Vec2::new(r * 0.72, ry), Color32::TRANSPARENT, Stroke::new(pass.0.max(0.8), fade(cc, pass.1 * alpha)));
            }
            pixel(painter, Pos2::new(c.x + r * 0.5, c.y + r * 0.45), r * 0.09, theme::CYAN, blink(1.0), alpha);
        }
        Device::Cloud => {
            let parts: [(f32, f32, f32); 3] = [(-0.45, 0.12, 0.46), (0.05, -0.2, 0.6), (0.55, 0.15, 0.42)];
            for (x, y, rad) in parts {
                painter.circle_filled(at(x, y), r * rad, fade(Color32::from_rgb(4, 3, 10), 0.92 * alpha));
            }
            painter.rect_filled(rr(-0.9, 0.08, 0.95, 0.58), CornerRadius::ZERO, fade(Color32::from_rgb(4, 3, 10), 0.92 * alpha));
            for (x, y, rad) in parts {
                neon_circle(painter, at(x, y), r * rad, col, w * 0.8, alpha * 0.8);
            }
            neon(painter, vec![at(-0.9, 0.58), at(0.95, 0.58)], false, col, w, alpha);
        }
        Device::Router => {
            let body = rr(-0.98, 0.12, 0.98, 0.62);
            cabinet_fill(painter, body, alpha);
            for (x0, x1) in [(-0.5, -0.72), (0.5, 0.72)] {
                neon(painter, vec![at(x0, 0.15), at(x1, -0.85)], false, col, w, alpha);
                pixel(painter, at(x1, -0.85), r * 0.1, theme::CYAN, blink(x1), alpha);
            }
            for k in 0..5 {
                pixel(painter, Pos2::new(c.x - r * 0.6 + k as f32 * r * 0.3, c.y + r * 0.37), r * 0.09, if k == 4 { theme::MAGENTA } else { theme::CYAN }, blink(k as f32 * 0.9), alpha);
            }
            neon_rect(painter, body, col, w, alpha);
        }
        Device::Phone => {
            let body = rr(-0.46, -0.98, 0.46, 0.98);
            cabinet_fill(painter, body, alpha);
            let screen = rr(-0.36, -0.8, 0.36, 0.76);
            painter.rect_stroke(screen, CornerRadius::ZERO, Stroke::new(w * 0.7, fade(col, 0.6 * alpha)), egui::StrokeKind::Inside);
            neon_rect(painter, body, col, w, alpha);
            pixel(painter, Pos2::new(c.x, c.y + r * 0.88), r * 0.08, theme::CYAN, blink(0.3), alpha);
        }
    }
}
