//! Painting helpers for the canvas: the background with its vignette and
//! dot grid, glows, glossy host orbs, edges with a gradient from origin to
//! destination, the dots that travel along an edge, arrowheads. Pure
//! painting; no state.

use egui::epaint::{Mesh, PathStroke, QuadraticBezierShape, Shape, Vertex, WHITE_UV};
use egui::{Color32, Pos2, Rect, Stroke, Vec2};

use super::views::Shape as NodeShape;

pub fn ease_out_cubic(t: f32) -> f32 {
    let u = 1.0 - t.clamp(0.0, 1.0);
    1.0 - u * u * u
}

/// Overshoots a little and settles: the "pop" of a host that appears.
pub fn ease_out_back(t: f32) -> f32 {
    let t = t.clamp(0.0, 1.0);
    let c1 = 1.70158;
    let c3 = c1 + 1.0;
    1.0 + c3 * (t - 1.0).powi(3) + c1 * (t - 1.0).powi(2)
}

/// `c` with its alpha scaled by `k` (0..1).
pub fn fade(c: Color32, k: f32) -> Color32 {
    let [r, g, b, a] = c.to_srgba_unmultiplied();
    Color32::from_rgba_unmultiplied(r, g, b, (a as f32 * k.clamp(0.0, 1.0)) as u8)
}

pub fn mix(a: Color32, b: Color32, t: f32) -> Color32 {
    let t = t.clamp(0.0, 1.0);
    let [ar, ag, ab, aa] = a.to_srgba_unmultiplied();
    let [br, bg, bb, ba] = b.to_srgba_unmultiplied();
    let l = |x: u8, y: u8| (x as f32 + (y as f32 - x as f32) * t) as u8;
    Color32::from_rgba_unmultiplied(l(ar, br), l(ag, bg), l(ab, bb), l(aa, ba))
}

/// A lighter tint of a colour, for rims and highlights.
pub fn lighten(c: Color32, k: f32) -> Color32 {
    mix(c, Color32::WHITE, k)
}

pub fn darken(c: Color32, k: f32) -> Color32 {
    mix(c, Color32::BLACK, k)
}

/// The canvas background: a flat fill, a soft spotlight in the middle
/// that darkens towards the corners, and a grid of faint dots that pans
/// and zooms with the camera so the picture has a floor.
pub fn background(painter: &egui::Painter, rect: Rect, base: Color32, centre: Color32, cam: (f32, f32), zoom: f32) {
    painter.rect_filled(rect, 0.0, base);
    // the vignette: a fan of triangles from a lighter centre to the dark rim
    let mut mesh = Mesh::default();
    let c = rect.center();
    let rim = fade(base, 1.0);
    let n = 40;
    mesh.vertices.push(Vertex { pos: c, uv: WHITE_UV, color: centre });
    let rx = rect.width() * 0.75;
    let ry = rect.height() * 0.85;
    for k in 0..=n {
        let a = k as f32 / n as f32 * std::f32::consts::TAU;
        mesh.vertices.push(Vertex { pos: Pos2::new(c.x + rx * a.cos(), c.y + ry * a.sin()), uv: WHITE_UV, color: rim });
    }
    for k in 0..n {
        mesh.add_triangle(0, 1 + k as u32, 2 + k as u32);
    }
    painter.add(Shape::mesh(mesh));
    // the dot grid: world spacing 60, doubled until at least 18 px apart
    let mut spacing = 60.0 * zoom;
    while spacing < 18.0 {
        spacing *= 2.0;
    }
    let alpha = ((spacing - 18.0) / 40.0).clamp(0.0, 1.0) * 0.5 + 0.25;
    let dot = fade(Color32::from_rgb(120, 134, 160), 0.22 * alpha);
    let world_spacing = spacing / zoom;
    let x0 = ((cam.0 - rect.width() * 0.5 / zoom) / world_spacing).floor() * world_spacing;
    let y0 = ((cam.1 - rect.height() * 0.5 / zoom) / world_spacing).floor() * world_spacing;
    let mut mesh = Mesh::default();
    let s = 1.2;
    let cols = (rect.width() / spacing) as i32 + 2;
    let rows = (rect.height() / spacing) as i32 + 2;
    if cols * rows < 20_000 {
        for i in 0..cols {
            for j in 0..rows {
                let wx = x0 + i as f32 * world_spacing;
                let wy = y0 + j as f32 * world_spacing;
                let p = Pos2::new(c.x + (wx - cam.0) * zoom, c.y + (wy - cam.1) * zoom);
                if !rect.contains(p) {
                    continue;
                }
                let i0 = mesh.vertices.len() as u32;
                mesh.vertices.push(Vertex { pos: Pos2::new(p.x - s, p.y - s), uv: WHITE_UV, color: dot });
                mesh.vertices.push(Vertex { pos: Pos2::new(p.x + s, p.y - s), uv: WHITE_UV, color: dot });
                mesh.vertices.push(Vertex { pos: Pos2::new(p.x + s, p.y + s), uv: WHITE_UV, color: dot });
                mesh.vertices.push(Vertex { pos: Pos2::new(p.x - s, p.y + s), uv: WHITE_UV, color: dot });
                mesh.add_triangle(i0, i0 + 1, i0 + 2);
                mesh.add_triangle(i0, i0 + 2, i0 + 3);
            }
        }
        painter.add(Shape::mesh(mesh));
    }
}

/// A soft halo: three concentric discs of falling alpha.
pub fn glow(painter: &egui::Painter, c: Pos2, r: f32, color: Color32, strength: f32) {
    if strength <= 0.01 {
        return;
    }
    painter.circle_filled(c, r * 1.75, fade(color, 0.07 * strength));
    painter.circle_filled(c, r * 1.4, fade(color, 0.12 * strength));
    painter.circle_filled(c, r * 1.15, fade(color, 0.18 * strength));
}

/// A host: filled shape with a darker rim, a highlight towards the top
/// left (so it reads as a sphere) and a thin bright ring.
pub fn orb(painter: &egui::Painter, shape: NodeShape, c: Pos2, r: f32, fill: Color32, ring: Color32, alpha: f32, ring_width: f32) {
    let body = fade(fill, alpha);
    let rim = fade(lighten(ring, 0.25), alpha * 0.95);
    if r < 5.0 {
        // a dot: one disc, a touch lighter so it stays bright
        painter.circle_filled(c, r.max(1.2), fade(lighten(fill, 0.15), alpha));
        return;
    }
    if r < 10.0 && shape == NodeShape::Circle {
        // small: body and ring, no highlight
        painter.circle_filled(c, r, body);
        painter.circle_stroke(c, r, Stroke::new(ring_width.min(1.5), rim));
        return;
    }
    match shape {
        NodeShape::Circle => {
            painter.circle_filled(c, r, fade(darken(fill, 0.18), alpha));
            painter.circle_filled(c, r * 0.9, body);
            if r > 7.0 {
                painter.circle_filled(Pos2::new(c.x - r * 0.28, c.y - r * 0.3), r * 0.5, fade(Color32::WHITE, 0.13 * alpha));
            }
            painter.circle_stroke(c, r, Stroke::new(ring_width, rim));
        }
        NodeShape::Square => {
            let rect = Rect::from_center_size(c, Vec2::splat(r * 1.8));
            let cr = egui::CornerRadius::same((r * 0.3).clamp(2.0, 40.0) as u8);
            painter.rect_filled(rect, cr, fade(darken(fill, 0.18), alpha));
            painter.rect_filled(rect.shrink(r * 0.1), cr, body);
            if r > 7.0 {
                painter.rect_filled(Rect::from_min_size(rect.min + Vec2::splat(r * 0.2), Vec2::new(r * 1.0, r * 0.7)), cr, fade(Color32::WHITE, 0.10 * alpha));
            }
            painter.rect_stroke(rect, cr, Stroke::new(ring_width, rim), egui::StrokeKind::Inside);
        }
        NodeShape::Diamond => {
            let pts = |k: f32| vec![Pos2::new(c.x, c.y - r * k), Pos2::new(c.x + r * k, c.y), Pos2::new(c.x, c.y + r * k), Pos2::new(c.x - r * k, c.y)];
            painter.add(Shape::convex_polygon(pts(1.15), fade(darken(fill, 0.18), alpha), Stroke::new(ring_width, rim)));
            painter.add(Shape::convex_polygon(pts(1.0), body, Stroke::NONE));
        }
        NodeShape::Hexagon => {
            let pts = |k: f32| {
                (0..6)
                    .map(|i| {
                        let a = std::f32::consts::PI / 3.0 * i as f32 + std::f32::consts::PI / 6.0;
                        Pos2::new(c.x + r * k * a.cos(), c.y + r * k * a.sin())
                    })
                    .collect::<Vec<_>>()
            };
            painter.add(Shape::convex_polygon(pts(1.1), fade(darken(fill, 0.18), alpha), Stroke::new(ring_width, rim)));
            painter.add(Shape::convex_polygon(pts(0.98), body, Stroke::NONE));
            if r > 7.0 {
                painter.circle_filled(Pos2::new(c.x - r * 0.25, c.y - r * 0.3), r * 0.45, fade(Color32::WHITE, 0.10 * alpha));
            }
        }
    }
}

pub fn bez(a: Pos2, c: Pos2, b: Pos2, t: f32) -> Pos2 {
    let u = 1.0 - t;
    Pos2::new(u * u * a.x + 2.0 * u * t * c.x + t * t * b.x, u * u * a.y + 2.0 * u * t * c.y + t * t * b.y)
}

/// The curve sampled into `n` segments.
pub fn polyline(a: Pos2, c: Pos2, b: Pos2, n: usize) -> Vec<Pos2> {
    (0..=n).map(|s| bez(a, c, b, s as f32 / n as f32)).collect()
}

/// A curve stroked with a gradient from `from` at the origin to `to` at
/// the destination; a solid stroke when the two are the same.
pub fn gradient_curve(painter: &egui::Painter, a: Pos2, c: Pos2, b: Pos2, width: f32, from: Color32, to: Color32) {
    if from == to {
        painter.add(QuadraticBezierShape { points: [a, c, b], closed: false, fill: Color32::TRANSPARENT, stroke: PathStroke::new(width, from) });
        return;
    }
    let d = b - a;
    let l2 = d.length_sq().max(1.0);
    let stroke = PathStroke::new_uv(width, move |_rect, p| {
        let t = ((p - a).dot(d) / l2).clamp(0.0, 1.0);
        mix(from, to, t)
    });
    painter.add(QuadraticBezierShape { points: [a, c, b], closed: false, fill: Color32::TRANSPARENT, stroke });
}

/// Short dashes along the curve.
pub fn dashed_curve(painter: &egui::Painter, a: Pos2, c: Pos2, b: Pos2, width: f32, color: Color32, dash: f32) {
    let len = (a - b).length() + (c - a).length() * 0.2;
    let n = (len / 8.0).clamp(4.0, 48.0) as usize;
    let pts = polyline(a, c, b, n);
    painter.extend(Shape::dashed_line(&pts, Stroke::new(width, color), dash, dash * 0.9));
}

/// A straight edge as two triangles in a shared mesh: the cheap way to
/// put tens of thousands of edges on screen in one draw call.
pub fn line_quad(mesh: &mut Mesh, a: Pos2, b: Pos2, width: f32, color: Color32) {
    let d = b - a;
    let len = d.length();
    if len < 0.5 {
        return;
    }
    let n = Vec2::new(-d.y, d.x) * (width.max(0.8) * 0.5 / len);
    let i0 = mesh.vertices.len() as u32;
    mesh.vertices.push(Vertex { pos: a + n, uv: WHITE_UV, color });
    mesh.vertices.push(Vertex { pos: b + n, uv: WHITE_UV, color });
    mesh.vertices.push(Vertex { pos: b - n, uv: WHITE_UV, color });
    mesh.vertices.push(Vertex { pos: a - n, uv: WHITE_UV, color });
    mesh.add_triangle(i0, i0 + 1, i0 + 2);
    mesh.add_triangle(i0, i0 + 2, i0 + 3);
}

/// A filled disc in a shared mesh, with a one-pixel feathered rim so it
/// stays smooth: the cheap host when there are thousands on screen.
pub fn disc(mesh: &mut Mesh, c: Pos2, r: f32, color: Color32) {
    let n = ((r * 1.2) as usize).clamp(6, 24);
    let i0 = mesh.vertices.len() as u32;
    let clear = fade(color, 0.0);
    mesh.vertices.push(Vertex { pos: c, uv: WHITE_UV, color });
    for k in 0..n {
        let a = k as f32 / n as f32 * std::f32::consts::TAU;
        let (sn, cs) = a.sin_cos();
        mesh.vertices.push(Vertex { pos: Pos2::new(c.x + cs * r, c.y + sn * r), uv: WHITE_UV, color });
        mesh.vertices.push(Vertex { pos: Pos2::new(c.x + cs * (r + 1.0), c.y + sn * (r + 1.0)), uv: WHITE_UV, color: clear });
    }
    for k in 0..n as u32 {
        let a = i0 + 1 + k * 2;
        let b = i0 + 1 + ((k + 1) % n as u32) * 2;
        mesh.add_triangle(i0, a, b);
        mesh.add_triangle(a, a + 1, b + 1);
        mesh.add_triangle(a, b + 1, b);
    }
}

/// A thin ring in a shared mesh (outer radius `r`, width `w`).
pub fn ring(mesh: &mut Mesh, c: Pos2, r: f32, w: f32, color: Color32) {
    let n = ((r * 1.2) as usize).clamp(6, 24);
    let i0 = mesh.vertices.len() as u32;
    let ri = (r - w).max(0.5);
    for k in 0..n {
        let a = k as f32 / n as f32 * std::f32::consts::TAU;
        let (sn, cs) = a.sin_cos();
        mesh.vertices.push(Vertex { pos: Pos2::new(c.x + cs * ri, c.y + sn * ri), uv: WHITE_UV, color });
        mesh.vertices.push(Vertex { pos: Pos2::new(c.x + cs * r, c.y + sn * r), uv: WHITE_UV, color });
    }
    for k in 0..n as u32 {
        let a = i0 + k * 2;
        let b = i0 + ((k + 1) % n as u32) * 2;
        mesh.add_triangle(a, a + 1, b + 1);
        mesh.add_triangle(a, b + 1, b);
    }
}

/// The arrowhead at the destination's rim, pointing along `dir`.
pub fn arrow(painter: &egui::Painter, tip: Pos2, dir: Vec2, size: f32, color: Color32) {
    let left = tip - dir * size + dir.rot90() * size * 0.48;
    let right = tip - dir * size - dir.rot90() * size * 0.48;
    let back = tip - dir * size * 0.7;
    painter.add(Shape::convex_polygon(vec![tip, left, back, right], color, Stroke::NONE));
}

/// A bright dot with a faint halo and a short tail, travelling along the
/// curve at `t`.
pub fn particle(painter: &egui::Painter, a: Pos2, c: Pos2, b: Pos2, t: f32, r: f32, color: Color32, alpha: f32) {
    let p = bez(a, c, b, t);
    painter.circle_filled(p, r * 2.6, fade(color, 0.16 * alpha));
    let tail = bez(a, c, b, (t - 0.045).max(0.0));
    painter.line_segment([tail, p], Stroke::new(r * 0.9, fade(color, 0.45 * alpha)));
    painter.circle_filled(p, r, fade(lighten(color, 0.55), alpha));
}

/// A rounded pill with text, for captions and chips.
pub fn pill(painter: &egui::Painter, at: Pos2, galley: std::sync::Arc<egui::Galley>, fill: Color32, border: Option<Color32>, text: Color32) -> Rect {
    let r = Rect::from_center_size(at, galley.size() + Vec2::new(12.0, 5.0));
    painter.rect_filled(r, egui::CornerRadius::same(10), fill);
    if let Some(b) = border {
        painter.rect_stroke(r, egui::CornerRadius::same(10), Stroke::new(1.0, b), egui::StrokeKind::Inside);
    }
    painter.galley(r.min + Vec2::new(6.0, 2.5), galley, text);
    r
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn easings_start_at_zero_and_end_at_one() {
        assert!((ease_out_cubic(0.0)).abs() < 1e-6);
        assert!((ease_out_cubic(1.0) - 1.0).abs() < 1e-6);
        assert!((ease_out_back(0.0)).abs() < 1e-6);
        assert!((ease_out_back(1.0) - 1.0).abs() < 1e-6);
        assert!(ease_out_back(0.7) > 1.0, "it overshoots");
    }

    #[test]
    fn colours_mix_and_fade() {
        let m = mix(Color32::BLACK, Color32::WHITE, 0.5);
        assert!(m.r() > 120 && m.r() < 136);
        assert_eq!(fade(Color32::WHITE, 0.5).a(), 127);
        let pts = polyline(Pos2::ZERO, Pos2::new(5.0, 10.0), Pos2::new(10.0, 0.0), 4);
        assert_eq!(pts.len(), 5);
        assert_eq!(pts[0], Pos2::ZERO);
        assert_eq!(pts[4], Pos2::new(10.0, 0.0));
    }
}
