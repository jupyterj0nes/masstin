//! Subnets: the hosts of a view grouped by where they sit on the network,
//! by the /24 of their address or by the analyst's own CIDRs with names.
//! Each group pulls its hosts together in the layout and is drawn as a
//! soft region behind them with its name.

use super::*;
use crate::view::icons as ic;
use crate::view::theme;

/// A group of the current view.
pub(super) struct SubnetGroup {
    pub name: String,
    pub color: Color32,
    pub members: Vec<usize>,
}

/// `a.b.c.d/n` → (network, bits), or None.
pub(super) fn parse_cidr(s: &str) -> Option<(u32, u32)> {
    let (ip, bits) = s.trim().split_once('/')?;
    let bits: u32 = bits.trim().parse().ok()?;
    if bits > 32 {
        return None;
    }
    let v4: std::net::Ipv4Addr = ip.trim().parse().ok()?;
    let mask = if bits == 0 { 0 } else { u32::MAX << (32 - bits) };
    Some((u32::from(v4) & mask, bits))
}

fn in_cidr(ip: u32, net: u32, bits: u32) -> bool {
    let mask = if bits == 0 { 0 } else { u32::MAX << (32 - bits) };
    ip & mask == net
}

/// The IPv4 address a host is known by, if any of its names is one.
fn host_ipv4(store: &Store, host: u32) -> Option<u32> {
    store.aliases.get(host as usize)?.iter().find_map(|a| a.parse::<std::net::Ipv4Addr>().ok()).map(u32::from)
}

impl Viewer {
    /// Group the view's hosts: the analyst's CIDRs first, then (when auto
    /// is on) the /24 of their address.
    pub(super) fn compute_subnets(&mut self) {
        self.subnets.clear();
        self.subnet_of = vec![None; self.graph.nodes.len()];
        if !self.style.show_subnets {
            return;
        }
        let defs: Vec<(u32, u32, String)> = self.subnet_defs.iter().filter_map(|(cidr, name)| parse_cidr(cidr).map(|(n, b)| (n, b, if name.trim().is_empty() { cidr.clone() } else { name.clone() }))).collect();
        let mut by_name: HashMap<String, usize> = HashMap::new();
        for (i, n) in self.graph.nodes.iter().enumerate() {
            let Some(ip) = host_ipv4(&self.store, n.host) else { continue };
            let name = match defs.iter().filter(|(net, bits, _)| in_cidr(ip, *net, *bits)).max_by_key(|(_, bits, _)| *bits) {
                Some((_, _, name)) => name.clone(),
                None => {
                    if !self.style.subnets_auto {
                        continue;
                    }
                    let o = ip.to_be_bytes();
                    format!("{}.{}.{}.0/24", o[0], o[1], o[2])
                }
            };
            let k = *by_name.entry(name.clone()).or_insert_with(|| {
                let idx = self.subnets.len();
                let c = palette_color(idx as u32 + 3);
                self.subnets.push(SubnetGroup { name, color: Color32::from_rgb(c[0], c[1], c[2]), members: Vec::new() });
                idx
            });
            self.subnets[k].members.push(i);
            self.subnet_of[i] = Some(k as u16);
        }
        // a group of one is no group
        let mut keep = vec![false; self.subnets.len()];
        for (k, g) in self.subnets.iter().enumerate() {
            keep[k] = g.members.len() >= 2;
        }
        for s in self.subnet_of.iter_mut() {
            if let Some(k) = *s {
                if !keep[k as usize] {
                    *s = None;
                }
            }
        }
        self.layout.group = self.subnet_of.clone();
    }

    /// The regions behind the groups: an expanded hull of the members,
    /// filled faintly in the group's colour, the name at its top.
    pub(super) fn draw_subnets(&self, painter: &egui::Painter, canvas: Rect, names: bool) {
        if self.subnets.is_empty() {
            return;
        }
        let z = self.zoom;
        for (k, g) in self.subnets.iter().enumerate() {
            if g.members.len() < 2 {
                continue;
            }
            let pts: Vec<Pos2> = g.members.iter().filter_map(|&i| if self.scene.nodes.get(i).map_or(true, |n| n.hide) { None } else { Some(self.to_screen(canvas, self.layout.pos[i])) }).collect();
            if pts.len() < 2 {
                continue;
            }
            let pad = (34.0 * z).clamp(14.0, 60.0) + g.members.iter().map(|&i| self.layout.radius[i]).fold(0.0, f32::max) * z * self.style.node_scale;
            let hull = convex_hull(&pts);
            let fill = draw::fade(g.color, 0.06);
            let line = Stroke::new(1.0, draw::fade(g.color, 0.3));
            if names {
                let top = hull.iter().map(|p| p.y).fold(f32::MAX, f32::min) - pad;
                let cx = hull.iter().map(|p| p.x).sum::<f32>() / hull.len() as f32;
                let galley = painter.layout_no_wrap(format!("{}  {}", ic::WIFI_HIGH, g.name), FontId::proportional((12.0 * z.sqrt()).clamp(10.0, 15.0)), g.color);
                draw::pill(painter, Pos2::new(cx, top - galley.size().y / 2.0 - 4.0), galley, draw::fade(Color32::from_rgb(8, 10, 16), 0.9), Some(draw::fade(g.color, 0.6)), g.color);
                continue;
            }
            // the expanded hull: discs at the corners, thick strokes on the edges, the hull itself
            for p in &hull {
                painter.circle_filled(*p, pad, fill);
            }
            for w in 0..hull.len() {
                let a = hull[w];
                let b = hull[(w + 1) % hull.len()];
                if hull.len() > 1 {
                    let d = b - a;
                    let l = d.length().max(0.1);
                    let n = Vec2::new(-d.y, d.x) / l * pad;
                    painter.add(egui::Shape::convex_polygon(vec![a + n, b + n, b - n, a - n], fill, Stroke::NONE));
                    painter.line_segment([a + n, b + n], line);
                    painter.line_segment([a - n, b - n], line);
                }
            }
            if hull.len() >= 3 {
                painter.add(egui::Shape::convex_polygon(hull.clone(), fill, Stroke::NONE));
            }
            for p in &hull {
                painter.circle_stroke(*p, pad, line);
            }
            let _ = k;
        }
    }

    /// Tools › Subnets: auto /24 on or off, and the named CIDRs.
    pub(super) fn subnets_window(&mut self, ctx: &egui::Context) {
        if !self.show_subnets_window {
            return;
        }
        let mut open = true;
        let mut changed = false;
        egui::Window::new(format!("{}  Subnets", ic::WIFI_HIGH)).open(&mut open).collapsible(false).resizable(true).default_width(520.0).anchor(egui::Align2::CENTER_CENTER, Vec2::ZERO).show(ctx, |ui| {
            ui.label(egui::RichText::new("Hosts grouped by where they sit on the network: each group pulls its hosts together and is drawn as a region behind them, with its name. A host joins a group through the address it is known by (its own names, or the address the hunt or you merged into it).").color(theme::MUTED));
            theme::section(ui, "Groups");
            changed |= ui.checkbox(&mut self.style.show_subnets, "show the subnet regions").changed();
            changed |= ui.checkbox(&mut self.style.subnets_auto, "a group per /24 for every host with an address, besides the ones named below").changed();
            theme::section(ui, "Named subnets (CIDR and name)");
            let mut remove: Option<usize> = None;
            for i in 0..self.subnet_defs.len() {
                ui.horizontal(|ui| {
                    changed |= ui.add(egui::TextEdit::singleline(&mut self.subnet_defs[i].0).desired_width(150.0).hint_text("10.10.0.0/24")).changed();
                    changed |= ui.add(egui::TextEdit::singleline(&mut self.subnet_defs[i].1).desired_width(220.0).hint_text("servers VLAN 10")).changed();
                    let ok = parse_cidr(&self.subnet_defs[i].0).is_some();
                    ui.label(egui::RichText::new(if ok { ic::CHECK } else { ic::WARNING }).color(if ok { theme::CYAN } else { CANDIDATE }));
                    if ui.add(egui::Button::new(egui::RichText::new(ic::TRASH).color(theme::DIM)).frame(false)).clicked() {
                        remove = Some(i);
                    }
                });
            }
            if let Some(i) = remove {
                self.subnet_defs.remove(i);
                changed = true;
            }
            if ui.button(format!("{}  Add a subnet", ic::PLUS)).clicked() {
                self.subnet_defs.push((String::new(), String::new()));
            }
            if !self.subnets.is_empty() {
                theme::section(ui, "In this view");
                for g in &self.subnets {
                    ui.horizontal(|ui| {
                        let (r, p) = ui.allocate_painter(Vec2::new(14.0, 14.0), Sense::hover());
                        p.circle_filled(r.rect.center(), 5.0, g.color);
                        ui.label(format!("{}  ·  {} host(s)", g.name, g.members.len()));
                    });
                }
            }
            ui.label(egui::RichText::new("Kept next to the timeline, in its views file.").color(theme::DIM).small());
        });
        if changed {
            self.persist();
            self.compute_subnets();
            self.layout.reheat(0.5);
        }
        self.show_subnets_window = open;
    }
}

/// Andrew's monotone chain; the points in counter-clockwise order.
fn convex_hull(pts: &[Pos2]) -> Vec<Pos2> {
    let mut p: Vec<Pos2> = pts.to_vec();
    p.sort_by(|a, b| a.x.partial_cmp(&b.x).unwrap().then(a.y.partial_cmp(&b.y).unwrap()));
    p.dedup_by(|a, b| (a.x - b.x).abs() < 0.01 && (a.y - b.y).abs() < 0.01);
    if p.len() < 3 {
        return p;
    }
    let cross = |o: Pos2, a: Pos2, b: Pos2| (a.x - o.x) * (b.y - o.y) - (a.y - o.y) * (b.x - o.x);
    let mut lower: Vec<Pos2> = Vec::new();
    for &q in &p {
        while lower.len() >= 2 && cross(lower[lower.len() - 2], lower[lower.len() - 1], q) <= 0.0 {
            lower.pop();
        }
        lower.push(q);
    }
    let mut upper: Vec<Pos2> = Vec::new();
    for &q in p.iter().rev() {
        while upper.len() >= 2 && cross(upper[upper.len() - 2], upper[upper.len() - 1], q) <= 0.0 {
            upper.pop();
        }
        upper.push(q);
    }
    lower.pop();
    upper.pop();
    lower.extend(upper);
    lower
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cidrs_parse_and_contain() {
        let (net, bits) = parse_cidr("10.10.0.0/24").unwrap();
        assert!(in_cidr(u32::from("10.10.0.39".parse::<std::net::Ipv4Addr>().unwrap()), net, bits));
        assert!(!in_cidr(u32::from("10.10.1.39".parse::<std::net::Ipv4Addr>().unwrap()), net, bits));
        assert!(parse_cidr("10.10.0.0/33").is_none());
        assert!(parse_cidr("servers").is_none());
    }

    #[test]
    fn the_hull_wraps_the_points() {
        let pts = [Pos2::new(0.0, 0.0), Pos2::new(10.0, 0.0), Pos2::new(10.0, 10.0), Pos2::new(0.0, 10.0), Pos2::new(5.0, 5.0)];
        let h = convex_hull(&pts);
        assert_eq!(h.len(), 4);
        assert!(!h.iter().any(|p| *p == Pos2::new(5.0, 5.0)));
    }
}
