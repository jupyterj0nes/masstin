//! Force-directed layout, the way d3-force (and so Neo4j Browser) does
//! it: every node repels every other, a link pulls its two ends towards
//! an ideal distance, a weak gravity keeps the whole thing centred, and
//! circles never overlap. The simulation has a temperature (`alpha`) that
//! decays; it stops when cold and is reheated when the graph changes or a
//! node is dragged. Repulsion is exact between neighbours and approximated
//! by cell centroids farther away, so a few thousand nodes still animate.

use std::collections::HashMap;

#[derive(Clone, Copy, Debug, Default, PartialEq)]
pub struct V2 {
    pub x: f32,
    pub y: f32,
}

impl V2 {
    pub fn new(x: f32, y: f32) -> V2 {
        V2 { x, y }
    }
    pub fn len(self) -> f32 {
        (self.x * self.x + self.y * self.y).sqrt()
    }
}

impl std::ops::Add for V2 {
    type Output = V2;
    fn add(self, o: V2) -> V2 {
        V2::new(self.x + o.x, self.y + o.y)
    }
}
impl std::ops::Sub for V2 {
    type Output = V2;
    fn sub(self, o: V2) -> V2 {
        V2::new(self.x - o.x, self.y - o.y)
    }
}
impl std::ops::Mul<f32> for V2 {
    type Output = V2;
    fn mul(self, k: f32) -> V2 {
        V2::new(self.x * k, self.y * k)
    }
}
impl std::ops::AddAssign for V2 {
    fn add_assign(&mut self, o: V2) {
        self.x += o.x;
        self.y += o.y;
    }
}
impl std::ops::SubAssign for V2 {
    fn sub_assign(&mut self, o: V2) {
        self.x -= o.x;
        self.y -= o.y;
    }
}

pub struct Layout {
    pub pos: Vec<V2>,
    vel: Vec<V2>,
    /// a node the analyst holds (or pinned): the forces do not move it
    pub fixed: Vec<bool>,
    pub radius: Vec<f32>,
    links: Vec<(usize, usize)>,
    degree: Vec<u32>,
    alpha: f32,
    pub link_distance: f32,
}

impl Layout {
    /// A fresh layout: nodes on a phyllotaxis spiral (so nothing starts on
    /// top of anything), the ones with a known position where they were.
    pub fn new(radius: Vec<f32>, links: Vec<(usize, usize)>, known: &[Option<V2>]) -> Layout {
        let n = radius.len();
        let mut pos = Vec::with_capacity(n);
        let golden = std::f32::consts::PI * (3.0 - 5f32.sqrt());
        let spread = 14.0 * (n as f32).sqrt().max(4.0);
        for i in 0..n {
            match known.get(i).copied().flatten() {
                Some(p) => pos.push(p),
                None => {
                    let r = spread * ((i + 1) as f32).sqrt() * 1.6;
                    let a = i as f32 * golden;
                    pos.push(V2::new(r * a.cos(), r * a.sin()));
                }
            }
        }
        let mut degree = vec![0u32; n];
        for &(a, b) in &links {
            degree[a] += 1;
            degree[b] += 1;
        }
        Layout { pos, vel: vec![V2::default(); n], fixed: vec![false; n], radius, links, degree, alpha: 1.0, link_distance: 150.0 }
    }

    pub fn len(&self) -> usize {
        self.pos.len()
    }

    pub fn reheat(&mut self, alpha: f32) {
        self.alpha = self.alpha.max(alpha);
    }

    pub fn is_running(&self) -> bool {
        self.alpha > 0.003
    }

    pub fn stop(&mut self) {
        self.alpha = 0.0;
    }

    /// One step. Returns whether anything still moves.
    pub fn tick(&mut self) -> bool {
        let n = self.pos.len();
        if n == 0 || !self.is_running() {
            return false;
        }
        let alpha = self.alpha;
        self.alpha += (0.0 - self.alpha) * 0.028;
        let mut force = vec![V2::default(); n];

        // repulsion: exact within the cell neighbourhood, centroids beyond
        let cell = (self.link_distance * 2.0).max(1.0);
        let key = |p: V2| ((p.x / cell).floor() as i32, (p.y / cell).floor() as i32);
        let mut cells: HashMap<(i32, i32), Vec<usize>> = HashMap::new();
        for (i, p) in self.pos.iter().enumerate() {
            cells.entry(key(*p)).or_default().push(i);
        }
        let centroids: Vec<((i32, i32), V2, f32)> = cells
            .iter()
            .map(|(k, v)| {
                let mut c = V2::default();
                for &i in v {
                    c += self.pos[i];
                }
                (*k, c * (1.0 / v.len() as f32), v.len() as f32)
            })
            .collect();
        let strength = -2600.0 * alpha;
        for i in 0..n {
            let p = self.pos[i];
            let (kx, ky) = key(p);
            let mut f = V2::default();
            for (ck, c, mass) in &centroids {
                let near = (ck.0 - kx).abs() <= 1 && (ck.1 - ky).abs() <= 1;
                if near {
                    for &j in &cells[ck] {
                        if j == i {
                            continue;
                        }
                        let d = p - self.pos[j];
                        let dist2 = (d.x * d.x + d.y * d.y).max(16.0);
                        let dist = dist2.sqrt();
                        let min = self.radius[i] + self.radius[j];
                        let k = strength / dist2 * if dist < min * 1.5 { 3.0 } else { 1.0 };
                        f += d * (k / dist);
                    }
                } else {
                    let d = p - *c;
                    let dist2 = (d.x * d.x + d.y * d.y).max(16.0);
                    let dist = dist2.sqrt();
                    f += d * (strength * mass / dist2 / dist);
                }
            }
            force[i] -= f;
        }
        // links: a spring towards the ideal distance, the lighter end moves more
        for &(a, b) in &self.links {
            let d = self.pos[b] - self.pos[a];
            let dist = d.len().max(1.0);
            let target = self.link_distance + self.radius[a] + self.radius[b] - 30.0;
            let k = (dist - target) / dist * 0.25 * alpha;
            let bias = self.degree[a] as f32 / (self.degree[a] + self.degree[b]).max(1) as f32;
            force[a] += d * (k * (1.0 - bias));
            force[b] -= d * (k * bias);
        }
        // gravity towards the origin
        for i in 0..n {
            force[i] -= self.pos[i] * (0.006 * alpha);
        }
        // integrate
        let mut moving = false;
        for i in 0..n {
            if self.fixed[i] {
                self.vel[i] = V2::default();
                continue;
            }
            self.vel[i] = (self.vel[i] + force[i]) * 0.55;
            let v = self.vel[i].len();
            if v > 60.0 {
                self.vel[i] = self.vel[i] * (60.0 / v);
            }
            self.pos[i] += self.vel[i];
            if v > 0.05 {
                moving = true;
            }
        }
        // collisions: push overlapping circles apart
        for _ in 0..2 {
            for (k, v) in &cells {
                for &i in v {
                    for dx in -1..=1 {
                        for dy in -1..=1 {
                            if let Some(w) = cells.get(&(k.0 + dx, k.1 + dy)) {
                                for &j in w {
                                    if j <= i {
                                        continue;
                                    }
                                    let d = self.pos[j] - self.pos[i];
                                    let dist = d.len().max(0.1);
                                    let min = self.radius[i] + self.radius[j] + 14.0;
                                    if dist < min {
                                        let push = d * ((min - dist) / dist * 0.5);
                                        if !self.fixed[i] {
                                            self.pos[i] -= push;
                                        }
                                        if !self.fixed[j] {
                                            self.pos[j] += push;
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
        moving || self.is_running()
    }

    /// Bounding box of the nodes (with their radii).
    pub fn bounds(&self) -> Option<(V2, V2)> {
        if self.pos.is_empty() {
            return None;
        }
        let mut lo = V2::new(f32::MAX, f32::MAX);
        let mut hi = V2::new(f32::MIN, f32::MIN);
        for (p, r) in self.pos.iter().zip(&self.radius) {
            lo.x = lo.x.min(p.x - r);
            lo.y = lo.y.min(p.y - r);
            hi.x = hi.x.max(p.x + r);
            hi.y = hi.y.max(p.y + r);
        }
        Some((lo, hi))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_triangle_settles_without_overlap() {
        let mut l = Layout::new(vec![25.0; 3], vec![(0, 1), (1, 2), (2, 0)], &[None, None, None]);
        for _ in 0..400 {
            l.tick();
        }
        assert!(!l.is_running());
        for i in 0..3 {
            for j in i + 1..3 {
                assert!((l.pos[i] - l.pos[j]).len() > 50.0, "{:?} {:?}", l.pos[i], l.pos[j]);
            }
        }
    }

    #[test]
    fn a_fixed_node_stays() {
        let mut l = Layout::new(vec![20.0; 2], vec![(0, 1)], &[Some(V2::new(5.0, 5.0)), None]);
        l.fixed[0] = true;
        for _ in 0..50 {
            l.tick();
        }
        assert_eq!(l.pos[0], V2::new(5.0, 5.0));
    }
}
