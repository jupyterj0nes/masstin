//! Force-directed layout, the way d3-force (and so Neo4j Browser) does
//! it: every node repels every other, a link pulls its two ends towards
//! an ideal distance, a weak gravity keeps the whole thing centred, and
//! circles never overlap. The simulation has a temperature (`alpha`) that
//! decays; it stops when cold and is reheated when the graph changes or a
//! node is dragged.
//!
//! Repulsion goes through a Barnes-Hut quadtree (a far cell counts as its
//! centre of mass), so a tick is `n log n` and a few thousand hosts still
//! animate; the tree's storage is kept between ticks. Collisions use a
//! hash grid rebuilt per tick.

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
    pub fn len2(self) -> f32 {
        self.x * self.x + self.y * self.y
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

/// Barnes-Hut opening angle: a cell whose width over its distance is
/// below this is one body at its centre of mass.
const THETA: f32 = 0.85;
const THETA2: f32 = THETA * THETA;

/// One cell of the quadtree. A leaf holds one body (or several that sit
/// on the same point, past the depth limit, counted in `mass`).
#[derive(Clone, Copy)]
struct Cell {
    /// centre of the square and half its side
    cx: f32,
    cy: f32,
    half: f32,
    /// mass and centre of mass of everything inside
    mass: f32,
    mx: f32,
    my: f32,
    /// index of the first child; the four are consecutive (u32::MAX = leaf)
    child: u32,
    /// the body of a leaf (u32::MAX = empty)
    body: u32,
}

const NONE: u32 = u32::MAX;

struct Tree {
    cells: Vec<Cell>,
}

impl Tree {
    fn new() -> Tree {
        Tree { cells: Vec::new() }
    }

    fn build(&mut self, pos: &[V2]) {
        self.cells.clear();
        if pos.is_empty() {
            return;
        }
        let mut lo = V2::new(f32::MAX, f32::MAX);
        let mut hi = V2::new(f32::MIN, f32::MIN);
        for p in pos {
            lo.x = lo.x.min(p.x);
            lo.y = lo.y.min(p.y);
            hi.x = hi.x.max(p.x);
            hi.y = hi.y.max(p.y);
        }
        let half = ((hi.x - lo.x).max(hi.y - lo.y) * 0.5 + 1.0).max(1.0);
        self.cells.push(Cell { cx: (lo.x + hi.x) * 0.5, cy: (lo.y + hi.y) * 0.5, half, mass: 0.0, mx: 0.0, my: 0.0, child: NONE, body: NONE });
        for (i, p) in pos.iter().enumerate() {
            self.insert(i as u32, *p, pos);
        }
        // centres of mass
        for c in &mut self.cells {
            if c.mass > 0.0 {
                c.mx /= c.mass;
                c.my /= c.mass;
            }
        }
    }

    fn quadrant(c: &Cell, p: V2) -> usize {
        (if p.x >= c.cx { 1 } else { 0 }) | (if p.y >= c.cy { 2 } else { 0 })
    }

    fn split(&mut self, k: usize) {
        let c = self.cells[k];
        let first = self.cells.len() as u32;
        let h = c.half * 0.5;
        for q in 0..4 {
            let dx = if q & 1 == 1 { h } else { -h };
            let dy = if q & 2 == 2 { h } else { -h };
            self.cells.push(Cell { cx: c.cx + dx, cy: c.cy + dy, half: h, mass: 0.0, mx: 0.0, my: 0.0, child: NONE, body: NONE });
        }
        self.cells[k].child = first;
    }

    fn insert(&mut self, body: u32, p: V2, pos: &[V2]) {
        let mut k = 0usize;
        let mut depth = 0;
        loop {
            let c = &mut self.cells[k];
            c.mass += 1.0;
            c.mx += p.x;
            c.my += p.y;
            if c.child != NONE {
                let q = Self::quadrant(c, p);
                k = c.child as usize + q;
                depth += 1;
                continue;
            }
            if c.body == NONE {
                c.body = body;
                return;
            }
            if depth > 24 {
                // two bodies on one point: the leaf keeps the first and the mass of both
                return;
            }
            // a leaf with a body: split, move that body down, go on with ours
            let other = c.body;
            c.body = NONE;
            self.split(k);
            let op = pos[other as usize];
            let c = self.cells[k];
            let ok = c.child as usize + Self::quadrant(&c, op);
            let oc = &mut self.cells[ok];
            oc.mass += 1.0;
            oc.mx += op.x;
            oc.my += op.y;
            oc.body = other;
            k = c.child as usize + Self::quadrant(&c, p);
            depth += 1;
        }
    }

    /// Repulsion on body `i` at `p`: sum of `strength / d²` away from every
    /// other body, far cells as one. `near` is the distance under which a
    /// pair counts triple (they are about to overlap).
    fn force(&self, i: u32, p: V2, strength: f32, near: f32, stack: &mut Vec<u32>) -> V2 {
        let mut f = V2::default();
        if self.cells.is_empty() {
            return f;
        }
        stack.clear();
        stack.push(0);
        let near2 = near * near;
        while let Some(k) = stack.pop() {
            let c = &self.cells[k as usize];
            if c.mass == 0.0 {
                continue;
            }
            let d = V2::new(p.x - c.mx, p.y - c.my);
            let dist2 = d.len2();
            let width = c.half * 2.0;
            if c.child == NONE {
                if c.body == i {
                    // our own leaf: bodies on the very same point, if any, are
                    // left to the collision pass
                    continue;
                }
                let dist2 = dist2.max(16.0);
                let k = strength * c.mass / dist2 * if dist2 < near2 { 3.0 } else { 1.0 };
                f += d * (k / dist2.sqrt());
            } else if width * width < THETA2 * dist2 && ((p.x - c.cx).abs() > c.half || (p.y - c.cy).abs() > c.half) {
                // far enough, and we are not inside it (a cell holding this body
                // would make it repel itself, and every body the same way)
                let dist2 = dist2.max(16.0);
                f += d * (strength * c.mass / dist2 / dist2.sqrt());
            } else {
                for q in 0..4 {
                    stack.push(c.child + q);
                }
            }
        }
        f
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
    /// the group (subnet) of each node, pulled towards its centre
    pub group: Vec<Option<u16>>,
    /// the canvas's width over its height: gravity stretches the picture to it
    pub aspect: f32,
    max_radius: f32,
    /// the last tick still pushed overlapping hosts apart
    unsettled: bool,
    /// when the forces went cold (overlaps alone are resolved from then on)
    cold_since: Option<std::time::Instant>,
    /// a host was held or pinned on the last tick (the centring waited)
    held: bool,
    /// how far the centring moved everything when it came back after a hold:
    /// the window moves its camera as much, so the picture does not jump
    pub recentred: V2,
    tree: Tree,
    force: Vec<V2>,
    stack: Vec<u32>,
    grid: HashMap<(i32, i32), Vec<u32>>,
}

impl Layout {
    /// A fresh layout: nodes on a phyllotaxis spiral (so nothing starts on
    /// top of anything), the ones with a known position where they were.
    pub fn new(radius: Vec<f32>, links: Vec<(usize, usize)>, known: &[Option<V2>]) -> Layout {
        let n = radius.len();
        let mut pos = Vec::with_capacity(n);
        let golden = std::f32::consts::PI * (3.0 - 5f32.sqrt());
        // d3's initial radius is 10·√i for links of 30: ours are five times longer
        let spread = 50.0;
        for i in 0..n {
            match known.get(i).copied().flatten() {
                Some(p) => pos.push(p),
                None => {
                    let r = spread * ((i + 1) as f32).sqrt();
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
        let max_radius = radius.iter().copied().fold(1.0f32, f32::max);
        Layout { pos, vel: vec![V2::default(); n], fixed: vec![false; n], radius, links, degree, alpha: 1.0, link_distance: 150.0, group: vec![None; n], aspect: 1.0, max_radius, unsettled: true, cold_since: None, held: false, recentred: V2::default(), tree: Tree::new(), force: vec![V2::default(); n], stack: Vec::new(), grid: HashMap::new() }
    }

    pub fn len(&self) -> usize {
        self.pos.len()
    }

    pub fn reheat(&mut self, alpha: f32) {
        self.alpha = self.alpha.max(alpha);
        self.cold_since = None;
    }

    pub fn is_running(&self) -> bool {
        self.alpha > 0.003 || self.unsettled
    }

    pub fn stop(&mut self) {
        self.alpha = 0.0;
        self.unsettled = false;
    }

    /// Ticks until the layout is cold or the time is spent, at most
    /// `max_ticks`. Returns whether anything still moves.
    pub fn tick_for(&mut self, budget: std::time::Duration, max_ticks: usize) -> bool {
        let start = std::time::Instant::now();
        let mut moving = false;
        for k in 0..max_ticks.max(1) {
            moving = self.tick();
            if !moving || (k + 1 < max_ticks && start.elapsed() >= budget) {
                break;
            }
        }
        moving
    }

    /// One step. Returns whether anything still moves.
    pub fn tick(&mut self) -> bool {
        let n = self.pos.len();
        if n == 0 || !self.is_running() {
            return false;
        }
        let alpha = if self.alpha > 0.003 { self.alpha } else { 0.0 };
        if alpha == 0.0 && self.cold_since.is_none() {
            self.cold_since = Some(std::time::Instant::now());
        }
        self.alpha += (0.0 - self.alpha) * 0.028;
        self.force.clear();
        self.force.resize(n, V2::default());

        // repulsion through the quadtree
        self.tree.build(&self.pos);
        let strength = -2600.0 * alpha;
        let mut stack = std::mem::take(&mut self.stack);
        for i in 0..n {
            let near = (self.radius[i] * 2.0) * 1.5;
            let f = self.tree.force(i as u32, self.pos[i], strength, near, &mut stack);
            self.force[i] -= f;
        }
        self.stack = stack;
        let held = self.fixed.iter().any(|&f| f);
        // the pulls from outside the free hosts (the springs to a held one,
        // gravity): what may move them as a whole while the centring waits
        let mut outside = V2::default();
        // links: a spring towards the ideal distance, weaker on a busy node
        // (d3: strength 1 / the smaller degree, so a hub's forty links do not
        // crush it), the lighter end moving more
        for &(a, b) in &self.links {
            let d = self.pos[b] - self.pos[a];
            let dist = d.len().max(1.0);
            let target = self.link_distance + self.radius[a] + self.radius[b] - 30.0;
            let strength = (0.5 / self.degree[a].min(self.degree[b]).max(1) as f32).clamp(0.02, 0.5);
            let k = (dist - target) / dist * strength * alpha;
            let bias = self.degree[a] as f32 / (self.degree[a] + self.degree[b]).max(1) as f32;
            self.force[a] += d * (k * (1.0 - bias));
            self.force[b] -= d * (k * bias);
            if held && self.fixed[a] != self.fixed[b] {
                if self.fixed[a] { outside -= d * (k * bias) } else { outside += d * (k * (1.0 - bias)) }
            }
        }
        // gravity towards the origin, weaker along the canvas's long side so
        // the picture fills it
        let (gx, gy) = (0.006 / self.aspect.max(0.5).sqrt(), 0.006 * self.aspect.max(0.5).sqrt());
        for i in 0..n {
            self.force[i].x -= self.pos[i].x * (gx * alpha);
            self.force[i].y -= self.pos[i].y * (gy * alpha);
            if held && !self.fixed[i] {
                outside -= V2::new(self.pos[i].x * gx, self.pos[i].y * gy) * alpha;
            }
        }
        // groups: every member pulled towards its group's centre, the groups
        // pushed apart a little
        if self.group.len() == n && self.group.iter().any(|g| g.is_some()) {
            let mut sum: Vec<(V2, f32)> = Vec::new();
            for i in 0..n {
                if let Some(g) = self.group[i] {
                    let g = g as usize;
                    if sum.len() <= g {
                        sum.resize(g + 1, (V2::default(), 0.0));
                    }
                    sum[g].0 += self.pos[i];
                    sum[g].1 += 1.0;
                }
            }
            let centres: Vec<Option<V2>> = sum.iter().map(|(s, c)| if *c > 0.0 { Some(*s * (1.0 / c)) } else { None }).collect();
            for i in 0..n {
                if let Some(g) = self.group[i] {
                    if let Some(Some(c)) = centres.get(g as usize) {
                        self.force[i] += (*c - self.pos[i]) * (0.14 * alpha);
                    }
                }
            }
            for a in 0..centres.len() {
                for b in (a + 1)..centres.len() {
                    if let (Some(ca), Some(cb)) = (centres[a], centres[b]) {
                        let d = cb - ca;
                        let dist = d.len().max(1.0);
                        let want = self.link_distance * 4.5;
                        if dist < want {
                            let push = d * ((want - dist) / dist * 0.06 * alpha);
                            for i in 0..n {
                                match self.group[i] {
                                    Some(g) if g as usize == a => self.force[i] -= push,
                                    Some(g) if g as usize == b => self.force[i] += push,
                                    _ => {}
                                }
                            }
                        }
                    }
                }
            }
        }
        // the springs do not pull both ends alike, so between them the free
        // hosts gain a push of their own; the centring takes it away, but it
        // waits while a host is held or pinned, and the graph sailed off (by
        // hundreds a second in light mode). Here the free hosts share that
        // push out, the pulls from outside them kept.
        if held {
            let mut sum = V2::default();
            let mut free = 0.0f32;
            for i in 0..n {
                if !self.fixed[i] {
                    sum += self.force[i];
                    free += 1.0;
                }
            }
            if free > 0.0 {
                let own = (sum - outside) * (1.0 / free);
                for i in 0..n {
                    if !self.fixed[i] {
                        self.force[i] -= own;
                    }
                }
            }
        }
        // integrate
        let mut moving = false;
        for i in 0..n {
            if self.fixed[i] {
                self.vel[i] = V2::default();
                continue;
            }
            self.vel[i] = (self.vel[i] + self.force[i]) * 0.55;
            let v = self.vel[i].len();
            if v > 60.0 {
                self.vel[i] = self.vel[i] * (60.0 / v);
            }
            self.pos[i] += self.vel[i];
            if v > 0.05 {
                moving = true;
            }
        }
        // centring, as d3's forceCenter: the springs do not conserve momentum
        // (a hub's leaves take the whole pull), so without it a graph with hubs
        // sails off; skipped while the analyst holds or pinned a host (it
        // would move that one too), the push shared out above instead
        if !held {
            let mut c = V2::default();
            for p in &self.pos {
                c += *p;
            }
            let c = c * (1.0 / n as f32);
            for p in &mut self.pos {
                *p -= c;
            }
            if self.held {
                self.recentred += c;
            }
        }
        self.held = held;
        // collisions: push overlapping circles apart (hash grid with cells the
        // size of the largest pair, two passes)
        let cell = (self.max_radius * 2.0 + 16.0).max(1.0);
        let key = |p: V2| ((p.x / cell).floor() as i32, (p.y / cell).floor() as i32);
        for v in self.grid.values_mut() {
            v.clear();
        }
        for (i, p) in self.pos.iter().enumerate() {
            self.grid.entry(key(*p)).or_default().push(i as u32);
        }
        self.grid.retain(|_, v| !v.is_empty());
        let mut grid = std::mem::take(&mut self.grid);
        let mut max_push = 0.0f32;
        for _ in 0..2 {
            for (k, v) in &grid {
                for &i in v {
                    let i = i as usize;
                    for dx in -1..=1 {
                        for dy in -1..=1 {
                            if let Some(w) = grid.get(&(k.0 + dx, k.1 + dy)) {
                                for &j in w {
                                    let j = j as usize;
                                    if j <= i {
                                        continue;
                                    }
                                    let mut d = self.pos[j] - self.pos[i];
                                    if d.len2() < 1e-6 {
                                        let a = (i * 7 + j * 13) as f32 * 0.7;
                                        d = V2::new(a.cos(), a.sin());
                                    }
                                    let dist = d.len().max(0.1);
                                    let min = self.radius[i] + self.radius[j] + 14.0;
                                    if dist < min {
                                        let push = d * ((min - dist) / dist * 0.5);
                                        max_push = max_push.max(min - dist);
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
        self.grid = std::mem::take(&mut grid);
        // a packed ball never settles to the last pixel: three seconds of cold
        // ticks are enough
        self.unsettled = max_push > 0.6 && self.cold_since.map_or(true, |t| t.elapsed().as_secs_f32() < 3.0);
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

    /// hubs of fifteen hosts, chained: the shape that made a held graph sail off
    fn hubs(n: usize) -> Layout {
        let links = (1..n).map(|i| if i % 15 == 0 { (i - 15, i) } else { (i - i % 15, i) }).collect();
        let mut l = Layout::new(vec![22.0; n], links, &vec![None; n]);
        for _ in 0..3000 {
            if !l.tick() {
                break;
            }
        }
        l
    }

    fn free_centroid(l: &Layout) -> V2 {
        let mut c = V2::default();
        let mut k = 0.0;
        for (p, f) in l.pos.iter().zip(&l.fixed) {
            if !f {
                c += *p;
                k += 1.0;
            }
        }
        c * (1.0 / k)
    }

    #[test]
    fn a_held_host_does_not_set_the_graph_sailing() {
        // a leaf held 300 away for as long as a drag in light mode ticks: the
        // rest follows it a little, it does not sail off (280 away with 200
        // hosts before, 700 to 1,000 in the window)
        for &n in &[60usize, 200] {
            let mut l = hubs(n);
            let before = free_centroid(&l);
            l.fixed[7] = true;
            l.pos[7] += V2::new(300.0, 0.0);
            for _ in 0..40 {
                l.reheat(0.3);
                for _ in 0..50 {
                    l.tick();
                }
            }
            let drift = (free_centroid(&l) - before).len();
            eprintln!("n={n}: free centroid drift {drift:.0}");
            assert!(drift < 30.0, "n={n}: the graph drifted {drift:.0} while a host was held");
        }
    }

    #[test]
    fn the_tree_repels_like_the_exact_sum_from_afar() {
        // 200 bodies in a blob and one probe far away: the tree's force on the
        // probe is within a few percent of the exact pairwise sum
        let mut pos: Vec<V2> = (0..200).map(|i| V2::new((i % 20) as f32 * 7.0, (i / 20) as f32 * 7.0)).collect();
        let probe = V2::new(2000.0, 300.0);
        pos.push(probe);
        let mut tree = Tree::new();
        tree.build(&pos);
        let mut stack = Vec::new();
        let f = tree.force(200, probe, -1000.0, 0.0, &mut stack);
        let mut exact = V2::default();
        for p in &pos[..200] {
            let d = probe - *p;
            let d2 = d.len2();
            exact += d * (-1000.0 / d2 / d2.sqrt());
        }
        assert!((f.x - exact.x).abs() < exact.x.abs() * 0.03 + 1e-3, "{f:?} {exact:?}");
        assert!((f.y - exact.y).abs() < exact.x.abs() * 0.03 + 1e-3, "{f:?} {exact:?}");
    }

    #[test]
    fn two_thousand_nodes_tick_fast() {
        let n = 2000;
        let links: Vec<(usize, usize)> = (1..n).map(|i| (i, i / 3)).collect();
        let mut l = Layout::new(vec![22.0; n], links, &vec![None; n]);
        let t = std::time::Instant::now();
        for _ in 0..20 {
            l.tick();
        }
        // debug builds are slow; the point is that it is not quadratic
        assert!(t.elapsed().as_millis() < 20 * 150, "{:?}", t.elapsed());
    }

    #[test]
    fn a_tick_budget_is_honoured() {
        let n = 500;
        let mut l = Layout::new(vec![22.0; n], (1..n).map(|i| (i, i / 2)).collect(), &vec![None; n]);
        let moving = l.tick_for(std::time::Duration::from_millis(1), 50);
        assert!(moving);
        assert!(l.is_running());
    }
}

#[cfg(test)]
mod drift_tests {
    use super::*;

    #[test]
    fn a_dense_ball_stays_centred() {
        let n = 3000;
        let mut seed = 12345u64;
        let mut rnd = move || {
            seed ^= seed << 13;
            seed ^= seed >> 7;
            seed ^= seed << 17;
            seed
        };
        // hubs like a real network: half the links go to twelve servers
        let mut links: Vec<(usize, usize)> = (0..47_000).map(|k| ((rnd() % n as u64) as usize, if k % 2 == 0 { (rnd() % 12) as usize } else { (rnd() % n as u64) as usize })).filter(|(a, b)| a != b).collect();
        links.sort_unstable();
        links.dedup();
        let radius: Vec<f32> = (0..n).map(|i| if i < 12 { 30.0 } else { 20.0 + (i % 7) as f32 }).collect();
        let mut l = Layout::new(radius, links, &vec![None; n]);
        l.link_distance = 120.0;
        let centroid = |l: &Layout| {
            let mut c = V2::default();
            for p in &l.pos {
                c += *p;
            }
            c * (1.0 / l.pos.len() as f32)
        };
        let c0 = centroid(&l);
        let (lo0, hi0) = l.bounds().unwrap();
        let t = std::time::Instant::now();
        for k in 0..300 {
            l.tick();
            if k % 50 == 0 {
                let c = centroid(&l);
                let (lo, hi) = l.bounds().unwrap();
                eprintln!("tick {k}: centroid ({:.0}, {:.0}) bounds ({:.0},{:.0})-({:.0},{:.0}) alpha {:.3}", c.x, c.y, lo.x, lo.y, hi.x, hi.y, l.alpha);
            }
        }
        eprintln!("300 ticks in {:?}", t.elapsed());
        let c = centroid(&l);
        let (lo, hi) = l.bounds().unwrap();
        eprintln!("start centroid ({:.0}, {:.0}) bounds ({:.0},{:.0})-({:.0},{:.0})", c0.x, c0.y, lo0.x, lo0.y, hi0.x, hi0.y);
        eprintln!("end   centroid ({:.0}, {:.0}) bounds ({:.0},{:.0})-({:.0},{:.0})", c.x, c.y, lo.x, lo.y, hi.x, hi.y);
        assert!(c.len() < 300.0, "the ball drifted to {:?}", c);
    }
}
