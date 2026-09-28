// Graph algorithms used by graph-hunt, computed in memory on the host graph
// (a few hundred nodes, distinct authenticated host pairs). Standard
// definitions, no tuning:
//   * PageRank    — damping 0.85 (the algorithm's defining constant),
//                   dangling mass spread uniformly, iterated until the L1
//                   change is below machine-level tolerance
//   * betweenness — Brandes, directed, unweighted, normalised by (n-1)(n-2)
//   * Louvain     — Blondel et al., undirected, unweighted, resolution 1,
//                   nodes visited in index order (deterministic)

/// Directed graph on nodes 0..n given as adjacency lists (deduplicated).
pub struct DiGraph {
    pub n: usize,
    pub out: Vec<Vec<usize>>,
}

impl DiGraph {
    pub fn from_edges(n: usize, edges: &[(usize, usize)]) -> Self {
        let mut out = vec![Vec::new(); n];
        for &(a, b) in edges {
            if a != b {
                out[a].push(b);
            }
        }
        for v in out.iter_mut() {
            v.sort_unstable();
            v.dedup();
        }
        DiGraph { n, out }
    }
}

pub const PAGERANK_DAMPING: f64 = 0.85;

/// PageRank scaled by n (mean 1.0) so values stay comparable when the node
/// count grows from one day to the next.
pub fn pagerank(g: &DiGraph) -> Vec<f64> {
    let nf = g.n.max(1) as f64;
    pagerank_from(g, &vec![1.0 / nf; g.n])
}

/// Convergence noise of PageRank on this graph: the largest difference
/// between the values reached from the uniform start and from a start
/// proportional to in-degree. A change smaller than this is not a change.
pub fn pagerank_noise(g: &DiGraph) -> f64 {
    if g.n == 0 {
        return 0.0;
    }
    let mut indeg = vec![1.0f64; g.n];
    for v in 0..g.n {
        for &w in &g.out[v] {
            indeg[w] += 1.0;
        }
    }
    let tot: f64 = indeg.iter().sum();
    let alt: Vec<f64> = indeg.iter().map(|x| x / tot).collect();
    let a = pagerank(g);
    let b = pagerank_from(g, &alt);
    a.iter().zip(&b).map(|(x, y)| (x - y).abs()).fold(0.0, f64::max)
}

fn pagerank_from(g: &DiGraph, init: &[f64]) -> Vec<f64> {
    let n = g.n;
    if n == 0 {
        return Vec::new();
    }
    let nf = n as f64;
    let mut pr: Vec<f64> = init.to_vec();
    for _ in 0..10_000 {
        let mut next = vec![(1.0 - PAGERANK_DAMPING) / nf; n];
        let mut dangling = 0.0;
        for v in 0..n {
            if g.out[v].is_empty() {
                dangling += pr[v];
            } else {
                let share = PAGERANK_DAMPING * pr[v] / g.out[v].len() as f64;
                for &w in &g.out[v] {
                    next[w] += share;
                }
            }
        }
        let d = PAGERANK_DAMPING * dangling / nf;
        for x in next.iter_mut() {
            *x += d;
        }
        let diff: f64 = next.iter().zip(&pr).map(|(a, b)| (a - b).abs()).sum();
        pr = next;
        // iterate to floating-point stationarity, not to a tolerance
        if diff <= 4.0 * f64::EPSILON {
            break;
        }
    }
    pr.into_iter().map(|x| x * nf).collect()
}

/// Brandes betweenness centrality, directed, unweighted, normalised by
/// (n-1)(n-2) so values are comparable across graph sizes.
pub fn betweenness(g: &DiGraph) -> Vec<f64> {
    let n = g.n;
    let mut cb = vec![0.0f64; n];
    let mut stack: Vec<usize> = Vec::with_capacity(n);
    let mut pred: Vec<Vec<usize>> = vec![Vec::new(); n];
    let mut sigma = vec![0.0f64; n];
    let mut dist = vec![-1i64; n];
    let mut delta = vec![0.0f64; n];
    let mut queue = std::collections::VecDeque::with_capacity(n);
    for s in 0..n {
        stack.clear();
        for p in pred.iter_mut() {
            p.clear();
        }
        sigma.iter_mut().for_each(|x| *x = 0.0);
        dist.iter_mut().for_each(|x| *x = -1);
        sigma[s] = 1.0;
        dist[s] = 0;
        queue.clear();
        queue.push_back(s);
        while let Some(v) = queue.pop_front() {
            stack.push(v);
            for &w in &g.out[v] {
                if dist[w] < 0 {
                    dist[w] = dist[v] + 1;
                    queue.push_back(w);
                }
                if dist[w] == dist[v] + 1 {
                    sigma[w] += sigma[v];
                    pred[w].push(v);
                }
            }
        }
        delta.iter_mut().for_each(|x| *x = 0.0);
        while let Some(w) = stack.pop() {
            for &v in &pred[w] {
                delta[v] += sigma[v] / sigma[w] * (1.0 + delta[w]);
            }
            if w != s {
                cb[w] += delta[w];
            }
        }
    }
    if n > 2 {
        let norm = ((n - 1) * (n - 2)) as f64;
        for x in cb.iter_mut() {
            *x /= norm;
        }
    }
    cb
}

/// Louvain community detection on the undirected, unweighted version of
/// the graph. Returns a community id per node (isolated nodes get their
/// own community).
pub fn louvain(g: &DiGraph) -> Vec<usize> {
    let n = g.n;
    // undirected weighted adjacency (weight 1 per connected pair)
    let mut adj: Vec<std::collections::BTreeMap<usize, f64>> = vec![Default::default(); n];
    for a in 0..n {
        for &b in &g.out[a] {
            adj[a].insert(b, 1.0);
            adj[b].insert(a, 1.0);
        }
    }
    let mut membership: Vec<usize> = (0..n).collect();
    let mut level_adj = adj;
    loop {
        let (comm, moved) = one_level(&level_adj);
        if !moved {
            break;
        }
        // relabel communities 0..k
        let mut map = std::collections::HashMap::new();
        for c in &comm {
            let k = map.len();
            map.entry(*c).or_insert(k);
        }
        let k = map.len();
        for m in membership.iter_mut() {
            *m = map[&comm[*m]];
        }
        // aggregate graph
        let mut agg: Vec<std::collections::BTreeMap<usize, f64>> = vec![Default::default(); k];
        for (v, nb) in level_adj.iter().enumerate() {
            let cv = map[&comm[v]];
            for (&w, &wt) in nb {
                let cw = map[&comm[w]];
                *agg[cv].entry(cw).or_insert(0.0) += wt;
            }
        }
        if k == level_adj.len() {
            break;
        }
        level_adj = agg;
    }
    membership
}

/// One Louvain local-moving phase. Self-loops (from aggregation) count in
/// the node degree as in the original formulation.
fn one_level(adj: &[std::collections::BTreeMap<usize, f64>]) -> (Vec<usize>, bool) {
    let n = adj.len();
    let k: Vec<f64> = adj.iter().map(|nb| nb.values().sum()).collect();
    let m2: f64 = k.iter().sum();
    let mut comm: Vec<usize> = (0..n).collect();
    if m2 == 0.0 {
        return (comm, false);
    }
    let mut tot: Vec<f64> = k.clone();
    let mut moved_any = false;
    loop {
        let mut moved = false;
        for v in 0..n {
            let cv = comm[v];
            // weights from v to each neighbouring community
            let mut to: std::collections::BTreeMap<usize, f64> = Default::default();
            for (&w, &wt) in &adj[v] {
                if w != v {
                    *to.entry(comm[w]).or_insert(0.0) += wt;
                }
            }
            tot[cv] -= k[v];
            let base = to.get(&cv).copied().unwrap_or(0.0) - tot[cv] * k[v] / m2;
            let mut best = cv;
            let mut best_gain = base;
            for (&c, &w_in) in &to {
                let gain = w_in - tot[c] * k[v] / m2;
                if gain > best_gain + 1e-12 {
                    best_gain = gain;
                    best = c;
                }
            }
            tot[best] += k[v];
            if best != cv {
                comm[v] = best;
                moved = true;
                moved_any = true;
            }
        }
        if !moved {
            break;
        }
    }
    (comm, moved_any)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn pagerank_cycle_uniform() {
        let g = DiGraph::from_edges(3, &[(0, 1), (1, 2), (2, 0)]);
        for x in pagerank(&g) {
            assert!((x - 1.0).abs() < 1e-9);
        }
    }
    #[test]
    fn betweenness_path() {
        // 0 -> 1 -> 2 : node 1 lies on the only 0->2 path
        let g = DiGraph::from_edges(3, &[(0, 1), (1, 2)]);
        let b = betweenness(&g);
        assert!((b[1] - 0.5).abs() < 1e-12); // 1 / ((3-1)(3-2))
        assert_eq!(b[0], 0.0);
    }
    #[test]
    fn louvain_two_cliques() {
        let mut e = Vec::new();
        for a in 0..4 {
            for b in 0..4 {
                if a < b {
                    e.push((a, b));
                    e.push((a + 4, b + 4));
                }
            }
        }
        e.push((0, 4));
        let g = DiGraph::from_edges(8, &e);
        let c = louvain(&g);
        assert!(c[0] == c[1] && c[1] == c[2] && c[2] == c[3]);
        assert!(c[4] == c[5] && c[5] == c[6] && c[6] == c[7]);
        assert!(c[0] != c[4]);
    }
}
