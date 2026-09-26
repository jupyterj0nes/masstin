// Statistical primitives for graph-hunt. Everything the detectors report
// is one of these, applied to counts measured in the corpus itself:
//
//   * empirical_p / upper_tail — tail probability of an observation against
//                        the values the same statistic took on baseline days
//   * simes            — combine the joint tests of one machine (valid
//                        under positive dependence)
//   * benjamini_hochberg — false-discovery-rate control across machines
//   * hypergeom_upper  — exact overlap test (campaign grouping)
//   * rayleigh         — time-of-day concentration (descriptive)
//
// No tuning constants live here. The only externally chosen number in the
// whole pipeline is alpha (CLI, default 0.05).

/// Empirical p-value with the add-one correction:
/// (1 + #null values at least as extreme) / (1 + N). Never 0; with an
/// empty null it is 1 (nothing to compare with = no evidence).
pub fn empirical_p(at_least_as_extreme: usize, n_null: usize) -> f64 {
    (1.0 + at_least_as_extreme as f64) / (1.0 + n_null as f64)
}

/// Upper-tail empirical p of `x` against an ascending-sorted null sample.
pub fn upper_tail(sorted_null: &[f64], x: f64) -> f64 {
    let idx = sorted_null.partition_point(|v| *v < x);
    empirical_p(sorted_null.len() - idx, sorted_null.len())
}

/// Simes combination of m p-values (valid under independence and positive
/// dependence): min_i m * p_(i) / i.
pub fn simes(ps: &[f64]) -> f64 {
    if ps.is_empty() {
        return 1.0;
    }
    let mut v: Vec<f64> = ps.to_vec();
    v.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));
    let m = v.len() as f64;
    v.iter()
        .enumerate()
        .map(|(i, p)| m * p / (i as f64 + 1.0))
        .fold(1.0, f64::min)
}

fn log_add(a: f64, b: f64) -> f64 {
    if a == f64::NEG_INFINITY {
        return b;
    }
    if b == f64::NEG_INFINITY {
        return a;
    }
    let (hi, lo) = if a > b { (a, b) } else { (b, a) };
    hi + (lo - hi).exp().ln_1p()
}

/// Benjamini-Hochberg adjusted p-values (q-values), in input order.
pub fn benjamini_hochberg(ps: &[f64]) -> Vec<f64> {
    let m = ps.len();
    if m == 0 {
        return Vec::new();
    }
    let mut idx: Vec<usize> = (0..m).collect();
    idx.sort_by(|&a, &b| ps[a].partial_cmp(&ps[b]).unwrap_or(std::cmp::Ordering::Equal));
    let mut q = vec![1.0; m];
    let mut running = 1.0f64;
    for rank in (0..m).rev() {
        let i = idx[rank];
        let v = (ps[i] * m as f64 / (rank as f64 + 1.0)).min(1.0);
        running = running.min(v);
        q[i] = running;
    }
    q
}

fn ln_gamma(x: f64) -> f64 {
    // Lanczos approximation (g = 7, n = 9), ~1e-15 relative accuracy
    const G: [f64; 9] = [
        0.999_999_999_999_809_9,
        676.520_368_121_885_1,
        -1_259.139_216_722_402_8,
        771.323_428_777_653_1,
        -176.615_029_162_140_6,
        12.507_343_278_686_905,
        -0.138_571_095_265_720_12,
        9.984_369_578_019_572e-6,
        1.505_632_735_149_311_6e-7,
    ];
    if x < 0.5 {
        return (std::f64::consts::PI / (std::f64::consts::PI * x).sin()).ln() - ln_gamma(1.0 - x);
    }
    let x = x - 1.0;
    let mut a = G[0];
    let t = x + 7.5;
    for (i, g) in G.iter().enumerate().skip(1) {
        a += g / (x + i as f64);
    }
    0.5 * (2.0 * std::f64::consts::PI).ln() + (x + 0.5) * t.ln() - t + a.ln()
}

fn ln_choose(n: u64, k: u64) -> f64 {
    if k > n {
        return f64::NEG_INFINITY;
    }
    ln_gamma(n as f64 + 1.0) - ln_gamma(k as f64 + 1.0) - ln_gamma((n - k) as f64 + 1.0)
}

/// P(X >= k) for X ~ Hypergeometric(population, successes, draws).
pub fn hypergeom_upper(pop: u64, succ: u64, draws: u64, k: u64) -> f64 {
    let hi = succ.min(draws);
    if k > hi {
        return 0.0;
    }
    let lo = k.max((draws + succ).saturating_sub(pop));
    let denom = ln_choose(pop, draws);
    let mut acc = f64::NEG_INFINITY;
    for i in lo..=hi {
        acc = log_add(acc, ln_choose(succ, i) + ln_choose(pop - succ, draws - i) - denom);
    }
    acc.exp().min(1.0)
}

/// Rayleigh test for a preferred time of day. Input: seconds of day.
/// Returns (mean resultant length R, p-value), Zar's approximation
/// p = exp(sqrt(1 + 4n + 4(n^2 - Rn^2)) - (1 + 2n)), Rn = n * R.
pub fn rayleigh(secs_of_day: &[f64]) -> (f64, f64) {
    let n = secs_of_day.len();
    if n < 2 {
        return (0.0, 1.0);
    }
    let (mut c, mut s) = (0.0, 0.0);
    for t in secs_of_day {
        let a = 2.0 * std::f64::consts::PI * t / 86400.0;
        c += a.cos();
        s += a.sin();
    }
    let nf = n as f64;
    let rn = (c * c + s * s).sqrt();
    let p = ((1.0 + 4.0 * nf + 4.0 * (nf * nf - rn * rn)).sqrt() - (1.0 + 2.0 * nf)).exp();
    (rn / nf, p.clamp(0.0, 1.0))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn bh_known() {
        let q = benjamini_hochberg(&[0.01, 0.04, 0.03, 0.2]);
        assert!((q[0] - 0.04).abs() < 1e-12);
        assert!((q[1] - 0.053_333_3).abs() < 1e-6);
        assert!((q[2] - 0.053_333_3).abs() < 1e-6);
        assert!((q[3] - 0.2).abs() < 1e-12);
    }
    #[test]
    fn hypergeom_known() {
        // N=39 K=32 n=31 k=31 -> C(32,31) C(7,0) / C(39,31) = 32 / 61523748
        let p = hypergeom_upper(39, 32, 31, 31);
        assert!((p - 32.0 / 61_523_748.0).abs() / p < 1e-9);
    }
    #[test]
    fn simes_known() {
        assert!((simes(&[0.01, 0.5, 0.9]) - 0.03).abs() < 1e-12);
    }
    #[test]
    fn empirical() {
        let null = vec![0.0, 0.0, 1.0, 2.0, 5.0];
        assert!((upper_tail(&null, 5.0) - 2.0 / 6.0).abs() < 1e-12);
        assert!((upper_tail(&null, 6.0) - 1.0 / 6.0).abs() < 1e-12);
    }
}
