// IP -> host name resolution from same-login co-occurrence.
//
// The same SSH login is often recorded twice on the destination: sshd
// writes the source IP, wtmp (with UseDNS) writes the reverse-DNS name.
// When, for one (destination, account, second, outcome), exactly one IP
// and exactly one name appear, that is one vote "IP is NAME".
//
// A vote can also be a coincidence: an unrelated login of the same account
// on the same destination from machine NAME landing in the same second as
// the IP's login. Under a Poisson model with that name's own login rate on
// that (destination, account, outcome), lambda = logins / observed
// seconds, the chance of one coincidence is 1 - exp(-lambda); independent
// votes multiply. The mapping is accepted when
//   * every vote names the same host (unanimity: conflicting evidence is
//     not resolved by majority), and
//   * the probability that all votes are coincidences is significant
//     after Benjamini-Hochberg across all candidate IPs at `alpha`.
// Nodes are never merged by the loaders; the result is an annotation
// (loaders) and the machine identity used by graph-hunt's report.

use std::collections::{HashMap, HashSet};

/// One recorded login with a remote source.
pub struct Obs<'a> {
    pub dst: &'a str,
    pub account: &'a str,
    pub outcome: &'a str,
    /// Unix seconds.
    pub sec: i64,
    /// Source as recorded: an IP or a host name.
    pub source: &'a str,
    pub source_is_ip: bool,
}

#[derive(Debug, Clone)]
pub struct Resolution {
    pub name: String,
    pub votes: u32,
    /// Probability that every vote is a coincidence.
    pub p_chance: f64,
    /// Benjamini-Hochberg adjusted value across candidate IPs.
    #[allow(dead_code)]
    pub q: f64,
}

pub fn resolve_ip_names<'a>(obs: impl Iterator<Item = Obs<'a>>, alpha: f64) -> HashMap<String, Resolution> {
    // (dst, account, outcome, second) -> (ips, names)
    let mut cooc: HashMap<(&str, &str, &str, i64), (Vec<&str>, Vec<&str>)> = HashMap::new();
    let mut span: HashMap<&str, (i64, i64)> = HashMap::new();
    for o in obs {
        let e = span.entry(o.dst).or_insert((o.sec, o.sec));
        if o.sec < e.0 {
            e.0 = o.sec;
        }
        if o.sec > e.1 {
            e.1 = o.sec;
        }
        let c = cooc.entry((o.dst, o.account, o.outcome, o.sec)).or_default();
        let list = if o.source_is_ip { &mut c.0 } else { &mut c.1 };
        if !list.contains(&o.source) {
            list.push(o.source);
        }
    }
    // name login rate per (dst, account, outcome, name): distinct seconds
    let mut n_name: HashMap<(&str, &str, &str, &str), u64> = HashMap::new();
    for ((d, a, oc, _), (_, names)) in &cooc {
        for nm in names {
            *n_name.entry((d, a, oc, nm)).or_insert(0) += 1;
        }
    }
    // votes: ip -> (names seen, votes, sum ln p_vote)
    struct Cand<'b> {
        names: HashSet<&'b str>,
        votes: u32,
        ln_p: f64,
        first: &'b str,
    }
    let mut cand: HashMap<&str, Cand> = HashMap::new();
    for ((d, a, oc, _), (ips, names)) in &cooc {
        if ips.len() != 1 || names.len() != 1 {
            continue;
        }
        let (ip, nm) = (ips[0], names[0]);
        let (lo, hi) = span[d];
        let t = (hi - lo + 1).max(1) as f64;
        let lambda = n_name[&(*d, *a, *oc, nm)] as f64 / t;
        let p_vote = (-(-lambda).exp_m1()).clamp(f64::MIN_POSITIVE, 1.0); // 1 - e^-lambda
        let c = cand.entry(ip).or_insert(Cand { names: HashSet::new(), votes: 0, ln_p: 0.0, first: nm });
        c.names.insert(nm);
        c.votes += 1;
        c.ln_p += p_vote.ln();
    }
    let unanimous: Vec<(&str, &Cand)> = cand.iter().filter(|(_, c)| c.names.len() == 1).map(|(k, v)| (*k, v)).collect();
    let ps: Vec<f64> = unanimous.iter().map(|(_, c)| c.ln_p.exp()).collect();
    let qs = super::stats::benjamini_hochberg(&ps);
    let mut out = HashMap::new();
    for (i, (ip, c)) in unanimous.iter().enumerate() {
        if qs[i] <= alpha {
            out.insert(
                ip.to_string(),
                Resolution { name: c.first.to_string(), votes: c.votes, p_chance: ps[i], q: qs[i] },
            );
        }
    }
    out
}

/// Loader entry point: the loaders already collect, per (destination,
/// ACCOUNT, "YYYY-MM-DDTHH:MM:SS", outcome), the IPs and names recorded for
/// that login. Returns ip -> (name, votes, chance probability).
pub fn resolve_from_cooc(
    cooc: &HashMap<(String, String, String, String), (Vec<String>, Vec<String>)>,
    alpha: f64,
) -> HashMap<String, (String, u32, f64)> {
    let mut obs: Vec<Obs> = Vec::new();
    for ((d, a, ts, oc), (ips, names)) in cooc {
        let sec = match chrono::NaiveDateTime::parse_from_str(ts, "%Y-%m-%dT%H:%M:%S")
            .or_else(|_| chrono::NaiveDateTime::parse_from_str(ts, "%Y-%m-%d %H:%M:%S"))
        {
            Ok(t) => t.and_utc().timestamp(),
            Err(_) => continue,
        };
        for ip in ips {
            obs.push(Obs { dst: d, account: a, outcome: oc, sec, source: ip, source_is_ip: true });
        }
        for nm in names {
            obs.push(Obs { dst: d, account: a, outcome: oc, sec, source: nm, source_is_ip: false });
        }
    }
    resolve_ip_names(obs.into_iter(), alpha)
        .into_iter()
        .map(|(ip, r)| (ip, (r.name, r.votes, r.p_chance)))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn one_rare_coincidence_resolves_frequent_does_not() {
        let mut v = Vec::new();
        // span of one day on DST
        v.push(Obs { dst: "DST", account: "X", outcome: "S", sec: 0, source: "OTHER", source_is_ip: false });
        v.push(Obs { dst: "DST", account: "X", outcome: "S", sec: 86_399, source: "OTHER", source_is_ip: false });
        // 10.0.0.1 and HOSTA together once; HOSTA logs in rarely
        v.push(Obs { dst: "DST", account: "U", outcome: "S", sec: 100, source: "10.0.0.1", source_is_ip: true });
        v.push(Obs { dst: "DST", account: "U", outcome: "S", sec: 100, source: "HOSTA", source_is_ip: false });
        // 10.0.0.2 with BUSY once, but BUSY logs in every second
        for s in 1000..87_000i64 {
            v.push(Obs { dst: "DST", account: "B", outcome: "S", sec: s, source: "BUSY", source_is_ip: false });
        }
        v.push(Obs { dst: "DST", account: "B", outcome: "S", sec: 5000, source: "10.0.0.2", source_is_ip: true });
        let r = resolve_ip_names(v.into_iter(), 0.05);
        assert_eq!(r.get("10.0.0.1").map(|x| x.name.as_str()), Some("HOSTA"));
        assert!(r.get("10.0.0.2").is_none());
    }
}
