// IP -> host name resolution from same-login co-occurrence.
//
// The same SSH login is often recorded twice on the destination: sshd
// writes the source IP, wtmp (with UseDNS) writes the reverse-DNS name.
// When, for one (destination, account, outcome, second), exactly one IP
// and exactly one name appear, that is one vote "IP is NAME".
//
// A vote can also be a coincidence: an unrelated login of the same account
// on the same destination from machine NAME landing in the same second as
// the IP's login. The test counts the trials as well as the votes: for a
// candidate pair (IP, NAME), every second in which the IP logged in alone
// (in any context (destination, account, outcome) the IP appears in) is a
// trial; the ones where NAME, and only NAME, was recorded in that second
// are the votes. Under a Poisson model with NAME's own login rate in that
// context, lambda = NAME's distinct login seconds / the destination's
// observed span, a trial coincides by chance with probability
// 1 - exp(-lambda). The number of chance votes is then Binomial(trials,
// mean chance probability over the trials), and the p-value is the upper
// tail at the observed votes. Genuine double-logging gives votes = trials
// and a p-value that vanishes with the number of logins; coincidences at
// the expected rate stay unremarkable however many there are.
//
// Benjamini-Hochberg runs across every (IP, NAME) candidate at `alpha`.
// An IP is resolved when exactly one NAME is significant for it; two
// significant names are a conflict and the IP stays unresolved. Nodes are
// never merged by the loaders; the result is an annotation (loaders) and
// the machine identity used by graph-hunt's report.

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
    /// seconds in which the IP and the name were recorded together, alone
    pub votes: u32,
    /// Binomial upper-tail probability of at least that many votes by chance
    pub p_chance: f64,
    /// Benjamini-Hochberg adjusted value across all (IP, name) candidates.
    #[allow(dead_code)]
    pub q: f64,
}

/// The rates the chance model needs, measured over EVERY login (not only
/// the seconds where an IP and a name coincide): a name's distinct login
/// seconds per (destination, account, outcome), and each destination's
/// observed span.
#[derive(Default)]
pub struct Rates<'a> {
    pub n_name: HashMap<(&'a str, &'a str, &'a str, &'a str), u64>,
    pub span: HashMap<&'a str, (i64, i64)>,
    seen: HashSet<u64>,
}

impl<'a> Rates<'a> {
    pub fn new() -> Self {
        Self::default()
    }
    /// Every login counts for the span; a name-sourced login counts once
    /// per second for its name's rate.
    pub fn add(&mut self, dst: &'a str, account: &'a str, outcome: &'a str, sec: i64, source: &'a str, source_is_ip: bool) {
        let e = self.span.entry(dst).or_insert((sec, sec));
        if sec < e.0 {
            e.0 = sec;
        }
        if sec > e.1 {
            e.1 = sec;
        }
        if !source_is_ip {
            use std::hash::{Hash, Hasher};
            let mut h = std::collections::hash_map::DefaultHasher::new();
            (dst, account, outcome, source, sec).hash(&mut h);
            if self.seen.insert(h.finish()) {
                *self.n_name.entry((dst, account, outcome, source)).or_insert(0) += 1;
            }
        }
    }
}

/// Resolution from every observation at once (the rates are taken from the
/// same observations). For large corpora use `resolve_ip_names_with` and
/// feed it only the seconds where an IP and a name can coincide.
pub fn resolve_ip_names<'a>(obs: impl Iterator<Item = Obs<'a>>, alpha: f64) -> HashMap<String, Resolution> {
    let all: Vec<Obs<'a>> = obs.collect();
    let mut rates = Rates::new();
    for o in &all {
        rates.add(o.dst, o.account, o.outcome, o.sec, o.source, o.source_is_ip);
    }
    resolve_ip_names_with(all.into_iter(), alpha, &rates)
}

/// `obs` must contain every IP-sourced login and the name-sourced logins of
/// the same (destination, account, outcome, second); `rates` the rates
/// measured over all logins.
pub fn resolve_ip_names_with<'a>(obs: impl Iterator<Item = Obs<'a>>, alpha: f64, rates: &Rates<'a>) -> HashMap<String, Resolution> {
    // (dst, account, outcome, second) -> (ips, names)
    let mut cooc: HashMap<(&str, &str, &str, i64), (Vec<&str>, Vec<&str>)> = HashMap::new();
    for o in obs {
        let c = cooc.entry((o.dst, o.account, o.outcome, o.sec)).or_default();
        let list = if o.source_is_ip { &mut c.0 } else { &mut c.1 };
        if !list.contains(&o.source) {
            list.push(o.source);
        }
    }
    let span = &rates.span;
    let n_name = &rates.n_name;
    // per IP: trials per context (seconds where the IP was the only IP)
    // and votes per (context, name)
    let mut trials: HashMap<&str, HashMap<(&str, &str, &str), u64>> = HashMap::new();
    let mut votes: HashMap<(&str, &str), HashMap<(&str, &str, &str), u64>> = HashMap::new();
    for ((d, a, oc, _), (ips, names)) in &cooc {
        if ips.len() != 1 {
            continue;
        }
        let ip = ips[0];
        *trials.entry(ip).or_default().entry((d, a, oc)).or_insert(0) += 1;
        if names.len() == 1 {
            *votes.entry((ip, names[0])).or_default().entry((d, a, oc)).or_insert(0) += 1;
        }
    }
    // one binomial test per (IP, name)
    struct Cand<'b> {
        ip: &'b str,
        name: &'b str,
        votes: u64,
        p: f64,
    }
    let mut cands: Vec<Cand> = Vec::new();
    for ((ip, nm), by_ctx) in &votes {
        let tr = &trials[ip];
        let mut n_tot = 0u64;
        let mut k_tot = 0u64;
        let mut p_sum = 0.0f64;
        for ((d, a, oc), &n_c) in tr {
            let (lo, hi) = span.get(d).copied().unwrap_or((0, 0));
            let t = (hi - lo + 1).max(1) as f64;
            let lambda = n_name.get(&(d, a, oc, nm)).copied().unwrap_or(0) as f64 / t;
            let p_c = -(-lambda).exp_m1(); // 1 - e^-lambda
            n_tot += n_c;
            p_sum += n_c as f64 * p_c;
            k_tot += by_ctx.get(&(d, a, oc)).copied().unwrap_or(0);
        }
        if n_tot == 0 {
            continue;
        }
        let p_mean = (p_sum / n_tot as f64).clamp(f64::MIN_POSITIVE, 1.0);
        cands.push(Cand { ip, name: nm, votes: k_tot, p: super::stats::binom_upper(n_tot, k_tot, p_mean) });
    }
    let qs = super::stats::benjamini_hochberg(&cands.iter().map(|c| c.p).collect::<Vec<_>>());
    // accept the unique significant name per IP
    let mut sig_by_ip: HashMap<&str, Vec<usize>> = HashMap::new();
    for (i, c) in cands.iter().enumerate() {
        if qs[i] <= alpha {
            sig_by_ip.entry(c.ip).or_default().push(i);
        }
    }
    let mut out = HashMap::new();
    for (ip, idx) in sig_by_ip {
        if idx.len() != 1 {
            continue; // conflicting names: unresolved
        }
        let c = &cands[idx[0]];
        out.insert(ip.to_string(), Resolution { name: c.name.to_string(), votes: c.votes as u32, p_chance: c.p, q: qs[idx[0]] });
    }
    out
}

/// Compact collector of same-login co-occurrences for the loaders. Names
/// are interned once and a login is keyed by small integers, so ten
/// million rows cost tens of megabytes instead of several gigabytes (the
/// former map of owned strings per row, fed with every pre-auth touch and
/// session end, ran a 20 GB machine out of memory on 12 M rows). Only rows
/// that are authentication outcomes with a named account are worth
/// adding: pre-auth touches and session ends carry no identity to vote
/// with.
#[derive(Default)]
pub struct CoocCollector {
    names: Vec<String>,
    ids: HashMap<String, u32>,
    outcomes: Vec<String>,
    /// (dst, account, second, outcome) -> (ip ids, name ids)
    map: HashMap<(u32, u32, i64, u8), (Vec<u32>, Vec<u32>)>,
}

impl CoocCollector {
    pub fn new() -> Self {
        Self::default()
    }
    fn id(&mut self, s: &str) -> u32 {
        if let Some(&i) = self.ids.get(s) {
            return i;
        }
        let i = self.names.len() as u32;
        self.names.push(s.to_string());
        self.ids.insert(s.to_string(), i);
        i
    }
    /// `ts` is the CSV timestamp ("YYYY-MM-DDTHH:MM:SS..." or with a space);
    /// `source` the single IP or name recorded for the login.
    pub fn add(&mut self, dst: &str, account: &str, ts: &str, outcome: &str, source: &str, is_ip: bool) {
        let t = match ts.get(..19) {
            Some(x) => x,
            None => return,
        };
        let sec = match chrono::NaiveDateTime::parse_from_str(t, "%Y-%m-%dT%H:%M:%S")
            .or_else(|_| chrono::NaiveDateTime::parse_from_str(t, "%Y-%m-%d %H:%M:%S"))
        {
            Ok(n) => n.and_utc().timestamp(),
            Err(_) => return,
        };
        let oc = match self.outcomes.iter().position(|o| o == outcome) {
            Some(i) => i as u8,
            None => {
                if self.outcomes.len() >= 255 {
                    return;
                }
                self.outcomes.push(outcome.to_string());
                (self.outcomes.len() - 1) as u8
            }
        };
        let d = self.id(dst);
        let a = self.id(&account.to_uppercase());
        let s = self.id(source);
        let e = self.map.entry((d, a, sec, oc)).or_default();
        let list = if is_ip { &mut e.0 } else { &mut e.1 };
        if !list.contains(&s) {
            list.push(s);
        }
    }
    pub fn len(&self) -> usize {
        self.map.len()
    }
    /// ip -> (name, votes, chance probability), see `resolve_ip_names`.
    pub fn resolve(&self, alpha: f64) -> HashMap<String, (String, u32, f64)> {
        let obs = self.map.iter().flat_map(|((d, a, sec, oc), (ips, nms))| {
            let (dst, account, outcome, sec) = (self.names[*d as usize].as_str(), self.names[*a as usize].as_str(), self.outcomes[*oc as usize].as_str(), *sec);
            ips.iter()
                .map(move |i| Obs { dst, account, outcome, sec, source: self.names[*i as usize].as_str(), source_is_ip: true })
                .chain(nms.iter().map(move |i| Obs { dst, account, outcome, sec, source: self.names[*i as usize].as_str(), source_is_ip: false }))
        });
        resolve_ip_names(obs, alpha).into_iter().map(|(ip, r)| (ip, (r.name, r.votes, r.p_chance))).collect()
    }
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
    #[test]
    fn coincidences_at_the_expected_rate_do_not_resolve() {
        // two machines share account S on DST: 10.0.0.9 logs in on 1000
        // seconds, HOSTB on 1000 other seconds spread over the day, and
        // they coincide 12 times, about what chance predicts
        // (1000 * 1000 / 86400 = 11.6)
        let mut v = Vec::new();
        v.push(Obs { dst: "DST", account: "S", outcome: "S", sec: 0, source: "HOSTB", source_is_ip: false });
        v.push(Obs { dst: "DST", account: "S", outcome: "S", sec: 86_399, source: "HOSTB", source_is_ip: false });
        for i in 0..1000i64 {
            v.push(Obs { dst: "DST", account: "S", outcome: "S", sec: 10 + i * 80, source: "10.0.0.9", source_is_ip: true });
        }
        for i in 0..998i64 {
            v.push(Obs { dst: "DST", account: "S", outcome: "S", sec: 50 + i * 80, source: "HOSTB", source_is_ip: false });
        }
        for i in 0..12i64 {
            v.push(Obs { dst: "DST", account: "S", outcome: "S", sec: 10 + i * 80, source: "HOSTB", source_is_ip: false });
        }
        let r = resolve_ip_names(v.into_iter(), 0.05);
        assert!(r.get("10.0.0.9").is_none());
        // the same IP double-logged on every login resolves
        let mut w = Vec::new();
        for i in 0..200i64 {
            w.push(Obs { dst: "DST2", account: "S", outcome: "S", sec: i * 300, source: "10.0.0.8", source_is_ip: true });
            w.push(Obs { dst: "DST2", account: "S", outcome: "S", sec: i * 300, source: "HOSTC", source_is_ip: false });
        }
        let r2 = resolve_ip_names(w.into_iter(), 0.05);
        assert_eq!(r2.get("10.0.0.8").map(|x| x.name.as_str()), Some("HOSTC"));
    }
    #[test]
    fn collector_matches_direct_resolution() {
        let mut c = CoocCollector::new();
        for i in 0..200i64 {
            let ts = chrono::DateTime::from_timestamp(i * 300, 0).unwrap().format("%Y-%m-%dT%H:%M:%S").to_string();
            c.add("DST2", "s", &ts, "SUCCESSFUL_LOGON", "10.0.0.8", true);
            c.add("DST2", "S", &ts, "SUCCESSFUL_LOGON", "HOSTC", false);
        }
        assert_eq!(c.len(), 200);
        let r = c.resolve(0.05);
        assert_eq!(r.get("10.0.0.8").map(|x| x.0.as_str()), Some("HOSTC"));
        assert_eq!(r["10.0.0.8"].1, 200);
    }
}
