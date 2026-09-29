// Analyst report for graph-hunt: one story per origin, in words.
//
// The CSV lists connections; an analyst reads origins. This module turns
// the same facts the engine measured into a Markdown document grouped by
// origin, most unusual first: what the origin is, whether it existed in the
// baseline, what it did in the window in chronological phases, why that is
// unusual with the baseline count behind every statement, who owns the
// accounts it used, the causal paths it took part in, the origins it moves
// with, and how to check everything in the graph and in the logs. Every
// number comes from the engine; nothing is computed here.

use std::io::Write;

pub struct Header {
    pub cutoff: String,
    pub window_from: String,
    pub window_to: String,
    pub alpha: f64,
    /// the engine's summary lines (machines, panel, connections, campaigns)
    pub lines: Vec<String>,
    pub n_origins_sig: usize,
    pub n_rows: usize,
    pub n_sig: usize,
    pub n_not_eval: usize,
}

/// What one origin did on one day with one kind of result.
pub struct Phase {
    pub day: String,
    pub t0: String,
    pub t1: String,
    /// "logged in", "failed to log in", "connected without authenticating"
    pub verb: String,
    pub accounts: Vec<String>,
    pub hosts: Vec<String>,
    pub events: u64,
    pub n_rows: usize,
    pub n_sig: usize,
    /// every connection of the phase already happened on baseline days
    pub habitual: bool,
    pub best_p: f64,
}

pub struct AccountNote {
    pub account: String,
    /// (origin label, baseline days it used the account from there)
    pub owners: Vec<(String, u32)>,
    pub n_owners: usize,
}

pub struct OriginStory {
    pub origin: String,
    pub class: String,
    pub best_q: f64,
    pub best_p: f64,
    pub n_sig: usize,
    pub n_rows: usize,
    pub n_not_eval: usize,
    /// baseline days with any event from this origin, first and last of them
    pub baseline_days: u32,
    pub baseline_first: String,
    pub baseline_last: String,
    /// first and last baseline day with data (any origin)
    pub data_first: String,
    pub data_last: String,
    pub usual_dests: Vec<(String, u32)>,
    pub usual_accts: Vec<(String, u32)>,
    pub phases: Vec<Phase>,
    /// per day: the origin-level reasons (each with its baseline count)
    pub why: Vec<(String, Vec<String>)>,
    pub accounts: Vec<AccountNote>,
    pub paths: Vec<String>,
    pub campaign: String,
    pub logs: Vec<String>,
    pub cypher: String,
}

fn p_str(p: f64) -> String {
    if p.is_nan() {
        "n/a".into()
    } else {
        format!("{:.1e}", p)
    }
}

fn list(v: &[String], max: usize) -> String {
    if v.len() <= max {
        v.join(", ")
    } else {
        format!("{} and {} more", v[..max].join(", "), v.len() - max)
    }
}

fn hm(ts: &str) -> &str {
    // "2026-09-23T15:35:07Z" -> "15:35:07"
    ts.get(11..19).unwrap_or(ts)
}

/// One hop of the seed reconstruction.
pub struct SeedHop {
    /// 0 = a session that entered a seed machine before it acted; 1 = a
    /// login by a seed; 2, 3, ... = the chain onward
    pub depth: i32,
    /// first and last login of the group (same origin, account,
    /// destination, depth and cause), and how many sessions it holds
    pub time: String,
    pub last: String,
    pub sessions: usize,
    /// end of the last session, empty when no LOGOFF was recorded (the
    /// day's end is assumed)
    pub end: String,
    pub origin: String,
    pub account: String,
    pub dest: String,
    /// 1 / number of sessions open on the origin when this login happened
    pub certainty: f64,
    pub n_cand: usize,
    /// the hop this one follows from ("seed", or "hop 3: ...")
    pub cause: String,
    /// p-value of the connection in the hunt, NaN when not evaluated
    pub p: f64,
    pub significant: String,
    /// class of the connection in the hunt
    pub class: String,
}

pub struct SeedRecon {
    pub seeds: Vec<String>,
    pub matched: Vec<String>,
    pub unmatched: Vec<String>,
    pub hops: Vec<SeedHop>,
    /// failed attempts and unauthenticated touches from chain machines
    pub touches: Vec<String>,
    pub machines: Vec<String>,
    pub first: String,
    pub last: String,
    pub cypher_chain: String,
    pub cypher_all: String,
    /// why hops are followed (stated once)
    pub rule: String,
}

pub fn render_seed(r: &SeedRecon) -> String {
    let mut s = String::new();
    s.push_str("## Reconstruction from seeds\n\n");
    s.push_str(&format!("Seeds: {}.", r.seeds.join(", ")));
    if !r.matched.is_empty() {
        s.push_str(&format!(" Matched: {}.", r.matched.join(", ")));
    }
    if !r.unmatched.is_empty() {
        s.push_str(&format!(" Not found in the graph: {}.", r.unmatched.join(", ")));
    }
    s.push_str("\n\n");
    if r.hops.is_empty() {
        s.push_str("No login by the seeds in the window.\n\n");
        return s;
    }
    s.push_str(&format!(
        "{} hop(s) over {} machine(s), from {} to {} UTC. {}\n\n",
        r.hops.len(),
        r.machines.len(),
        r.first,
        r.last,
        r.rule
    ));
    s.push_str("| # | depth | first login (UTC) | last login | sessions | last session end | origin | account | destination | certainty | follows | hunt |\n|---|---|---|---|---|---|---|---|---|---|---|---|\n");
    for (i, h) in r.hops.iter().enumerate() {
        let cert = if h.n_cand <= 1 { "1".to_string() } else { format!("1/{}", h.n_cand) };
        let hunt = if h.p.is_nan() {
            "not evaluated".to_string()
        } else {
            format!("p = {}, {}; {}", p_str(h.p), h.significant, h.class)
        };
        s.push_str(&format!(
            "| {} | {} | {} | {} | {} | {} | {} | {} | {} | {} | {} | {} |\n",
            i + 1,
            h.depth,
            h.time,
            if h.last == h.time { "same".to_string() } else { h.last.clone() },
            h.sessions,
            if h.end.is_empty() { "unknown" } else { h.end.as_str() },
            h.origin,
            h.account,
            h.dest,
            cert,
            h.cause,
            hunt
        ));
    }
    s.push('\n');
    if !r.touches.is_empty() {
        s.push_str("**Failed attempts and unauthenticated touches from the chain machines in the window.**\n\n");
        for t in &r.touches {
            s.push_str(&format!("- {}\n", t));
        }
        s.push('\n');
    }
    s.push_str("**Draw the chain** (exactly these hops, as a virtual graph):\n\n```cypher\n");
    s.push_str(&r.cypher_chain);
    s.push_str("\n```\n\n**Everything between the chain machines in that time span** (real edges, for verification):\n\n```cypher\n");
    s.push_str(&r.cypher_all);
    s.push_str("\n```\n\n");
    s
}

pub fn render(h: &Header, stories: &[OriginStory]) -> String {
    render_with_seed(h, stories, None)
}

pub fn render_with_seed(h: &Header, stories: &[OriginStory], seed: Option<&SeedRecon>) -> String {
    let mut s = String::new();
    s.push_str("# graph-hunt report\n\n");
    s.push_str(&format!(
        "Baseline: every event before {} (UTC). Window: {} to {}. False discovery rate (alpha): {}.\n\n",
        h.cutoff, h.window_from, h.window_to, h.alpha
    ));
    for l in &h.lines {
        s.push_str(&format!("- {}\n", l));
    }
    s.push_str(&format!(
        "\n{} connections in the window: {} significant, {} not evaluated (destination without comparable coverage). {} origin(s) have at least one significant connection and are described below, most unusual first.\n\n",
        h.n_rows, h.n_sig, h.n_not_eval, h.n_origins_sig
    ));
    if let Some(r) = seed {
        s.push_str(&render_seed(r));
    }
    s.push_str("## How to read this\n\n");
    s.push_str("A connection is one origin logging in (or failing, or connecting without authenticating) to one destination with one account on one day. A connection that already happened on another baseline day is habitual and is never reported. A new connection is compared with the new connections of the baseline days: the p-value is the share of baseline connections at least as unusual, and q is the p-value adjusted so that, among everything marked significant, the expected share of false alarms is alpha. Every statement below carries the baseline count it rests on.\n\n");
    s.push_str("Classes follow Hopper (Ho et al., USENIX Security 2021), which found that lateral movement almost always combines a **credential switch** (an account that belongs to other origins, used from one that never used it) with a **new access** (a destination that origin or account never reached). Origins with that signature come first. Origins that reach new destinations with their habitual credential (scanners, orchestration, administrators on their own account) are still measured and listed, but after them.\n\n");
    s.push_str("## Origins\n\n");
    for (i, st) in stories.iter().enumerate() {
        s.push_str(&format!("### {}. {}\n\n", i + 1, st.origin));
        s.push_str(&format!(
            "**Class:** {}. **Most unusual connection:** p = {}, q = {}. **Connections:** {} in the window, {} significant{}.\n\n",
            st.class,
            p_str(st.best_p),
            p_str(st.best_q),
            st.n_rows,
            st.n_sig,
            if st.n_not_eval > 0 { format!(", {} on destinations without comparable coverage", st.n_not_eval) } else { String::new() }
        ));
        // baseline
        if st.baseline_days == 0 {
            s.push_str(&format!(
                "**Baseline.** No event of any kind from this origin in the baseline (logs from {} to {}): it appears for the first time in the window.\n\n",
                st.data_first, st.data_last
            ));
        } else {
            s.push_str(&format!(
                "**Baseline.** Active on {} baseline day(s), from {} to {} (logs from {} to {}).",
                st.baseline_days, st.baseline_first, st.baseline_last, st.data_first, st.data_last
            ));
            if !st.usual_dests.is_empty() {
                s.push_str(&format!(
                    " Usual destinations (days): {}.",
                    st.usual_dests.iter().map(|(d, n)| format!("{} ({})", d, n)).collect::<Vec<_>>().join(", ")
                ));
            }
            if !st.usual_accts.is_empty() {
                s.push_str(&format!(
                    " Usual accounts (days): {}.",
                    st.usual_accts.iter().map(|(a, n)| format!("{} ({})", a, n)).collect::<Vec<_>>().join(", ")
                ));
            }
            s.push_str("\n\n");
        }
        // phases
        s.push_str("**What happened.**\n\n");
        for ph in &st.phases {
            let acc = if ph.accounts.is_empty() { String::new() } else { format!(" as {}", list(&ph.accounts, 4)) };
            if ph.habitual {
                s.push_str(&format!(
                    "- {} {}–{} UTC: {}{} on {} host(s) ({}); {} event(s); habitual, seen on other baseline days.\n",
                    ph.day,
                    hm(&ph.t0),
                    hm(&ph.t1),
                    ph.verb,
                    acc,
                    ph.hosts.len(),
                    list(&ph.hosts, 8),
                    ph.events
                ));
                continue;
            }
            s.push_str(&format!(
                "- {} {}–{} UTC: {}{} on {} host(s) ({}); {} event(s); {} of {} connection(s) significant, best p = {}.\n",
                ph.day,
                hm(&ph.t0),
                hm(&ph.t1),
                ph.verb,
                acc,
                ph.hosts.len(),
                list(&ph.hosts, 8),
                ph.events,
                ph.n_sig,
                ph.n_rows,
                p_str(ph.best_p)
            ));
        }
        s.push('\n');
        // why
        if st.why.iter().any(|(_, v)| !v.is_empty()) {
            s.push_str("**Why it is unusual.**\n\n");
            for (day, clauses) in &st.why {
                if clauses.is_empty() {
                    continue;
                }
                s.push_str(&format!("- {}: {}.\n", day, clauses.join("; ")));
            }
            s.push('\n');
        }
        // accounts
        if !st.accounts.is_empty() {
            s.push_str("**Accounts it used for the first time.**\n\n");
            for a in &st.accounts {
                if a.owners.is_empty() {
                    s.push_str(&format!("- `{}`: unknown to the network, no successful login anywhere in the baseline.\n", a.account));
                } else {
                    s.push_str(&format!(
                        "- `{}`: in the baseline it logged in from {}{}. This origin had never used it.\n",
                        a.account,
                        a.owners.iter().map(|(o, n)| format!("{} ({} day{})", o, n, if *n == 1 { "" } else { "s" })).collect::<Vec<_>>().join(", "),
                        if a.n_owners > a.owners.len() { format!(" and {} other origin(s)", a.n_owners - a.owners.len()) } else { String::new() }
                    ));
                }
            }
            s.push('\n');
        }
        if !st.paths.is_empty() {
            s.push_str("**Causal paths.**\n\n");
            for p in &st.paths {
                s.push_str(&format!("- {}.\n", p));
            }
            s.push('\n');
        }
        if !st.campaign.is_empty() {
            s.push_str(&format!("**Moves with other origins.** {}.\n\n", st.campaign));
        }
        s.push_str(&format!(
            "**Check it.** Log families: {}. Graph query for every connection of this origin in the window:\n\n```cypher\n{}\n```\n\n",
            if st.logs.is_empty() { "n/a".to_string() } else { st.logs.join(", ") },
            st.cypher
        ));
    }
    s
}

pub fn write(path: &str, h: &Header, stories: &[OriginStory], seed: Option<&SeedRecon>) -> std::io::Result<()> {
    let text = render_with_seed(h, stories, seed);
    std::fs::File::create(path)?.write_all(text.as_bytes())
}
