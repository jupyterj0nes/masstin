// =============================================================================
//   Noise filtering for masstin parser outputs.
//
//   Supports four complementary flags that apply sequentially to each parsed
//   LogData record before it is written to the output CSV:
//
//     --ignore-local        drop records lacking any usable source information
//     --exclude-users LIST  drop records where a user field matches a glob
//     --exclude-hosts LIST  drop records where a computer field matches a glob
//     --exclude-ips LIST    drop records where src_ip matches an IP or CIDR
//
//   LIST accepts inline CSV (`svc_*,admin*`), @file.txt (one entry per line),
//   or a mix (`svc_foo,@bigfile.txt`). Globs support `*` at start/end/both.
//
//   The filter is configured once at startup from CLI flags via init_filter()
//   and accessed by every parser action through should_keep_record(). If
//   init_filter was never called, should_keep_record returns true for every
//   record — backward compatible with pre-filter masstin behavior.
// =============================================================================

use crate::parse::LogData;
use ipnet::IpNet;
use once_cell::sync::OnceCell;
use std::net::IpAddr;
use std::sync::Mutex;

// ─── Compiled config ────────────────────────────────────────────────────────

#[derive(Default, Debug)]
pub struct FilterConfig {
    pub ignore_local: bool,
    pub exclude_users: Vec<GlobPattern>,
    pub exclude_hosts: Vec<GlobPattern>,
    pub exclude_ips: Vec<IpMatcher>,
}

#[derive(Debug, Clone)]
pub struct GlobPattern {
    pub original: String,
    kind: GlobKind,
}

#[derive(Debug, Clone)]
enum GlobKind {
    Exact(String),
    Prefix(String),
    Suffix(String),
    Contains(String),
}

impl GlobPattern {
    pub fn parse(pattern: &str) -> Self {
        let trimmed = pattern.trim();
        let p = trimmed.to_lowercase();
        let starts = p.starts_with('*');
        let ends = p.ends_with('*');
        let kind = match (starts, ends) {
            (false, false) => GlobKind::Exact(p.clone()),
            (true, false) => GlobKind::Suffix(p.trim_start_matches('*').to_string()),
            (false, true) => GlobKind::Prefix(p.trim_end_matches('*').to_string()),
            (true, true) => GlobKind::Contains(p.trim_matches('*').to_string()),
        };
        GlobPattern { original: trimmed.to_string(), kind }
    }

    pub fn matches(&self, value: &str) -> bool {
        if value.is_empty() { return false; }
        let v = value.to_lowercase();
        match &self.kind {
            GlobKind::Exact(s) => v == *s,
            GlobKind::Prefix(p) => !p.is_empty() && v.starts_with(p.as_str()),
            GlobKind::Suffix(s) => !s.is_empty() && v.ends_with(s.as_str()),
            GlobKind::Contains(c) => !c.is_empty() && v.contains(c.as_str()),
        }
    }
}

#[derive(Debug, Clone)]
pub enum IpMatcher {
    Single(IpAddr),
    Cidr(IpNet),
}

impl IpMatcher {
    pub fn parse(entry: &str) -> Result<Self, String> {
        let e = entry.trim();
        if e.contains('/') {
            e.parse::<IpNet>()
                .map(IpMatcher::Cidr)
                .map_err(|err| format!("invalid CIDR '{}': {}", e, err))
        } else {
            e.parse::<IpAddr>()
                .map(IpMatcher::Single)
                .map_err(|err| format!("invalid IP '{}': {}", e, err))
        }
    }

    pub fn matches(&self, addr: &IpAddr) -> bool {
        match self {
            IpMatcher::Single(single) => single == addr,
            IpMatcher::Cidr(net) => net.contains(addr),
        }
    }
}

// ─── Stats ──────────────────────────────────────────────────────────────────

#[derive(Default, Debug)]
pub struct FilterStats {
    pub total_seen: u64,
    pub total_kept: u64,
    pub ignore_local: u64,
    pub il_breakdown: IgnoreLocalBreakdown,
    pub exclude_users: u64,
    pub exclude_hosts: u64,
    pub exclude_ips: u64,
}

#[derive(Default, Debug)]
pub struct IgnoreLocalBreakdown {
    pub loopback_ip: u64,
    pub literal_local: u64,
    pub service_logon: u64,
    pub interactive_logon: u64,
    pub self_reference: u64,
    pub both_noise: u64,
}

// ─── Global state ───────────────────────────────────────────────────────────

static FILTER_CONFIG: OnceCell<FilterConfig> = OnceCell::new();
static FILTER_STATS: OnceCell<Mutex<FilterStats>> = OnceCell::new();
static FILTER_DRY_RUN: OnceCell<bool> = OnceCell::new();

pub fn init_filter(cfg: FilterConfig, dry_run: bool) {
    let _ = FILTER_CONFIG.set(cfg);
    let _ = FILTER_STATS.set(Mutex::new(FilterStats::default()));
    let _ = FILTER_DRY_RUN.set(dry_run);
}

pub fn is_filter_active() -> bool {
    match FILTER_CONFIG.get() {
        Some(cfg) => {
            cfg.ignore_local
                || !cfg.exclude_users.is_empty()
                || !cfg.exclude_hosts.is_empty()
                || !cfg.exclude_ips.is_empty()
        }
        None => false,
    }
}

pub fn is_filter_dry_run() -> bool {
    *FILTER_DRY_RUN.get().unwrap_or(&false) && is_filter_active()
}

// ─── The filter entry point ─────────────────────────────────────────────────

/// Returns true if the record should be KEPT (written to output).
/// Updates internal stats regardless of return value.
///
/// In dry-run mode with any active filter, always returns false — the
/// parsers still run but produce empty output (header only), and the
/// caller is expected to inspect print_filter_summary() at the end.
pub fn should_keep_record(r: &LogData) -> bool {
    let cfg = match FILTER_CONFIG.get() {
        Some(c) => c,
        None => return true,
    };
    // If no filter at all is active, skip all the work.
    if !cfg.ignore_local
        && cfg.exclude_users.is_empty()
        && cfg.exclude_hosts.is_empty()
        && cfg.exclude_ips.is_empty()
    {
        return true;
    }

    let stats_mutex = match FILTER_STATS.get() {
        Some(s) => s,
        None => return true,
    };
    let mut stats = stats_mutex.lock().unwrap();
    stats.total_seen += 1;

    let dry_run = is_filter_dry_run();

    // Layer 1 — --ignore-local
    if cfg.ignore_local {
        if let Some(reason) = classify_local(r) {
            stats.ignore_local += 1;
            match reason {
                LocalReason::LoopbackIp => stats.il_breakdown.loopback_ip += 1,
                LocalReason::LiteralLocal => stats.il_breakdown.literal_local += 1,
                LocalReason::ServiceLogon => stats.il_breakdown.service_logon += 1,
                LocalReason::InteractiveLogon => stats.il_breakdown.interactive_logon += 1,
                LocalReason::SelfReference => stats.il_breakdown.self_reference += 1,
                LocalReason::BothNoise => stats.il_breakdown.both_noise += 1,
            }
            return false;
        }
    }

    // Layer 2 — --exclude-users
    if !cfg.exclude_users.is_empty() {
        let matched = cfg
            .exclude_users
            .iter()
            .any(|g| g.matches(&r.subject_user_name) || g.matches(&r.target_user_name));
        if matched {
            stats.exclude_users += 1;
            return false;
        }
    }

    // Layer 3 — --exclude-hosts
    if !cfg.exclude_hosts.is_empty() {
        let matched = cfg
            .exclude_hosts
            .iter()
            .any(|g| g.matches(&r.computer) || g.matches(&r.workstation_name));
        if matched {
            stats.exclude_hosts += 1;
            return false;
        }
    }

    // Layer 4 — --exclude-ips
    if !cfg.exclude_ips.is_empty() {
        if let Ok(ip) = r.ip_address.parse::<IpAddr>() {
            if cfg.exclude_ips.iter().any(|m| m.matches(&ip)) {
                stats.exclude_ips += 1;
                return false;
            }
        }
    }

    stats.total_kept += 1;
    // Dry-run drops everything so the user only sees stats at the end.
    !dry_run
}

// ─── is_local_event classification ──────────────────────────────────────────

#[derive(Debug)]
pub enum LocalReason {
    LoopbackIp,
    LiteralLocal,
    ServiceLogon,
    InteractiveLogon,
    SelfReference,
    BothNoise,
}

/// Decide whether a record has no usable source info. The decision is based
/// on whether src_ip OR src_computer carries meaningful lateral-movement
/// signal; if EITHER is useful the record is kept regardless of the other.
///
/// See the blog post and docs/ignore-local.md for the full rule rationale.
pub fn classify_local(r: &LogData) -> Option<LocalReason> {
    let src_ip_noise = is_src_ip_noise(&r.ip_address);
    let src_computer_noise = is_src_computer_noise(&r.workstation_name, &r.computer);

    // Fast path: either side is useful → keep, no reason.
    if !src_ip_noise || !src_computer_noise {
        return None;
    }

    // Both are noise. Determine the specific reason for breakdown stats.
    // Order matters only for stats grouping; any of these would filter.

    // 1. Loopback / unspecified / link-local IP
    if let Ok(ip) = r.ip_address.parse::<IpAddr>() {
        if ip.is_loopback() || ip.is_unspecified() || is_link_local(&ip) {
            return Some(LocalReason::LoopbackIp);
        }
    }
    let ip_lower = r.ip_address.to_lowercase();
    if ip_lower == "::1" || ip_lower == "127.0.0.1" || ip_lower == "0.0.0.0"
        || ip_lower == "localhost"
    {
        return Some(LocalReason::LoopbackIp);
    }

    // 2. Literal LOCAL marker in src_computer
    if r.workstation_name.eq_ignore_ascii_case("LOCAL") {
        return Some(LocalReason::LiteralLocal);
    }

    // 3. Service logon with noise source (Windows logon_type 5)
    if r.logon_type == "5" {
        return Some(LocalReason::ServiceLogon);
    }

    // 4. Interactive logon with noise source (Windows logon_type 2)
    if r.logon_type == "2" {
        return Some(LocalReason::InteractiveLogon);
    }

    // 5. Self-reference (workstation == dst_computer) with no IP
    if !r.workstation_name.is_empty()
        && r.workstation_name.eq_ignore_ascii_case(&r.computer)
    {
        return Some(LocalReason::SelfReference);
    }

    // 6. Catch-all: both fields are empty / dash / MSTSC / default_value
    Some(LocalReason::BothNoise)
}

fn is_src_ip_noise(ip: &str) -> bool {
    if ip.is_empty() || ip == "-" {
        return true;
    }
    let lower = ip.to_lowercase();
    if lower == "local" || lower == "localhost" {
        return true;
    }
    match ip.parse::<IpAddr>() {
        Ok(addr) => addr.is_loopback() || addr.is_unspecified() || is_link_local(&addr),
        Err(_) => true, // not a valid IP → treat as noise
    }
}

fn is_src_computer_noise(hostname: &str, dst_computer: &str) -> bool {
    if hostname.is_empty() || hostname == "-" {
        return true;
    }
    let lower = hostname.to_lowercase();
    // Hardcoded noise markers observed in real masstin outputs:
    //   - "LOCAL"          TerminalServices LocalSessionManager no remote source
    //   - "MSTSC"          RDP client program name emitted on failed NLA with no IP
    //   - "default_value"  Legacy parser placeholder (being fixed separately)
    if lower == "local" || lower == "mstsc" || lower == "default_value" {
        return true;
    }
    // Self-reference: src_computer == dst_computer is noise when combined with
    // an absent src_ip (handled by the outer classify_local).
    if !dst_computer.is_empty() && hostname.eq_ignore_ascii_case(dst_computer) {
        return true;
    }
    false
}

fn is_link_local(addr: &IpAddr) -> bool {
    match addr {
        IpAddr::V4(v4) => v4.is_link_local(),
        IpAddr::V6(v6) => (v6.segments()[0] & 0xffc0) == 0xfe80, // fe80::/10
    }
}

// ─── CLI argument parsing (flag string → compiled FilterConfig) ─────────────

/// Parse `--exclude-*` CLI argument into glob patterns.
/// Accepts inline CSV (`svc_*,admin*`), @file.txt (one per line), or mixed.
pub fn parse_glob_list(arg: &str) -> Result<Vec<GlobPattern>, String> {
    let mut out = Vec::new();
    for token in arg.split(',') {
        let t = token.trim();
        if t.is_empty() {
            continue;
        }
        if let Some(path) = t.strip_prefix('@') {
            let content = std::fs::read_to_string(path)
                .map_err(|e| format!("cannot read {}: {}", path, e))?;
            for line in content.lines() {
                let l = line.trim();
                if !l.is_empty() && !l.starts_with('#') {
                    out.push(GlobPattern::parse(l));
                }
            }
        } else {
            out.push(GlobPattern::parse(t));
        }
    }
    Ok(out)
}

/// Parse `--exclude-ips` CLI argument into IP/CIDR matchers.
pub fn parse_ip_list(arg: &str) -> Result<Vec<IpMatcher>, String> {
    let mut out = Vec::new();
    for token in arg.split(',') {
        let t = token.trim();
        if t.is_empty() {
            continue;
        }
        if let Some(path) = t.strip_prefix('@') {
            let content = std::fs::read_to_string(path)
                .map_err(|e| format!("cannot read {}: {}", path, e))?;
            for line in content.lines() {
                let l = line.trim();
                if !l.is_empty() && !l.starts_with('#') {
                    out.push(IpMatcher::parse(l)?);
                }
            }
        } else {
            out.push(IpMatcher::parse(t)?);
        }
    }
    Ok(out)
}

pub fn build_config(
    ignore_local: bool,
    exclude_users: Option<&str>,
    exclude_hosts: Option<&str>,
    exclude_ips: Option<&str>,
) -> Result<FilterConfig, String> {
    let mut cfg = FilterConfig {
        ignore_local,
        ..Default::default()
    };
    if let Some(arg) = exclude_users {
        cfg.exclude_users = parse_glob_list(arg)?;
    }
    if let Some(arg) = exclude_hosts {
        cfg.exclude_hosts = parse_glob_list(arg)?;
    }
    if let Some(arg) = exclude_ips {
        cfg.exclude_ips = parse_ip_list(arg)?;
    }
    Ok(cfg)
}

// ─── Summary printer ────────────────────────────────────────────────────────

pub fn print_filter_summary() {
    if !is_filter_active() {
        return;
    }
    let cfg = match FILTER_CONFIG.get() { Some(c) => c, None => return };
    let stats_mutex = match FILTER_STATS.get() { Some(s) => s, None => return };
    let stats = stats_mutex.lock().unwrap();

    let dry_run = is_filter_dry_run();
    let total = stats.total_seen;
    if total == 0 {
        return;
    }
    let total_filtered = total.saturating_sub(stats.total_kept);
    let pct = |n: u64| -> String {
        if total == 0 { "0.0%".to_string() } else {
            format!("{:.1}%", 100.0 * n as f64 / total as f64)
        }
    };

    eprintln!();
    eprintln!("  ──────────────────────────────────────────────────");
    if dry_run {
        eprintln!("  🔍 Filter summary [DRY-RUN — no CSV written]:");
    } else {
        eprintln!("  🧹 Filter summary:");
    }
    eprintln!("     Total records seen: {}", total);
    eprintln!("     Total kept:         {} ({})", stats.total_kept, pct(stats.total_kept));
    eprintln!("     Total filtered:     {} ({})", total_filtered, pct(total_filtered));
    eprintln!();

    if cfg.ignore_local {
        eprintln!("     --ignore-local:     {} ({})", stats.ignore_local, pct(stats.ignore_local));
        if stats.ignore_local > 0 {
            let b = &stats.il_breakdown;
            if b.loopback_ip > 0 {
                eprintln!("        loopback_ip         {:>8}", b.loopback_ip);
            }
            if b.literal_local > 0 {
                eprintln!("        literal_LOCAL       {:>8}", b.literal_local);
            }
            if b.service_logon > 0 {
                eprintln!("        service_logon       {:>8}", b.service_logon);
            }
            if b.interactive_logon > 0 {
                eprintln!("        interactive_logon   {:>8}", b.interactive_logon);
            }
            if b.self_reference > 0 {
                eprintln!("        self_reference      {:>8}", b.self_reference);
            }
            if b.both_noise > 0 {
                eprintln!("        both_noise          {:>8}", b.both_noise);
            }
        }
    }
    if !cfg.exclude_users.is_empty() {
        eprintln!(
            "     --exclude-users:    {} ({})   [{} patterns]",
            stats.exclude_users, pct(stats.exclude_users), cfg.exclude_users.len()
        );
    }
    if !cfg.exclude_hosts.is_empty() {
        eprintln!(
            "     --exclude-hosts:    {} ({})   [{} patterns]",
            stats.exclude_hosts, pct(stats.exclude_hosts), cfg.exclude_hosts.len()
        );
    }
    if !cfg.exclude_ips.is_empty() {
        eprintln!(
            "     --exclude-ips:      {} ({})   [{} ranges]",
            stats.exclude_ips, pct(stats.exclude_ips), cfg.exclude_ips.len()
        );
    }
    eprintln!();
    if dry_run {
        eprintln!("     Re-run without --dry-run to write the filtered CSV.");
    } else {
        eprintln!("     Re-run with --dry-run to preview without writing CSV.");
    }
    eprintln!("  ──────────────────────────────────────────────────");
}
