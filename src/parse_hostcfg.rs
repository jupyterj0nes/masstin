// =============================================================================
//   A machine's own network configuration, from its SYSTEM hive
//   (`Windows\System32\config\SYSTEM` of a triage, loose or inside a zip).
//
//   The hive says the machine's name and the address of each of its
//   interfaces: a static one, or the DHCP lease it held with the times it
//   was obtained and ends. No login, so no row of the timeline: a fact about
//   whose an address is (kind `own`), kept in the timeline's masstin file
//   for the host map (graph_hunt_common::hostmap), where it is the one piece
//   of evidence that tells which of two addresses is a host's.
//
//   A dirty hive given as a file gets its .LOG1/.LOG2 replayed
//   (blockcarve::hive_logs, as parse_mountpoints does); one read from a zip
//   is read as it is on disk.
// =============================================================================

use std::io::Cursor;
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::path::Path;

use nt_hive2::{CleanHive, Hive, HiveParseMode, KeyNode, RegistryValue, SubPath};

use crate::graph_hunt_common::hostmap::Fact;

type HiveImage = Hive<Cursor<Vec<u8>>, CleanHive>;

/// A hive larger than this is not read into memory from an archive.
pub const MAX_HIVE: u64 = 1 << 30;

/// `...\Windows\System32\config\SYSTEM`, whatever the separators and the
/// case; not the copy under `RegBack`.
pub fn is_system_hive(path: &str) -> bool {
    path.replace('\\', "/").to_ascii_lowercase().ends_with("/config/system")
}

fn value<'a>(node: &'a KeyNode, name: &str) -> Option<&'a RegistryValue> {
    node.values().iter().find(|v| v.name().eq_ignore_ascii_case(name)).map(|v| v.value())
}

fn text(node: &KeyNode, name: &str) -> Vec<String> {
    match value(node, name) {
        Some(RegistryValue::RegSZ(s)) | Some(RegistryValue::RegExpandSZ(s)) => vec![s.clone()],
        Some(RegistryValue::RegMultiSZ(v)) => v.clone(),
        _ => Vec::new(),
    }
    .into_iter()
    .map(|s| s.trim_matches(['\0', ' ']).to_string())
    .filter(|s| !s.is_empty())
    .collect()
}

fn dword(node: &KeyNode, name: &str) -> Option<u32> {
    match value(node, name) {
        Some(RegistryValue::RegDWord(d)) => Some(*d),
        _ => None,
    }
}

/// An address a machine can be reached at (not unset, automatic or loopback).
fn usable(a: &str) -> bool {
    match a.parse::<std::net::IpAddr>() {
        Ok(ip) => !(ip.is_unspecified() || ip.is_loopback() || a.starts_with("169.254.") || a == "255.255.255.255"),
        Err(_) => false,
    }
}

fn utc(secs: u32) -> String {
    if secs == 0 {
        return String::new();
    }
    chrono::DateTime::from_timestamp(secs as i64, 0).map(|d| d.format("%Y-%m-%d %H:%M:%S").to_string()).unwrap_or_default()
}

fn facts_of(mut hive: HiveImage, label: &str) -> Result<Vec<Fact>, String> {
    let root = hive.root_key_node().map_err(|e| format!("{label}: cannot read the root key: {e}"))?;
    let current = match root.subpath("Select", &mut hive) {
        Ok(Some(k)) => dword(&k.borrow(), "Current"),
        _ => None,
    }
    .unwrap_or(1);
    let cs = format!("ControlSet{:03}", current);
    // the name the logs use: the DNS host name, else the NetBIOS one
    let mut name = match root.subpath(format!("{cs}\\Services\\Tcpip\\Parameters").as_str(), &mut hive) {
        Ok(Some(k)) => text(&k.borrow(), "Hostname").into_iter().next(),
        _ => None,
    };
    if name.is_none() {
        name = match root.subpath(format!("{cs}\\Control\\ComputerName\\ComputerName").as_str(), &mut hive) {
            Ok(Some(k)) => text(&k.borrow(), "ComputerName").into_iter().next(),
            _ => None,
        };
    }
    let Some(name) = name else { return Err(format!("{label}: no computer name in the hive")) };
    let mut out = Vec::new();
    let Ok(Some(ifs)) = root.subpath(format!("{cs}\\Services\\Tcpip\\Parameters\\Interfaces").as_str(), &mut hive) else { return Ok(out) };
    let ifs = ifs.borrow();
    let subkeys = ifs.subkeys(&mut hive).map_err(|e| format!("{label}: cannot read the interfaces: {e}"))?;
    for sub in subkeys.iter() {
        let k = sub.borrow();
        if dword(&k, "EnableDHCP") == Some(1) {
            let (from, to) = (utc(dword(&k, "LeaseObtainedTime").unwrap_or(0)), utc(dword(&k, "LeaseTerminatesTime").unwrap_or(0)));
            for a in text(&k, "DhcpIPAddress").into_iter().filter(|a| usable(a)) {
                out.push(Fact { host: name.clone(), address: a, kind: "own".into(), from: from.clone(), to: to.clone(), source: format!("SYSTEM hive of {}: the DHCP lease of its interface {}", name.to_uppercase(), k.name()) });
            }
        } else {
            for a in text(&k, "IPAddress").into_iter().filter(|a| usable(a)) {
                out.push(Fact { host: name.clone(), address: a, kind: "own".into(), from: String::new(), to: String::new(), source: format!("SYSTEM hive of {}: the static address of its interface {}", name.to_uppercase(), k.name()) });
            }
        }
    }
    Ok(out)
}

fn open(bytes: Vec<u8>, label: &str) -> Result<HiveImage, String> {
    match catch_unwind(AssertUnwindSafe(|| Hive::new(Cursor::new(bytes), HiveParseMode::NormalWithBaseBlock))) {
        Ok(Ok(h)) => Ok(h.treat_hive_as_clean()),
        Ok(Err(e)) => Err(format!("{label}: {e}")),
        Err(_) => Err(format!("{label}: the hive reader panicked")),
    }
}

/// The facts of a SYSTEM hive held in memory (an entry of an archive).
pub fn facts_from_bytes(raw: Vec<u8>, label: &str) -> Result<Vec<Fact>, String> {
    let hive = open(raw, label)?;
    match catch_unwind(AssertUnwindSafe(|| facts_of(hive, label))) {
        Ok(r) => r,
        Err(_) => Err(format!("{label}: the hive reader panicked")),
    }
}

/// The facts of a SYSTEM hive on disk, its transaction logs replayed.
pub fn facts_from_file(path: &Path) -> Result<Vec<Fact>, String> {
    let label = path.display().to_string();
    let raw = std::fs::read(path).map_err(|e| format!("{label}: {e}"))?;
    let bytes = blockcarve::hive_logs::replay_beside(path, &raw).data.into_owned();
    facts_from_bytes(bytes, &label)
}

/// Read a SYSTEM hive come upon while looking for evidence and note what it
/// says for the timeline's masstin file. Never fails the parse.
pub fn note(result: Result<Vec<Fact>, String>) {
    match result {
        Ok(facts) => {
            for f in facts {
                crate::graph_hunt_common::hostmap::note_fact(f);
            }
        }
        Err(e) => {
            if crate::parse::is_debug_mode() {
                eprintln!("[DEBUG] host configuration: {e}");
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn which_file_is_the_system_hive() {
        assert!(is_system_hive(r"C\Windows\System32\config\SYSTEM"));
        assert!(is_system_hive("uploads/auto/C%3A/Windows/System32/config/system"));
        assert!(!is_system_hive(r"C\Windows\System32\config\RegBack\SYSTEM"));
        assert!(!is_system_hive(r"C\Windows\System32\config\SYSTEM.LOG1"));
        assert!(!is_system_hive(r"C\Windows\System32\config\SOFTWARE"));
        assert!(!is_system_hive("SYSTEM"));
    }

    #[test]
    fn which_addresses_count() {
        for a in ["10.10.0.38", "192.168.1.7", "2001:db8::5"] {
            assert!(usable(a), "{a}");
        }
        for a in ["", "0.0.0.0", "169.254.12.9", "127.0.0.1", "255.255.255.255", "::", "::1", "not an address"] {
            assert!(!usable(a), "{a}");
        }
        assert_eq!(utc(0), "");
        assert_eq!(utc(1_794_300_000), "2026-11-10 08:40:00");
    }

    /// On a real hive, when `MASSTIN_SYSTEM_HIVE` names one (and
    /// `MASSTIN_SYSTEM_HIVE_EXPECT` what it must say, `HOST=ADDRESS`):
    /// without the variable the test passes with nothing checked.
    #[test]
    fn a_real_hive_says_its_name_and_address() {
        let Ok(path) = std::env::var("MASSTIN_SYSTEM_HIVE") else { return };
        let facts = facts_from_file(Path::new(&path)).unwrap();
        eprintln!("{facts:#?}");
        assert!(!facts.is_empty(), "no address read from {path}");
        if let Ok(expect) = std::env::var("MASSTIN_SYSTEM_HIVE_EXPECT") {
            let (host, address) = expect.split_once('=').unwrap();
            assert!(facts.iter().any(|f| f.host.eq_ignore_ascii_case(host) && f.address == address && f.kind == "own"), "{expect} not in {facts:?}");
        }
        // the same hive held in memory, as one read from an archive
        let again = facts_from_bytes(std::fs::read(&path).unwrap(), "memory").unwrap();
        assert_eq!(again.len(), facts.len());
    }
}
