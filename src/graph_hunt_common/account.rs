//! Who an account is: its name AND where it is an account.
//!
//! `Administrator` is not one account. The Administrator of the domain
//! PARTNER, the one of the domain EXAMPLE and the local Administrator of
//! each machine are different credentials that happen to share a name,
//! and a hunt that takes them for one sees a habitual account where a
//! credential nobody used there before has just been used. The name
//! alone is therefore never the account: the account is the name and its
//! domain, written `NAME@DOMAIN`.
//!
//! The domain comes from the name itself when it carries one
//! (`administrator@EXAMPLE.TEST`, a Kerberos ticket; `DEV\alice`), else
//! from the event's domain column. The same domain is written in more
//! than one way by the same network (`DEV`, `DEV.EXAMPLE.TEST`,
//! `dev.example.test`): its key is the first label, in upper case. Where
//! a NetBIOS name is not the first label of the DNS one, an account
//! written both ways is two accounts here; it is never merged with
//! another one. A local account has the machine's own name as its domain,
//! so the local Administrator of SRV01 and the one of SRV02 are two
//! accounts; NetBIOS cuts that name at 15 characters, and a domain that
//! is the first 15 characters of the destination's longer name is that
//! destination. An event that gives no domain (4776, an SSH login) names
//! the account by its name alone, and that is an account of its own: it
//! is not guessed into one of the others.

use super::engine::account_type;
use super::is_no_account;

/// The name without what says where it is an account: `DEV\alice` and
/// `alice@DEV.CORP` are `alice`.
pub(crate) fn bare_name(user: &str) -> &str {
    let u = user.trim();
    let u = u.rsplit('\\').next().unwrap_or(u);
    u.split('@').next().unwrap_or(u)
}

/// The key of the domain an account is of; empty when nothing says.
pub(crate) fn domain_key(user: &str, domain: &str, destination: &str) -> String {
    let u = user.trim();
    let before = u.rsplit_once('\\').map(|(d, _)| d);
    let after = u.rsplit('\\').next().unwrap_or(u).split_once('@').map(|(_, r)| r);
    let raw = after.or(before).unwrap_or(domain).trim();
    if raw.is_empty() || raw == "-" || raw == "." {
        return String::new();
    }
    let clean = |s: &str| -> String {
        let up = s.to_uppercase();
        let first = if up.parse::<std::net::IpAddr>().is_ok() { up.as_str() } else { up.split('.').next().unwrap_or("") };
        first.chars().map(|c| if c.is_alphanumeric() || c == '-' || c == '_' { c } else { '_' }).collect()
    };
    let key = clean(raw);
    // a local account whose machine has a name longer than NetBIOS keeps
    let dest = clean(destination);
    if key.chars().count() == 15 && dest.chars().count() > 15 && dest.starts_with(&key) {
        return dest;
    }
    key
}

/// The account of a row, as the hunt names it: `NAME@DOMAIN` (the name as
/// `account_type` writes it), the name alone when no domain is given or
/// the row names no account.
pub(crate) fn account_id(user: &str, domain: &str, destination: &str) -> String {
    with_domain(&account_type(bare_name(user)), &domain_key(user, domain, destination))
}

/// A name the hunt already has (a relationship type of a loaded graph)
/// with the key of its domain.
pub(crate) fn with_domain(name: &str, domain_key: &str) -> String {
    if domain_key.is_empty() || is_no_account(name) {
        name.to_string()
    } else {
        format!("{}@{}", name, domain_key)
    }
}

/// The account of a row as a person reads it: the name as written and
/// its domain (`Administrator@PARTNER`).
pub(crate) fn account_shown(user: &str, domain: &str, destination: &str) -> String {
    let name = bare_name(user);
    let key = domain_key(user, domain, destination);
    if key.is_empty() || name.is_empty() {
        name.to_string()
    } else {
        format!("{}@{}", name, key)
    }
}

/// `NAME@DOMAIN` -> (`NAME`, `DOMAIN`); the domain empty when it has none.
pub(crate) fn split(account: &str) -> (&str, &str) {
    account.split_once('@').unwrap_or((account, ""))
}

/// The Cypher condition that picks the edges of an account in a loaded
/// graph: its relationship type and, when it has a domain, the edge's
/// `target_domain_name` by the same key (and by its first 15 characters:
/// what NetBIOS writes for a local account of a long-named machine).
pub(crate) fn cypher_condition(account: &str, quote: &dyn Fn(&str) -> String) -> String {
    let (name, dom) = split(account);
    if dom.is_empty() {
        return format!("type(r) = '{}'", quote(name));
    }
    let short: String = dom.chars().take(15).collect();
    let keys = if short == dom { format!("'{}'", quote(dom)) } else { format!("'{}', '{}'", quote(dom), quote(&short)) };
    format!("type(r) = '{}' AND toUpper(split(coalesce(r.target_domain_name, ''), '.')[0]) IN [{}]", quote(name), keys)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_account_is_its_name_and_its_domain() {
        // the same account of a domain, however the domain is written, and with its ticket's name
        for (user, domain) in [("Administrator", "PARTNER"), ("administrator", "PARTNER.TEST"), ("Administrator", "partner.test"), ("Administrator@PARTNER.TEST", "PARTNER.TEST"), ("administrator@partner.test", ""), ("PARTNER\\Administrator", "")] {
            assert_eq!(account_id(user, domain, "SRV01"), "ADMINISTRATOR@PARTNER", "{user} / {domain}");
        }
        // another domain, a local account, and no domain given: three other accounts
        assert_eq!(account_id("Administrator", "EXAMPLE.TEST", "SRV01"), "ADMINISTRATOR@EXAMPLE");
        assert_eq!(account_id("Administrator", "SRV01", "SRV01.corp.test"), "ADMINISTRATOR@SRV01");
        assert_eq!(account_id("Administrator", "SRV02", "SRV02"), "ADMINISTRATOR@SRV02");
        assert_eq!(account_id("Administrator", "", "SRV01"), "ADMINISTRATOR");
        assert_eq!(account_id("Administrator", "-", "SRV01"), "ADMINISTRATOR");
        // the name in the event says more than the column
        assert_eq!(account_id("alice@DEV.CORP.TEST", "CORP", "SRV01"), "ALICE@DEV");
        // a local account of a machine whose name NetBIOS cuts at 15 characters
        assert_eq!(account_id("vagrant", "BUILD-AGENT-EU-", "BUILD-AGENT-EU-JUMPBOX.corp.test"), "VAGRANT@BUILD-AGENT-EU-JUMPBOX");
        assert_eq!(account_id("vagrant", "BUILD-AGENT-EU-", "BUILD-AGENT-EU-DEV-SRV01"), "VAGRANT@BUILD-AGENT-EU-DEV-SRV01");
        assert_eq!(account_id("vagrant", "BUILD-AGENT-EU-", "SRV01"), "VAGRANT@BUILD-AGENT-EU-", "another machine's: as written");
        // machine accounts, the system's own, an address as a domain
        assert_eq!(account_id("LNX01$@EXAMPLE.TEST", "EXAMPLE.TEST", "DC01"), "LNX01_@EXAMPLE");
        assert_eq!(account_id("SYSTEM", "NT AUTHORITY", "SRV01"), "SYSTEM@NT_AUTHORITY");
        assert_eq!(account_id("root", "10.0.0.5", "LNX01"), "ROOT@10_0_0_5");
        // a row that names no account stays that
        assert_eq!(account_id("", "CORP", "SRV01"), "NO_USER");
        assert_eq!(account_id("(unknown)", "CORP", "SRV01"), "_UNKNOWN_");
        assert_eq!(account_id("uid:1101", "", "LNX01"), "UID_1101");
        // as a person reads it
        assert_eq!(account_shown("Administrator", "partner.test", "SRV01"), "Administrator@PARTNER");
        assert_eq!(account_shown("ryan.devlead@DEV.EXAMPLE.TEST", "", "SRV01"), "ryan.devlead@DEV");
        assert_eq!(account_shown("root", "", "LNX01"), "root");
        assert_eq!(account_shown("", "CORP", "SRV01"), "");
        assert_eq!((bare_name("DEV\\alice"), bare_name("alice@DEV.CORP"), bare_name(" alice ")), ("alice", "alice", "alice"));
        assert_eq!(split("ALICE@DEV"), ("ALICE", "DEV"));
        assert_eq!(split("ROOT"), ("ROOT", ""));
    }

    #[test]
    fn the_edges_of_an_account_in_a_loaded_graph() {
        let q = |s: &str| s.replace('\'', "\\'");
        assert_eq!(cypher_condition("ROOT", &q), "type(r) = 'ROOT'");
        assert_eq!(cypher_condition("ADMINISTRATOR@PARTNER", &q), "type(r) = 'ADMINISTRATOR' AND toUpper(split(coalesce(r.target_domain_name, ''), '.')[0]) IN ['PARTNER']");
        assert_eq!(cypher_condition("VAGRANT@BUILD-AGENT-EU-JUMPBOX", &q), "type(r) = 'VAGRANT' AND toUpper(split(coalesce(r.target_domain_name, ''), '.')[0]) IN ['BUILD-AGENT-EU-JUMPBOX', 'BUILD-AGENT-EU-']");
    }
}
