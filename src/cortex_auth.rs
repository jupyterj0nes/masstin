//! Authentication with the Cortex XDR public API, for both Cortex actions.
//!
//! A tenant issues two kinds of API key. A *Standard* key goes as it is in
//! the `Authorization` header. An *Advanced* key never travels: every request
//! carries a 64-character nonce (`x-xdr-nonce`), the time in milliseconds
//! (`x-xdr-timestamp`) and, as `Authorization`, the SHA-256 of key + nonce +
//! timestamp. masstin cannot tell the kind from the key, so it asks the
//! tenant: the first request (the XQL quota, which costs nothing) is sent as
//! a Standard key and, on 401, again as an Advanced one; whichever the tenant
//! accepts is used from then on. `CORTEX_API_KEY_TYPE=standard|advanced`
//! skips the question.
//!
//! When the tenant refuses, its own words are shown (`err_code`, `err_msg`,
//! `err_extra`), with what each status usually means.

use std::error::Error;
use std::sync::atomic::{AtomicBool, Ordering};

use reqwest::header::{HeaderMap, HeaderValue, CONTENT_TYPE};
use reqwest::Client;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

/// The key, its id, and the kind the tenant accepted.
pub struct Auth {
    key: String,
    id: String,
    advanced: AtomicBool,
}

impl Auth {
    pub fn new(key: &str, id: &str, advanced: bool) -> Auth {
        Auth { key: key.trim().to_string(), id: id.trim().to_string(), advanced: AtomicBool::new(advanced) }
    }

    pub fn is_advanced(&self) -> bool {
        self.advanced.load(Ordering::Relaxed)
    }

    /// Headers for one request: an Advanced key signs each with a new nonce
    /// and the time of sending.
    pub fn fresh(&self) -> HeaderMap {
        let now_ms = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_millis()).unwrap_or(0);
        self.headers_at(&nonce(), now_ms)
    }

    fn headers_at(&self, nonce: &str, now_ms: u128) -> HeaderMap {
        let mut h = HeaderMap::new();
        let put = |h: &mut HeaderMap, k: &'static str, v: &str| {
            if let Ok(v) = HeaderValue::from_str(v) {
                h.insert(k, v);
            }
        };
        put(&mut h, "x-xdr-auth-id", &self.id);
        if self.is_advanced() {
            let ts = now_ms.to_string();
            put(&mut h, "x-xdr-nonce", nonce);
            put(&mut h, "x-xdr-timestamp", &ts);
            put(&mut h, "Authorization", &advanced_signature(&self.key, nonce, &ts));
        } else {
            put(&mut h, "Authorization", &self.key);
        }
        h.insert(CONTENT_TYPE, HeaderValue::from_static("application/json"));
        h.insert("Accept-Encoding", HeaderValue::from_static("gzip"));
        h
    }

    /// Ask the tenant which kind of key this is, with a request that costs
    /// nothing; says what the tenant answered when it refuses both.
    pub async fn connect(client: &Client, base_url: &str, key: &str, id: &str) -> Result<Auth, Box<dyn Error>> {
        let url = format!("{}/public_api/v1/xql/get_quota", base_url.trim_end_matches('/'));
        let forced = std::env::var("CORTEX_API_KEY_TYPE").ok().map(|v| v.trim().to_ascii_lowercase());
        let kinds: Vec<bool> = match forced.as_deref() {
            Some("advanced") => vec![true],
            Some("standard") => vec![false],
            _ => vec![false, true],
        };
        let mut last = String::new();
        for advanced in kinds {
            let auth = Auth::new(key, id, advanced);
            let resp = client.post(&url).headers(auth.fresh()).json(&json!({ "request_data": {} })).send().await?;
            let status = resp.status().as_u16();
            let body = resp.text().await.unwrap_or_default();
            if status == 200 {
                crate::banner::print_phase_detail("Key:", if advanced { "Advanced (signed with a nonce and the time)" } else { "Standard" });
                if let Some(q) = quota_line(&body) {
                    crate::banner::print_phase_detail("Quota:", &q);
                }
                return Ok(auth);
            }
            last = describe(status, &body, "the first request (XQL quota)");
            if status != 401 {
                break;
            }
        }
        Err(last.into())
    }
}

/// SHA-256 of key + nonce + timestamp, in hex: what an Advanced key sends.
pub fn advanced_signature(key: &str, nonce: &str, timestamp_ms: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(key.as_bytes());
    hasher.update(nonce.as_bytes());
    hasher.update(timestamp_ms.as_bytes());
    hasher.finalize().iter().map(|b| format!("{:02x}", b)).collect()
}

/// 64 letters and digits, new for every request.
fn nonce() -> String {
    use std::collections::hash_map::RandomState;
    use std::hash::{BuildHasher, Hasher};
    const ALPHABET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
    let mut out = String::with_capacity(64);
    while out.len() < 64 {
        // every RandomState carries fresh random keys from the system
        let mut h = RandomState::new().build_hasher();
        h.write_usize(out.len());
        let mut x = h.finish();
        for _ in 0..8 {
            if out.len() < 64 {
                out.push(ALPHABET[(x % ALPHABET.len() as u64) as usize] as char);
                x /= ALPHABET.len() as u64;
            }
        }
    }
    out
}

/// The quota answer in a line, when the tenant gives one.
fn quota_line(body: &str) -> Option<String> {
    let v: Value = serde_json::from_str(body).ok()?;
    let r = v.get("reply")?;
    let num = |k: &str| r.get(k).and_then(|x| x.as_f64());
    match (num("license_quota"), num("used_quota")) {
        (Some(total), Some(used)) => Some(format!("{:.2} of {:.0} compute units used today", used, total)),
        _ => None,
    }
}

/// A refusal in words: the status, what the tenant said, what it usually means.
pub fn describe(status: u16, body: &str, what: &str) -> String {
    let said = serde_json::from_str::<Value>(body)
        .ok()
        .and_then(|v| {
            let r = v.get("reply")?.clone();
            let part = |k: &str| r.get(k).map(|x| x.as_str().map(|s| s.to_string()).unwrap_or_else(|| x.to_string())).filter(|s| !s.is_empty() && s != "null");
            let parts: Vec<String> = ["err_code", "err_msg", "err_extra"].iter().filter_map(|k| part(k)).collect();
            if parts.is_empty() { None } else { Some(parts.join(" · ")) }
        })
        .unwrap_or_else(|| body.trim().chars().take(300).collect());
    let hint = match status {
        401 => "the key or its ID is not accepted: check the ID column of the key (Settings > Configurations > API Keys), that the key has not expired or been revoked, and that the URL is this tenant's (Copy API URL)",
        402 => "the tenant's licence does not include this (XQL needs Cortex XDR Pro; the forensics datasets need the Forensics add-on)",
        403 => "the key's role may not run XQL queries: it needs a role with the XQL / Public API permission (Instance Administrator has it)",
        429 => "too many queries at once, or the daily compute-unit quota is spent",
        500..=599 => "the tenant failed: try again, with a shorter time window if it persists",
        _ => "",
    };
    let mut out = format!("Cortex refused {}: HTTP {}", what, status);
    if !said.is_empty() {
        out.push_str(&format!(" · the tenant said: {}", said));
    }
    if !hint.is_empty() {
        out.push_str(&format!(" · {}", hint));
    }
    out
}

/// A query the tenant ran and failed (status FAIL, or anything that is not
/// SUCCESS / PENDING / RUNNING): its own explanation. An unknown dataset or
/// field, a syntax error, a quota spent all end here, and used to pass for
/// "0 events".
pub fn query_failure(status: &str, poll: &Value) -> String {
    let reply = poll.get("reply").cloned().unwrap_or(Value::Null);
    let mut said: Vec<String> = Vec::new();
    for k in ["error", "err_msg", "err_extra", "message", "reason"] {
        if let Some(v) = reply.get(k).filter(|v| !v.is_null()) {
            let t = v.as_str().map(|s| s.to_string()).unwrap_or_else(|| v.to_string());
            if !t.is_empty() && !said.contains(&t) {
                said.push(t);
            }
        }
    }
    if said.is_empty() {
        let mut compact = reply.clone();
        if let Some(o) = compact.as_object_mut() {
            o.remove("results");
        }
        said.push(compact.to_string().chars().take(500).collect());
    }
    format!("Cortex ran the query and it ended as {}: {}", status, said.join(" · "))
}

/// The body of a refused response, described; consumes the response.
pub async fn refusal(resp: reqwest::Response, what: &str) -> String {
    let status = resp.status().as_u16();
    let body = resp.text().await.unwrap_or_default();
    describe(status, &body, what)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_advanced_key_signs_with_nonce_and_time() {
        // SHA-256("keyNONCE1700000000000")
        assert_eq!(advanced_signature("key", "NONCE", "1700000000000"), "2c293f8bcb49f27772ec1bf38baba0e230fde8620645767400339cf80068dc10");
        let sig = advanced_signature("key", "NONCE", "1700000000000");
        assert_eq!(sig.len(), 64);
        assert!(sig.chars().all(|c| c.is_ascii_hexdigit()));
        assert_ne!(sig, advanced_signature("key", "NONCE", "1700000000001"));
        let a = Auth::new(" secret ", " 7 ", true);
        let h = a.headers_at("N".repeat(64).as_str(), 1700000000000);
        assert_eq!(h.get("x-xdr-auth-id").unwrap(), "7");
        assert_eq!(h.get("x-xdr-timestamp").unwrap(), "1700000000000");
        assert_eq!(h.get("x-xdr-nonce").unwrap().len(), 64);
        assert_eq!(h.get("Authorization").unwrap().to_str().unwrap(), advanced_signature("secret", &"N".repeat(64), "1700000000000"));
        assert!(!h.get("Authorization").unwrap().to_str().unwrap().contains("secret"));
    }

    #[test]
    fn a_standard_key_goes_as_it_is() {
        let a = Auth::new("secret", "7", false);
        let h = a.headers_at("x", 1);
        assert_eq!(h.get("Authorization").unwrap(), "secret");
        assert!(h.get("x-xdr-nonce").is_none() && h.get("x-xdr-timestamp").is_none());
    }

    #[test]
    fn nonces_are_64_characters_and_differ() {
        let (a, b) = (nonce(), nonce());
        assert_eq!(a.len(), 64);
        assert!(a.chars().all(|c| c.is_ascii_alphanumeric()));
        assert_ne!(a, b);
    }

    #[test]
    fn a_refusal_says_what_the_tenant_said_and_what_it_means() {
        let body = r#"{"reply":{"err_code":401,"err_msg":"Public API request unauthorized","err_extra":null}}"#;
        let d = describe(401, body, "the query");
        assert!(d.contains("HTTP 401") && d.contains("Public API request unauthorized") && d.contains("ID column"), "{}", d);
        assert!(describe(402, "", "the query").contains("licence"));
        assert!(describe(403, "not json", "the query").contains("not json"));
        assert_eq!(describe(418, "", "x"), "Cortex refused x: HTTP 418");
    }

    #[test]
    fn a_failed_query_is_told_not_taken_for_no_events() {
        let poll: Value = serde_json::from_str(r#"{"reply":{"status":"FAIL","error":"Dataset forensics_event_log does not exist","results":{"data":[]}}}"#).unwrap();
        let t = query_failure("FAIL", &poll);
        assert!(t.contains("ended as FAIL") && t.contains("does not exist"), "{}", t);
        let bare: Value = serde_json::from_str(r#"{"reply":{"status":"FAIL","number_of_results":0}}"#).unwrap();
        assert!(query_failure("FAIL", &bare).contains("number_of_results"));
    }

    #[test]
    fn the_quota_in_a_line() {
        assert_eq!(quota_line(r#"{"reply":{"license_quota":5,"used_quota":0.25}}"#).as_deref(), Some("0.25 of 5 compute units used today"));
        assert_eq!(quota_line("{}"), None);
    }
}
