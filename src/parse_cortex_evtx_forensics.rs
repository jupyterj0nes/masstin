use chrono::{DateTime, TimeZone, Utc};
use csv::WriterBuilder;
use flate2::read::GzDecoder;
use reqwest::{Client, header::HeaderMap};
use serde_json::{json, Value};
use std::error::Error;
use std::io::{BufReader, Read, stdin, stdout, Write};
use std::time::Duration;
use tokio::time::sleep;
use std::sync::atomic::{AtomicBool, Ordering};

// ----------------------------------------------
// Debug mode global
// ----------------------------------------------
static DEBUG_MODE: AtomicBool = AtomicBool::new(false);

pub fn set_debug_mode(val: bool) {
    DEBUG_MODE.store(val, Ordering::SeqCst);
}

pub fn is_debug_mode() -> bool {
    DEBUG_MODE.load(Ordering::SeqCst)
}

// ----------------------------------------------
// Columns for final CSV
// Adaptar según tu formato deseado
// ----------------------------------------------
static FINAL_COLUMNS: &[&str] = &[
    "time_created",
    "dst_computer",
    "event_type",
    "event_id",
    "logon_type",
    "target_user_name",
    "target_domain_name",
    "src_computer",
    "src_ip",
    "subject_user_name",
    "subject_domain_name",
    "logon_id",
    "detail",
    "log_filename",
];

// ----------------------------------------------
// Main function to parse the new Cortex data
// using the custom XQL query for EVTX forensics
// ----------------------------------------------
pub async fn parse_cortex_evtx_forensics_data(
    base_url: &str,
    output: Option<&String>,
    debug: bool,
    start_time: Option<&String>,
    end_time: Option<&String>,
    ignore_local: bool,
    event_ids: Option<&String>,
    min_window_secs: i64,
    max_passes: usize,
) -> Result<(), Box<dyn Error>> {
    let start_clock = std::time::Instant::now();

    // Phase 1: API Authentication
    crate::banner::print_phase("1", "3", "Authenticating with Cortex XDR Forensics API...");
    let (token, x_xdr_auth_id) = prompt_for_api_key_and_id()?;

    // 1) turn CLI parameters into epochs
    let epoch_start = match start_time {
        Some(s) if !s.is_empty() => Some(to_epoch_secs(s)?),
        _ => None,
    };
    let epoch_end = match end_time {
        Some(s) if !s.is_empty() => Some(to_epoch_secs(s)?),
        _ => None,
    };

    // Build the time_filter XQL clause as a function of window bounds. When
    // auto-pagination bisects, each pass uses its own (start, end) to rebuild
    // the clause. If no bounds are provided, the clause is empty and the query
    // uses the default `timeframe=365d` at the top.
    let build_time_filter = |start: Option<i64>, end: Option<i64>| -> String {
        match (start, end) {
            (Some(s), Some(e)) => format!(
                r#"| filter (timestamp_diff(to_timestamp({e}), Timestamp, "SECOND") > 0) and
                     (timestamp_diff(Timestamp,      to_timestamp({s}), "SECOND") > 0 )"#
            ),
            _ => String::new(),
        }
    };



    let client = Client::new();

    // Endpoints
    let start_query_url = format!("{}/public_api/v1/xql/start_xql_query/", base_url.trim_end_matches('/'));
    let get_results_url = format!("{}/public_api/v1/xql/get_query_results/", base_url.trim_end_matches('/'));
    let get_stream_url = format!("{}/public_api/v1/xql/get_query_results_stream", base_url.trim_end_matches('/'));

    // Headers
    let headers = build_headers(&token, &x_xdr_auth_id)?;

    // Event IDs pushed into XQL. Default set now matches the canonical list from
    // parse-windows (src/parse.rs constants) so that `parse-cortex-evtx-forensics`
    // covers exactly the same lateral-movement surface as `parse-windows`:
    //   Security:       4624,4625,4634,4647,4648,4768,4769,4770,4771,4776,4778,4779,5140
    //                   (5145 intentionally excluded — see SECURITY_EVENT_IDS in parse.rs)
    //   SMB Client:     31001
    //   SMB Client Conn:30803-30808
    //   SMB Server:     1009,551
    //   RDP Client:     1024,1102
    //   RDP ConnMgr:    1149
    //   RDP LSM:        21,22,24,25
    //   RDP Core TS:    131
    //   WinRM:          6
    //   WMI-Activity:   5858
    // --cortex-event-ids overrides to narrow (e.g. "4624,4625,4648").
    let default_ids = "4624,4625,4634,4647,4648,4768,4769,4770,4771,4776,4778,4779,5140,31001,30803,30804,30805,30806,30807,30808,1009,551,1024,1102,1149,21,22,24,25,131,6,5858";
    let event_ids_clause: String = match event_ids {
        Some(raw) => raw.split(',').map(|s| s.trim()).filter(|s| !s.is_empty()).collect::<Vec<_>>().join(","),
        None => default_ids.to_string(),
    };

    // --ignore-local pushed server-side: drop events where srcip/source_host map
    // to the same host as dst_host or are loopback/link-local markers. The final
    // `dst_host != source_host` check already exists below; here we add IP-shape
    // exclusions up front so less data has to traverse the stream.
    let ignore_local_post_clause = if ignore_local {
        r#"| filter (srcip not in ("127.0.0.1","::1","0.0.0.0","localhost","-") or srcip = null)
           | filter (source_host not in ("127.0.0.1","::1","0.0.0.0","localhost","-") or source_host = null)"#
    } else {
        ""
    };

    // XQL query. Sources and event_id set mirror parse-windows exactly.
    //
    // Locale coverage for the `regextract` branches:
    //   EN, ES: validated against the Unit42 academy tenant.
    //   DE, FR, IT: derived from Microsoft Learn localized KB3097467,
    //               wallix/pylogsparser French normalizer, and ManageEngine
    //               ADAudit Plus localized event reference pages.
    //   Niche events (131 RdpCoreTS, 6 WinRM, 5858 WMI-Activity) carry
    //               English-only templates on every locale — confirmed from the
    //               ETW manifests and Microsoft WMI KB — so no localization
    //               layer is needed for their branches.
    //
    // Extending to new locales is forward-compatible: each field is a
    // `(?:EN|ES|DE|FR|IT|...)` alternation, so wrong or missing additions
    // silently fail to match without affecting other languages.
    // Community contributions welcome — see CONTRIBUTING and the README
    // section "Help us localize the Cortex XDR EVTX query".
    //
    // Field semantics (mirror parse.rs parse_security_log / parse_smb_server /
    // parse_rdp_localsession / parse_winrm / parse_wmi):
    //   dst_host     = host where the auth/event landed
    //   source_host  = workstation name reported by the source system
    //   srcip        = source IP reported by the source system
    //   subject_*    = initiator (Subject: block)
    //   target_*     = account whose credentials were used / for whom the logon was created
    //   lt           = logon type (string), or "runas"/"10"/"3" derived by event_id
    //   process      = process name (4624/4648), or overloaded carrier for
    //                  detail content of 5140/5858/6/4625
    let build_query = |w_start: Option<i64>, w_end: Option<i64>| -> String {
        let time_filter = build_time_filter(w_start, w_end);
        format!(
        r#"config case_sensitive = false timeframe=365d |
       dataset = forensics_event_log
                    | filter event_id in ({event_ids_clause}) and source in (
                        "Security",
                        "Microsoft-Windows-TerminalServices-LocalSessionManager/Operational",
                        "Microsoft-Windows-SMBServer/Security",
                        "Microsoft-Windows-SmbClient/Security",
                        "Microsoft-Windows-TerminalServices-RDPClient/Operational",
                        "Microsoft-Windows-TerminalServices-RemoteConnectionManager/Operational",
                        "Microsoft-Windows-RemoteDesktopServices-RdpCoreTS/Operational",
                        "Microsoft-Windows-WinRM/Operational",
                        "Microsoft-Windows-WMI-Activity/Operational")
                    | filter message not in ("""::""", null, """""","-")
                    | alter lt = if(
                        event_id in (4624,4625,4634), arrayindex(regextract(message, "(?i)(?:Logon Type|Tipo de inicio de sesión|Anmeldetyp|Type d.ouverture de session|Tipo di accesso):\s*(\d+)"), 0),
                        event_id = 4648, "runas",
                        event_id in (21,22,24,25,1024,1102,1149,131), "10",
                        event_id in (6,5858), "",
                        "3")
                    | alter srcip = if(
                        event_id in (4624,4625,21,22,24,25,1149,1009,551), arrayindex(regextract(message, "(?i)(?:Source Network Address|Dirección de red de origen|Quellnetzwerkadresse|Adresse du réseau source|Indirizzo di rete di origine|Client Name|Nombre de.? cliente|Clientname|Nom du client|Nome client):\s*\\*([\w.-]+)"), 0),
                        event_id = 5140, arrayindex(regextract(message, "(?i)(?:Source Address|Dirección de origen|Quelladresse|Adresse source|Indirizzo di origine):\s*([\w.:-]+)"), 0),
                        event_id = 131, arrayindex(regextract(message, "(?i)from client\s+([^:\s]+)"), 0),
                        event_id = 5858, arrayindex(regextract(message, "ClientMachine\s*=\s*([\w.\-$]+)"), 0))
                    | alter process = if(
                        event_id in (4624,4625,4648), arrayindex(regextract(message, "(?i)(?:Process Name|Nombre de proceso|Prozessname|Nom du processus|Nome processo|Nome del processo):\s*([^\r\n]+)"), 0),
                        event_id = 5140, arrayindex(regextract(message, "(?i)(?:Share Name|Nombre del recurso compartido|Freigabename|Nom du partage|Nome condivisione):\s*(\S+)"), 0),
                        event_id = 5858, arrayindex(regextract(message, "Operation\s*=\s*([^;]{{1,120}})"), 0),
                        event_id = 6,    arrayindex(regextract(message, "(?i)connection\s*[:=]?\s*(\S+)"), 0),
                        event_id = 4625, arrayindex(regextract(message, "(?i)(?:Sub Status|Subestado|Unterstatus|Sous-état|Sottostato):\s*(0x[0-9a-f]+)"), 0))
                    | alter source_host = if(
                        event_id in (4624,4625,4634), arrayindex(regextract(message, "(?i)(?:Workstation Name|Nombre de estación de trabajo|Arbeitsstationsname|Nom de la station de travail|Nome workstation|Nome stazione di lavoro):\s*\\*([\w.-]+)"), 0),
                        event_id = 4776, arrayindex(regextract(message, "(?i)(?:Source Workstation|Estación de trabajo de origen|Quellarbeitsstation|Station de travail source|Workstation di origine):\s*([\w.-]+)"), 0),
                        event_id in (4648,31001,30803,30804,30805,30806,30807,30808,1024,1102), host_name)
                    | alter subject_name = if(
                        event_id in (4624,4625,4634,4647,4648,5140), arrayindex(regextract(message, "(?si)(?:Subject:.*?Account Name|Firmante:.*?Nombre de cuenta|Antragsteller:.*?Kontoname|Sujet:.*?Nom du compte|Soggetto:.*?Nome account|Oggetto:.*?Nome account):\s*([\w.\-$]+)"), 0))
                    | alter subject_domain = if(
                        event_id in (4624,4625,4634,4647,4648,5140), arrayindex(regextract(message, "(?si)(?:Subject:.*?Account Domain|Firmante:.*?Dominio de cuenta|Antragsteller:.*?Kontodomäne|Sujet:.*?Domaine du compte|Soggetto:.*?Dominio account|Oggetto:.*?Dominio account):\s*([\w.\-$ ]+)"), 0))
                    | alter target_user = if(
                        event_id in (4624,4625,4648), arrayindex(regextract(message, "(?si)(?:New Logon:.*?Account Name|Nuevo inicio de sesión:.*?Nombre de cuenta|Neue Anmeldung:.*?Kontoname|Nouvelle ouverture de session:.*?Nom du compte|Nuovo accesso:.*?Nome account|Account For Which Logon Failed:.*?Account Name|Cuenta con error de inicio de sesión:.*?Nombre de cuenta|Konto, für das die Anmeldung fehlschlug:.*?Kontoname|Compte pour lequel l.ouverture de session a échoué:.*?Nom du compte|Account per cui l.accesso non è riuscito:.*?Nome account|Account Whose Credentials Were Used:.*?Account Name|Cuenta cuyas credenciales se usaron:.*?Nombre de cuenta|Konto, dessen Anmeldeinformationen verwendet wurden:.*?Kontoname|Compte dont les informations d.identification ont été utilisées:.*?Nom du compte|Account le cui credenziali sono state usate:.*?Nome account):\s*([\w.\-$]+)"), 0),
                        event_id = 4776, arrayindex(regextract(message, "(?i)(?:Logon Account|Cuenta de inicio de sesión|Anmeldekonto|Compte d.ouverture de session|Account di accesso):\s*([\w.\-$]+)"), 0),
                        event_id = 5858, arrayindex(regextract(message, "User\s*=\s*(?:[^\s\\]+\\)?([\w.\-$]+)"), 0),
                        event_id in (1009,551,31001,21,22,24,25,1149), arrayindex(regextract(message, "(?:User Name|Nombre de.? usuario|Benutzername|Nom d.utilisateur|Nome utente|User|Usuario):\s(?:[^\s\\]+)\\([^\s]+)"), 0))
                    | alter target_domain = if(
                        event_id in (4624,4625,4648), arrayindex(regextract(message, "(?si)(?:New Logon:.*?Account Domain|Nuevo inicio de sesión:.*?Dominio de cuenta|Neue Anmeldung:.*?Kontodomäne|Nouvelle ouverture de session:.*?Domaine du compte|Nuovo accesso:.*?Dominio account|Account For Which Logon Failed:.*?Account Domain|Cuenta con error de inicio de sesión:.*?Dominio de cuenta|Konto, für das die Anmeldung fehlschlug:.*?Kontodomäne|Compte pour lequel l.ouverture de session a échoué:.*?Domaine du compte|Account per cui l.accesso non è riuscito:.*?Dominio account|Account Whose Credentials Were Used:.*?Account Domain|Cuenta cuyas credenciales se usaron:.*?Dominio de cuenta|Konto, dessen Anmeldeinformationen verwendet wurden:.*?Kontodomäne|Compte dont les informations d.identification ont été utilisées:.*?Domaine du compte|Account le cui credenziali sono state usate:.*?Dominio account):\s*([\w.\-$]+)"), 0),
                        event_id in (1009,551,31001,21,22,24,25,1149), arrayindex(regextract(message, "(?:User Name|Nombre de.? usuario|Benutzername|Nom d.utilisateur|Nome utente|User|Usuario):\s([^\s\\]+)\\(?:[^\s]+)"), 0))
                    | alter dst_host = if(
                        event_id in (4624,4625,4634,4647,4776,4778,4779,5140,21,22,24,25,1149,131,5858), host_name,
                        event_id = 4648, arrayindex(regextract(message, "(?i)(?:Target Server Name|Nombre de servidor de destino|Zielservername|Nom du serveur cible|Nome del server di destinazione):\s*\\*([\w.-]+)"), 0),
                        event_id in (31001,30803,30804,30805,30806,30807), arrayindex(regextract(message, "(?i)(?:Server Name|Nombre de servidor|Servername|Nom du serveur|Nome del server):\s\\*(.+)"), 0),
                        event_id = 30808, arrayindex(regextract(message, "(?i)(?:Share Name|Nombre del recurso compartido|Freigabename|Nom du partage|Nome condivisione):\s\\*(.+)"), 0),
                        event_id = 1102, arrayindex(regextract(message, "(?i)(?:server|servidor|serveur)\s+([\w.-]+)\b"), 0),
                        event_id = 6,    arrayindex(regextract(message, "(?i)connection\s*[:=]?\s*(?:https?://)?([\w.-]+)"), 0))
                    | alter Timestamp  = to_timestamp(event_generated, "millis")
                    {time_filter}
                    | filter ((`source_host` not in ("","-","LOCAL", "127.0.0.1", "::1",null,"localhost") or srcip not in ("","-","LOCAL", "127.0.0.1", "::1",null,"localhost")) and dst_host not in ("","-","LOCAL", "127.0.0.1", "::1",null,"localhost"))
                    | filter (dst_host != source_host) and (dst_host != srcip )
                    {ignore_local_post_clause}
                    | fields Timestamp, dst_host, event_id, subject_name, subject_domain, target_user, target_domain,lt, source_host, srcip, process"#)
    };

    // Phase 2: Query API
    crate::banner::print_phase("2", "3", "Querying Cortex XDR Forensics API...");
    if start_time.is_some() {
        crate::banner::print_phase_detail("Time range:", &format!("{} to {}", start_time.unwrap_or(&String::new()), end_time.unwrap_or(&String::new())));
    }

    // Auto-pagination by time splitting. Same pattern as parse_cortex: when a
    // query hits the API cap near 1M records, bisect the time window and retry
    // each half. Only active when both bounds are provided; otherwise a single
    // query runs with the default 365d timeframe.
    const API_CAP: usize = 1_000_000;
    const SATURATION_THRESHOLD: usize = 999_000;

    let has_bounds = epoch_start.is_some() && epoch_end.is_some();
    let mut all_data: Vec<Value> = Vec::new();
    let mut work: Vec<(Option<i64>, Option<i64>)> = vec![(epoch_start, epoch_end)];
    let mut pass = 0usize;
    let mut truncated_passes = 0usize;
    let mut max_cap_hit = false;

    if has_bounds {
        crate::banner::print_phase_detail(
            "Auto-pagination:",
            &format!(
                "min window {}s, max {} passes, saturation threshold {}",
                min_window_secs, max_passes, SATURATION_THRESHOLD
            ),
        );
    }

    while let Some((w_start, w_end)) = work.pop() {
        pass += 1;

        if has_bounds {
            let span_secs = match (w_start, w_end) { (Some(s), Some(e)) => e - s, _ => -1 };
            let span_label = if span_secs < 0 {
                "?".to_string()
            } else if span_secs < 3600 {
                format!("{}m", span_secs / 60)
            } else if span_secs < 86400 {
                format!("{}h {}m", span_secs / 3600, (span_secs % 3600) / 60)
            } else {
                format!("{}d {}h", span_secs / 86400, (span_secs % 86400) / 3600)
            };
            crate::banner::print_phase_detail(
                &format!("Pass {}/{}", pass, max_passes),
                &format!(
                    "window {} → {}  (span {})  queue={}  collected={}",
                    w_start.map(epoch_to_str).unwrap_or_else(|| "-".into()),
                    w_end.map(epoch_to_str).unwrap_or_else(|| "-".into()),
                    span_label,
                    work.len(),
                    all_data.len()
                ),
            );
        }

        let pass_start = std::time::Instant::now();
        let batch = run_forensics_query(
            &client,
            &start_query_url,
            &get_results_url,
            &get_stream_url,
            &headers,
            &build_query(w_start, w_end),
            debug,
        )
        .await?;
        let batch_len = batch.len();
        let elapsed = pass_start.elapsed().as_secs();

        if has_bounds {
            crate::banner::print_phase_detail(
                "  ↳",
                &format!("retrieved {} events in {}s", batch_len, elapsed),
            );
        }

        if has_bounds && batch_len >= SATURATION_THRESHOLD {
            if pass >= max_passes {
                max_cap_hit = true;
                crate::banner::print_warning(&format!(
                    "Pass cap {} reached — accepting saturated window as-is. Raise --cortex-max-passes if you need deeper recovery.",
                    max_passes
                ));
                all_data.extend(batch);
                truncated_passes += 1;
                continue;
            }
            match bisect_epoch_window(w_start, w_end, min_window_secs) {
                Some(mid) => {
                    crate::banner::print_warning(&format!(
                        "Saturated at {}/{} — bisecting at {}. Queue will grow by 1.",
                        batch_len, API_CAP, epoch_to_str(mid)
                    ));
                    // Push later half first so we pop the earlier half next.
                    work.push((Some(mid), w_end));
                    work.push((w_start, Some(mid)));
                    continue;
                }
                None => {
                    truncated_passes += 1;
                    crate::banner::print_warning(&format!(
                        "Saturated at {} but window is already at the {}s floor — accepting truncation. Lower --cortex-min-window-secs to go finer.",
                        batch_len, min_window_secs
                    ));
                    all_data.extend(batch);
                }
            }
        } else {
            all_data.extend(batch);
        }
    }

    if has_bounds {
        crate::banner::print_phase_detail(
            "Auto-pagination complete:",
            &format!(
                "{} passes, {} events collected, {} windows truncated",
                pass, all_data.len(), truncated_passes
            ),
        );
        if max_cap_hit {
            crate::banner::print_warning(
                "One or more windows hit --cortex-max-passes. Consider raising it or narrowing --start-time/--end-time."
            );
        }
    }

    // Count unique destination hosts and unique event sources for the summary.
    // The query returns `dst_host` (renamed from host_name) so we count that.
    let mut machines: std::collections::HashSet<String> = std::collections::HashSet::new();
    let mut event_ids_seen: std::collections::HashSet<String> = std::collections::HashSet::new();
    for record in &all_data {
        for key in &["dst_host", "source_host"] {
            if let Some(host) = record.get(*key).and_then(|v| v.as_str()) {
                if !host.is_empty() && host != "-" { machines.insert(host.to_string()); }
            }
        }
        if let Some(eid) = record.get("event_id") {
            let s = eid.as_str().map(|v| v.to_string()).or_else(|| eid.as_i64().map(|v| v.to_string()));
            if let Some(v) = s { event_ids_seen.insert(v); }
        }
    }
    crate::banner::print_cortex_forensics_summary(machines.len(), event_ids_seen.len(), all_data.len());

    // Sort by _time
    all_data.sort_by(|a, b| {
        let a_ts = get_timestamp(a).unwrap_or(0);
        let b_ts = get_timestamp(b).unwrap_or(0);
        a_ts.cmp(&b_ts)
    });

    // Write CSV
    if debug {
        eprintln!("[DEBUG] Total final records: {}", all_data.len());
    }
    let out_path = match output {
        Some(path) => path,
        None => "cortex_evtx_forensics_output.csv",
    };
    if debug {
        eprintln!("[DEBUG] Writing results to: {}", out_path);
    }

    // Phase 3: Generate output
    crate::banner::print_phase("3", "3", "Generating output...");
    write_processed_csv(&all_data, out_path, debug)?;

    crate::banner::print_summary(all_data.len(), all_data.len(), 0, Some(out_path), start_clock);
    Ok(())
}

// ----------------------------------------------
// Single-query runner (used by the auto-pagination loop)
// Posts one XQL query, polls for completion, fetches streamed results.
// ----------------------------------------------
async fn run_forensics_query(
    client: &Client,
    start_query_url: &str,
    get_results_url: &str,
    get_stream_url: &str,
    headers: &HeaderMap,
    query_string: &str,
    debug: bool,
) -> Result<Vec<Value>, Box<dyn Error>> {
    let payload = json!({
        "request_data": { "query": query_string, "tenants": [] }
    });

    if debug {
        eprintln!("[DEBUG] POST to: {}", start_query_url);
        eprintln!("[DEBUG] Query: {}", query_string);
    }

    let resp = client.post(start_query_url)
        .headers(headers.clone())
        .json(&payload)
        .send().await?;
    if resp.status() != 200 {
        return Err(format!("start_xql_query failed with status: {}", resp.status()).into());
    }
    let resp_json: Value = resp.json().await?;
    let query_id = resp_json
        .get("reply")
        .and_then(|r| r.as_str())
        .ok_or("Could not retrieve 'query_id' from start query response")?
        .to_string();

    let spinner = crate::banner::create_spinner("Waiting for forensic query results...");
    let mut out: Vec<Value> = Vec::new();
    let poll_payload = json!({
        "request_data": { "query_id": query_id, "offset": 0 }
    });

    // Poll up to 10 minutes (120 * 5s) — large saturated windows can take a while.
    let max_retries = 120;
    for attempt in 0..max_retries {
        if debug {
            eprintln!("[DEBUG] Poll attempt {}", attempt + 1);
        }
        let poll_resp = client.post(get_results_url)
            .headers(headers.clone())
            .json(&poll_payload)
            .send().await?;
        if poll_resp.status() != 200 { break; }
        let poll_json: Value = poll_resp.json().await?;
        let status = poll_json.pointer("/reply/status").and_then(|v| v.as_str()).unwrap_or("UNKNOWN");

        if status == "SUCCESS" {
            if let Some(results_data) = poll_json.pointer("/reply/results/data") {
                if let Some(arr) = results_data.as_array() {
                    out.extend_from_slice(arr);
                }
            }
            if let Some(stream_id) = poll_json.pointer("/reply/results/stream_id").and_then(|v| v.as_str()) {
                let more = fetch_stream_data(client, get_stream_url, headers, stream_id, debug).await?;
                out.extend(more);
            }
            break;
        } else if status == "PENDING" || status == "RUNNING" {
            sleep(Duration::from_secs(5)).await;
        } else {
            break;
        }
    }
    spinner.finish_and_clear();
    Ok(out)
}

/// Bisect a (start_epoch, end_epoch) window. Returns the midpoint epoch
/// (seconds) or None if the window is smaller than 2× the min_window_secs
/// floor (which would produce a half below the floor).
fn bisect_epoch_window(start: Option<i64>, end: Option<i64>, min_window_secs: i64) -> Option<i64> {
    let (s, e) = (start?, end?);
    let span = e - s;
    if span < min_window_secs * 2 {
        return None;
    }
    Some(s + span / 2)
}

/// Format an epoch-seconds timestamp as "YYYY-MM-DD HH:MM:SS UTC" for logs.
fn epoch_to_str(epoch: i64) -> String {
    Utc.timestamp(epoch, 0)
        .format("%Y-%m-%d %H:%M:%S UTC")
        .to_string()
}

// ----------------------------------------------
// Stream fetch if large dataset
// (Misma lógica que parse_cortex, se conserva)
// ----------------------------------------------
async fn fetch_stream_data(
    client: &Client,
    url: &str,
    headers: &HeaderMap,
    stream_id: &str,
    debug: bool
) -> Result<Vec<Value>, Box<dyn Error>> {
    let payload = json!({
        "request_data": {
            "stream_id": stream_id
        }
    });

    if debug {
        eprintln!("[DEBUG] GET stream data from: {}", url);
    }

    let resp = client.post(url)
        .headers(headers.clone())
        .json(&payload)
        .send()
        .await?;

    if resp.status() != 200 {
        return Err(format!("get_query_results_stream failed: {}", resp.status()).into());
    }

    let bytes = resp.bytes().await?;
    // Check if it's gzip
    if bytes.len() > 2 && bytes[0] == 0x1F && bytes[1] == 0x8B {
        if debug { eprintln!("[DEBUG] GZIP detected"); }
        let gz = GzDecoder::new(&bytes[..]);
        let mut decompressed = String::new();
        BufReader::new(gz).read_to_string(&mut decompressed)?;
        parse_ndjson(&decompressed, debug)
    } else {
        let data_str = String::from_utf8_lossy(&bytes).to_string();
        parse_ndjson(&data_str, debug)
    }
}

fn parse_ndjson(data: &str, debug: bool) -> Result<Vec<Value>, Box<dyn Error>> {
    let mut out = Vec::new();
    for line in data.lines() {
        let trim = line.trim();
        if trim.is_empty() { continue; }
        match serde_json::from_str::<Value>(trim) {
            Ok(json_val) => out.push(json_val),
            Err(e) => {
                if debug {
                    eprintln!("[DEBUG] Could not parse JSON line: {} => {}", e, trim);
                }
            }
        }
    }
    Ok(out)
}

// ----------------------------------------------
// Time extraction
// ----------------------------------------------
fn get_timestamp(record: &Value) -> Option<i64> {
    if let Some(ts) = record.get("Timestamp").and_then(|v| v.as_i64()) {
        Some(ts)
    } else if let Some(ts_str) = record.get("Timestamp").and_then(|v| v.as_str()) {
        if let Ok(dt) = Utc.datetime_from_str(ts_str, "%Y-%m-%d %H:%M:%S%.f UTC") {
            Some(dt.timestamp_millis())
        } else if let Ok(dt) = DateTime::parse_from_rfc3339(ts_str) {
            Some(dt.timestamp_millis())
        } else {
            None
        }
    } else {
        None
    }
}

// ----------------------------------------------
// CSV writing
// ----------------------------------------------
fn write_processed_csv(records: &[Value], filename: &str, debug: bool) -> Result<(), Box<dyn Error>> {
    let mut wtr = WriterBuilder::new().from_path(filename)?;
    // Write header
    wtr.write_record(FINAL_COLUMNS)?;

    // Process each record. Applies the global noise filter
    // (--ignore-local / --exclude-*) by reconstructing a minimal LogData
    // view of the processed row — FINAL_COLUMNS order matches the
    // canonical masstin CSV header, so indices are fixed.
    for record in records {
        let row = process_record(record, debug);
        if row.len() >= 14 {
            let ld = crate::parse::LogData {
                time_created: row[0].clone(),
                computer: row[1].clone(),
                event_type: row[2].clone(),
                event_id: row[3].clone(),
                logon_type: row[4].clone(),
                target_user_name: row[5].clone(),
                target_domain_name: row[6].clone(),
                workstation_name: row[7].clone(),
                ip_address: row[8].clone(),
                subject_user_name: row[9].clone(),
                subject_domain_name: row[10].clone(),
                logon_id: row[11].clone(),
                detail: row[12].clone(),
                filename: row[13].clone(),
            };
            if !crate::filter::should_keep_record(&ld) {
                continue;
            }
        }
        wtr.write_record(&row)?;
    }
    wtr.flush()?;
    Ok(())
}

// ----------------------------------------------
// Example of a simpler "process_record"
// Tomado de tu query, ajusta la lógica real
// ----------------------------------------------
fn process_record(record: &Value, debug: bool) -> Vec<String> {
    // Extraer `_time` como timestamp formateado en RFC 3339 (UTC)
    let time_created = if let Some(ts) = record.get("Timestamp").and_then(|v| v.as_i64()) {
        let dt = Utc.timestamp_millis(ts);
        dt.format("%Y-%m-%dT%H:%M:%S%.6fZ").to_string()
    } else if let Some(time_str) = record.get("Timestamp").and_then(|v| v.as_str()) {
        // Try to parse a string in the format "YYYY-MM-DD HH:MM:SS.mmm UTC"
        if let Ok(dt) = Utc.datetime_from_str(time_str, "%Y-%m-%d %H:%M:%S%.f UTC") {
            dt.format("%Y-%m-%dT%H:%M:%S%.6fZ").to_string()
        } else {
            // Fallback: return the original string if parsing fails.
            time_str.to_string()
        }
    } else {
        "".to_string()
    };

    // Extraer los valores esperados de la query
    let dst_computer = record.get("dst_host").and_then(|v| v.as_str()).unwrap_or("").to_string();
    let event_id = record.get("event_id").and_then(|v| v.as_str()).unwrap_or("").to_string();
    
    let subject_user_name = record.get("subject_name").and_then(|v| v.as_str()).unwrap_or("").to_string();
    let subject_domain_name = record.get("subject_domain").and_then(|v| v.as_str()).unwrap_or("").to_string();
    
    let target_user_name = record.get("target_user").and_then(|v| v.as_str()).unwrap_or("").to_string();
    let target_domain_name = record.get("target_domain").and_then(|v| v.as_str()).unwrap_or("").to_string();

    let logon_type = record.get("lt").and_then(|v| v.as_str()).unwrap_or("").to_string();

    let src_computer = record.get("source_host").and_then(|v| v.as_str()).unwrap_or("").to_string();
    let src_ip = record.get("srcip").and_then(|v| v.as_str()).unwrap_or("").to_string();

    let process = record.get("process").and_then(|v| v.as_str()).unwrap_or("").to_string();

    // Classify event_type — must match parse.rs (parse_security_log / parse_smb_server
    // / parse_rdp_localsession / parse_winrm / parse_wmi) exactly. Any divergence
    // would produce different CSV output for the same underlying event depending
    // on whether it came from parse-windows or parse-cortex-evtx-forensics.
    //
    // For 4768/4769/4776 parse-windows branches on Status=="0x0" to classify
    // success/failure. We don't have the Status field in the Cortex query — it
    // would need yet another alter branch. As a best-effort we classify as
    // SUCCESSFUL_LOGON and rely on 4771 (pre-auth fail) for the FAILED signal.
    // TODO: add Status extraction to the XQL query if the false-positive rate
    // on 4768/4769/4776 proves to be a problem in practice.
    let event_type = match event_id.as_str() {
        "4624" => "SUCCESSFUL_LOGON".to_string(),
        "4625" => "FAILED_LOGON".to_string(),
        "4634" | "4647" | "4779" => "LOGOFF".to_string(),
        "4648" => "SUCCESSFUL_LOGON".to_string(),
        "4768" | "4769" | "4776" => "SUCCESSFUL_LOGON".to_string(),
        "4770" => "SUCCESSFUL_LOGON".to_string(),
        "4771" => "FAILED_LOGON".to_string(),
        "4778" => "SUCCESSFUL_LOGON".to_string(),
        "5140" => "SUCCESSFUL_LOGON".to_string(),
        "21" | "22" | "25" | "1149" => "SUCCESSFUL_LOGON".to_string(),
        "24" => "LOGOFF".to_string(),
        "1024" | "1102" | "131" => "CONNECT".to_string(),
        "1009" | "31001" => "SUCCESSFUL_LOGON".to_string(),
        "30803" | "30804" | "30805" | "30806" | "30807" | "30808" => "CONNECT".to_string(),
        "551" => "FAILED_LOGON".to_string(),
        "6" | "5858" => "CONNECT".to_string(),
        _ => "CONNECT".to_string(),
    };

    // detail — replicate parse.rs semantics. The XQL `process` column is
    // overloaded to carry whichever raw string the event's detail field needs
    // (ProcessName for 4624/4648, SubStatus for 4625, ShareName for 5140,
    // Operation for 5858, connection for 6). Final wrapping happens here.
    let detail = match event_id.as_str() {
        "4624" | "4648" => process.clone(),
        "4625" => {
            if process.is_empty() {
                String::new()
            } else {
                crate::parse::translate_substatus(&process)
            }
        }
        "5140" => process.clone(),
        "5858" => {
            if process.is_empty() {
                String::new()
            } else {
                format!("WMI: {}", process)
            }
        }
        "6" => {
            if process.is_empty() {
                String::new()
            } else {
                format!("WinRM: {}", process)
            }
        }
        _ => String::new(),
    };

    // logon_id empty for Cortex forensics
    let logon_id = "".to_string();

    // Nombre del log fijo
    let log_filename = "cortex_evtx_forensics".to_string();

    // Devolver la fila en el orden esperado por `FINAL_COLUMNS`
    vec![
        time_created,
        dst_computer,
        event_type,
        event_id,
        logon_type,
        target_user_name,
        target_domain_name,
        src_computer,
        src_ip,
        subject_user_name,
        subject_domain_name,
        logon_id,
        detail,
        log_filename,
    ]
}


// ----------------------------------------------
// Pide la API key al usuario
// ----------------------------------------------
/// Prompts the user for an API key and returns it as a `String`.
fn prompt_for_api_key_and_id() -> Result<(String, String), Box<dyn Error>> {
    // Prompt for API Key ID
    print!("Enter your Cortex/XDR API Key ID (numeric): ");
    stdout().flush()?;
    let mut api_key_id_input = String::new();
    stdin().read_line(&mut api_key_id_input)?;
    let api_key_id: u32 = api_key_id_input.trim().parse()?; // 👈 fuerza número

    // Prompt for API Key
    print!("Enter your Cortex/XDR API Key: ");
    stdout().flush()?;
    let mut api_key = String::new();
    stdin().read_line(&mut api_key)?;
    let api_key = api_key.trim().to_string();

    Ok((api_key, api_key_id.to_string())) // 👈 lo devuelves como string
}

// ----------------------------------------------
// Construye los headers
// ----------------------------------------------
/// Builds the necessary headers for the Cortex/XDR API requests.
fn build_headers(token: &str, x_xdr_auth_id: &str) -> Result<HeaderMap, Box<dyn Error>> {

    use reqwest::header::{HeaderMap, HeaderValue, CONTENT_TYPE};
    let mut headers = HeaderMap::new();

    // Example: "x-xdr-auth-id" is often a static integer, e.g., "5".
    //headers.insert("x-xdr-auth-id", HeaderValue::from_str("194").unwrap());
    headers.insert("x-xdr-auth-id", HeaderValue::from_str(x_xdr_auth_id.trim())?);
    headers.insert("Authorization", HeaderValue::from_str(token)?);

    headers.insert(CONTENT_TYPE, HeaderValue::from_static("application/json"));
    // If the server supports gzip, add this header.
    headers.insert("Accept-Encoding", HeaderValue::from_static("gzip"));
    Ok(headers)
}

// Convert clap-supplied date-time (with or without “ -0000”) to epoch *seconds*
fn to_epoch_secs(ts: &str) -> Result<i64, Box<dyn Error>> {
    let trimmed = ts.trim();

    // First try with a timezone offset (e.g. "2025-02-01 17:12:00 -0000")
    if let Ok(dt) = DateTime::parse_from_str(trimmed, "%Y-%m-%d %H:%M:%S %z") {
        return Ok(dt.timestamp());
    }

    // Fallback: treat a naive string (no offset) as UTC
    let naive = chrono::NaiveDateTime::parse_from_str(trimmed, "%Y-%m-%d %H:%M:%S")?;
    Ok(DateTime::<Utc>::from_utc(naive, Utc).timestamp())
}



