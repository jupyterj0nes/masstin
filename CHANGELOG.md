# Changelog

## Unreleased

- `parse-linux`: **UAC (Unix-like Artifacts Collector) triage detection**, alongside KAPE / Velociraptor / Cortex XDR. Detected by `uac.log` + `[root]/` layout or by the `uac-<host>-<os>-<timestamp>` filename; hostname from the filename, `[root]/etc/hostname`, `/etc/sysconfig/network`, `uac.log`, `/etc/hosts` or the syslog header when UAC was run against a mounted image (`unknown`).
- `parse-linux`: **tar / tar.gz / tgz archives** are now walked (streamed, selective extraction of log files only), including nested combinations (zip → tar.gz, tar.gz → tar.gz). Archives copied off the victim filesystem under `[root]/` are never recursed into.
- `parse-linux`: rotated `wtmp-YYYYMMDD` / `btmp-YYYYMMDD[.gz]` are parsed; the logrotate suffix drives the year of RFC3164 timestamps in rotated `secure` / `messages` / `auth.log` files.
- `parse-linux`: `log_filename` shows `<archive>:<path inside>` for artifacts that came out of an archive instead of a temp path; `/etc/hosts` no longer yields `localhost.localdomain` as a hostname.
- ZIP extraction streams entries to disk instead of loading the whole archive into memory.
- `parse-linux`: **RFC3164 timestamps converted from the host's local zone to UTC** (zone from `/etc/timezone`, `/etc/sysconfig/clock`, `/etc/localtime` symlink or TZif contents, or live `timedatectl`). Previously syslog lines were taken as UTC and sat hours away from wtmp / audit / journald for the same login.
- `parse-linux`: sshd regexes generalised — any `Accepted <method>`, `Failed <method>` **including `invalid user`** (previously unmatched), and `not allowed because` policy denials; method recorded in `detail`. `Failed none` probes ignored. `pam_unix(sshd:auth)` failures demoted to a fallback (false failed logons on SSSD hosts).
- `parse-linux`: wtmp/utmp/secure keep sources that are hostnames, not only IPs (`UseDNS yes` estates lost >99% of wtmp). Boot / runlevel utmp records dropped.
- `parse-linux`: **lastlog parsed** (last login per account, uid resolved via the collected `/etc/passwd`).
- `parse-linux`: journald ⟷ rsyslog duplicates removed across files; truncated archives reported with a warning.
- `parse-linux`: audit.log now keeps `USER_LOGIN` only (one record per SSH connection; `USER_AUTH` PAM/key stages were producing 3–4 rows per login and are used only as a fallback), collapses the duplicate `USER_LOGIN` pairs sshd writes per pid, resolves the `id=`/`auid=` uid of successful logins through the collected `/etc/passwd` (previously an empty user → `NO_USER` in the graph) and tags `acct="(unknown)"` failures as `audit invalid-user` in `detail`. `logon_type` is `SSH` on every Linux row.
- `load-neo4j`: **fix silent edge loss** — host nodes were merged lazily every 256 names while edge batches went out every 5000 rows; batches whose origin node did not exist yet were dropped by Cypher without an error while the summary still counted them (a 76k-row timeline came out as 21k edges). Nodes are now flushed before every edge batch and the summary reports the server-side count. Edges carry `event_type` and `event_id` so success and failure can be told apart in the graph.
- `graph-hunt` / `graph-hunt-neo4j`: findings CSV is aggregated per (detector, host, origin/user/destination pattern) with an `events` column and a first..last `time_window`, instead of one row per edge (a 9000-attempt brute force is one row, not 9000).
- `graph-hunt` / `graph-hunt-neo4j` detector rework:
  - structural detectors, the baseline and the GDS projections use **authenticated logins with a real account only**; failed / unauthenticated attempts go to the new `failed-sweep` detector. Fixes PageRank / betweenness "spikes" caused by monitoring probes.
  - new **`origin-fanout`** (one row per origin reaching 3+ never-reached destinations, scored by novelty, breadth and 60 s burst) and **`probe-then-success`** (refused named account, then within 6 h a login with a different account new for that origin).
  - **periodicity demotion** (x0.3) for (origin, account) pairs that repeat daily at a fixed time or constant rate and already existed before the cutoff.
  - **corroboration**: +0.25 per other detector on the same origin; new `origin`, `corroboration` columns.
  - community-bridge only for origins with authenticated baseline history; Louvain on a login-count-weighted projection.
  - novel-edge / community-bridge aggregate per (origin, account, destination) in Cypher (events + first..last).
  - lastlog counts as proof a relationship existed, not as frequency.
  - Browser-ready snippets on Neo4j (APOC virtual graph — no "connect result nodes" explosion).
  - coverage warning per log source (needs `log_source` on edges).
  - shared code in `graph_hunt_common` for both backends.
- `load-neo4j` / `load-memgraph`: `count` stored as an integer (was a string); edges carry `event_type`, `event_id`, `log_source`; IP nodes annotated with `resolved_name` from unanimous same-login IP/name pairs (not merged); **grouped mode keyed by source and outcome** — two origins using the same account on the same host used to collapse into one edge, and refused attempts merged with successes.
- `neo4j-resources/style.grass`: fixed syntax (missing colons — Neo4j Browser ignored the file), host name as node caption, `origen` label style.
- `parse-linux`: prints per-host log coverage (continuous since) for each source family. CSV output unchanged.
- `graph-hunt-neo4j`: works on GDS 1.x again (Neo4j 4.x installs): falls back to `gds.graph.create` / `gds.graph.create.cypher` when `gds.graph.project` is not registered.

## v1.0.0 — 2026-04-21

### First official release

This is the masstin I presented at **[ViCON](https://vicon.gal)** in Vigo on April 18, 2026. Huge thanks to the organisers for a conference with a genuinely close-knit feel and for the tremendous amount of work behind the scenes — the faces around the table at the closing dinner said the rest. Thanks too to everyone who came up after the talk, and later during dinner, to ask about the details of the tool — that was the moment I realised I had actually built something.

The last time I talked about cybersecurity in Vigo was defending my undergraduate final project in Telecommunications Engineering at UVigo, fifteen years ago. Good to be back.

¡Gracias, ViCON!

### What's in 1.0

**Windows parsing**

- `parse-windows`: EVTX from directories, files, and recursive zip trees. Dispatch by `Provider.Name`, so archived and renamed logs (`Security-YYYY-MM-DD-HH-MM-SS.evtx`, operator-renamed copies, third-party triage extracts) all parse correctly.
- `parse-image`: forensic disk images (E01, VMDK in every variant, raw/dd, img) with per-partition OS auto-detection, NTFS walker, VSS recovery, UAL, Scheduled Tasks, MountPoints2.
- `parse-massive`: everything above plus KAPE / Velociraptor / Cortex XDR triage detection and loose-artifact promotion. One command for mixed evidence piles.
- `carve-image`: Tier 1 chunk recovery + Tier 2 orphan record detection from unallocated space, hardened against the upstream `evtx` crate's pathological BinXML allocations via subprocess isolation.

**Linux parsing**

- `parse-linux`: auth.log, secure, messages, audit.log, utmp, wtmp, btmp, lastlog.
- `parse-image` on ext4: the same plus a pure-Rust systemd-journald binary log reader, for modern systems where the text logs are empty and all authentication events live in the journal.

**Third-party integrations**

- `parse-cortex` and `parse-cortex-evtx-forensics`: Cortex XDR API queries for network connections and forensic EVTX collections.
- `parser-elastic`: Winlogbeat JSON dumps exported from Elasticsearch.
- `parse-custom`: any VPN / firewall / proxy / web app log via YAML rule files. Ships with 8 pre-built rules for Palo Alto GlobalProtect, Cisco AnyConnect, Fortinet SSL-VPN, OpenVPN, Palo Alto traffic logs, Cisco ASA, Fortinet FortiGate, and Squid.

**Graph output**

- `load-neo4j` / `load-memgraph`: grouped (topology) or ungrouped (temporal path hunting) loading modes.
- `merge-neo4j-nodes` / `merge-memgraph-nodes`: vanilla Cypher node fusion, no APOC / MAGE required.

**Binaries**

Zero runtime dependencies on every platform:

- Windows x86_64
- Linux x86_64
- macOS Apple Silicon (arm64) — native
- macOS Intel (x86_64) — native

**Filtering**

`--ignore-local`, `--exclude-users`, `--exclude-hosts`, `--exclude-ips` (CIDR and `@file.txt` syntax) for cutting noise out of long timelines.

---

Full technical documentation at [weinvestigateanything.com](https://weinvestigateanything.com) — bilingual (EN + ES). Bug reports at [github.com/jupyterj0nes/masstin/issues](https://github.com/jupyterj0nes/masstin/issues).
