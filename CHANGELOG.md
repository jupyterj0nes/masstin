# Changelog

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
