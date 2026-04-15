# Masstin - Lateral movement tracker for anything!

<div align="center">
  <img src="resources/masstin_logo.png" alt="Masstin Logo" width="600"/>
  <br><br>
  <strong>Lateral movement tracker for anything!</strong>
  <br><br>

  [![License: AGPL v3](https://img.shields.io/badge/License-AGPLv3-blue.svg)](https://www.gnu.org/licenses/agpl-3.0)
  [![Rust](https://img.shields.io/badge/Rust-000000?logo=rust&logoColor=white)](https://www.rust-lang.org/)
  [![Platform](https://img.shields.io/badge/Platform-Windows%20%7C%20Linux%20%7C%20macOS-lightgrey)]()

</div>

---

**Masstin** is a high-speed DFIR tool written in Rust that parses forensic artifacts and unifies lateral movement data into a single chronological timeline. It supports Windows EVTX, Linux logs, Winlogbeat JSON, and EDR APIs — all merged into one CSV, ready for analysis or graph database visualization (Neo4j, Memgraph).

Named after the [Mastín Leonés](https://en.wikipedia.org/wiki/Spanish_Mastiff) — the guardian dog from the mountains of León, Spain. Like its namesake, Masstin watches over your network and tracks every movement.

> Evolved from [Sabonis](https://github.com/jupyterj0nes/sabonis) (Python), rewritten in Rust for ~90% faster performance.

> **[We Investigate Anything](https://weinvestigateanything.com)** — Masstin is part of the WIA project, a DFIR knowledge base where you'll find detailed documentation for every artifact masstin parses, investigation guides, and real-world case studies — all in English and Spanish.

<div align="center">
  <img src="memgraph-resources/memgraph_temporal_path.png" alt="Temporal path reconstruction — attacker's chronologically-valid route through the network, rendered in Memgraph"/>
  <br>
  <em>Temporal path reconstruction — the attacker's chronologically-valid route between two hosts, rendered from a masstin timeline in Memgraph. Each hop is validated as happening strictly after the previous one.</em>
</div>

## Table of Contents

- [Key Features](#key-features)
- [Install](#install)
- [Usage](#usage)
- [Output Format](#output-format)
- [Graph Visualization](#graph-visualization-neo4j--memgraph)
- [All Options](#all-options)
- [Supported Artifacts](#supported-artifacts)
- [Documentation](#documentation)
- [Roadmap](#roadmap)
- [License](#license)
- [Contact](#contact)

## Key Features

### Core capabilities

| Feature | Description | Details |
|---------|-------------|---------|
| **Unified cross-OS image parsing** | Single `parse-image` command auto-detects OS per partition — NTFS partitions get Windows parsing (EVTX + UAL + VSS + registry), ext4 partitions get Linux parsing (auth.log, wtmp, secure, audit, **systemd-journald binary logs**) — all merged into one chronological timeline. Zero manual mounting. | [Forensic images](https://weinvestigateanything.com/en/tools/masstin-vss-recovery/) |
| **Bulk evidence processing** | Point `-d` at an evidence folder and masstin recursively walks it, finds every E01/VMDK/dd image, auto-detects OS, extracts all artifacts from live + VSS, and produces a single unified timeline. Per-image artifact grouping in the summary tells you exactly which image produced which events. One command, entire incident. | [Forensic images](https://weinvestigateanything.com/en/tools/masstin-vss-recovery/) |
| **Unified 14-column timeline** | All sources merged into a single chronological CSV with a canonical 14-column schema. Every event classified as `SUCCESSFUL_LOGON`, `FAILED_LOGON`, `LOGOFF` or `CONNECT` with human-readable failure reasons. `logon_id` carried through for session correlation. | [CSV format](https://weinvestigateanything.com/en/tools/masstin-csv-format/) |
| **Custom parsers (YAML)** | `parse-custom` parses arbitrary VPN / firewall / proxy logs via YAML rule files with three extractor types (csv, regex, keyvalue) and nested sub-extract with `strip_before` preprocessing. Ships with **8 researched rules / 31 sub-parsers** out of the box: Palo Alto GlobalProtect, Palo Alto TRAFFIC (with User-ID filter), Cisco AnyConnect, Cisco ASA, Fortinet SSL VPN, FortiGate, OpenVPN, Squid. Every rule backed by vendor documentation — see [`rules/README.md#references`](rules/README.md#references). Full schema in [`docs/custom-parsers.md`](docs/custom-parsers.md). | [Custom parsers](https://weinvestigateanything.com/en/tools/masstin-custom-parsers/) |
| **Noise filtering** | Four opt-in flags to cut output down to signal only: `--ignore-local` drops records with no usable source (loopback IPs, LOCAL markers, service/interactive logons without src, MSTSC/default_value placeholders); `--exclude-users`, `--exclude-hosts`, `--exclude-ips` accept comma-separated lists, glob wildcards (`svc_*`, `*$`) and `@file.txt` imports; `--exclude-ips` also accepts CIDR ranges (`10.0.0.0/8`). Combine with `--dry-run` for a pre-flight stats report showing exactly what would be filtered. | [Noise filtering](https://weinvestigateanything.com/en/tools/masstin-noise-filtering/) |
| **Triage-aware discovery** | When the directory walker hits a ZIP, masstin lists its top-level entries and matches against three known triage tool layouts: **KAPE** (`_kape.cli` / `Console/KAPE.log` / `<host>/C/Windows/System32/winevt/Logs/`), **Velociraptor Offline Collector** (`client_info.json` + `collection_context.json` / `uploads.json`), and **Cortex XDR Offline Collector** (`output/cortex-xdr-payload.log`). Detected packages surface as `=> Triage found: <type> [host: ...]` lines in phase 1 with hostname extracted from the ZIP filename when possible. | [Triage detection](https://weinvestigateanything.com/en/tools/masstin-triage-detection/) |
| **Per-source breakdown** | The phase-2 summary groups every parsed artifact by its source — forensic image, triage zip, plain archive, or loose folder — instead of by its leaf directory name. Each group shows the total event count plus the per-EVTX list underneath. Lets the analyst tell at a glance how many events came from `HRServer.e01` vs from a Cortex XDR triage of `WIN-DC01` vs from a folder of loose EVTX dropped in `D:\evidence\`. | [Per-source breakdown](https://weinvestigateanything.com/en/tools/masstin-triage-detection/) |
| **Graph visualization** | Direct upload to [Neo4j](https://weinvestigateanything.com/en/tools/neo4j-cypher-visualization/) or [Memgraph](https://weinvestigateanything.com/en/tools/memgraph-visualization/) with connection grouping and IP-to-hostname resolution. Ships with a Cypher query for **temporal path reconstruction** — find the chronologically coherent attacker route between any two nodes. | [Neo4j](https://weinvestigateanything.com/en/tools/neo4j-cypher-visualization/) |
| **Automation-ready** | `--silent` for Velociraptor / SOAR pipelines, single cross-platform binary for Windows / Linux / macOS, no runtime dependencies. | |

### Input format support

| Feature | Description | Details |
|---------|-------------|---------|
| **Forensic images** | E01 (ewf), VMDK (flat + sparse + streamOptimized with zlib-compressed grains), raw dd, multi-part images. Handles OVA exports, cloud templates, vSphere backups, and incomplete SFTP uploads via `.filepart` fallback. | [Forensic images](https://weinvestigateanything.com/en/tools/masstin-vss-recovery/) |
| **Mounted volumes** | Point `-d D:` at a mounted drive or pass `--all-volumes` to scan every NTFS disk on the host — live EVTX + VSS recovery without imaging first. | |
| **BitLocker detection** | Automatically detects BitLocker-encrypted partitions via the `-FVE-FS-` VBR signature, warns with the exact offset, and skips encrypted volumes instead of crashing on unreadable data. | [Forensic images](https://weinvestigateanything.com/en/tools/masstin-vss-recovery/) |
| **Compressed triage** | Recursive ZIP extraction with auto-detection of standard forensic passwords (`infected`, `kape`, etc.). | |

### Artifact coverage

| Feature | Description | Details |
|---------|-------------|---------|
| **Multi-source Windows EVTX** | 32+ Windows Event IDs across 11 EVTX providers: Security, TerminalServices-LocalSessionManager + RemoteConnectionManager, RDPClient, RDPCoreTS, SMBServer, SMBClient + Connectivity, WinRM, WMI-Activity, plus Scheduled Tasks XML. | [Artifacts](#supported-artifacts) |
| **VSS snapshot recovery** | Detect and extract EVTX from Volume Shadow Copies — recover event logs an attacker deleted from the live volume. Uses [vshadow-rs](https://github.com/jupyterj0nes/vshadow-rs). | [VSS recovery](https://weinvestigateanything.com/en/tools/masstin-vss-recovery/) |
| **EVTX carving** | `carve-image` scans raw disk data for EVTX chunks (`ElfChnk`) in unallocated space — recovers lateral movement events even after logs AND VSS are deleted. Implements **Tier 1** (full 64 KB chunks) and **Tier 2** (orphan record detection); Tier 3 (template matching) is planned. Hardened against upstream `evtx` crate bugs (infinite loops, multi-GB OOMs) via thread isolation + `alloc_error_hook`. Corrupted chunks can be skipped with `--skip-offsets`. | [EVTX carving](https://weinvestigateanything.com/en/tools/evtx-carving-unallocated/) |
| **UAL (User Access Logging)** | Auto-detect and parse SUM/UAL ESE databases — 3-year server logon history that survives Security event log clearing. Essential for Windows Server forensics where attackers wipe EVTX but forget UAL. | [UAL](https://weinvestigateanything.com/en/tools/masstin-ual/) |
| **MountPoints2 registry** | Extract NTUSER.DAT from every user profile and parse MountPoints2 registry keys — reveals which user connected to which remote share (`\\SERVER\SHARE`) with timestamps. Survives event log clearing. Supports dirty hives with transaction log recovery (`.LOG1` / `.LOG2`). | [MountPoints2](https://weinvestigateanything.com/en/artifacts/mountpoints2-lateral-movement/) |
| **Linux logs** | `auth.log`, `secure`, `wtmp`, `audit.log` with smart inference: auto-detects hostname, infers year from `dpkg.log`, supports Debian and RHEL, RFC3164 and RFC5424 formats. **Plus pure-Rust systemd-journald binary reader** that walks `/var/log/journal/<machine-id>/*.journal[~]` (compact mode + zstd) and extracts sshd `Accepted`/`Failed` events — essential on Ubuntu 22 / RHEL 8+ with SSSD + Active Directory, where `/var/log/auth.log` is nearly empty because PAM routes auth through the journal. Works on Windows analyst hosts without libsystemd. | [Linux artifacts](https://weinvestigateanything.com/en/artifacts/linux-forensic-artifacts/) |
| **EDR & SIEM feeds** | Winlogbeat JSON export (`parser-elastic`), Cortex XDR legacy export (`parse-cortex`), Cortex XDR forensics EVTX export (`parse-cortex-evtx-forensics`). All feeds normalized to the same 14-column schema so they merge cleanly with host-side artifacts. | |

> **Build note.** Core masstin builds on **stable Rust** with a plain `cargo build --release` — the default configuration does not require nightly. The EVTX carving path ships with an optional OOM-recovery hook (`nightly-oom-hook` Cargo feature) that uses `std::alloc::set_alloc_error_hook`, currently nightly-only. The **pre-built release binaries** on the [Releases page](https://github.com/jupyterj0nes/masstin/releases) are compiled on nightly with this feature enabled, so end users downloading those binaries get full OOM protection automatically — no Rust toolchain required at runtime. Contributors building from source on stable get a fully functional masstin; the OOM hook becomes a no-op stub, which only affects the 1% of forensic images with pathological BinXML corruption in carved chunks.

## Install

### Download pre-built binary (recommended)

> **No Rust toolchain needed.** Just download and run.

| Platform | Download |
|----------|----------|
| Windows | [`masstin-windows.exe`](https://github.com/jupyterj0nes/masstin/releases/latest) |
| Linux | [`masstin-linux`](https://github.com/jupyterj0nes/masstin/releases/latest) |
| macOS | [`masstin-macos`](https://github.com/jupyterj0nes/masstin/releases/latest) |

Go to [**Releases**](https://github.com/jupyterj0nes/masstin/releases) and download the binary for your platform. That's it.

### Install from crates.io

```bash
cargo install masstin
```

### Build from source

```bash
git clone https://github.com/jupyterj0nes/masstin.git
cd masstin
cargo build --release
# Binary at ./target/release/masstin
```

## Usage

### Parse Windows: Generate a lateral movement timeline

Parses Windows EVTX files and UAL databases from directories or individual files, extracting lateral movement events and merging them into a single chronological CSV. Supports compressed triage packages directly — masstin recursively decompresses and identifies all EVTX files, handling archived logs with duplicate filenames.

> **Note:** The legacy command `parse` is still supported as an alias for backwards compatibility.

```bash
# Single directory (or compressed triage package)
masstin -a parse-windows -d /evidence/logs/ -o timeline.csv

# Multiple machines
masstin -a parse-windows -d /machine1/logs -d /machine2/logs -o timeline.csv --overwrite

# Individual EVTX files
masstin -a parse-windows -f Security.evtx -f System.evtx -o timeline.csv
```

<div align="center">
  <img src="resources/masstin_cli_output.png" alt="Masstin CLI output — parse-windows"/>
</div>

### Parse Linux logs

Parses Linux system logs and accounting entries to extract SSH sessions and authentication events. Supports both Debian/Ubuntu (`auth.log`) and RHEL/CentOS (`secure`) log formats, with both RFC3164 (legacy syslog) and RFC5424 (structured) timestamp formats.

```bash
masstin -a parse-linux -d /evidence/var/log/ -o linux-timeline.csv
```

<div align="center">
  <img src="resources/masstin_cli_linux.png" alt="Masstin CLI output — parse-linux"/>
</div>

### Parse forensic images — auto-detect Windows and Linux

**One command. Any OS. Any image format.** Masstin opens forensic disk images directly, auto-detects every partition type (NTFS or ext4), and applies the right parser to each — all without mounting, external tools, or manual OS identification.

- **NTFS partitions** → Windows parsing: EVTX + UAL from live volume + VSS snapshot recovery
- **ext4 partitions** → Linux parsing: auth.log, secure, messages, audit.log, wtmp, btmp, lastlog, and `/var/log/journal/` systemd-journald binary logs

All results are merged into a **single chronological CSV**, deduplicated across sources. This means a folder full of mixed Windows and Linux images — from a ransomware incident spanning dozens of servers — becomes a single unified timeline with one command.

Supports **E01**, **dd/raw**, and **VMDK** (sparse, flat, split sparse, streamOptimized, VMFS/ESXi). Detects **BitLocker-encrypted** partitions and warns the analyst. Handles incomplete SFTP uploads (`.filepart` fallback). Pure Rust parsers for all formats. VSS recovery via [vshadow-rs](https://github.com/jupyterj0nes/vshadow-rs). [Full documentation →](https://weinvestigateanything.com/en/tools/masstin-vss-recovery/)

```bash
# Single image — auto-detects OS
masstin -a parse-image -f HRServer.e01 -o timeline.csv

# Mix Windows E01 + Linux VMDK — single merged timeline
masstin -a parse-image -f DC01.e01 -f "kali-linux.vmdk" -o timeline.csv

# Multiple images of any OS
masstin -a parse-image -f DC01.e01 -f SRV-FILE.vmdk -f ubuntu-server.e01 -o incident.csv
```

<div align="center">
  <img src="resources/masstin_cli_parse_image.png" alt="Masstin parse-image with cross-OS auto-detection"/>
</div>

### Bulk evidence processing — one command, entire incident

Point `-d` at a folder containing forensic images and masstin recursively scans for all E01, VMDK, and dd/raw files. Each image is opened, partitions are auto-detected (NTFS or ext4), artifacts are extracted with the appropriate parser, and everything is merged into a single chronological timeline. **No need to separate Windows and Linux images** — masstin handles it all.

```bash
# Scan an entire evidence folder — finds all images, any OS
masstin -a parse-image -d /evidence/all_machines/ -o full_timeline.csv

# Mix: evidence folder + individual images + mounted volume
masstin -a parse-image -d /evidence/ -f extra.e01 -d F: -o timeline.csv
```

Masstin automatically filters VMDK split extents (`-s001.vmdk`), snapshots (`-000001.vmdk`), flat data files (`-flat.vmdk`) and change tracking blocks (`-ctk.vmdk`), keeping only the base descriptor. For E01, only the first segment (`.E01`) is processed — subsequent segments (`.E02`, `.E03`) are loaded automatically.

### Parse massive — images + triage + loose artifacts in one pass

When you have a mix of forensic images **and** loose EVTX/log files in the same evidence folder, `parse-massive` processes everything together. It combines `parse-image` (for E01/VMDK/dd) with directory scanning (for extracted triage packages and individual EVTX files), producing a single unified timeline.

```bash
# Process all images AND loose artifacts from evidence directories
masstin -a parse-massive -d /evidence/ -o everything.csv
```

> **Difference from `parse-image`:** `parse-image` only processes forensic images found in `-d` directories. `parse-massive` also includes any loose EVTX and log files in those directories — useful when evidence arrives as a mix of disk images and extracted triage packages.

> **Backward compatibility:** The legacy commands `parse-image-windows` and `parse-image-linux` are still accepted as aliases for `parse-image`.

### Parse from mounted volumes (live disk / write-blocker)

Point masstin at a drive letter and it reads the raw volume directly — extracting all EVTX from the live filesystem and from every VSS snapshot found on the disk. No need to image the disk first. Ideal for triage or when working with a write-blocker.

```bash
# Single volume (requires Administrator on Windows)
masstin -a parse-image -d D: -o timeline.csv

# Multiple volumes
masstin -a parse-image -d D: -d E: -o timeline.csv

# Scan all NTFS volumes on the system
masstin -a parse-image --all-volumes -o timeline.csv
```

> **Note:** Reading raw volumes requires elevated privileges — run as Administrator on Windows or with `sudo` on Linux.

> **PowerShell users:** Do not end paths with `\` inside single quotes — PowerShell interprets `\` before the closing quote as an escape character, corrupting the command arguments. Masstin detects this and warns you, but the safest approach is to omit the trailing `\` or use double quotes: `-d "C:\evidence\image.vmdk"`.

### User Access Logging (UAL)

Masstin auto-detects UAL databases (`.mdb` files from `C:\Windows\System32\LogFiles\Sum`) and extracts server access records going back **up to 3 years** — surviving event log clearing and rollover. UAL records include username, source IP, role (File Server/SMB, Remote Access/RDP, etc.), access count, and first/last seen timestamps.

```bash
# Automatic: UAL is detected when scanning directories or forensic images
masstin -a parse-windows -d /evidence/Windows/System32/LogFiles/Sum/ -o timeline.csv

# Direct: point at individual .mdb files
masstin -a parse-windows -f Current.mdb -f SystemIdentity.mdb -o timeline.csv

# From forensic images: UAL databases are extracted and parsed automatically
masstin -a parse-image -f DC01.e01 -o timeline.csv
```

Each UAL record generates two timeline entries (first seen + last seen). Server hostname is resolved from `SystemIdentity.mdb`. Roles are mapped to protocols: File Server → `SMB`, Remote Access → `RDP`, Web Server → `HTTP`, etc. [Full documentation →](https://weinvestigateanything.com/en/tools/masstin-ual/)

### Parse Winlogbeat JSON

Parses Winlogbeat JSON logs forwarded to Elasticsearch. Extracts the same lateral movement data from JSON format when EVTX files are unavailable.

```bash
masstin -a parser-elastic -d /evidence/winlogbeat/ -o elastic-timeline.csv
```

### Parse Cortex XDR

Queries the Cortex XDR API directly to retrieve network connection data or EVTX forensic artifacts collected by Cortex agents.

```bash
# Network connection data
masstin -a parse-cortex --cortex-url api-xxxx.xdr.xx.paloaltonetworks.com \
  --start-time "2024-08-12 00:00:00" --end-time "2024-08-14 00:00:00" \
  -o cortex-network.csv

# EVTX forensics collected by Cortex agents
masstin -a parse-cortex-evtx-forensics --cortex-url api-xxxx.xdr.xx.paloaltonetworks.com \
  --start-time "2024-08-12 00:00:00" --end-time "2024-08-14 00:00:00" \
  -o cortex-evtx.csv
```

`parse-cortex-evtx-forensics` queries the Cortex XDR `forensics_event_log` dataset —
the backing store for Cortex's forensic triage feature, where the XDR forensic
agent collects Windows Event Logs from endpoints on demand. The same dataset also
receives logs uploaded by the Cortex XDR offline collector, so triage packages
gathered from air-gapped or unreachable hosts and pushed into the tenant are
queried through the exact same path. masstin mirrors the event IDs and extraction
logic of `parse-windows`, so output from this action merges cleanly with host-side
artifacts.

### Custom parsers (parse-custom): VPN, firewall and proxy logs via YAML rules

For any log format masstin doesn't natively support (Palo Alto GlobalProtect, Cisco AnyConnect, Fortinet SSL VPN, OpenVPN, Squid, etc.), the `parse-custom` action reads YAML rule files that describe how to turn each line into a masstin `LogData` record. The repo ships with a library of 8 researched rules in [`rules/`](rules/) that you can use out of the box.

```bash
# Run a single rule against a log file
masstin -a parse-custom --rules rules/vpn/palo-alto-globalprotect.yaml -f vpn.log -o timeline.csv

# Run the ENTIRE library — every log file is tried against every rule
masstin -a parse-custom --rules rules/ -f vpn.log -f firewall.log -f proxy.log -o timeline.csv

# Dry-run: show first matches + rejected samples, no CSV written
masstin -a parse-custom --rules rules/vpn/palo-alto-globalprotect.yaml -f vpn.log --dry-run

# Debug: preserve rejected lines sample alongside the output
masstin -a parse-custom --rules rules/ -f vpn.log -o timeline.csv --debug
```

The library currently covers:

| Rule | Parsers | Format |
|------|---------|--------|
| `vpn/palo-alto-globalprotect.yaml` | 5 | Palo Alto SYSTEM log subtype=globalprotect (legacy CSV syslog) |
| `vpn/cisco-anyconnect.yaml` | 4 | Cisco ASA `%ASA-6-113039/722022/722023` + `%ASA-4-113019` |
| `vpn/fortinet-ssl-vpn.yaml` | 3 | FortiGate `type=event subtype=vpn` (tunnel-up/down/ssl-login-fail) |
| `vpn/openvpn.yaml` | 4 | OpenVPN free-form syslog (Peer Connection / AUTH_FAILED / SIGTERM) |
| `firewall/palo-alto-traffic.yaml` | 2 | PAN-OS TRAFFIC log CSV — authenticated sessions (User-ID) only |
| `firewall/cisco-asa.yaml` | 6 | ASA `113004/113005/605004/605005/716001/716002` |
| `firewall/fortinet-fortigate.yaml` | 4 | FortiGate `subtype=system\|user` admin login, user auth |
| `proxy/squid.yaml` | 3 | Squid access.log CONNECT tunnel, HTTP, TCP_DENIED |

Every rule is researched against vendor official documentation and validated against realistic sample log lines committed under each category's `samples/` directory. See [`rules/README.md`](rules/README.md) for the full references table and [`docs/custom-parsers.md`](docs/custom-parsers.md) for the schema specification.

### Noise filtering: `--ignore-local` and `--exclude-*`

Real forensic cases often generate CSVs with 50%+ of rows that carry no useful lateral movement signal — service logons from LOCAL SYSTEM, RDP failures where the source IP was never captured, brute force attempts from noisy internal jumpboxes, and so on. Masstin ships with four opt-in flags that let you cut the output down to just the records that matter. All four are off by default, so existing workflows are not affected.

```bash
# Drop records with no usable source (loopback, service/interactive logons
# without src, LOCAL markers, MSTSC/default_value placeholders)
masstin -a parse-image -d /evidence/ -o timeline.csv --ignore-local

# Exclude known noisy service accounts and machine accounts
masstin -a parse-image -d /evidence/ -o timeline.csv --ignore-local \
    --exclude-users 'svc_*,*$,@corpsvc.txt'

# Exclude known jumpbox hostnames
masstin -a parse-image -d /evidence/ -o timeline.csv --ignore-local \
    --exclude-hosts 'JUMP01,JUMP02,*-MON,@jumpboxes.txt'

# Exclude internal subnets via CIDR
masstin -a parse-image -d /evidence/ -o timeline.csv --ignore-local \
    --exclude-ips '10.0.0.0/8,172.16.0.0/12,fe80::/10'

# Pre-flight: --dry-run with any filter shows a stats breakdown without
# writing the CSV — validate the filter composition before committing
masstin -a parse-image -d /evidence/ -o timeline.csv --ignore-local --dry-run

# Re-filter an existing CSV via merge (no re-parsing of images)
masstin -a merge -f old-timeline.csv --ignore-local --exclude-users @svc.txt \
    -o filtered.csv
```

**Filter rules**

| Flag | Drops records where... | Applies to |
|---|---|---|
| `--ignore-local` | Neither src_ip nor src_computer carries a useful value. IP useful = valid, non-loopback, non-link-local. Computer useful = non-empty, non-`-`, non-`LOCAL`, non-`MSTSC`, non-`default_value`, non-self-reference. | All parser actions |
| `--exclude-users LIST` | `subject_user_name` OR `target_user_name` matches any glob in the list (case-insensitive). | All parser actions + `merge` |
| `--exclude-hosts LIST` | `dst_computer` OR `src_computer` matches any glob. | All parser actions + `merge` |
| `--exclude-ips LIST` | `src_ip` matches any individual IP or CIDR range in the list. | All parser actions + `merge` |

**List syntax** (same for all three `--exclude-*` flags):

- **Inline CSV:** `svc_backup,svc_monitor,svc_sql`
- **File import:** `@users.txt` — one entry per line, `#` for comments
- **Mix:** `svc_foo,@bigfile.txt,admin*`
- **Glob wildcards:** `svc_*` (prefix), `*$` (suffix, matches machine accounts), `*admin*` (contains), `exact_match` (exact)
- **CIDR (ips only):** `10.0.0.0/24`, `fe80::/10`, individual IPs

**Filter summary**

After every run with any filter flag active, masstin prints a breakdown:

```
  🧹 Filter summary:
     Total records seen: 178,274
     Total kept:         110,070 (61.7%)
     Total filtered:     68,204 (38.3%)

     --ignore-local:     68,204 (38.3%)
        both_noise             67,703
        self_reference            134
        service_logon             306
        interactive_logon          21
        literal_LOCAL              39
        loopback_ip                 1
     --exclude-users:       523 (0.3%)   [3 patterns]
     --exclude-hosts:       245 (0.1%)   [2 patterns]
     --exclude-ips:          12 (0.0%)   [1 ranges]
```

The stats always attribute each filtered record to exactly one cause (the first filter layer that matched), so the numbers add up. Use `--dry-run` to see this report without writing the CSV.

**Safety guarantee:** records with a valid routable public `src_ip` are never filtered by `--ignore-local`, regardless of what `src_computer` contains. This preserves brute force and external attack signal even when Windows couldn't resolve a workstation name — the most common missing-metadata case in real forensics.

### Triage detection and per-source breakdown

When the directory walker encounters a ZIP archive, masstin reads its top-level entry list and runs pattern matching against three known triage tool layouts. Detected packages surface as `=> Triage found:` lines in phase 1 and drive the per-source grouping in phase 2 — so the analyst can tell at a glance which events came from which source.

**Detection signatures**

| Triage tool | Marker (any of) | Hostname extracted from |
|---|---|---|
| **KAPE** | `_kape.cli` at any level, `Console/KAPE.log`, or 5+ entries matching `<host>/C/Windows/System32/winevt/Logs/*.evtx` | Filename pattern `<host>_<digits>...zip` (only when the shape is unambiguous; KAPE has no enforced filename) |
| **Velociraptor Offline Collector** | Top-level `client_info.json` + (`collection_context.json` OR `uploads.json`); encrypted variant uses `metadata.json` + `data.zip` | Filename pattern `Collection-<host>-<YYYY-MM-DD>T...Z.zip` |
| **Cortex XDR Offline Collector** | Any entry ending in `cortex-xdr-payload.log` (this filename is unique to the XDR collector) | Filename pattern `offline_collector_output_<host>_<YYYY-MM-DD>_<HH-MM-SS>.zip` |

**Phase 1 output** (folder containing 2 triages plus a forensic image with NTUSER.DAT hives). Notice that every counter — triages, EVTX inside compressed archives, MountPoints2 from registry, Scheduled Tasks from XML — appears as `=>` lines INSIDE the same `[1/3]` block, not scattered before/after the phase header:

```
[1/3] Searching for artifacts...
        => Triage found: Velociraptor Offline Collector [host: WIN-DC01]
           source: K:/CEN26-1164N-B/SFTP/triages/Collection-WIN-DC01-2026-04-13T15_30_00Z.zip
           entries inside: 247 (EVTX or other matched files)
        => Triage found: Cortex XDR Offline Collector [host: TESTHOST01]
           source: K:/CEN26-1164N-B/SFTP/triages/offline_collector_output_TESTHOST01_2026-04-13_15-30-00.zip
           entries inside: 173 (EVTX or other matched files)
        420 EVTX artifacts found inside 2 of 2 compressed archives
        => 432 EVTX artifacts found total
        => 12 MountPoints2 remote share events found
        => 13 remote Scheduled Task events found
```

The `source:` line under each triage shows the **full path** to the zip — critical because real cases often have duplicate copies of the same host's triage in different folders (e.g. one in `SFTP/...` and another in `To-Unit42/...`). Showing only the filename would make them look identical even though they're physically different files.

**Phase 2 output** — every artifact is grouped by SOURCE (image, triage, archive, or loose folder), each group showing the total event count plus the per-EVTX list. **VSS-recovered events are tagged inline** so the analyst can tell at a glance which logs came from a shadow copy vs which came from the live partition:

```
[+] Lateral movement events grouped by source (4 sources):

        => [IMAGE]  HRServer_Disk0.e01  (4521 events total)
           - Security.evtx (3220)
           - Microsoft-Windows-TerminalServices-LocalSessionManager%4Operational.evtx (134)
           - Security.evtx (1095)  [VSS]
           - Microsoft-Windows-TerminalServices-LocalSessionManager%4Operational.evtx (72)  [VSS]

        => [TRIAGE: Cortex XDR]  triages/offline_collector_output_TESTHOST01_2026-04-13_15-30-00.zip  [host: TESTHOST01]  (834 events total)
           - Security.evtx (612)
           - Microsoft-Windows-WinRM%4Operational.evtx (89)
           - Microsoft-Windows-TerminalServices-LocalSessionManager%4Operational.evtx (133)

        => [TRIAGE: Velociraptor]  triages/Collection-WIN-DC01-2026-04-13T15_30_00Z.zip  [host: WIN-DC01]  (4521 events total)
           - Security.evtx (4380)
           - Microsoft-Windows-WinRM%4Operational.evtx (141)

        => [FOLDER]  D:/evidence/loose/extracted_evtx  (131 events total)
           - Security.evtx (120)
           - Microsoft-Windows-TerminalServices-LocalSessionManager%4Operational.evtx (11)
```

**VSS tagging** is automatic — the helper detects `partition_<N>_vss_<M>/` paths in the temp extraction tree and labels matching entries with a `[VSS]` suffix (or `[VSS-0]`, `[VSS-1]` when multiple snapshots from the same image coexist, so each one stays visually distinct). Live entries carry no annotation. Within each source group, items are sorted **live-first then by VSS index**, so the analyst reads "what the system has now" at the top and "what masstin recovered from snapshots" underneath as a clearly demarcated bonus section. This is exactly the forensic story masstin's VSS recovery feature is supposed to tell.

**Triage source labels** include the **immediate parent directory** of the zip (`triages/<filename>` above) so two physical copies of the same host's triage living in different folders (e.g. `SFTP/host.zip` vs `To-Unit42/host.zip`) appear as DIFFERENT source groups instead of collapsing into one bucket with duplicated entries inside.

**Source tags** are ASCII only — no emoji — so they render correctly in conhost legacy on Windows Server 2016/2019, RDP sessions, mosh/tmux, and any analyst environment regardless of fonts or terminal capabilities. Each tag is colour-coded for visual distinction:

- `[IMAGE]` — cyan — forensic image extract (works for E01, VMDK, dd, all formats)
- `[TRIAGE: <type>]` — yellow — detected triage package, with hostname and parent-directory hint
- `[ARCHIVE]` — white — ZIP that doesn't match any known triage layout
- `[FOLDER]` — dim — loose artifacts in a regular directory, identified by their full parent path (not just the leaf name)
- `[VSS]` / `[VSS-N]` suffix — yellow — appended to individual EVTX entries within an `[IMAGE]` group when they were recovered from a Volume Shadow Copy

This applies to **every parser action** that walks directories: `parse-windows`, `parse-image`, `parse-massive`, `parse-linux`. The same source labels show up regardless of which action you ran, so the breakdown format is consistent across the whole tool.

After the summary, the action prints a **load-into-graph hint** with both Memgraph and Neo4j commands ready to copy-paste, with the output path canonicalised to the long form (no 8.3 short names like `C00PR~1.DES` leaking into the suggestion):

```
        Load into graph (pick one):
          Memgraph:  masstin -a load-memgraph -f C:/Users/c00pr/.../timeline.csv --database localhost:7687
          Neo4j:     masstin -a load-neo4j   -f C:/Users/c00pr/.../timeline.csv --database bolt://localhost:7687 --user neo4j
```

### EVTX carving: last-resort recovery from unallocated space

When the attacker cleared the logs, wiped VSS, and deleted the UAL databases, there's still one place where event data can survive: the unallocated space of the disk itself. `carve-image` scans the raw image looking for 64 KB EVTX chunks (`ElfChnk\x00` magic), validates them, groups them by provider, builds synthetic EVTX files, and feeds them through the normal masstin pipeline.

```bash
# Carve a single image
masstin -a carve-image -f server.e01 -o carved.csv

# Carve multiple images at once
masstin -a carve-image -f DC01.e01 -f SRV-FILE.vmdk -o carved.csv

# Skip known-bad offsets on a pathological E01 (corrupted EWF chunks)
masstin -a carve-image -f broken.e01 --skip-offsets 0x6478b6000 -o carved.csv

# Keep rejected synthetic EVTX files for post-mortem / upstream bug reports
masstin -a carve-image -f image.e01 -o carved.csv --debug
```

**What it implements today:**
- **Tier 1 — full chunk recovery**: complete 64 KB chunks recovered from unallocated space, parsed with full fidelity through the regular pipeline. Events are indistinguishable from live ones in the output.
- **Tier 2 — orphan record detection**: individual records outside recoverable chunks are counted and reported (header metadata only; full XML reconstruction is Tier 3).
- **Tier 3 — template matching**: planned. Will reconstruct XML from orphan records using templates harvested from Tier 1 chunks plus a common Windows template library.

**Hardened against a hostile ecosystem**: the upstream `evtx` crate was designed to parse well-formed live logs, not arbitrary corrupted 64 KB buffers from unallocated space. We found three classes of bugs during development (infinite loop on malformed BinXML, two unbounded multi-GB allocations that abort the process), reported them upstream, and shipped an in-process defense:

- Every chunk parse runs in an isolated worker thread with a timeout
- `std::alloc::set_alloc_error_hook` converts allocation aborts into catchable panics
- A validation phase walks each synthetic EVTX end-to-end before it reaches the main pipeline; files that hang, panic or OOM are rejected, the rest of the timeline proceeds unaffected
- `--skip-offsets` lets you tell masstin to jump over a 32 MB window around a problematic E01 offset on re-runs
- `--debug` preserves rejected synthetic EVTX files to `<output_dir>/masstin_rejected_evtx/` for post-mortem

Full technical breakdown: [EVTX carving article](https://weinvestigateanything.com/en/tools/evtx-carving-unallocated/).

### Merge: Combine multiple timelines

```bash
masstin -a merge -f timeline1.csv -f timeline2.csv -o merged.csv
```

### Load into graph database

```bash
# Neo4j
masstin -a load-neo4j -f timeline.csv --database localhost:7687 --user neo4j

# Memgraph
masstin -a load-memgraph -f timeline.csv --database localhost:7687
```

#### Load options

| Flag | Effect |
|------|--------|
| `--ungrouped` | Emit one edge per CSV row (`CREATE`) instead of collapsing identical `(src, user, dst, logon_type)` tuples into a single edge with a `count` property. Use it when investigating a narrow time window where individual events matter. Pair with `--start-time` / `--end-time`. |
| `--start-time "YYYY-MM-DD HH:MM:SS"` | Drop rows whose `time_created` is earlier than this. Reuses the same parser as the Cortex flags. |
| `--end-time "YYYY-MM-DD HH:MM:SS"` | Drop rows whose `time_created` is later than this. |

```bash
# Investigate every individual lateral movement event during a 30-minute window
masstin -a load-neo4j -f timeline.csv --database localhost:7687 --user neo4j \
        --ungrouped --start-time "2026-03-15 14:00:00" --end-time "2026-03-15 14:30:00"
```

#### IP ↔ hostname unification

The same physical host often appears as both an IP and a hostname depending on which event populated each row. Both loaders build an internal `ip → hostname` map and resolve them to a single graph node automatically. Events `4778` (Session Reconnected) and `4779` (Session Disconnected) get an **x1000 weight** in the frequency map because Windows always populates both fields reliably for those events, so a single 4778/4779 outweighs hundreds of conflicting normal events.

When the loader can't tie an IP to a hostname (for example an external attacker IP with no matching session), the IP stays as its own node.

### Merge graph nodes after loading

If you discover post-hoc that two `:host` nodes are the same physical machine (for example because the loader had no 4778/4779 evidence to unify them), use the `merge-*-nodes` actions to fuse them. They transfer every relationship from `--old-node` to `--new-node`, preserving relationship type and properties, and then delete the orphan node. **No APOC or MAGE plugin required** — masstin introspects the relationship types client-side and emits one transfer query per type.

```bash
# Neo4j
masstin -a merge-neo4j-nodes \
        --database bolt://localhost:7687 --user neo4j \
        --old-node "10.0.0.10" --new-node "WORKSTATION-A"

# Memgraph
masstin -a merge-memgraph-nodes \
        --database localhost:7687 \
        --old-node "10.0.0.10" --new-node "WORKSTATION-A"
```

## Output Format

All actions produce a unified CSV with 14 columns:

| Column | Description |
|--------|-------------|
| `time_created` | Event timestamp |
| `dst_computer` | Destination hostname |
| `event_type` | Event classification: `SUCCESSFUL_LOGON`, `FAILED_LOGON`, `LOGOFF`, `CONNECT` |
| `event_id` | Original Event ID (e.g., `4624`, `SSH_SUCCESS`, `SMB`, `RDP`) |
| `logon_type` | Windows logon type (e.g., `2`, `3`, `10`) |
| `target_user_name` | Target user account |
| `target_domain_name` | Target domain |
| `src_computer` | Source hostname |
| `src_ip` | Source IP address |
| `subject_user_name` | Subject user account |
| `subject_domain_name` | Subject domain |
| `logon_id` | Logon ID for session correlation |
| `detail` | Additional context: SubStatus, process name, SSH auth method, UAL role |
| `log_filename` | Source file (e.g., `HRServer.e01:vss_0:Security.evtx`) |

For the complete Event ID mapping, see [CSV Format and Event Classification](https://weinvestigateanything.com/en/tools/masstin-csv-format/).

## Graph Visualization (Neo4j / Memgraph)

Masstin supports two graph databases. Both use the Cypher query language and the same queries work on both with minor differences.

### Neo4j

| Step | Windows | Linux | macOS | Docker (all platforms) |
|------|---------|-------|-------|------------------------|
| **Install** | Download [Neo4j Desktop](https://neo4j.com/download/) and install | `sudo apt install neo4j` or [download](https://neo4j.com/download/) | `brew install neo4j` or [download](https://neo4j.com/download/) | `docker run -p 7474:7474 -p 7687:7687 -e NEO4J_AUTH=neo4j/password neo4j` |
| **Start** | Open Neo4j Desktop, create a database, click Start | `sudo systemctl start neo4j` | `neo4j start` | Runs automatically |
| **Browser** | `http://localhost:7474` | `http://localhost:7474` | `http://localhost:7474` | `http://localhost:7474` |
| **Load data** | `masstin.exe -a load-neo4j -f timeline.csv --database localhost:7687 --user neo4j` | `masstin -a load-neo4j -f timeline.csv --database localhost:7687 --user neo4j` | Same as Linux | Same as Linux |

### Memgraph

| Step | Windows | Linux | macOS | Docker (all platforms) |
|------|---------|-------|-------|------------------------|
| **Install** | Via Docker — requires WSL 2 + Docker Desktop (see below) | `sudo apt install memgraph` or [download](https://memgraph.com/download/) | Use Docker (recommended) | `docker compose` with `memgraph/memgraph-mage` + `memgraph/lab` |
| **Start** | `iwr https://windows.memgraph.com \| iex` (starts DB + Lab via docker compose) | `sudo systemctl start memgraph` | — | Runs automatically |
| **Browser** | `http://localhost:3000` (Memgraph Lab) | `http://localhost:3000` | `http://localhost:3000` | `http://localhost:3000` |
| **Load data** | `masstin.exe -a load-memgraph -f timeline.csv --database localhost:7687` | `masstin -a load-memgraph -f timeline.csv --database localhost:7687` | Same as Linux | Same as Linux |

> **Note:** Memgraph runs in-memory. Data is lost on restart unless [snapshots are configured](https://memgraph.com/docs/fundamentals/data-durability).

> **Graph style:** A ready-to-use GSS style for Memgraph Lab is available at [`memgraph-resources/style.gss`](memgraph-resources/style.gss). Copy its contents into the Graph Style editor in Memgraph Lab, click Apply, then click **Save style** with name `masstin` and enable **Default Graph Style** to apply it automatically to all future queries.
>
> <div align="center"><img src="memgraph-resources/memgraph_save_style.png" alt="Save masstin style as default in Memgraph Lab" width="600"/></div>

<details>
<summary><strong>Windows prerequisites for Memgraph (WSL 2 + Docker)</strong></summary>

On Windows, Memgraph runs inside a Docker container, and Docker Desktop requires WSL 2. The dependency chain is: **WSL 2 → Docker Desktop → Memgraph container**.

**1. Enable WSL 2** — Open PowerShell as Administrator:

```powershell
dism.exe /online /enable-feature /featurename:Microsoft-Windows-Subsystem-Linux /all /norestart
dism.exe /online /enable-feature /featurename:VirtualMachinePlatform /all /norestart
```

Restart your PC, then:

```powershell
wsl --update
wsl --set-default-version 2
wsl --install
```

**2. Install Docker Desktop** — Download from [docker.com](https://www.docker.com/products/docker-desktop/). Select "Use WSL 2 instead of Hyper-V" during installation. Restart if prompted.

**3. Install and run Memgraph:**

```powershell
iwr https://windows.memgraph.com | iex
```

This downloads a `docker-compose.yml` and starts the database (`memgraph/memgraph-mage`) and the web interface (`memgraph/lab`). Open `http://localhost:3000` — Memgraph Lab is ready.

</details>

### Querying the graph

After loading data, use Cypher queries to explore lateral movement.

**Neo4j** — filter by time range:

```cypher
MATCH (h1:host)-[r]->(h2:host)
WHERE datetime(r.time) >= datetime("2024-08-12T00:00:00Z")
  AND datetime(r.time) <= datetime("2024-08-13T00:00:00Z")
RETURN h1, r, h2
```

<div align="center">
  <img src="neo4j-resources/neo4j_output1.png" alt="Lateral movement graph in Neo4j"/>
</div>

**Memgraph** — view all lateral movement:

```cypher
MATCH (h1:host)-[r]->(h2:host)
RETURN h1, r, h2
```

<div align="center">
  <img src="memgraph-resources/memgraph_output1.png" alt="Lateral movement graph in Memgraph"/>
</div>

**Temporal path reconstruction** (from `10_99_88_77` to `SRV_BACKUP`):

```cypher
MATCH path = (start:host {name:'10_99_88_77'})-[*]->(end:host {name:'SRV_BACKUP'})
WHERE ALL(i IN range(0, size(relationships(path))-2)
  WHERE localDateTime(relationships(path)[i].time) < localDateTime(relationships(path)[i+1].time))
RETURN path
ORDER BY length(path)
LIMIT 5
```

<div align="center">
  <img src="memgraph-resources/memgraph_temporal_path.png" alt="Temporal path reconstruction in Memgraph"/>
</div>

For the full query catalog (10+ queries), see the [Cypher Resources](neo4j-resources/cypher_queries.md).

## All Options

| Option | Description |
|--------|-------------|
| `-a, --action` | `parse-windows` \| `parse-linux` \| `parse-image` \| `parse-massive` \| `carve-image` \| `parser-elastic` \| `parse-cortex` \| `parse-cortex-evtx-forensics` \| `parse-custom` \| `merge` \| `load-neo4j` \| `load-memgraph` \| `merge-neo4j-nodes` \| `merge-memgraph-nodes` |
| `-d, --directory` | Directories to process — also accepts drive letters (`D:`) for mounted volumes (repeatable) |
| `-f, --file` | Individual files: EVTX, .mdb, E01, VMDK, dd/raw (repeatable) |
| `-o, --output` | Output file path |
| `--database` | Graph database URL (e.g., `localhost:7687`) |
| `-u, --user` | Database user (Neo4j) |
| `--cortex-url` | Cortex XDR API base URL |
| `--start-time` | Filter start: `"YYYY-MM-DD HH:MM:SS"` (Cortex actions, `merge`, `load-neo4j` / `load-memgraph`) |
| `--end-time` | Filter end: `"YYYY-MM-DD HH:MM:SS"` (same scope as `--start-time`) |
| `--ungrouped` | For `load-neo4j` / `load-memgraph`: emit one edge per CSV row instead of grouping |
| `--old-node` | For `merge-neo4j-nodes` / `merge-memgraph-nodes`: name of the `:host` node to remove (its edges are transferred to `--new-node`) |
| `--new-node` | For `merge-neo4j-nodes` / `merge-memgraph-nodes`: name of the `:host` node that survives the merge |
| `--filter-cortex-ip` | Filter by IP in Cortex queries |
| `--all-volumes` | Scan all NTFS volumes on the system (parse-image, requires admin) |
| `--overwrite` | Overwrite output file if it exists |
| `--stdout` | Print output to stdout only |
| `--debug` | Print debug information |
| `--silent` | Suppress all output for automation (Velociraptor, SOAR) |

## Supported Artifacts

Masstin parses **32+ Windows Event IDs** across **11 EVTX sources**, plus Linux artifacts, UAL databases, Winlogbeat JSON, and Cortex XDR. For a full breakdown, see [ARTIFACTS.md](ARTIFACTS.md).

### Windows EVTX

| Source | Event IDs | What it tracks | Article |
|--------|-----------|---------------|---------|
| **Security.evtx** | 4624, 4625, 4634, 4647, 4648, 4768, 4769, 4770, 4771, 4776, 4778, 4779, 5140 | Logons, logoffs, Kerberos, NTLM, RDP reconnect, share access | [Read more →](https://weinvestigateanything.com/en/artifacts/security-evtx-lateral-movement/) |
| **TerminalServices-LocalSessionManager** | 21, 22, 24, 25 | RDP session lifecycle | [Read more →](https://weinvestigateanything.com/en/artifacts/terminal-services-evtx/) |
| **TerminalServices-RDPClient** | 1024, 1102 | Outgoing RDP connections | [Read more →](https://weinvestigateanything.com/en/artifacts/terminal-services-evtx/) |
| **TerminalServices-RemoteConnectionManager** | 1149 | Incoming RDP accepted | [Read more →](https://weinvestigateanything.com/en/artifacts/terminal-services-evtx/) |
| **RdpCoreTS** | 131 | RDP transport negotiation | [Read more →](https://weinvestigateanything.com/en/artifacts/terminal-services-evtx/) |
| **SMBServer/Security** | 1009, 551 | SMB server connections and auth | [Read more →](https://weinvestigateanything.com/en/artifacts/smb-evtx-events/) |
| **SMBClient/Security** | 31001 | SMB client share access | [Read more →](https://weinvestigateanything.com/en/artifacts/smb-evtx-events/) |
| **SMBClient/Connectivity** | 30803-30808 | SMB connectivity and share events | [Read more →](https://weinvestigateanything.com/en/artifacts/smb-evtx-events/) |
| **WinRM/Operational** | 6 | PowerShell Remoting session init — destination host from connection field (source system) | [Read more →](https://weinvestigateanything.com/en/artifacts/winrm-wmi-schtasks-lateral-movement/) |
| **WMI-Activity/Operational** | 5858 | Remote WMI execution — source machine from ClientMachine field (destination system) | [Read more →](https://weinvestigateanything.com/en/artifacts/winrm-wmi-schtasks-lateral-movement/) |
| **Scheduled Tasks XML** | — | Remotely registered tasks detected via Author field (MACHINE\user) | [Read more →](https://weinvestigateanything.com/en/artifacts/winrm-wmi-schtasks-lateral-movement/) |
| **MountPoints2 (NTUSER.DAT)** | — | Remote share connections from each user's registry (##SERVER#SHARE with LastWriteTime) | [Read more →](https://weinvestigateanything.com/en/artifacts/mountpoints2-lateral-movement/) |

### UAL (User Access Logging)

| Source | What it tracks | Article |
|--------|---------------|---------|
| `SystemIdentity.mdb` | Server hostname, role mappings | [Read more →](https://weinvestigateanything.com/en/tools/masstin-ual/) |
| `Current.mdb` + `{GUID}.mdb` | Username, source IP, role, access count, first/last seen (up to 3 years) | [Read more →](https://weinvestigateanything.com/en/tools/masstin-ual/) |

### Linux

| Source | What it tracks | Article |
|--------|---------------|---------|
| `/var/log/auth.log` (Debian/Ubuntu) | SSH success, failure, PAM authentication | [Read more →](https://weinvestigateanything.com/en/artifacts/linux-forensic-artifacts/) |
| `/var/log/secure` (RHEL/CentOS) | SSH success, failure, PAM authentication | [Read more →](https://weinvestigateanything.com/en/artifacts/linux-forensic-artifacts/) |
| `/var/log/messages` | SSH events via syslog | [Read more →](https://weinvestigateanything.com/en/artifacts/linux-forensic-artifacts/) |
| `/var/log/audit/audit.log` | `USER_LOGIN` / `USER_AUTH` from auditd — primary SSH signal on Ubuntu + SSSD | [Read more →](https://weinvestigateanything.com/en/artifacts/linux-forensic-artifacts/) |
| `/var/log/journal/<machine-id>/*.journal[~]` | systemd-journald binary logs — sshd `Accepted`/`Failed` events on modern SSSD / AD hosts | [Read more →](https://weinvestigateanything.com/en/artifacts/linux-forensic-artifacts/) |
| `utmp` / `wtmp` / `btmp` / `lastlog` | Login sessions, failed attempts | [Read more →](https://weinvestigateanything.com/en/artifacts/linux-forensic-artifacts/) |

### Winlogbeat & Cortex XDR

| Source | What it tracks | Article |
|--------|---------------|---------|
| Winlogbeat JSON | All Windows Event IDs in JSON format | [Read more →](https://weinvestigateanything.com/en/artifacts/winlogbeat-elastic-artifacts/) |
| Cortex XDR Network | RDP, SMB, SSH connections via API | [Read more →](https://weinvestigateanything.com/en/artifacts/cortex-xdr-artifacts/) |
| Cortex XDR EVTX Forensics | Forensic event logs from agents | [Read more →](https://weinvestigateanything.com/en/artifacts/cortex-xdr-artifacts/) |

## Documentation

Full documentation at **[We Investigate Anything](https://weinvestigateanything.com)** — bilingual DFIR knowledge base (English/Spanish).

### Tools

| Topic | Article |
|-------|---------|
| Masstin main page | [weinvestigateanything.com — masstin](https://weinvestigateanything.com/en/tools/masstin-lateral-movement-rust/) |
| CSV format and event classification | [CSV Format](https://weinvestigateanything.com/en/tools/masstin-csv-format/) |
| Forensic images and VSS recovery | [VSS Recovery](https://weinvestigateanything.com/en/tools/masstin-vss-recovery/) |
| User Access Logging (UAL) | [UAL](https://weinvestigateanything.com/en/tools/masstin-ual/) |
| vshadow-rs — pure Rust VSS parser | [vshadow-rs](https://weinvestigateanything.com/en/tools/vshadow-rs/) |
| Neo4j and Cypher guide | [Neo4j](https://weinvestigateanything.com/en/tools/neo4j-cypher-visualization/) |
| Memgraph guide | [Memgraph](https://weinvestigateanything.com/en/tools/memgraph-visualization/) |

### Artifacts

| Artifact | Article |
|----------|---------|
| Security.evtx (14 Event IDs) | [Security.evtx](https://weinvestigateanything.com/en/artifacts/security-evtx-lateral-movement/) |
| Terminal Services EVTX (RDP) | [Terminal Services](https://weinvestigateanything.com/en/artifacts/terminal-services-evtx/) |
| SMB EVTX (Server + Client) | [SMB Events](https://weinvestigateanything.com/en/artifacts/smb-evtx-events/) |
| Linux forensic artifacts | [Linux](https://weinvestigateanything.com/en/artifacts/linux-forensic-artifacts/) |
| Winlogbeat JSON | [Winlogbeat](https://weinvestigateanything.com/en/artifacts/winlogbeat-elastic-artifacts/) |
| Cortex XDR | [Cortex](https://weinvestigateanything.com/en/artifacts/cortex-xdr-artifacts/) |

## Roadmap

- [ ] VHD/VHDX image support
- [x] ~~Event reconstruction from cleared logs (EVTX record carving)~~ — **done (Tier 1 + Tier 2 detection)**
- [x] ~~MountPoints2 registry hive parsing for lateral movement traces~~ — **done**
- [x] ~~Custom parser framework for VPN/firewall/proxy logs (YAML rules)~~ — **done (v1: csv/regex/keyvalue + sub-extract + strip_before)**
- [x] ~~Initial community rule library~~ — **done (8 rules, 31 parsers: Palo Alto GP + TRAFFIC, Cisco AnyConnect + ASA, Fortinet SSL VPN + FortiGate, OpenVPN, Squid)**
- [ ] EVTX carving Tier 3: template matching for orphan records (reconstruct XML from records whose parent chunks are gone)
- [ ] Unallocated-only carving scan (`--carve-unalloc`) — currently scans the whole image
- [ ] Custom parsers v2: JSON extractor, conditional map, per-rule `--validate` command
- [ ] More community parser rules: Checkpoint, ZScaler, Cloudflare Access, Juniper, SonicWall
- [ ] **EVTX header tampering detection** — flag chunks whose record numbers, timestamps or CRCs have been edited (Event Log Edit / similar tooling)
- [x] ~~**systemd-journald binary log parsing** — pure-Rust reader for `/var/log/journal/*.journal[~]` (compact mode + zstd), essential on Ubuntu 22 / RHEL 8+ with SSSD + AD~~ — **done**
- [ ] **Linux event recovery / carving** — recover deleted entries from `auth.log`, `wtmp`, `btmp`, `journald` after rotation or attacker cleanup
- [ ] **macOS support** — `parse-mac` (live `/var/log` and unified logs) and `parse-image-mac` (HFS+/APFS forensic images), bringing Mac to feature parity with Windows and Linux
- [ ] **Official Velociraptor plugin** — package masstin so analysts can run it from a Velociraptor artifact and get a unified timeline back without leaving the platform

## License

GNU Affero General Public License v3.0 — see [LICENSE](LICENSE) for details.

## Contact

**Toño Díaz** ([@jupyterj0nes](https://github.com/jupyterj0nes)) · [LinkedIn](https://www.linkedin.com/in/antoniodiazcastano/) · [weinvestigateanything.com](https://weinvestigateanything.com)
