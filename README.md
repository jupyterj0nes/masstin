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

| Feature | Description | Details |
|---------|-------------|---------|
| **Unified cross-OS image parsing** | **NEW:** Single `parse-image` command auto-detects OS per partition — NTFS partitions get Windows parsing (EVTX + UAL + VSS), ext4 partitions get Linux parsing (auth.log, wtmp, etc.) — all merged into one timeline. Point `-d` at a folder with mixed Windows and Linux images and get a single chronological CSV. Zero manual steps, zero mounting. | [Forensic images](https://weinvestigateanything.com/en/tools/masstin-vss-recovery/) |
| **Bulk evidence processing** | Point `-d` at an evidence folder and masstin recursively finds all E01/VMDK/dd images, auto-detects OS, extracts all forensic artifacts from live + VSS, and generates a single unified timeline. Per-image artifact grouping in the summary shows exactly which image produced which events. One command, entire incident. | [Forensic images](https://weinvestigateanything.com/en/tools/masstin-vss-recovery/) |
| **BitLocker detection** | Automatically detects BitLocker-encrypted partitions by reading the `-FVE-FS-` signature at VBR offset 3. Warns the analyst with the exact partition offset and skips encrypted volumes — no wasted time on unreadable data. | [Forensic images](https://weinvestigateanything.com/en/tools/masstin-vss-recovery/) |
| **streamOptimized VMDK** | Full support for streamOptimized VMDKs (compressed grains with zlib) commonly found in OVA exports, cloud templates and vSphere backups. Also handles incomplete SFTP uploads via `.filepart` fallback for flat VMDKs. | [Forensic images](https://weinvestigateanything.com/en/tools/masstin-vss-recovery/) |
| **VSS snapshot recovery** | Detect and extract EVTX from Volume Shadow Copies — recover event logs deleted by attackers. Uses [vshadow-rs](https://github.com/jupyterj0nes/vshadow-rs) | [VSS recovery](https://weinvestigateanything.com/en/tools/masstin-vss-recovery/) |
| **Mounted volume support** | Point `-d D:` at a mounted volume or use `--all-volumes` to scan every NTFS disk — live EVTX + VSS recovery without imaging first | |
| **UAL parsing** | Auto-detect and parse User Access Logging (SUM/UAL) ESE databases — 3-year server logon history surviving event log clearing | [UAL](https://weinvestigateanything.com/en/tools/masstin-ual/) |
| **MountPoints2 registry** | Extract NTUSER.DAT from each user profile and parse MountPoints2 registry keys — reveals which user connected to which remote share (\\\\SERVER\\SHARE), with timestamps. Survives event log clearing. Supports dirty hives with transaction log recovery (.LOG1/.LOG2). | [MountPoints2](https://weinvestigateanything.com/en/artifacts/mountpoints2-lateral-movement/) |
| **EVTX carving** | `carve-image` scans raw disk data for EVTX chunks (`ElfChnk`) in unallocated space — recovers lateral movement events even after logs AND VSS are deleted. Implements **Tier 1** (full 64 KB chunks) and **Tier 2** (orphan record detection); **Tier 3** (template matching for partially overwritten records) is planned. Builds synthetic EVTX files grouped by provider and parses them through the full pipeline. Hardened against upstream `evtx` crate bugs (infinite loops, multi-GB OOMs) via thread isolation + `alloc_error_hook`. Corrupted chunks can be skipped with `--skip-offsets`. | [EVTX carving](https://weinvestigateanything.com/en/tools/evtx-carving-unallocated/) |
| **Multi-artifact parsing** | 32+ Windows Event IDs from 11 EVTX sources + Scheduled Tasks XML + MountPoints2 registry + Linux logs + Winlogbeat JSON + Cortex XDR | [Artifacts](#supported-artifacts) |
| **Custom parsers (YAML)** | `parse-custom` action parses arbitrary VPN / firewall / proxy logs via YAML rule files with 3 extractor types (csv, regex, keyvalue) and nested sub-extract. Ships with 8 researched rules and 31 sub-parsers out of the box: Palo Alto GlobalProtect (5), Palo Alto TRAFFIC with User-ID filter (2), Cisco AnyConnect (4), Cisco ASA (6), Fortinet SSL VPN (3), Fortinet FortiGate (4), OpenVPN (4), Squid proxy (3). Every rule is backed by vendor official documentation — see [`rules/README.md#references`](rules/README.md#references). Full schema spec in [`docs/custom-parsers.md`](docs/custom-parsers.md). | [Custom parsers](https://weinvestigateanything.com/en/tools/masstin-custom-parsers/) |

> **Build note.** Core masstin builds on **stable Rust** with a plain `cargo build --release` — the default configuration does not require nightly. The EVTX carving path ships with an optional OOM-recovery hook (`nightly-oom-hook` Cargo feature) that uses `std::alloc::set_alloc_error_hook`, which is currently nightly-only. The official **pre-built release binaries** on the [Releases page](https://github.com/jupyterj0nes/masstin/releases) are compiled on nightly with this feature enabled, so end users downloading those binaries get the full OOM protection automatically — no Rust toolchain required at runtime. Contributors building from source on stable get a fully functional masstin; the OOM hook becomes a no-op stub, which only affects the 1% of forensic images with pathological BinXML corruption in carved chunks.
| **Event classification** | Every event classified as `SUCCESSFUL_LOGON`, `FAILED_LOGON`, `LOGOFF` or `CONNECT` with human-readable failure reasons | [CSV format](https://weinvestigateanything.com/en/tools/masstin-csv-format/) |
| **Unified timeline** | All sources merged into a single chronological CSV with 14 standardized columns | [CSV format](https://weinvestigateanything.com/en/tools/masstin-csv-format/) |
| **Cross-platform timeline** | Windows EVTX + Linux SSH + EDR data in one timeline — `parse-image` auto-merges across OS boundaries, or use `merge` for manual combination | |
| **Compressed triage support** | Recursive ZIP extraction with auto-detection of forensic passwords | |
| **Graph visualization** | Direct upload to [Neo4j](https://weinvestigateanything.com/en/tools/neo4j-cypher-visualization/) or [Memgraph](https://weinvestigateanything.com/en/tools/memgraph-visualization/) with connection grouping and IP-to-hostname resolution | |
| **Temporal path reconstruction** | Cypher query to find the chronologically coherent attacker route between two nodes | [Neo4j](https://weinvestigateanything.com/en/tools/neo4j-cypher-visualization/) |
| **Session correlation** | `logon_id` field for matching logon/logoff to determine session duration | [CSV format](https://weinvestigateanything.com/en/tools/masstin-csv-format/) |
| **Linux smart inference** | Auto-detects hostname, infers year from `dpkg.log`, supports Debian and RHEL, RFC3164 and RFC5424 | [Linux artifacts](https://weinvestigateanything.com/en/artifacts/linux-forensic-artifacts/) |
| **Silent mode** | `--silent` flag for Velociraptor, SOAR and automation integration | |
| **Cross-platform** | Windows, Linux & macOS — single binary | |

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
- **ext4 partitions** → Linux parsing: auth.log, secure, messages, audit.log, wtmp, btmp, lastlog

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
| `-a, --action` | `parse-windows` \| `parse-linux` \| `parse-image` \| `parse-massive` \| `carve-image` \| `parser-elastic` \| `parse-cortex` \| `parse-cortex-evtx-forensics` \| `merge` \| `load-neo4j` \| `load-memgraph` |
| `-d, --directory` | Directories to process — also accepts drive letters (`D:`) for mounted volumes (repeatable) |
| `-f, --file` | Individual files: EVTX, .mdb, E01, VMDK, dd/raw (repeatable) |
| `-o, --output` | Output file path |
| `--database` | Graph database URL (e.g., `localhost:7687`) |
| `-u, --user` | Database user (Neo4j) |
| `--cortex-url` | Cortex XDR API base URL |
| `--start-time` | Filter start: `"YYYY-MM-DD HH:MM:SS"` |
| `--end-time` | Filter end: `"YYYY-MM-DD HH:MM:SS"` |
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
| **Security.evtx** | 4624, 4625, 4634, 4647, 4648, 4768, 4769, 4770, 4771, 4776, 4778, 4779, 5140, 5145 | Logons, logoffs, Kerberos, NTLM, RDP reconnect, share access | [Read more →](https://weinvestigateanything.com/en/artifacts/security-evtx-lateral-movement/) |
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
| `/var/log/audit/audit.log` | Authentication via audit subsystem | [Read more →](https://weinvestigateanything.com/en/artifacts/linux-forensic-artifacts/) |
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

## License

GNU Affero General Public License v3.0 — see [LICENSE](LICENSE) for details.

## Contact

**Toño Díaz** ([@jupyterj0nes](https://github.com/jupyterj0nes)) · [LinkedIn](https://www.linkedin.com/in/antoniodiazcastano/) · [weinvestigateanything.com](https://weinvestigateanything.com)
