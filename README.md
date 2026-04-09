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
| **Bulk image processing** | Point `-d` at an evidence folder and masstin recursively finds all E01/VMDK/dd images, extracts EVTX + UAL from live + VSS of each, and generates a single unified timeline. One command, entire incident. | |
| **Forensic image analysis** | Open E01, dd/raw, and VMDK (sparse, flat, split, VMFS/ESXi) images directly — pure Rust, no external tools, no mounting needed | [VSS recovery](https://weinvestigateanything.com/en/tools/masstin-vss-recovery/) |
| **VSS snapshot recovery** | Detect and extract EVTX from Volume Shadow Copies — recover event logs deleted by attackers. Uses [vshadow-rs](https://github.com/jupyterj0nes/vshadow-rs) | [VSS recovery](https://weinvestigateanything.com/en/tools/masstin-vss-recovery/) |
| **Mounted volume support** | Point `-d D:` at a mounted volume or use `--all-volumes` to scan every NTFS disk — live EVTX + VSS recovery without imaging first | |
| **UAL parsing** | Auto-detect and parse User Access Logging (SUM/UAL) ESE databases — 3-year server logon history surviving event log clearing | [UAL](https://weinvestigateanything.com/en/tools/masstin-ual/) |
| **Multi-artifact parsing** | 30+ Windows Event IDs from 9 sources + Linux logs + Winlogbeat JSON + Cortex XDR | [Artifacts](#supported-artifacts) |
| **Event classification** | Every event classified as `SUCCESSFUL_LOGON`, `FAILED_LOGON`, `LOGOFF` or `CONNECT` with human-readable failure reasons | [CSV format](https://weinvestigateanything.com/en/tools/masstin-csv-format/) |
| **Unified timeline** | All sources merged into a single chronological CSV with 14 standardized columns | [CSV format](https://weinvestigateanything.com/en/tools/masstin-csv-format/) |
| **Cross-platform timeline** | Windows EVTX + Linux SSH + EDR data merged with `merge` — one timeline across OS boundaries | |
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

### Parse forensic images (E01/dd/VMDK) with VSS recovery

Opens forensic disk images directly — no mounting needed. Supports **E01**, **dd/raw**, and **VMDK** (sparse, flat, split sparse, and VMFS/ESXi). Pure Rust parsers for all formats — no external tools required. Finds NTFS partitions (GPT/MBR), extracts EVTX + UAL from the live volume, detects Volume Shadow Copies using [vshadow-rs](https://github.com/jupyterj0nes/vshadow-rs), and recovers EVTX from each VSS snapshot — including events deleted by attackers. Events are deduplicated across live and VSS sources. [Full VSS documentation →](https://weinvestigateanything.com/en/tools/masstin-vss-recovery/)

```bash
# Single image
masstin -a parse-image-windows -f HRServer.e01 -o timeline.csv

# VMDK directly (split sparse, flat, monolithic, VMFS)
masstin -a parse-image-windows -f "Windows Server 2019.vmdk" -o timeline.csv

# Multiple images
masstin -a parse-image-windows -f DC01.e01 -f SRV-FILE.vmdk -f Desktop.e01 -o incident.csv
```

<div align="center">
  <img src="resources/masstin_cli_parse_image.png" alt="Masstin parse-image-windows with VSS recovery"/>
</div>

### Bulk evidence processing — one command, entire incident

Point `-d` at a folder containing forensic images and masstin recursively scans for all E01, VMDK, and dd/raw files, processing each one — extracting EVTX from live volumes and every VSS snapshot, parsing UAL databases, deduplicating, and merging everything into a single chronological timeline.

```bash
# Scan an entire evidence folder — finds all images automatically
masstin -a parse-image-windows -d /evidence/all_machines/ -o full_timeline.csv

# Mix: evidence folder + individual images + mounted volume
masstin -a parse-image-windows -d /evidence/ -f extra.e01 -d F: -o timeline.csv
```

Masstin automatically filters VMDK split extents (`-s001.vmdk`) and snapshots (`-000001.vmdk`), keeping only the base descriptor. For E01, only the first segment (`.E01`) is processed — subsequent segments (`.E02`, `.E03`) are loaded automatically.

### Parse from mounted volumes (live disk / write-blocker)

Point masstin at a drive letter and it reads the raw volume directly — extracting all EVTX from the live filesystem and from every VSS snapshot found on the disk. No need to image the disk first. Ideal for triage or when working with a write-blocker.

```bash
# Single volume (requires Administrator on Windows)
masstin -a parse-image-windows -d D: -o timeline.csv

# Multiple volumes
masstin -a parse-image-windows -d D: -d E: -o timeline.csv

# Scan all NTFS volumes on the system
masstin -a parse-image-windows --all-volumes -o timeline.csv
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
masstin -a parse-image-windows -f DC01.e01 -o timeline.csv
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
| `-a, --action` | `parse-windows` \| `parse-linux` \| `parse-image-windows` \| `parser-elastic` \| `parse-cortex` \| `parse-cortex-evtx-forensics` \| `merge` \| `load-neo4j` \| `load-memgraph` |
| `-d, --directory` | Directories to process — also accepts drive letters (`D:`) for mounted volumes (repeatable) |
| `-f, --file` | Individual files: EVTX, .mdb, E01, VMDK, dd/raw (repeatable) |
| `-o, --output` | Output file path |
| `--database` | Graph database URL (e.g., `localhost:7687`) |
| `-u, --user` | Database user (Neo4j) |
| `--cortex-url` | Cortex XDR API base URL |
| `--start-time` | Filter start: `"YYYY-MM-DD HH:MM:SS"` |
| `--end-time` | Filter end: `"YYYY-MM-DD HH:MM:SS"` |
| `--filter-cortex-ip` | Filter by IP in Cortex queries |
| `--all-volumes` | Scan all NTFS volumes on the system (parse-image-windows, requires admin) |
| `--overwrite` | Overwrite output file if it exists |
| `--stdout` | Print output to stdout only |
| `--debug` | Print debug information |
| `--silent` | Suppress all output for automation (Velociraptor, SOAR) |

## Supported Artifacts

Masstin parses **30+ Windows Event IDs** across **9 EVTX sources**, plus Linux artifacts, UAL databases, Winlogbeat JSON, and Cortex XDR. For a full breakdown, see [ARTIFACTS.md](ARTIFACTS.md).

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
- [ ] Event reconstruction from cleared logs

## License

GNU Affero General Public License v3.0 — see [LICENSE](LICENSE) for details.

## Contact

**Toño Díaz** ([@jupyterj0nes](https://github.com/jupyterj0nes)) · [LinkedIn](https://www.linkedin.com/in/antoniodiazcastano/) · [weinvestigateanything.com](https://weinvestigateanything.com)
