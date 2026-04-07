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

**Masstin** is a high-speed DFIR tool written in Rust that parses forensic artifacts and unifies lateral movement data into a single chronological timeline. It supports Windows EVTX, Linux logs, Winlogbeat JSON, and Cortex XDR — all merged into one CSV, ready for analysis or Neo4j graph visualization.

Named after the [Mastín Leonés](https://en.wikipedia.org/wiki/Spanish_Mastiff) — the guardian dog from the mountains of León, Spain. Like its namesake, Masstin watches over your network and tracks every movement.

> Evolved from [Sabonis](https://github.com/jupyterj0nes/sabonis) (Python), rewritten in Rust for ~90% faster performance.

> **[We Investigate Anything](https://weinvestigateanything.com)** — Masstin is part of the WIA project, a DFIR knowledge base where you'll find detailed documentation for every artifact masstin parses, investigation guides, and real-world case studies — all in English and Spanish.

## Table of Contents

- [Key Features](#key-features)
- [Supported Artifacts](#supported-artifacts)
- [Quick Start](#quick-start)
- [Usage](#usage)
- [Output Format](#output-format)
- [Neo4j Visualization](#neo4j-visualization)
- [All Options](#all-options)
- [Roadmap](#roadmap)
- [Documentation](#documentation)
- [Contributing](#contributing)
- [License](#license)
- [Contact](#contact)

## Key Features

| Feature | Description |
|---------|-------------|
| **Multi-artifact parsing** | 28 Windows Event IDs + Linux logs + Winlogbeat JSON + Cortex XDR |
| **Unified timeline** | All sources merged into a single chronological CSV |
| **Compressed triage support** | Processes compressed packages from Velociraptor or Cortex XDR Offline Collector, recursively decompressing and identifying EVTX files — even archived logs with duplicate filenames |
| **Neo4j integration** | Direct upload with Cypher queries for graph-based investigation |
| **Auto IP→hostname** | Frequency-based resolution from the logs themselves |
| **Connection grouping** | Reduces noise by grouping repetitive connections between the same hosts |
| **Time filtering** | Filter by start/end time at parse level |
| **Cross-platform** | Windows, Linux & macOS — zero dependencies |
| **Merge mode** | Combine multiple CSV outputs into one sorted timeline |

## Supported Artifacts

Masstin parses **28 Windows Event IDs** across **9 EVTX sources**, plus Linux artifacts, Winlogbeat JSON, and Cortex XDR. For a full breakdown, see [ARTIFACTS.md](ARTIFACTS.md).

### Windows EVTX

| Source | Event IDs | What it tracks | Article |
|--------|-----------|---------------|---------|
| **Security.evtx** | 4624, 4625, 4634, 4647, 4648, 4768, 4769, 4770, 4771, 4776, 4778, 4779 | Logons, logoffs, Kerberos, NTLM, RDP reconnect | [Read more →](https://weinvestigateanything.com/en/artifacts/security-evtx-lateral-movement/) |
| **TerminalServices-LocalSessionManager** | 21, 22, 24, 25 | RDP session lifecycle | [Read more →](https://weinvestigateanything.com/en/artifacts/terminal-services-evtx/) |
| **TerminalServices-RDPClient** | 1024, 1102 | Outgoing RDP connections | [Read more →](https://weinvestigateanything.com/en/artifacts/terminal-services-evtx/) |
| **TerminalServices-RemoteConnectionManager** | 1149 | Incoming RDP accepted | [Read more →](https://weinvestigateanything.com/en/artifacts/terminal-services-evtx/) |
| **RdpCoreTS** | 131 | RDP transport negotiation | [Read more →](https://weinvestigateanything.com/en/artifacts/terminal-services-evtx/) |
| **SMBServer/Security** | 1009, 551 | SMB server connections and auth | [Read more →](https://weinvestigateanything.com/en/artifacts/smb-evtx-events/) |
| **SMBClient/Security** | 31001 | SMB client share access | [Read more →](https://weinvestigateanything.com/en/artifacts/smb-evtx-events/) |
| **SMBClient/Connectivity** | 30803-30808 | SMB connectivity and share events | [Read more →](https://weinvestigateanything.com/en/artifacts/smb-evtx-events/) |

### Linux

| Source | What it tracks | Article |
|--------|---------------|---------|
| `/var/log/secure`, `/var/log/messages` | SSH success, failure, connections | [Read more →](https://weinvestigateanything.com/en/artifacts/linux-forensic-artifacts/) |
| `/var/log/audit/audit.log` | Authentication via audit subsystem | [Read more →](https://weinvestigateanything.com/en/artifacts/linux-forensic-artifacts/) |
| `utmp` / `wtmp` | Active and historical login sessions | [Read more →](https://weinvestigateanything.com/en/artifacts/linux-forensic-artifacts/) |
| `btmp` | Failed login attempts | [Read more →](https://weinvestigateanything.com/en/artifacts/linux-forensic-artifacts/) |
| `lastlog` | Last login per user | [Read more →](https://weinvestigateanything.com/en/artifacts/linux-forensic-artifacts/) |

### Winlogbeat

| Source | What it tracks | Article |
|--------|---------------|---------|
| Winlogbeat JSON | All 28 Windows Event IDs in JSON format | [Read more →](https://weinvestigateanything.com/en/artifacts/winlogbeat-elastic-artifacts/) |

### Cortex XDR

| Source | What it tracks | Article |
|--------|---------------|---------|
| Cortex XDR Network | RDP (3389), SMB (445), SSH (22) via API | [Read more →](https://weinvestigateanything.com/en/artifacts/cortex-xdr-artifacts/) |
| Cortex XDR EVTX Forensics | Forensic event logs collected by forensic agents | [Read more →](https://weinvestigateanything.com/en/artifacts/cortex-xdr-artifacts/) |

## Quick Start

Download the latest binary from the [Releases page](https://github.com/jupyterj0nes/masstin/releases) — no installation needed.

Or build from source:

```bash
git clone https://github.com/jupyterj0nes/masstin.git
cd masstin
cargo build --release
# Binary at ./target/release/masstin
```

## Usage

### Parse Windows: Generate a lateral movement timeline

Parses Windows EVTX files from directories or individual files, extracting lateral movement events and merging them into a single chronological CSV. Supports compressed triage packages directly — masstin recursively decompresses and identifies all EVTX files, handling archived logs with duplicate filenames.

> **Note:** The legacy command `parse` is still supported as an alias for backwards compatibility.

```bash
# Single directory (or compressed triage package)
masstin -a parse-windows -d /evidence/logs/ -o timeline.csv

# Multiple machines
masstin -a parse-windows -d /machine1/logs -d /machine2/logs -o timeline.csv --overwrite

# Individual EVTX files
masstin -a parse-windows -f Security.evtx -f System.evtx -o timeline.csv

# Time filtering
masstin -a parse-windows -d /evidence/ -o timeline.csv \
  --start-time "2024-08-12 00:00:00" \
  --end-time "2024-08-14 00:00:00"
```

### Parse Linux logs

Parses Linux system logs and accounting entries (`secure`, `messages`, `audit.log`, `utmp`, `wtmp`, `btmp`, `lastlog`) to extract SSH sessions and authentication events.

```bash
masstin -a parse-linux -d /evidence/var/log/ -o linux-timeline.csv
```

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

Merges multiple CSV files into a single time-sorted timeline. Useful when artifacts were parsed from different sources or at different times.

```bash
masstin -a merge -f timeline1.csv -f timeline2.csv -o merged.csv
```

### Load: Visualize in Neo4j

Uploads a previously generated CSV into a Neo4j graph database. Automatically resolves IPs to hostnames using frequency analysis, and groups repetitive connections to reduce noise.

```bash
masstin -a load -f timeline.csv --database localhost:7687 --user neo4j
```

## Output Format

All actions produce a unified CSV:

| Column | Description |
|--------|-------------|
| `time_created` | Event timestamp (UTC) |
| `dst_computer` | Destination hostname |
| `event_id` | Windows Event ID or equivalent |
| `subject_user_name` | Source user account |
| `subject_domain_name` | Source domain |
| `target_user_name` | Target user account |
| `target_domain_name` | Target domain |
| `logon_type` | 3 (Network/SMB), 10 (RDP), SSH |
| `src_computer` | Source hostname |
| `src_ip` | Source IP address |
| `log_filename` | Original log file |

## Neo4j Visualization

After loading data, use the included [Cypher queries](neo4j-resources/cypher_queries.md) to explore the graph:

```cypher
MATCH (h1:host)-[r]->(h2:host)
WHERE datetime(r.time) >= datetime("2024-08-12T00:00:00Z")
  AND datetime(r.time) <= datetime("2024-08-13T20:00:00Z")
  AND r.target_user_name STARTS WITH 'SVC'
RETURN h1, r, h2
ORDER BY datetime(r.time)
```

<div align="center">
  <img src="neo4j-resources/neo4j_output1.png" alt="Neo4j lateral movement graph"/>
</div>

For more Cypher queries, see the [Cypher Resources](neo4j-resources/cypher_queries.md).

## All Options

| Option | Description |
|--------|-------------|
| `-a, --action` | `parse-windows` \| `parse-linux` \| `parser-elastic` \| `parse-cortex` \| `parse-cortex-evtx-forensics` \| `merge` \| `load` |
| `-d, --directory` | Directories to process (repeatable) |
| `-f, --file` | Individual files to process (repeatable) |
| `-o, --output` | Output file path |
| `--database` | Neo4j URL (e.g., `localhost:7687`) |
| `-u, --user` | Neo4j user |
| `--cortex-url` | Cortex API base URL |
| `--start-time` | Filter start: `"YYYY-MM-DD HH:MM:SS"` |
| `--end-time` | Filter end: `"YYYY-MM-DD HH:MM:SS"` |
| `--filter-cortex-ip` | Filter by IP in Cortex queries |
| `--overwrite` | Overwrite output file if it exists |
| `--stdout` | Print output to stdout only |
| `--debug` | Print debug information |

## Roadmap

- [ ] **Event reconstruction** — Reconstruct lateral movement events even when EVTX logs have been cleared or tampered with on the system

## Documentation - We Investigate Anything

Masstin's full documentation lives at **[We Investigate Anything](https://weinvestigateanything.com)** (WIA), a bilingual DFIR knowledge base (English/Spanish). There you'll find:

- [Masstin main page](https://weinvestigateanything.com/en/tools/masstin-lateral-movement-rust/) — complete tool guide
- [Security.evtx events](https://weinvestigateanything.com/en/artifacts/security-evtx-lateral-movement/) — 12 Event IDs explained
- [Terminal Services events](https://weinvestigateanything.com/en/artifacts/terminal-services-evtx/) — RDP session lifecycle
- [SMB events](https://weinvestigateanything.com/en/artifacts/smb-evtx-events/) — Server and client artifacts
- [Linux forensic artifacts](https://weinvestigateanything.com/en/artifacts/linux-forensic-artifacts/) — SSH, utmp, wtmp, btmp
- [Winlogbeat artifacts](https://weinvestigateanything.com/en/artifacts/winlogbeat-elastic-artifacts/) — JSON log parsing
- [Cortex XDR artifacts](https://weinvestigateanything.com/en/artifacts/cortex-xdr-artifacts/) — Network and forensic agent modes

## Contributing

Contributions are welcome! Fork the repository and submit pull requests.

## License

GNU Affero General Public License v3.0 — see [LICENSE](LICENSE) for details.

## Contact

**Toño Díaz** ([@jupyterj0nes](https://github.com/jupyterj0nes)) · [LinkedIn](https://www.linkedin.com/in/antoniodiazcastano/) · [weinvestigateanything.com](https://weinvestigateanything.com)
