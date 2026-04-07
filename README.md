# Masstin

<div align="center">
  <img src="resources/masstin_logo.png" alt="Masstin Logo" width="600"/>
  <br><br>
  <strong>Lateral movement tracker for anything!</strong>
  <br><br>

  [![License: GPL v3](https://img.shields.io/badge/License-GPLv3-blue.svg)](https://www.gnu.org/licenses/gpl-3.0)
  [![Rust](https://img.shields.io/badge/Rust-000000?logo=rust&logoColor=white)](https://www.rust-lang.org/)
  [![Platform](https://img.shields.io/badge/Platform-Windows%20%7C%20Linux-lightgrey)]()

</div>

---

**Masstin** is a high-speed DFIR tool written in Rust that parses forensic artifacts and unifies lateral movement data into a single chronological timeline. It supports Windows EVTX, Linux logs, Winlogbeat JSON, and Cortex XDR — all merged into one CSV, ready for analysis or Neo4j graph visualization.

Named after the [Mastín Leonés](https://en.wikipedia.org/wiki/Spanish_Mastiff) — the guardian dog from the mountains of León, Spain. Like its namesake, Masstin watches over your network and tracks every movement.

> Evolved from [Sabonis](https://github.com/jupyterj0nes/sabonis) (Python), rewritten in Rust for ~90% faster performance.

## Key Features

| Feature | Description |
|---------|-------------|
| **Multi-artifact parsing** | EVTX, Linux logs, Winlogbeat JSON, Cortex XDR |
| **Unified timeline** | All sources merged into a single chronological CSV |
| **Neo4j integration** | Direct upload for graph visualization with Cypher queries |
| **Auto IP→hostname resolution** | Frequency-based resolution from the logs themselves |
| **Connection grouping** | Reduces noise by grouping repetitive connections |
| **Cross-platform** | Windows & Linux, no dependencies (static binary) |
| **Merge mode** | Combine multiple CSV outputs into one sorted timeline |

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

### Parse: Generate a lateral movement timeline

```bash
# Single directory
masstin -a parse -d /evidence/logs/ -o timeline.csv

# Multiple machines
masstin -a parse -d /machine1/logs -d /machine2/logs -o timeline.csv --overwrite

# Individual EVTX files
masstin -a parse -f Security.evtx -f System.evtx -o timeline.csv

# Time filtering
masstin -a parse -d /evidence/ -o timeline.csv \
  --start-time "2024-08-12 00:00:00" \
  --end-time "2024-08-14 00:00:00"
```

### Load: Visualize in Neo4j

```bash
masstin -a load -f timeline.csv --database localhost:7687 --user neo4j
```

### Merge: Combine multiple timelines

```bash
masstin -a merge -f timeline1.csv -f timeline2.csv -o merged.csv
```

### Parse Linux logs

```bash
masstin -a parse-linux -d /evidence/var/log/ -o linux-timeline.csv
```

### Parse Winlogbeat JSON

```bash
masstin -a parser-elastic -d /evidence/winlogbeat/ -o elastic-timeline.csv
```

### Parse Cortex XDR

```bash
# Network data
masstin -a parse-cortex --cortex-url api-xxxx.xdr.xx.paloaltonetworks.com \
  --start-time "2024-08-12 00:00:00" --end-time "2024-08-14 00:00:00" \
  -o cortex-network.csv

# EVTX forensics
masstin -a parse-cortex-evtx-forensics --cortex-url api-xxxx.xdr.xx.paloaltonetworks.com \
  --start-time "2024-08-12 00:00:00" --end-time "2024-08-14 00:00:00" \
  -o cortex-evtx.csv
```

## Supported Actions

| Action | Description |
|--------|-------------|
| `parse` | Parse EVTX files/directories → CSV |
| `load` | Upload CSV to Neo4j graph database |
| `merge` | Merge multiple CSVs into one sorted timeline |
| `parser-elastic` | Parse Winlogbeat JSON logs |
| `parse-cortex` | Parse Cortex XDR network data via API |
| `parse-cortex-evtx-forensics` | Parse Cortex XDR EVTX forensics via API |
| `parse-linux` | Parse Linux logs and accounting entries |

## CSV Output Format

```
time_created,dst_computer,event_id,subject_user_name,subject_domain_name,target_user_name,target_domain_name,logon_type,src_computer,src_ip,log_filename
```

Events from all sources are merged and sorted chronologically. This means you'll see TerminalServices, SMB, Security, and other EVTX events interleaved in a single timeline — exactly what you need to reconstruct lateral movement.

## Neo4j Visualization

After loading data, use the included [Cypher queries](neo4j-resources/cypher_queries.md) to explore the graph:

```cypher
// Service accounts in a time range
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

For more Cypher queries and tips, see the [Cypher Resources](neo4j-resources/cypher_queries.md).

## Auto IP→Hostname Resolution

When loading into Neo4j, masstin automatically resolves IPs to hostnames by analyzing frequency of IP-hostname associations in the logs. This eliminates the need for external DNS lookups and ensures every node in the graph has a hostname.

## All Options

```
Options:
  -a, --action <ACTION>         parse | load | merge | parser-elastic | parse-cortex | parse-cortex-evtx-forensics | parse-linux
  -d, --directory <DIRECTORY>   Directories to process (repeatable)
  -f, --file <FILE>             Individual files to process (repeatable)
  -o, --output <OUTPUT>         Output file path
      --database <DATABASE>     Neo4j URL (e.g., localhost:7687)
  -u, --user <USER>             Neo4j user
      --cortex-url <URL>        Cortex API base URL
      --start-time <TIME>       Filter start: "YYYY-MM-DD HH:MM:SS"
      --end-time <TIME>         Filter end: "YYYY-MM-DD HH:MM:SS"
      --filter-cortex-ip <IP>   Filter by IP in Cortex queries
      --overwrite               Overwrite output file if it exists
      --stdout                  Print output to stdout only
      --debug                   Print debug information
  -h, --help                    Print help
  -V, --version                 Print version
```

## Documentation

For in-depth guides, artifact explanations, and investigation walkthroughs, visit the full documentation at **[weinvestigateanything.com](https://weinvestigateanything.com)**.

## Contributing

Contributions are welcome! Fork the repository and submit pull requests.

## License

GNU General Public License v3.0 — see [LICENSE](LICENSE) for details.

## Contact

**Toño Díaz** ([@jupyterj0nes](https://github.com/jupyterj0nes)) — [LinkedIn](https://www.linkedin.com/in/antoniodiazcastano/) — [weinvestigateanything.com](https://weinvestigateanything.com)
