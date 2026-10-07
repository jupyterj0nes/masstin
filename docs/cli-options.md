| `-a, --action` | `parse-windows` | `parse-linux` | `parse-mac` |# All command-line options
| `-a, --action` | `parse-windows` | `parse-linux` | `parse-mac` |
| `-a, --action` | `parse-windows` | `parse-linux` | `parse-mac` |Every flag, grouped by the actions that use it. Back to the [README](../README.md).
| `-a, --action` | `parse-windows` | `parse-linux` | `parse-mac` |
| `-a, --action` | `parse-windows` | `parse-linux` | `parse-mac` |
| `-a, --action` | `parse-windows` | `parse-linux` | `parse-mac` || Option | Description |
| `-a, --action` | `parse-windows` | `parse-linux` | `parse-mac` ||--------|-------------|
| `-a, --action` | `parse-windows` \| `parse-linux` \| `parse-mac` \| `parse-image` \| `parse-massive` \| `carve-image` \| `parser-elastic` \| `parse-cortex` \| `parse-cortex-evtx-forensics` \| `parse-custom` \| `merge` \| `load-neo4j` \| `load-memgraph` \| `merge-neo4j-nodes` \| `merge-memgraph-nodes` \| `graph-hunt` \| `graph-hunt-neo4j` \| `graph-hunt-csv` |
| `-a, --action` | `parse-windows` | `parse-linux` | `parse-mac` || `-d, --directory` | Directories to process — also accepts drive letters (`D:`) for mounted volumes (repeatable) |
| `-a, --action` | `parse-windows` | `parse-linux` | `parse-mac` || `-f, --file` | Individual files: EVTX, .mdb, E01, VMDK, dd/raw (repeatable) |
| `-a, --action` | `parse-windows` | `parse-linux` | `parse-mac` || `-o, --output` | Output file path |
| `-a, --action` | `parse-windows` | `parse-linux` | `parse-mac` || `--database` | Graph database URL (e.g., `localhost:7687`) |
| `-a, --action` | `parse-windows` | `parse-linux` | `parse-mac` || `-u, --user` | Database user (Neo4j) |
| `-a, --action` | `parse-windows` | `parse-linux` | `parse-mac` || `--db` | Target database name on the graph server (default `neo4j` for Neo4j actions, `memgraph` for Memgraph). Useful in multi-database Neo4j 5.x/2026.x setups. |
| `-a, --action` | `parse-windows` | `parse-linux` | `parse-mac` || `--cortex-url` | Cortex XDR API base URL |
| `-a, --action` | `parse-windows` | `parse-linux` | `parse-mac` || `--start-time` | Filter start: `"YYYY-MM-DD HH:MM:SS"` (Cortex actions, `merge`, `load-neo4j` / `load-memgraph`) |
| `-a, --action` | `parse-windows` | `parse-linux` | `parse-mac` || `--end-time` | Filter end: `"YYYY-MM-DD HH:MM:SS"` (same scope as `--start-time`) |
| `-a, --action` | `parse-windows` | `parse-linux` | `parse-mac` || `--ungrouped` | For `load-neo4j` / `load-memgraph`: emit one edge per CSV row instead of grouping |
| `-a, --action` | `parse-windows` | `parse-linux` | `parse-mac` || `--old-node` | For `merge-neo4j-nodes` / `merge-memgraph-nodes`: name of the `:host` node to remove (its edges are transferred to `--new-node`) |
| `-a, --action` | `parse-windows` | `parse-linux` | `parse-mac` || `--new-node` | For `merge-neo4j-nodes` / `merge-memgraph-nodes`: name of the `:host` node that survives the merge |
| `-a, --action` | `parse-windows` | `parse-linux` | `parse-mac` || `--filter-cortex-ip` | Filter by IP in Cortex queries |
| `-a, --action` | `parse-windows` | `parse-linux` | `parse-mac` || `--admin-ports` | `parse-cortex`: widen network port list to full admin set (22, 135, 139, 445, 1433, 3306, 3389, 5900, 5985, 5986). Default is RDP/SMB/SSH + WinRM. |
| `-a, --action` | `parse-windows` | `parse-linux` | `parse-mac` || `--cortex-event-ids` | `parse-cortex-evtx-forensics`: comma-separated override of the default Windows Event ID set |
| `-a, --action` | `parse-windows` | `parse-linux` | `parse-mac` || `--cortex-min-window-secs` | Auto-pagination floor for both Cortex actions when a time window saturates the API 1M cap (default 300) |
| `-a, --action` | `parse-windows` | `parse-linux` | `parse-mac` || `--cortex-max-passes` | Hard cap on auto-pagination passes for both Cortex actions (default 200) |
| `-a, --action` | `parse-windows` | `parse-linux` | `parse-mac` || `--all-volumes` | Scan all NTFS volumes on the system (parse-image, requires admin) |
| `-a, --action` | `parse-windows` | `parse-linux` | `parse-mac` || `--overwrite` | Overwrite output file if it exists |
| `-a, --action` | `parse-windows` | `parse-linux` | `parse-mac` || `--stdout` | Print output to stdout only |
| `-a, --action` | `parse-windows` | `parse-linux` | `parse-mac` || `--debug` | Print debug information (also keeps rejected synthetic EVTX in `carve-image` and rejected lines in `parse-custom`) |
| `-a, --action` | `parse-windows` | `parse-linux` | `parse-mac` || `--silent` | Suppress all output for automation (Velociraptor, SOAR) |
| `-a, --action` | `parse-windows` | `parse-linux` | `parse-mac` || `--rules PATH` | `parse-custom`: YAML rule file or directory of rules (see [`rules/`](../rules/)) |
| `-a, --action` | `parse-windows` | `parse-linux` | `parse-mac` || `--dry-run` | `parse-custom`: show first matches and rejected lines, write no CSV. With any filter flag on a parser action: print the filter stats and write only the CSV header |
| `-a, --action` | `parse-windows` | `parse-linux` | `parse-mac` || `--ignore-local`, `--exclude-users`, `--exclude-hosts`, `--exclude-ips` | Noise filtering on every parser action and `merge` (see [Noise filtering](parsing.md#noise-filtering---ignore-local-and---exclude-)) |
| `-a, --action` | `parse-windows` | `parse-linux` | `parse-mac` || `--carve-unalloc` | `carve-image`: scan unallocated space only (planned; currently scans the whole image) |
| `-a, --action` | `parse-windows` | `parse-linux` | `parse-mac` || `--skip-offsets LIST` | `carve-image`: comma-separated hex offsets to skip (32 MB window each) on a pathological E01 |
| `-a, --action` | `parse-windows` | `parse-linux` | `parse-mac` || `--investigation-from "YYYY-MM-DD HH:MM:SS"` | `graph-hunt*`: cutoff (UTC). Days before it are the baseline, the rest the window. Required |
| `-a, --action` | `parse-windows` | `parse-linux` | `parse-mac` || `--alpha` | `graph-hunt*` and loaders: false discovery rate for Benjamini-Hochberg (default 0.05), the only chosen number |
| `-a, --action` | `parse-windows` | `parse-linux` | `parse-mac` || `--only-detectors` / `--skip-detectors` | `graph-hunt*`: comma-separated signal names to run exclusively or to drop (mutually exclusive) |
| `-a, --action` | `parse-windows` | `parse-linux` | `parse-mac` || `--report FILE.md` | `graph-hunt*`: also write the analyst report, one story per origin with a significant connection |
| `-a, --action` | `parse-windows` | `parse-linux` | `parse-mac` || `--seed LIST` | `graph-hunt*`: known-bad hosts, IPs, accounts or `host:account`; the report opens with the reconstructed chain. Requires `--report` |
| `-a, --action` | `parse-windows` | `parse-linux` | `parse-mac` || `--seed-from` / `--seed-to` | `graph-hunt*`: only logins in this UTC range start the seed chain |
| `-a, --action` | `parse-windows` | `parse-linux` | `parse-mac` || `--sigma LIST` | `graph-hunt*`: Hayabusa / Chainsaw JSON or JSONL files or directories; a rule that fired during a login session becomes one more measured signal |
