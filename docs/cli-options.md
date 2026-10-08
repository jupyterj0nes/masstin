# All command-line options

Every flag, grouped by the actions that use it. Back to the [README](../README.md).


| Option | Description |
|--------|-------------|
| `-a, --action` | `parse-windows` \| `parse-linux` \| `parse-mac` \| `parse-image` \| `parse-massive` \| `carve-image` \| `parser-elastic` \| `parse-cortex` \| `parse-cortex-evtx-forensics` \| `parse-custom` \| `merge` \| `load-neo4j` \| `load-memgraph` \| `merge-neo4j-nodes` \| `merge-memgraph-nodes` \| `graph-hunt` \| `graph-hunt-neo4j` \| `graph-hunt-csv`. Aliases: `parse` (parse-windows), `parse-macos` (parse-mac), `parse-image-windows` / `parse-image-linux` (parse-image), `load` (load-neo4j) |
| `-d, --directory` | Directories to process — also accepts drive letters (`D:`) for mounted volumes (repeatable) |
| `-f, --file` | Individual files (repeatable): EVTX, `.mdb`, E01, VMDK, VHD/VHDX, dd/raw for the Windows and image actions; Winlogbeat JSON for `parser-elastic`; `.logarchive` or `log show` JSON for `parse-mac`; any text or JSON log for `parse-custom`; masstin CSVs for `merge`, the loaders and `graph-hunt-csv` |
| `-o, --output` | Output file path. Without it the timeline goes to stdout |
| `--database` | Graph database URL (e.g., `localhost:7687`) |
| `-u, --user` | Database user. Required by `load-neo4j` and `merge-neo4j-nodes`; `graph-hunt-neo4j` defaults to `neo4j`; optional (empty) on the Memgraph actions |
| `--db` | Target database name on the graph server (default `neo4j` for Neo4j actions, `memgraph` for Memgraph). Useful in multi-database Neo4j 5.x/2026.x setups. |
| `--cortex-url` | Cortex XDR API base URL, starting with `https://api-` |
| `--start-time` | Filter start: `"YYYY-MM-DD HH:MM:SS"` (Cortex actions, `merge`, `load-neo4j` / `load-memgraph`) |
| `--end-time` | Filter end: `"YYYY-MM-DD HH:MM:SS"` (same scope as `--start-time`); for `graph-hunt*`, the end of the hunted window |
| `--ungrouped` | For `load-neo4j` / `load-memgraph`: emit one edge per CSV row instead of grouping |
| `--old-node` | For `merge-neo4j-nodes` / `merge-memgraph-nodes`: name of the `:host` node to remove (its edges are transferred to `--new-node`) |
| `--new-node` | For `merge-neo4j-nodes` / `merge-memgraph-nodes`: name of the `:host` node that survives the merge |
| `--filter-cortex-ip` | Filter by IP in Cortex queries |
| `--admin-ports` | `parse-cortex`: widen network port list to full admin set (22, 135, 139, 445, 1433, 3306, 3389, 5900, 5985, 5986). Default is RDP/SMB/SSH + WinRM. |
| `--cortex-event-ids` | `parse-cortex-evtx-forensics`: comma-separated override of the default Windows Event ID set |
| `--cortex-min-window-secs` | Auto-pagination floor for both Cortex actions when a time window saturates the API 1M cap (default 300) |
| `--cortex-max-passes` | Hard cap on auto-pagination passes for both Cortex actions (default 200) |
| `--all-volumes` | Scan all NTFS volumes on the system (parse-image, requires admin) |
| `--overwrite` | Overwrite output file if it exists |
| `--debug` | Print debug information (also keeps rejected synthetic EVTX in `carve-image` and, when `-o` is given, a sample of rejected lines in `parse-custom`) |
| `--silent` | Suppress all output for automation (Velociraptor, SOAR) |
| `--rules PATH` | `parse-custom`: YAML rule file or directory of rules (see [`rules/`](../rules/)) |
| `--dry-run` | `parse-custom`: show first matches and rejected lines, write no CSV. With any filter flag on a parser action: print the filter stats and write only the CSV header |
| `--ignore-local`, `--exclude-users`, `--exclude-hosts`, `--exclude-ips` | Noise filtering on every parser action and `merge` (see [Noise filtering](parsing.md#noise-filtering---ignore-local-and---exclude-)) |
| `--carve-unalloc` | `carve-image`: planned unallocated-only scan; not implemented yet, the whole image is scanned and a warning says so |
| `--skip-offsets LIST` | `carve-image`: comma-separated hex offsets to skip (32 MB window each) on a pathological E01 |
| `--investigation-from "YYYY-MM-DD HH:MM:SS"` | `graph-hunt*`: cutoff (UTC). Days before it are the baseline, the rest the window. Required |
| `--alpha` | `graph-hunt*` and loaders: false discovery rate for Benjamini-Hochberg (default 0.05), the only chosen number |
| `--only-detectors` / `--skip-detectors` | `graph-hunt*`: comma-separated signal names to run exclusively or to drop (mutually exclusive) |
| `--report FILE.md` | `graph-hunt*`: also write the analyst report, one story per origin with a significant connection |
| `--seed LIST` | `graph-hunt*`: known-bad hosts, IPs, accounts or `host:account`; the report opens with the reconstructed chain. Requires `--report` |
| `--seed-from` / `--seed-to` | `graph-hunt*`: only logins in this UTC range start the seed chain |
| `--sigma LIST` | `graph-hunt*`: Hayabusa / Chainsaw JSON or JSONL files or directories; a rule that fired during a login session becomes one more measured signal |
