# Output format

The 19-column timeline every action writes: 14 columns that describe the event and an analysis tail that the hunt and the analyst fill. Back to the [README](../README.md).


Every parse action (and `merge`) produces a unified CSV with 19 columns. The first 14 describe the event and are written by the parsers; the last 5 are empty when the parser writes them and are filled later: three by `graph-hunt-csv`, two by the analyst. The same five columns close the CSVs of caarea, faramir and allymacb, so a case tool maps them once.

## The 14 event columns

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

## The analysis tail

| Column | Written by | Values |
|--------|-----------|--------|
| `hunt` | `graph-hunt-csv` | What the hunt made of the row's connection (see below) |
| `hunt_q` | `graph-hunt-csv` | The connection's q-value (false discovery rate); `1` for a habitual connection; empty when there is no test |
| `hunt_why` | `graph-hunt-csv` | Why the connection is unusual, in words; the Hopper class is its first clause |
| `verdict` | the analyst | `suspicious`, `confirmed`, `benign`, or empty |
| `notes` | the analyst | Free text (`#tags` welcome) |

`graph-hunt-csv` writes the hunt's verdict into every row of the timeline it reads, in place (a temporary file is renamed over the original once complete). The hunt's unit is the connection (origin, destination, account, result, day), so every row of the same connection on the same day carries the same `hunt`, `hunt_q` and `hunt_why`. The six states of `hunt`:

| `hunt` | Meaning |
|--------|---------|
| `significant` | A new connection, tested, q ≤ `--alpha` |
| `candidate` | A new connection, tested, q > `--alpha`: nothing that passes the bar, but worth a look |
| `habitual` | A connection already seen on an earlier day; p = 1, not a test |
| `not_evaluated` | The destination has no comparable log coverage and the origin has a history, so nothing there can be judged new or habitual |
| `baseline` | A day before `--investigation-from`: reference, not judged |
| *(empty)* | The row did not enter the hunt: no usable origin (loopback, `LOCAL`, `-`), origin = destination, unparseable time, a `CONNECT` or logon without an account, or a time after `--end-time` |

A `LOGOFF` is not a connection: it takes the state of the login it closes, found by logon ID on the same destination (empty when that login is not in the timeline).

Running the hunt again overwrites `hunt`, `hunt_q` and `hunt_why`; `verdict` and `notes` are kept as they are. `--no-annotate` leaves the timeline untouched. When the evidence is parsed again, `--carry-marks old.csv` (on `merge` and on `graph-hunt-csv`) copies `verdict` and `notes` from the earlier timeline onto every row with the same 14 event columns.

## Older layouts

Timelines written before v1.4.0 have the 14 event columns only; the ones of 2023 had 12 (no `event_type`, no `logon_id`, `process` where `detail` is now). `merge`, the loaders and `graph-hunt-csv` read all three (the 12-column layout is not read by `graph-hunt-csv`) and `merge` writes the 19.
