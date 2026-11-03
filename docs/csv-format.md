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
| `hunt_score` | `graph-hunt-csv` | How rare the connection is, an integer from 0 to 100 (see below); `0` for a habitual connection; empty when there is no test |
| `hunt_why` | `graph-hunt-csv` | Why the connection is unusual, in words; the Hopper class is its first clause |
| `verdict` | the analyst (the viewer, a case tool, or by hand) | `suspicious`, `confirmed`, `benign`, or empty |
| `notes` | the analyst | Free text (`#tags` welcome) |

`graph-hunt-csv` writes the hunt's verdict into every row of the timeline it reads, in place (a temporary file is renamed over the original once complete). The hunt's unit is the connection (origin, destination, account, result, day), so every row of the same connection on the same day carries the same `hunt`, `hunt_score` and `hunt_why`. The six states of `hunt`:

| `hunt` | Meaning |
|--------|---------|
| `significant` | A new connection, tested, q ≤ `--alpha` |
| `candidate` | A new connection, tested, q > `--alpha`: nothing that passes the bar, but worth a look |
| `habitual` | A connection already seen on an earlier day; p = 1, not a test |
| `not_evaluated` | The destination has no comparable log coverage and the origin has a history, so nothing there can be judged new or habitual |
| `baseline` | A day before `--investigation-from`: reference, not judged |
| *(empty)* | The row did not enter the hunt: no usable origin (loopback, `LOCAL`, `-`), origin = destination, unparseable time, a `CONNECT` or logon without an account, or a time after `--end-time` |

A `LOGOFF` is not a connection: it takes the state of the login it closes, found by logon ID on the same destination (empty when that login is not in the timeline).

**`hunt_score`** is the test's q-value (the false discovery rate of calling the connection new) turned into a number people can read and filter: `-10 · log10(q)`, rounded, capped at 100. It only grows as the connection gets rarer; ten points are one order of magnitude.

| `hunt_score` | q | Read as |
|---|---|---|
| 0 | 1 | no rarer than chance (every `habitual` row, and a new connection the data cannot tell from chance) |
| 13 | 0.05 | one in twenty (the default `--alpha`: `significant` starts here) |
| 20 | 0.01 | one in a hundred |
| 30 | 0.001 | one in a thousand |
| 60 | 10⁻⁶ | one in a million |
| 100 | ≤ 10⁻¹⁰ | one in ten thousand million, or rarer |

`hunt_score >= 30` in a spreadsheet filter keeps what is rarer than one in a thousand. The exact q-values stay in the hunt's own output (`-o`). Timelines annotated by the first build of the tail carried the raw q-value under the name `hunt_q`; every reader converts them, and the next hunt or mark rewrites the column under its name.

### The same tail in caarea, faramir and allymacb

The five columns, the six words of `hunt`, the three of `verdict` and the scale of `hunt_score` are the same in the four tools, so a case tool maps the tail once. masstin only tests; the others also run **static rules** (a known-bad pattern, with no probability behind it), and a row must say which of the two spoke:

- **The state comes from the strongest evidence.** A high rule gives `significant`, a medium rule `candidate`, a low rule leaves the statistical state as it is. When a test and a rule both speak, the stronger state wins. No other word goes into `hunt`: not `alert`, `review`, `suspicious` (that is the analyst's word, in `verdict`), `malicious` or `anomalous`.
- **`hunt_why` names the source.** A rule's clause begins with its id and level, `rule H1001 (high): …`; a test's clause is in words, as above (in masstin, the Hopper class first). When both fired, the rule's clause comes first, the clauses separated by `; `. A reader that wants only the rules filters `hunt_why` on `rule `; one that wants only the statistics, on its absence.
- **`hunt_score` is rarity in the four tools.** A test contributes `-10 · log10(q)`. A rule contributes the same scale measured, not chosen: how often its pattern fires on the rows of a clean reference corpus, `-10 · log10(hits / rows)` (one hit in a hundred and twenty-eight rows is 21 points). A pattern that never fired is not "never": the corpus bounds what it can say, so it gets `-10 · log10(1 / (rows + 1))`, which is 38 points on six thousand reference rows and 41 on twelve thousand; 90 would take a thousand million clean rows. Points are per rule pattern, not per level, and a rule not measured yet contributes 0 and says so in its clause (`…, rarity not measured`). Contributions add, capped at 100.
- **A rule on an entry something vouches for adds nothing.** When the entry is stock, in a known-good list or present across the fleet, its state stays (`habitual`) and the rule contributes no points; the rule's clause stays in `hunt_why`, so the reader still sees it fired. Only a high rule whose pattern has no benign reading overrides the vouching. A rule's own catalogue score (a 0 to 100 of the author's confidence) is not a `hunt_score` and does not go into the column.

Running the hunt again overwrites `hunt`, `hunt_score` and `hunt_why`; `verdict` and `notes` are kept as they are. `--no-annotate` leaves the timeline untouched. When the evidence is parsed again, `--carry-marks old.csv` (on `merge` and on `graph-hunt-csv`) copies `verdict` and `notes` from the earlier timeline onto every row with the same 14 event columns.

## Older layouts

Timelines written before v1.4.0 have the 14 event columns only; the ones of 2023 had 12 (no `event_type`, no `logon_id`, `process` where `detail` is now). `merge`, the loaders and `graph-hunt-csv` read all three (the 12-column layout is not read by `graph-hunt-csv`) and `merge` writes the 19.
