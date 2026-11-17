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
| `logon_id` | Logon ID for session correlation: the session the row opened or closed on the destination (Windows: the logon ID of 4624 / 4634 / 4647; Linux: the process id of the sshd of the connection, on the logon and on its end). In a row written from the ORIGIN of a connection it is the session ON THE ORIGIN that made it: `4648` (the subject's logon ID) and `AUDIT_CONNECT` (the logon ID of the login of that auditd session) |
| `detail` | Additional context: SubStatus, process name, SSH auth method, UAL role |
| `log_filename` | Source file: the path of the evidence when parsed from a folder; for a file taken out of a forensic image, the image and the place inside it, never the temp folder it sat in while masstin ran: `HRServer.e01:live:Security.evtx`, `HRServer.e01:vss_0:Security.evtx` (`HRServer.e01:partition_1:live:…` for a partition other than the first), `HRServer.e01:UAL:Current.mdb`, `HRServer.e01:ntuser:Administrator/NTUSER.DAT`, `HRServer.e01:tasks:Microsoft/Windows/…`, `HRServer.e01:partition_0:/var/log/auth.log`; an EVTX inside a zip as `archive.zip -> logs/Security.evtx` |

For the complete Event ID mapping, see [CSV Format and Event Classification](https://weinvestigateanything.com/en/tools/masstin-csv-format/).

## The analysis tail

| Column | Written by | Values |
|--------|-----------|--------|
| `hunt` | `graph-hunt-csv` | What the hunt made of the row's connection (see below) |
| `hunt_score` | `graph-hunt-csv` | How rare the connection is, an integer from 0 to 100 (see below); `0` for a habitual connection; empty when there is no test |
| `hunt_why` | `graph-hunt-csv` | Why the connection is unusual, in words; the Hopper class is its first clause |
| `verdict` | the analyst (the viewer, a case tool, or by hand) | `suspicious`, `confirmed`, `benign`, or empty |
| `notes` | the analyst | Free text (`#tags` welcome) |

`graph-hunt-csv` writes the hunt's verdict into every row of the timeline it reads, in place (a temporary file is renamed over the original once complete).

**What a timeline was read from.** Every action that parses evidence files into a timeline leaves a record in the timeline's masstin file, `<name>.masstin` next to it (key `ingests`): the evidence given with `-f` and `-d` (absolute paths), the action, the command line, when it ran and with which masstin. `merge` carries the records of the timelines it merges. An action that reads no file (the Cortex API) leaves none. The 19 columns are not touched by it. Whoever takes the timeline further finds there what it came from: a case tool that is given the timeline can bring that evidence into the case with masstin recorded as already run on it.

**Whose an address is.** Evidence that is no login can still say that an address is a host: a machine's own network configuration (the addresses of its interfaces in the SYSTEM hive of a triage, a folder or a zip) and the domain controller a machine found and bound to, by name and address (Group Policy 5308). The parsers keep it in the same file (key `hosts`: host, address, kind, the period it was seen, where it was read), `merge` carries it, and the host map reads it next to what the rows themselves say (see [the host map](graph-hunt.md#whose-address-is-it-the-host-map)). The 19 columns are not touched by it.

**What a hunt was run with.** The columns say what each row is, not from which date on the hunt judged. Every hunt therefore leaves a record in the masstin file of the timeline it wrote, `<name>.masstin` next to it (key `hunt`): the start of the investigation (`investigation_from`), the end of the window when one was given, `alpha`, the masstin that hunted and when, how many connections it judged and how many were significant, and the timelines hunted together. The 19 columns are not touched by it. A timeline that travels without its record still shows the start to the day: the rows of every day before it are `baseline`, so the investigation started after the last day with `baseline` rows and by the first day with judged ones.

**Hunting a timeline that is already hunted.** masstin says so before writing, with what the earlier hunt was run with (from the record, or read off the rows) and what this one is run with, and `--if-hunted` decides: `overwrite` (the default) replaces the hunt in place, `keep` leaves that timeline as it is, `new` writes the timeline with the new hunt to `<name>.hunt-<date>.csv` next to it and the one given keeps the hunt it had. The window asks the same three before it runs a hunt.

 The hunt's unit is the connection (origin, destination, account, result, day), so every row of the same connection on the same day carries the same `hunt`, `hunt_score` and `hunt_why`. The six states of `hunt`:

| `hunt` | Meaning |
|--------|---------|
| `significant` | A new connection, tested, q ≤ `--alpha` |
| `candidate` | A new connection, tested, q > `--alpha`: nothing that passes the bar, but worth a look |
| `habitual` | A connection already seen on an earlier day; p = 1, not a test |
| `not_evaluated` | The destination has no comparable log coverage and the origin has a history, so nothing there can be judged new or habitual |
| `baseline` | A day before `--investigation-from`: reference, not judged |
| *(empty)* | The row did not enter the hunt: no usable origin (loopback, `LOCAL`, `-`), origin = destination, unparseable time, a `CONNECT` or logon without an account, or a time after `--end-time` |

A `LOGOFF` is not a connection: it takes the state of the login it closes, found by logon ID on the same destination (empty when that login is not in the timeline).

**`hunt_score`** is how rare the connection is among the connections of normal days, as a number people can read and filter. Of the baseline connections of the same result (logins, failures, unauthenticated contacts) on the destinations the logs cover, new and habitual alike, the hunt counts the ones that look at least as unusual on its joint test; the score is `-10 · log10((1 + that count) / (1 + baseline connections))`, rounded, capped at 100. It only grows as the connection gets rarer; ten points are one order of magnitude. A connection the network already made (`habitual`) is like any other: 0.

| `hunt_score` | share | Read as |
|---|---|---|
| 0 | 1 | like any other (every `habitual` row) |
| 13 | 0.05 | one normal connection in twenty looks at least this unusual |
| 20 | 0.01 | one in a hundred |
| 30 | 0.001 | one in a thousand |
| 40 | 0.0001 | one in ten thousand |
| 60 | 10⁻⁶ | one in a million |
| 100 | ≤ 10⁻¹⁰ | one in ten thousand million, or rarer |

The score cannot say more than the baseline holds: with 13,600 baseline logins the rarest a login can read is one in 13,601, 41 points (the run prints this ceiling). And it is a rarity, not the decision. Whether a connection is `significant` is decided on its q-value, which also accounts for how many connections were put to the test at once; a score of 30 on a quiet day and on a day with three thousand new connections is the same rarity and not the same evidence, and `hunt` says which. Both numbers are in the hunt's own output (`-o`: `p_value`, `q_value`, `rarity`, `hunt_score`).

`hunt_score >= 30` in a spreadsheet filter keeps what is rarer than one in a thousand. Until v1.4.x the score was `-10 · log10(q)`. The q-value is corrected for every connection tested and is counted against the new baseline connections only, a few hundred on most cases, so the first finding of a real intrusion scored 7 to 15 while a rule of caarea, faramir or allymacb that fires on one clean row in a thousand scored 30: in a timeline that mixes the tools, masstin's findings sat below everybody's noise. The two were not the same quantity; they are now (see below). Timelines annotated by the first build of the tail carried the raw q-value under the name `hunt_q`; every reader converts them, and the next hunt or mark rewrites the column under its name.

### The same tail in caarea, faramir and allymacb

The five columns, the six words of `hunt`, the three of `verdict` and the scale of `hunt_score` are the same in the four tools, so a case tool maps the tail once. masstin only tests; the others also run **static rules** (a known-bad pattern, with no probability behind it), and a row must say which of the two spoke:

- **The state comes from the strongest evidence.** A high rule gives `significant`, a medium rule `candidate`, a low rule leaves the statistical state as it is; on a row no test judged, a low rule gives `candidate`, so a `hunt_score` above 0 always comes with a word in `hunt`. When a test and a rule both speak, the stronger state wins. A rule whose measured rarity is below 10 points (it fires on more than one clean row in ten) is noise on that kind of row: it changes no state and adds no points, whatever its level; its clause stays in `hunt_why`. The level is the author's opinion, the measurement decides. No other word goes into `hunt`: not `alert`, `review`, `suspicious` (that is the analyst's word, in `verdict`), `malicious` or `anomalous`.
- **`hunt_why` names the source.** A rule's clause begins with its id and level, `rule H1001 (high): …`; a test's clause is in words, as above (in masstin, the Hopper class first). When both fired, the rule's clause comes first, the clauses separated by `; `. A reader that wants only the rules filters `hunt_why` on `rule `; one that wants only the statistics, on its absence.
- **`hunt_score` is rarity in the four tools, and the same rarity.** Every contribution is `-10 · log10` of one quantity: the share of normal items that show at least this. A statistical test measures it on the case's own baseline: of the baseline items of the kind (connections for masstin, file records for allymacb, entries of the technique for faramir), unusual or not, how many score at least as high. It never contributes its q-value, which is corrected for the number of items tested and is what `hunt` decides on. A rule contributes the same quantity measured on clean reference machines, not chosen: how often its pattern fires on the rows of a clean reference corpus, `-10 · log10(hits / rows)` (one hit in a hundred and twenty-eight rows is 21 points). A pattern that never fired is not "never": the corpus bounds what it can say, so it gets `-10 · log10(1 / (rows + 1))`, which is 38 points on six thousand reference rows and 41 on twelve thousand; 90 would take a thousand million clean rows. Points are per rule pattern, not per level, and a rule not measured yet contributes 0 and says so in its clause (`…, rarity not measured`). Contributions add, capped at 100.
- **A rule on an entry something vouches for adds nothing.** When the entry is stock, in a known-good list, present across the fleet, carried by a clean reference host (faramir and caarea ship the entries of the lab's clean hosts and match them by a host-independent identity: user names, SIDs, GUIDs, drive letters, version folders and random temp names neutralised), or installed with its own volume (allymacb reads the installation window off the `$MFT`: from the birth of the volume through the hours that populated it), its state stays (`habitual`, or `baseline` for the installation) and the rule contributes no points; the rule's clause stays in `hunt_why`, so the reader still sees it fired. Only a high rule whose pattern has no benign reading overrides the vouching.
- **A rule hit is judged with the others of its hour, against the hours of clean machines.** Of the entries that changed in the hour, what share carry the pattern, and how many measured clean hours reach that share: an empirical p with the add-one correction, as the tests use. Above alpha, a clean machine does that (its first boot, its updates, its hourly housekeeping): `habitual`, no points, the clause gives the numbers (`1139 of the 3319 records changed in 2026-11-03T10 carry si_before_fn+si_subsec_zero and 1 of 14 clean hours reach that share (what a clean machine does)`). At or below alpha, one operation, not that many anomalies: the first entry keeps the state and the points and says how many came with it, the others are `habitual` and point at it (`same burst as record …`). A pattern no clean hour has at all is never explained by its hour and never folded. A machine's creation, its installation and first boot, is therefore ordinary by measurement, not by exception, and a freshly installed machine shows nothing. What the hour can say is bounded by the clean hours measured: fourteen cannot call anything rarer than one in fifteen. A rule's own catalogue score (a 0 to 100 of the author's confidence) is not a `hunt_score` and does not go into the column.

Running the hunt again overwrites `hunt`, `hunt_score` and `hunt_why`; `verdict` and `notes` are kept as they are. `--no-annotate` leaves the timeline untouched. When the evidence is parsed again, `--carry-marks old.csv` (on `merge` and on `graph-hunt-csv`) copies `verdict` and `notes` from the earlier timeline onto every row with the same 14 event columns.

## Older layouts

Timelines written before v1.4.0 have the 14 event columns only; the ones of 2023 had 12 (no `event_type`, no `logon_id`, `process` where `detail` is now). `merge`, the loaders and `graph-hunt-csv` read all three (the 12-column layout is not read by `graph-hunt-csv`) and `merge` writes the 19.
