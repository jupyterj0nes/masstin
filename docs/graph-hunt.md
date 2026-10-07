# graph-hunt: statistical lateral-movement detection

How the hunt decides, what it writes and how well it does on the public LANL set. The maths are in [graph-hunt-statistics.md](graph-hunt-statistics.md). Back to the [README](../README.md).


Once the graph is loaded (with `--ungrouped`: the hunt needs per-event times), masstin looks for lateral-movement anomalies and reports them with **probabilities measured in the network itself** — no hand-picked weights, windows or thresholds. Two flavors, same engine:

- **`-a graph-hunt`** — reads a **Memgraph** graph.
- **`-a graph-hunt-neo4j`** — reads a **Neo4j** graph.
- **`-a graph-hunt-csv`** — reads the timeline **CSV** directly (`-f`), no database at all. Same engine, same results; the graph is only needed to explore afterwards.

No server-side plugin is needed: masstin reads the edges once over bolt and computes everything — including PageRank, betweenness and Louvain — in memory.

```bash
# No database: straight from the timeline
masstin -a graph-hunt-csv -f timeline.csv \
        --investigation-from "2026-03-15 00:00:00" -o findings.csv --report findings.md

# Memgraph
masstin -a graph-hunt --database bolt://localhost:7687 \
        --investigation-from "2026-03-15 00:00:00" -o findings.csv

# Neo4j (password from $NEO4J_PASSWORD or prompt; --db for a named database)
NEO4J_PASSWORD='your-pass' masstin -a graph-hunt-neo4j \
        --database bolt://localhost:7687 --user neo4j --db mycase \
        --investigation-from "2026-03-15 00:00:00" -o findings.csv
```

Days before `--investigation-from` are the **baseline**, the rest the **window**. `--alpha` (default 0.05) is the false discovery rate and the only number the analyst chooses.

### How it decides

The full design, with the reasons behind each choice, is in [docs/graph-hunt-statistics.md](graph-hunt-statistics.md). In short:

- **The past only, every day alike.** A fact is *new* on a day if it happened on no earlier day, whether that day is in the baseline or in the window, so a fact is new on the first day it appears and nothing depends on how long the baseline or the window is. Baseline days are then a fair yardstick for window days: same rule, same statistics.
- **Coverage from the log files.** The loaders record on every host node the time span of each collected log file (`cov_ok` for sources that show logins, `cov_fail` for sources that show failures). Counts are only compared over a **panel** of destinations watched continuously; its start day is the one that maximises panel size × baseline days. Window activity on hosts outside the panel is listed as *not evaluable* instead of being ranked.
- **The unit is the connection**: (origin, destination, account, result) on one day. A connection seen on another baseline day is habitual and scores zero. A new one is described by what is new about it and by its origin's day: destinations reached for the first time (`origin-fanout`), new accounts for the origin (`cred-rotation`), never-seen account/destination pairs (`novel-edge`), new destinations outside the origin's Louvain community (`community-bridge`), destinations with failures (`failed-sweep`), SSH pre-auth touches (`preauth-sweep`), refused named attempts followed by a login with a new account (`probe-then-success`), origin without any history, rarest logon type (`rare-logon-type`), causal paths with a credential switch (`causal-path`), logins with a credential switch and a new access (`credential-switch`), and the destination's PageRank / betweenness change (`pagerank-spike`, `betweenness-spike`). One joint test combines them; its calibration against the baseline connections gives a p-value that stays valid however the signals depend on each other.
- **Decision.** Benjamini-Hochberg across the new connections at `--alpha` (habitual ones have p = 1 and are not tests). Significant connections first; the rest stay in the CSV, marked. Every count in an explanation also says on how many baseline days it occurred.
- **Hopper's signature orders the rows.** Following Hopper (Ho et al., USENIX Security 2021), a connection that combines a **credential switch** (an account owned by other origins, never used by this one) with a **new access** (destination new for the origin or the account) comes before one that reaches a new destination with its habitual credential (scanners, orchestration, administrators on their own account). Hopper reads the owner of each account from an inventory; masstin reads it from the logs: the share of the account's earlier login-days that came from its most frequent origin (1 = it always came from one machine, near 0 = used from everywhere), and a switch weighs that much. The explanation names the home: "the account belongs elsewhere: 100% of its earlier login-days came from C8198". The class is the first clause of `why_unusual`; the p-value is untouched. A **causal path** is the same signature across two hops: A entered B as a1, B went on to C as a2 ≠ a1, and a1 had never reached C.
- **Origins without history** are judged by their own novelty even on destinations without comparable coverage, so their connections are never left out as *not evaluable*.
- **Campaigns.** Origins with no history that share a new account and hit overlapping destinations beyond chance (exact hypergeometric test) are grouped in one row. Nodes are not merged.
- **Machines, not nodes.** An IP and a host name are reported as one machine when the same logins appear once with each (sshd IP vs wtmp reverse-DNS) far more often than chance allows (binomial test over the IP's logins, false discovery rate across candidates, one unambiguous name). The loaders store this on the IP node as `resolved_name` / `resolved_votes` / `resolved_p`; nodes are never merged.

`--only-detectors` / `--skip-detectors` take the signal names above (mutually exclusive).

### Output

One row per connection, most unusual first:

`rank, significant, p_value, q_value, day, first_seen_utc, last_seen_utc, origin, destination, account, result, events, logs, signature, why_unusual, evidence, chain, campaign, cypher_snippet`

- `result`: login OK, login FAILED, or connection without authentication (SSH pre-auth).
- `logs`: the log families that recorded it (secure, wtmp, audit, btmp, journal, evtx...).
- `signature`: the Hopper class ("credential switch with new access", "account unknown to the network", "habitual credential on a new connection", "no credential", "habitual connection"), one value per row, made to filter on.
- `why_unusual`: what is new about the connection and its context, in short phrases without numbers ("origin never seen before; that day the origin reached 29 destination(s) for the first time").
- `evidence`: the same reasons with the baseline count behind each one ("origin never seen before: shared by 56 of 1280 new baseline logins, on 19 of 28 days; ...").
- `chain`: with `--seed`, the connection's place in the reconstruction ("hop 3 depth 1"); empty otherwise.
- `significant`: yes / no at the chosen false discovery rate; `not evaluated` when the destination lacks comparable log coverage and the origin has a history.
- On Neo4j the snippet returns an APOC virtual graph of that connection for Browser.

**Reconstruction from seeds.** Add `--seed 10.0.0.5,svc-backup` (host names, IPs or accounts you already know to be bad) and the report opens with the chain: every login the seeds made in the window, then every login that left the entered machine while that session was open and was either a new connection or used an account the chain already used, with a certainty of 1 over the sessions open on that machine at the moment; what was open on a seed machine when it first acted; the failed attempts and unauthenticated touches of the chain machines; and one Cypher query that draws the whole chain, plus one that returns everything between the chain machines in that time span. A seed that already existed in the baseline starts the chain only with its new connections (a shared jump host's routine is listed, not followed); a never-seen seed with everything it did. `host:account` names both at once, and `--seed-from` / `--seed-to` bound the logins that start the chain.

**Corroboration with Sigma tools.** Add `--sigma hayabusa.jsonl,chainsaw/` (Hayabusa or Chainsaw JSON output). A rule that fired on a machine while a login session was open on it becomes one more measured signal of that connection, and the explanation says which rule, when and at what level: "Sigma: 2 rule(s) fired on SRV01 while the session was open: 'PsExec Service Installation' at 15:36:02 (high), ...". masstin does not detect PsExec, WMI or service installs itself; it joins what those tools found to the login that made it possible.

**Analyst report.** Add `--report findings.md` to also get one story per origin, most unusual first, in words: whether it existed in the baseline and what it usually did, what it did in the window in chronological phases, why that is unusual with the baseline count behind every statement, who owns the accounts it used for the first time, its causal paths, the origins it moves with, what legitimate situation produces the same pattern and how to rule it out, which raw events to pull, and a Browser query to check everything. The CSV is unchanged.

### Detection quality

**Public benchmark: LANL.** The [Los Alamos "Comprehensive, Multi-Source Cyber-Security Events"](https://csr.lanl.gov/data/cyber1/) set (58 days of a real enterprise, 1.05 billion authentication events, 749 labelled red-team logins from 4 machines) is the reference every lateral-movement paper uses. It was converted to a masstin timeline the way a DFIR collection would look (`viconppt/graph-hunt-tests/lanl_to_masstin.py`): the logs of the 305 red-team machines plus a fixed sample of 200 others, remote logons with a user account only (machine accounts are the Kerberos chatter of every workstation with the domain controllers, 70 % of the volume, and not a person moving), days 0 to 16, cutoff at day 7. The baseline days 0 to 6 contain 50 of the 749 red-team events; the window days 7 to 15 contain 640. Run with `graph-hunt-csv`, no database, 21.3 million rows, 14 minutes, 3.3 GB.

| | value |
|---|---:|
| rows in the window (connections) | 465,074 |
| red-team connections among them | 444 |
| significant at FDR 0.05 | 204: 185 red team (42 % of the 444) and 19 from one unlabelled machine that failed on 47 hosts and then logged in with 7 accounts new to it |
| precision of the first 100 rows | 99 % |
| first row that is not red team | rank 84 (that same machine) |
| red-team connections in the first 500 rows (0.1 % of the rows) | 286 of 444 (64 %) |
| red-team sources found | the main one (610 of the 640 window events) at rank 1; the second (26 events, each a single login to a new host) first appears at rank 23,301 |
| incident-free period (days 40 to 43, 241,423 connections, 34,587 of them new) | 0 significant |

Before the null skipped the shallow baseline days (October 2026), the same run gave 56 significant connections, all red team, first non-red-team row at rank 168 and 13 % of the red-team connections: the first baseline days, with one or two days of reference behind them, were filling the null with "new" connections that were merely unseen. The owner weight of the credential switch, added at the same time, does not change the count here (203 without it): on this network a person's own account from a never-seen machine is an everyday event, so the weight tells the analyst whose account it is without making the login rarer.

Reading: an analyst who reads the first 83 rows of 465 thousand sees nothing but attack, and the 19 rows that are not labelled red team are one machine spraying 47 hosts and succeeding with seven accounts it had never used, which no analyst would want hidden. What it does not catch is the red-team machine that made one quiet login per host with a different user each time, an action this network's own baseline contains thousands of times a day (people using their own account from a machine never seen before); no login-graph method detects those without an inventory of who owns which machine (Hopper's own 9 misses are of that kind). For comparison, Hopper reports 94.5 % detection at about 9 alerts a day on 15 months of a 2,300-machine enterprise, with an inventory and two months of training; Argus, the best graph-neural-network result on LANL, reports an average precision of 0.32 that falls to 0.09 under fair labelling (Larroche 2026).

The synthetic-corpus figures of the previous, hand-weighted detectors (May 2026) were retired together with that engine; they were never re-run with the statistical one. The current results are described in the [graph-hunt blog post](https://weinvestigateanything.com/en/tools/masstin-graph-hunt/).
