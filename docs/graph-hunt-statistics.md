# graph-hunt: statistical scoring

Status: implemented September 2026 (masstin `graph-hunt` / `graph-hunt-neo4j`).

## Why

Until September 2026 every graph-hunt number was chosen by hand:
- fixed bonuses (+0.5, +0.25, 0.6, 0.7, 1.1, ×0.3);
- fixed windows (60 s burst, 6 h probe, 300 s chain, 600 s audit session);
- fixed minimums (3 destinations, 100 failures, 50 baseline events, 14 days);
- fixed thresholds (30 % out-degree, 0.5 % logon-type rarity, MAD z ≥ 2).

None of them had a statistical justification. The ranking they produced could not be defended in a report, and they created alerts that existed only because of the constant.

Every such number is now either an exact identifier from the log (parser) or an empirical probability measured in the network being analysed (graph-hunt, loaders).

## Principle

For every signal the question is: **how often does something at least this unusual happen in this network, in normal operation?** The answer is an empirical p-value computed against the network's own baseline.

The only number the analyst chooses is `--alpha`, the false discovery rate (default 0.05).

## Pipeline

1. **Pull.** The engine reads every edge once over bolt:
   - per-event rows for logins and named failures;
   - per-day aggregates for SSH pre-auth touches and unnamed failures;
   - each host node's coverage spans, written by the loaders.

   PageRank, betweenness and Louvain are computed in memory, so no GDS or MAGE plugin is needed.
2. **Machines.** An IP and a host name become one machine when the same-login co-occurrence evidence is unanimous and the chance of coincidence is significant (see below).
3. **Unit.** The unit of observation is the UTC day. Days before the cutoff are the baseline, the rest are the window.
4. **Reference (leave-one-day-out).** A fact is new on a baseline day when it occurs on no other baseline day. It is new on a window day when it occurs on no baseline day. Every day is therefore judged against almost the same amount of reference, wherever it falls in the calendar. That is what makes baseline days a fair null for window days.
5. **Coverage.** The loaders record, for every destination, the time span of every collected log file: first to last record. Spans are merged per kind of evidence:
   - logins: every source except lastlog and btmp;
   - failures: every source except lastlog, wtmp and utmp.

   A destination is covered on a day when a span touches it. A quiet day inside a log file still counts as covered, and a missing rotation does not.
6. **Panel.** Counts are only comparable over destinations that were watched on every compared day. The panel is the set of destinations covered on every day from a start day S to the cutoff. S is the baseline day that maximises min(login panel, failure panel) × null days: the information of the worse-served kind of evidence. It is purely data-driven. A plain sum was tried first and let four weeks of wtmp history buy out 25 of the 33 hosts with failure coverage. On each window day the panel is further restricted to destinations covered that day. Window logins to destinations outside the panel are listed in a *not evaluable* section and never ranked.
7. **Origin-day profile.** For each origin and day, restricted to panel destinations, the engine computes:

   | coordinate | meaning |
   |---|---|
   | origin-fanout | destinations reached for the first time |
   | cred-rotation | accounts used for the first time by this origin (uid:N is not a name) |
   | novel-edge | (account, destination) combinations never seen |
   | community-bridge | new destinations outside the origin's Louvain community in the reference graph |
   | failed-sweep | destinations with failed attempts |
   | preauth-sweep | destinations touched without authenticating (SSH pre-auth) |
   | probe-then-success | refused named attempts followed the same day by a login with an account new for the origin |
   | no-history | origin has no event of any kind on the other baseline days |
   | rare-logon-type | −ln(share of the destination's other-day logins whose logon type is at most as frequent) |
   | chain-motif | 1 / (1 + seconds) for the fastest chain A→B (new) then B→C (new) |

8. **Joint test.** The statistic is T = Σ −ln(marginal tail share) over the coordinates above zero. It is calibrated empirically: p = (1 + #baseline origin-days with T ≥ T_obs) / (1 + N), with each baseline point's T computed leaving itself out. This is a conformal p-value. It is valid for exchangeable days whatever the dependence between coordinates, because dependence only costs power. Corroboration is therefore measured jointly, not added as a bonus. The number of baseline origin-days at least as high in every coordinate at once is reported alongside as a plain check.
9. **Host-day profile.** For destination hosts in the panel, the engine measures the change in PageRank (scaled to mean 1) and in normalised betweenness when the day's logins are added to the baseline graph. On baseline days the same is done by removing that day's unique pairs and adding them back. The same joint calibration applies.
10. **Decision.** Each machine's joint tests are combined with Simes (valid under positive dependence). Benjamini-Hochberg across machines controls the false discovery rate at alpha. Significant machines come first; everything else stays in the CSV, marked `significant = no`.

## Unit of the test: the connection

The anomaly is a connection, not a machine: (origin, destination, account,
result) on one day, where result is login OK, login failed or
unauthenticated contact. A connection that already happened on another
baseline day is habitual and scores zero, whatever its context. A new
connection is described by what is new about it (triple, account on the
destination, destination for the origin, account for the origin, origin
never seen) and by its context: what its origin did that day (the
origin-day profile below), a Louvain community crossing, the rarity of its
logon type, a chain it starts, the destination's centrality change. It is
compared, with the same conformal joint test, against the connections of
the same result on the baseline days, on the destinations both days could
show. Benjamini-Hochberg runs across all connections. The machine-level
tests described below are the building blocks of that context.

## Output (CSV, machine-level version, superseded)

Columns: `section, rank, machine, machine_p, machine_q, significant, detector, role, p_value, day, hosts, account, events, time_window, summary, cypher_snippet`.

- **`section = campaign`.** Origins with no baseline event that share a new account and reach overlapping destinations beyond chance. Overlap is tested with the exact hypergeometric test over the panel, with Benjamini-Hochberg across candidate pairs. This is a grouping only: nodes are not merged and scores are unchanged.
- **`section = finding`.**
  - `role = decision` rows (`origin-profile`, `centrality-profile`) carry the joint p that counts for the machine.
  - `role = component` rows show each coordinate with its univariate tail, for explanation.
  - `role = detail` rows (`novel-edge`) give the novelty profile of each login triple. They are pooled over destinations with at most the observation's reference days, which is conservative because novelty only falls with more reference.
- **`section = not-evaluable`.** Window logins to destinations without continuous coverage.

Summaries state the counts behind every p-value, for example "0 of 1214 baseline origin-days at least as high".

## IP ↔ host name (loaders and graph-hunt)

The same SSH login is often recorded twice on the destination: sshd writes the IP, and wtmp (with UseDNS) writes the reverse-DNS name. When one (destination, account, second, outcome) shows exactly one IP and one name, that is one vote.

A vote can also be a coincidence: an unrelated login from that name in the same second. The model is Poisson, with λ = that name's logins on that (destination, account, outcome) divided by the observed seconds, so P(one coincidence) = 1 − e^−λ. The mapping is kept when:
- all votes name the same host, and
- the product of the per-vote coincidence probabilities is significant after Benjamini-Hochberg across candidate IPs.

This replaces the former fixed minimum of two votes. The loaders write `resolved_name`, `resolved_votes` and `resolved_p` on the IP node and never merge nodes.

## Parser changes (parse-linux; they change the CSV, approved)

1. **SSH pre-authentication touches** become CONNECT rows with event_id `SSH_PREAUTH` and detail `ssh/preauth-no-ident`, `ssh/preauth-bad-proto` or `ssh/preauth-closed [user=…]`. Only lines that are pre-authentication by definition are taken:
   - "Did not receive identification string";
   - "Bad protocol version identification";
   - closed, reset or disconnect lines carrying `[preauth]`.

   Ordinary session ends are excluded, and the user column stays empty. This was validated against the raw logs: 171 lines from 10.240.240.86 on 29 hosts, matched exactly on three re-parsed hosts.
2. **auditd ↔ sshd pairing by identifier.**
   - A successful audit connection is one (pid, `ses`) pair: its further USER_LOGIN records are channels of the same connection, collapsed per host across rotated files.
   - A failed USER_LOGIN is one connection and is never collapsed.
   - An audit record is dropped when an sshd line of the same host, pid, source and outcome exists in a log file whose span covers it. The pairing is one-to-one, closest first. Pre-auth closes pair with audit failures.
   - For files without USER_LOGIN, only USER_AUTH `op=success` records (one per successful connection) and `op=PAM:authentication` failures are used.

   This replaces the 600 s window and the ±1 s same-user match. It was validated row for row against an independent reference on lvrmvp03, finanwasi01 and circulawasp01. That reference found Nessus sessions whose audit record trails sshd by up to 40 minutes; a time window would have missed them.

## Declared decisions (not derived from data)

- alpha = 0.05 (conventional; `--alpha`).
- The cutoff date, chosen by the analyst.
- The UTC day as the unit of observation.
- PageRank damping 0.85 and Louvain resolution 1: the algorithms' standard definitions.
- A destination counts as covered on a day when a log-file span touches that day.

## Deviations from the first version of the plan, and why

- **History plateau H\* (Mann-Kendall) → leave-one-day-out.** The novelty rate never levels off, because rare legitimate combinations keep appearing. On millions of observations the trend test declared even tiny declines significant (H\* = 490 days). Leave-one-day-out gives every day the same reference instead.
- **Simes within families + Fisher across families → one joint test per origin-day.** Fisher assumes independent families, which does not hold. Testing each signal separately also multiplied the testing burden: 31 novel-edge tests for one fan-out. The joint test measures corroboration directly and stays valid under any dependence.

## Validation

- **Parser:** row-for-row against counts computed independently from the raw logs.
- **Statistics:** each p-value states its counts, which are recomputed independently from the CSV for selected machines (10.240.240.86/.87, datapower, scanners).
- **Calibration:** a hunt over a period without the incident should give few significant machines, consistent with the controlled false discovery rate.
- **Synthetic corpus** with ground truth (5M edges, Neo4j database `neo4j`): precision and recall.
