# graph-hunt: statistical scoring

Status: implemented September 2026 (masstin `graph-hunt` / `graph-hunt-neo4j` / `graph-hunt-csv`).

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
4. **Reference (the past only, every day alike).** A fact is new on a day when it occurred on no earlier day, whether that day is in the baseline or in the window: earlier window days are reference too. A fact that repeats is therefore new on its first day only, wherever that day falls, and nothing depends on the length of the baseline or of the window. Early days have less reference and more novelty: the second day of the data has one day of reference and sees almost everything as new. On LANL the second day contributed 19,824 new connections (1,022 from never-seen origins) and the fifth 2,047 (38). Those days would fill the null with novelty that is unseen rather than unusual, while every window day has the whole baseline behind it; so **a baseline day enters the null only when at least half of the baseline days with data lie before it** (the panel start S is chosen among those days too). On a case with years of wtmp history this excludes nothing; on a 7-day baseline it keeps the last three days. Two earlier rules were tried and dropped: leave-one-day-out (a baseline day judged against all other baseline days, before and after) made a repeating fact never new in the baseline while it was new on every window day, and on an incident-free window every new connection came out significant; "the past with the window's gap" (a baseline day *d* judged against days up to *d* − *L*) fixed that but needs a baseline longer than the window, and on LANL (7 baseline days, 9 window days) it left no null at all.
5. **Coverage.** The loaders record, for every destination, the time span of every collected log file: first to last record. Spans are merged per kind of evidence:
   - logins: every source except lastlog and btmp;
   - failures: every source except lastlog, wtmp and utmp.

   A destination is covered on a day when a span touches it. A quiet day inside a log file still counts as covered, and a missing rotation does not.
6. **Panel.** Counts are only comparable over destinations that were watched on every compared day. The panel is the set of destinations covered on every day from a start day S to the last covered baseline day (normally the day before the cutoff; if no log reaches that day the panel ends on the last day any log does, and the run says so). S is the baseline day that maximises min(login panel, failure panel) × null days: the information of the worse-served kind of evidence. A kind of evidence absent from the whole graph does not veto the other. It is purely data-driven and depends on coverage only, never on the events, so it cannot bias the p-values. A plain sum was tried first and let four weeks of wtmp history buy out 25 of the 33 hosts with failure coverage. On each window day the panel is further restricted to destinations covered that day. Window logins to destinations outside the panel are listed as *not evaluated* and never ranked, unless the origin has no history at all (see below). An empty panel stops the run with a message instead of comparing against nothing.
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
   | causal-path | causal paths through this origin as pivot with a credential switch and a new access, summed over path certainties (see below) |
   | credential-switch | logins with a credential switch and a new access: the account belongs to other origins in the reference, this origin never used it, and the destination is new for the origin or for the account |

8. **Joint test.** The test is per connection (see below): its coordinates are what is new about it, its origin-day profile above, and its destination-side context. The statistic is T = Σ −ln(marginal tail share) over the coordinates above zero. It is calibrated empirically: p = (1 + #new baseline connections of the same result with T ≥ T_obs) / (1 + N), with each baseline point's T computed leaving itself out. This is a conformal p-value. It is valid for exchangeable connections whatever the dependence between coordinates, because dependence only costs power. Corroboration is therefore measured jointly, not added as a bonus. For each coordinate, the number of baseline connections at least as high and the baseline days they fall on are reported alongside as a plain check.
9. **Host-day profile.** For destination hosts in the panel, the engine measures the change in PageRank (scaled to mean 1) and in normalised betweenness that the pairs first seen that day make in the graph of the earlier days: the same rule on baseline and window days, the one novelty follows. Both changes are coordinates of the connection's joint test, and the only two whose value belongs to a (destination, day) and not to a connection: every connection into the destination that day carries the same number, a thousand of them on a domain controller. They are therefore compared day against day (on how many null days did any connection see a destination rise this much), so with five null days they weigh at most one in six. Counted over null connections, one day on which a hub rose was one event read as a thousand, and it was told apart from five days as if from 28,000 connections. (Until November 2026 a baseline day added the pairs seen on that one day only and a window day every pair the baseline did not hold, and both coordinates were counted over connections: an incident-free period of the LANL set gave 1,928 significant connections. With both corrections it gives 0.)
10. **Decision.** Benjamini-Hochberg across the new window connections controls the false discovery rate at alpha; habitual connections have p = 1 and are not tests. Significant connections come first; everything else stays in the CSV, marked `significant = no`.

## Unit of the test: the connection

**What an account is.** The account of a connection is its name *and its domain*, written `NAME@DOMAIN`: `Administrator` is not one account but the Administrator of each domain and the local one of each machine, different credentials that share a name. Taken for one, a credential nobody had used on a host looked habitual because another Administrator had been there. The domain is read from the name when it carries one (`administrator@EXAMPLE.TEST`, a Kerberos ticket; `DEV\alice`), else from the event's `target_domain_name`. One domain is written several ways by the same network (`DEV`, `DEV.EXAMPLE.TEST`, `dev.example.test`): its key is the first label, upper case; where a NetBIOS name is not the first label of the DNS one, an account written both ways is two accounts, never merged with another. A local account has its machine's name as domain, so the local Administrator of two servers is two accounts (NetBIOS cuts that name at 15 characters: a domain that is the first 15 characters of the destination's longer name is that destination). An event that gives no domain (4776, an SSH login) names the account by its name alone, an account of its own. On a loaded graph the relationship type is still the name; the hunt reads the domain off the edge's `target_domain_name`, and the Cypher it prints filters by both. On LANL this made 895 names into several accounts (10,073 to 10,968) and left every published figure as it was (256 significant, 230 red team, first other row at rank 108, 0 on the incident-free period, the same calibration); on a lab with three domains and local accounts of the same name, 14 accounts became 34.


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
show. Benjamini-Hochberg runs across the new connections. The origin-day
and host-day profiles described above are the building blocks of that context.

### Hopper's signature: credential switch and new access

Hopper (Ho et al., *Hopper: Modeling and Detecting Lateral Movement*,
USENIX Security 2021) showed on 15 months of enterprise logins that
lateral movement almost always combines two properties, and that requiring
both cuts false alarms eightfold against per-login anomaly detection:

- **credential switch**: a login uses an account that does not belong to
  the actor. Here, without an inventory of machine owners, the account's
  owners are the origins that used it on the reference days; a switch is
  an account with owners that this origin never used. An account with no
  owner anywhere is *unknown to the network* and is reported as such, not
  as a switch. How strongly the account belongs elsewhere is its **home
  share**: of its earlier successful login-days summed over the origins
  that used it, the share that came from the most frequent one. 1 means
  it always came from one machine (a person's own workstation); near 0
  means it is used from everywhere (a service or administrator account).
  This is the owner Hopper reads from an inventory, read from the logs
  instead, and it is computed before the day in question only. The
  `credential-switch` coordinate sums the home shares of that day's
  switch logins, so four logins with an account that lives on one other
  machine weigh 4 and four logins with an account used from 900 machines
  weigh almost nothing; before, both counted 4. The connection's
  explanation names the home: "the account belongs elsewhere: 100% of its
  earlier login-days came from C8198 (7 day(s))". Measured on LANL
  (baseline of 7 days): the account U3486 had 946 logins from one origin,
  U568 628 from one origin, U1653 came from 897 origins; a quiet red-team
  machine that logged in four times with U3486 was indistinguishable from
  the U1653 traffic until the weight was added.
- **new access**: the destination is new for the origin or for the account.

Both are facts already measured by the past-only reference; no
constant is involved. They enter the engine in two ways:

1. as the origin-day coordinate `credential-switch` (logins that day with
   both properties), tested like every other coordinate;
2. as the **class** of each connection, which orders the rows within the
   significant set and within the rest. The p-value is untouched. Classes,
   in order: credential switch with new access (or a causal path with both,
   or the same origin-day as one); account unknown to the network, or a
   switch to a known destination; habitual credential on a new connection,
   or no credential (failures, pre-auth); habitual connection.

   The class is the `signature` column of the CSV (and the first clause of
   `why_unusual` in versions before 2026-09-30). On real data it separates the attacker (every one of its logins in the first class) from scanners, orchestration accounts and administrators on their own account.

### Causal paths

Hopper's unit is the path, not the login. Here a login B→C with account a2
is *caused* by one of the sessions open on B at that moment: a login A→B
that entered before and had not ended yet. A session ends at its LOGOFF
when one was recorded (parse-linux writes one per closed SSH session, with
the same `logon_id`; Windows has 4634/4647), else at the end of the UTC
day. Each distinct (A, a1) open on B is a candidate cause with certainty
1 / #candidates, as in Hopper (who uses a fixed 24 h session). A path carries the signature when a1 ≠ a2
(the credential changed at B) and a1 never logged in to C in the reference.
Paths are attributed to the pivot B: the `causal-path` coordinate of B's
origin-day is the sum of certainties of such paths, and the connection B→C
shows its best path in words ("B had been entered from A as a1 at 15:35;
it went on to C as a2, and a1 had never logged in there"). This replaces
the former `chain-motif` (1 / (1 + seconds) between two new logins), which
had no notion of who was acting.

### Origins without history

A connection to a destination outside the panel cannot be judged by the
destination's history, but when the origin has no event of any kind in the
reference, the connection is new by the origin alone. Such connections are
evaluated with the destination-dependent fact (account new on the
destination) switched off and are never listed as *not evaluated*. Without
this rule the attacker's logins to the three hosts with journal-only
coverage fell outside the ranking.

## Analyst report (`--report`)

The CSV lists connections; an analyst reads origins. With `--report path.md`
the engine also writes one story per origin with a significant connection,
in the order of the CSV: its baseline presence (days active, usual
destinations and accounts) or its absence; what it did in the window as
chronological phases (day, time range, result, accounts, hosts, events,
how many connections were significant and the best p); why that is unusual,
one clause per origin-level fact with its baseline count; who owns each
account it used for the first time; its causal paths; the origins it moves
with (campaign test); the log families that recorded it; and a Browser
query for every connection of the origin in the window. Every number is one
the engine already measured; the report computes nothing.

## Assumptions, limits and what the numbers mean

- **What is exchangeable.** The null is the set of baseline connections of the same result on the panel; each window connection is compared with all of them. The p-value is therefore valid when *connections* are exchangeable across baseline days, not merely days: a day with thousands of habitual batch connections weighs more than a quiet weekend day. Weekly seasonality can break this in either direction. The check that matters is the calibration run on an incident-free window (see Validation), which should be done on a window that contains both weekdays and weekend days. A day-weighted p-value (each baseline day counting once) would be valid under exchangeable days alone, but its floor would be 1 / (days + 1): with 28 baseline days nothing could ever pass a 5 % false discovery rate over thousands of tests. That is why the connection-level null is kept and stated.
- **The null is the set of new baseline connections** of the same result, and the family of tests the set of new window connections: the question answered is "given that a connection is new, how unusual is its profile among the new connections of normal days?". With habitual connections in the null, merely being new read as a 4 % event (400 new among 10,519), and on an incident-free window every new connection passed a 5 % false discovery rate once habitual connections were taken out of the family. The rate of new connections itself is measured by the origin-day coordinates (destinations reached for the first time, accounts new to the origin), not by the fact of novelty alone.
- **Null connections need prior coverage.** A baseline connection enters the null only if its destination was covered on some earlier day: on the first covered day of a destination every connection to it is new for lack of history, not for being unusual, and those days would fill the null with spurious fan-outs.
- **The family of tests** is the set of *new* window connections (some fact about them is new). Habitual connections are not tests: they are listed with p = 1 and stay outside Benjamini-Hochberg, so they cost no power. The run prints the smallest reachable p per result (1 / (N + 1), N being the null size), which is the resolution of the data.
- **Ties.** Every connection more extreme than the whole null gets the floor p. Rows with the same p are ordered by the joint surprise T (the sum of the marginal surprises), then by time. T is informative but is not a probability and is not comparable across results (logins, failures, pre-auth have different nulls).
- **Counts in the explanations.** "shared by 27 of 10519 baseline logins, on 9 of 28 days" gives the share of the null with that fact and the number of distinct baseline days it fell on. The second number is what an analyst can defend without reference to the model.
- **Origins without history** are evaluated on off-panel destinations with every destination-side fact switched off (account on the destination, community, logon type, centrality): only what is known about the origin counts.
- **Centrality.** PageRank is iterated to floating-point stationarity, and a change smaller than twice the difference between two starting points (the convergence noise of that graph) is no change. Betweenness is exact.
- **Causal paths.** A path's certainty is 1 / #candidate causes; the pivot's coordinate sums, over its distinct (destination, account) connections of the day, the best certainty of each, so it is a count of connections weighted by certainty, not of sessions.
- **Campaigns** are a grouping, not a detection. The overlap test draws from the shared account's own footprint (every panel destination that account reached in the window, from any origin), not from the whole panel: two newcomers using the same account go where the account goes, and that overlap is the expectation. Drawing from the panel called 96 % of the candidate pairs on LANL campaigns (172,719 of 180,707); within the footprint a pair stands out only when the two overlap more than two independent users of that account would. Two origins whose window logins coincide in destination, account and second are one machine recorded twice and are never paired.
- **Logon-type rarity** is weighted by events, so double-logged logins weigh twice; on Linux the type is the same for every row and the coordinate is inert.
- **Conformal detail.** Each null point's surprise is computed leaving itself out; the exact full-conformal construction would also add the observation to the reference. The difference is ln((N + 1) / N) per positive coordinate and goes in the conservative direction for observations above the null.

## The score: rarity among all the connections of normal days

The decision (step 10) answers "given that this connection is new, is its profile unusual among the new connections of normal days, once every connection tested is accounted for?". That is the right question for calling something significant and the wrong number to show as "how rare is this": the q-value is bounded below by the few hundred *new* baseline connections and raised again by the correction, so the first finding of a real intrusion read 7 to 15 on the `-10 · log10` scale while the rules of caarea, faramir and allymacb, scored by the share of clean reference rows they fire on, read 20 to 40 for ordinary patterns. In a timeline that mixes the tools the hunt's findings disappeared under the others' noise.

The score (`hunt_score` in the timeline, `rarity` and `hunt_score` in the findings table) is the quantity the rules use, measured on the baseline:

    rarity = (1 + baseline connections with T ≥ T_obs) / (1 + baseline connections)

over **every** baseline connection of the same result that the null was drawn from (same days, same panel, destinations with earlier coverage), habitual ones included. A habitual connection is never unusual (its T is 0 by definition), so it is never counted above and always counted below: the numerator is the one of the test's p-value and the denominator is larger. `hunt_score = -10 · log10(rarity)`.

- **Validity.** It is a conformal p-value against the whole baseline: under exchangeable connections, the chance that a normal connection gets a rarity of x or less is at most x. Checked on four incident-free weeks of a 200,000-row corpus (2,871 to 2,926 window connections each): a rarity of 0.01 or less in 1.22 %, 0.79 %, 1.20 % and 0.59 % of the connections; 0.003 or less in 0.42 %, 0.31 %, 0.34 % and 0.14 %; 0.001 or less in 0, 0.07 %, 0.21 % and 0. On the LANL set, the connections of the attack window that are not labelled red team (463,881): 0.35 % at 0.01 or less, 0.09 % at 0.003, 0.08 % at 0.001, 0.006 % at 0.0001, all within the bound. On its incident-free period (241,252 connections, 0 significant): 0.77 % at 0.01, within the bound, and above it further out: 0.43 % at 0.003, 0.32 % at 0.001, 0.09 % at 0.0001. The days of a real network are not exchangeable to that depth (that window is four weekdays against a null with a weekend in it), so on that period a score of 30 is reached by one normal connection in 300, not in 1,000: read the score as exact to 20 and as good to about half an order of magnitude (5 points) above it. The decision does not rest on it: `hunt` is decided on q, and that period has no significant connection.
- **It is not used to decide.** Only the new connections are looked at, and being new is itself rare (one connection in a hundred on that corpus), so among the connections one looks at the rarity is small by selection: on a clean week every new connection reads 20 or more. Benjamini-Hochberg on the conditional p-value is what keeps the false discovery rate; on those four clean weeks it called nothing significant while 20 to 35 connections a week scored 20 or more. A score says how rare; `hunt` says whether that is evidence.
- **The ceiling is the baseline.** One in (baseline connections + 1): 41 points with 13,600 baseline logins, 35 with 3,300. The run prints it. It is the same bound a rule has on its reference corpus (39 points on caarea's 8,671 reference rows, 33 on faramir's 2,003).
- **The unit is the connection** (origin, destination, account, result, day), not the row: a connection of a thousand events counts once in the numerator and in the denominator, and every row of it carries its score.

On the incident week of the same corpus the 24 significant connections score 29 to 41 and the 20 new ones that are not significant 0 to 27; with the earlier score they read 14 to 18. On a real intrusion (Cortex XDR forensics, a year of events) the two movements of the compromised account read 35 and 31 where they had read 11.

## Output (CSV, machine-level version, superseded)

Columns: `section, rank, machine, machine_p, machine_q, significant, detector, role, p_value, day, hosts, account, events, time_window, summary, cypher_snippet`.

- **`section = campaign`.** Origins with no baseline event that share a new account and reach overlapping destinations beyond chance. Overlap is tested with the exact hypergeometric test over the shared account's footprint in the window, with Benjamini-Hochberg across candidate pairs. This is a grouping only: nodes are not merged and scores are unchanged.
- **`section = finding`.**
  - `role = decision` rows (`origin-profile`, `centrality-profile`) carry the joint p that counts for the machine.
  - `role = component` rows show each coordinate with its univariate tail, for explanation.
  - `role = detail` rows (`novel-edge`) give the novelty profile of each login triple. They are pooled over destinations with at most the observation's reference days, which is conservative because novelty only falls with more reference.
- **`section = not-evaluable`.** Window logins to destinations without continuous coverage.

Summaries state the counts behind every p-value, for example "0 of 1214 baseline origin-days at least as high".

## IP ↔ host name (loaders and graph-hunt)

The same SSH login is often recorded twice on the destination: sshd writes the IP, and wtmp (with UseDNS) writes the reverse-DNS name. When one (destination, account, outcome, second) shows exactly one IP and one name, that is one vote "IP is NAME".

A vote can also be a coincidence: an unrelated login from that name in the same second. The test counts the trials as well as the votes. For a candidate pair (IP, NAME), every second in which the IP logged in alone, in any context (destination, account, outcome) the IP appears in, is a trial; the seconds where NAME, and only NAME, was recorded too are the votes. Under a Poisson model with NAME's own login rate in that context (λ = NAME's distinct login seconds / the destination's observed span), a trial coincides by chance with probability 1 − e^−λ; the number of chance votes is Binomial(trials, mean chance probability over the trials) and the p-value is its upper tail at the observed votes. Genuine double-logging gives votes = trials and a p-value that vanishes with the number of logins; coincidences at the expected rate stay unremarkable however many there are. (The first version multiplied the per-vote probabilities without counting the trials, which is a likelihood, not a tail probability, and folded busy machines that merely shared an account.)

Benjamini-Hochberg runs across every (IP, NAME) candidate. An IP is resolved when exactly one NAME is significant for it; two significant names are a conflict and the IP stays unresolved.

One rule of machine identity, everywhere. `graph-hunt-csv` folds IP and name by this test; the loaders fold an IP into a name node at load time by this same test and nothing else, and list the folded IPs on the host node (`aliases`, `alias_votes`, `alias_p`). Until October 2026 the loaders used a frequency map of (src_ip, src_computer) pairs weighted by 4778/4779 and machine-account hints, which took the most frequent name: on a renamed host (DFIR Madness: the DC was `WIN-E0PO207ERMD` before `CITADEL-DC01`) it kept the old name alive as a second node and the loaded graph disagreed with the CSV path. A hunt run over a loaded graph and over the CSV now see the same machines.

## Parser changes (parse-linux; they change the CSV, approved)

1. **SSH pre-authentication touches** become CONNECT rows with event_id `SSH_PREAUTH` and detail `ssh/preauth-no-ident`, `ssh/preauth-bad-proto` or `ssh/preauth-closed [user=…]`. Only lines that are pre-authentication by definition are taken:
   - "Did not receive identification string";
   - "Bad protocol version identification";
   - closed, reset or disconnect lines carrying `[preauth]`.

   Ordinary session ends are excluded, and the user column stays empty. This was validated against raw logs, matched exactly on re-parsed hosts.
2. **auditd ↔ sshd pairing by identifier.**
   - A successful audit connection is one (pid, `ses`) pair: its further USER_LOGIN records are channels of the same connection, collapsed per host across rotated files.
   - A failed USER_LOGIN is one connection and is never collapsed.
   - An audit record is dropped when an sshd line of the same host, pid, source and outcome exists in a log file whose span covers it. The pairing is one-to-one, closest first. Pre-auth closes pair with audit failures.
   - For files without USER_LOGIN, only USER_AUTH `op=success` records (one per successful connection) and `op=PAM:authentication` failures are used.

   This replaces the 600 s window and the ±1 s same-user match. It was validated row for row against an independent reference on three hosts. That reference found scanner sessions whose audit record trails sshd by up to 40 minutes; a time window would have missed them.

## Declared decisions (not derived from data)

- alpha = 0.05 (conventional; `--alpha`).
- The cutoff date, chosen by the analyst.
- The UTC day as the unit of observation.
- PageRank damping 0.85 and Louvain resolution 1: the algorithms' standard definitions.
- A destination counts as covered on a day when a log-file span touches that day.

## Deviations from the first version of the plan, and why

- **History plateau H\* (Mann-Kendall) → past-only reference, every day alike.** The novelty rate never levels off, because rare legitimate combinations keep appearing. On millions of observations the trend test declared even tiny declines significant (H\* = 490 days). The past-only reference (step 4) gives every day the same rule instead; leave-one-day-out, tried on the way, was dropped (step 4).
- **Simes within families + Fisher across families → one joint test (first per origin-day, now per connection).** Fisher assumes independent families, which does not hold. Testing each signal separately also multiplied the testing burden: 31 novel-edge tests for one fan-out. The joint test measures corroboration directly and stays valid under any dependence.

- **Null matched to the window day's kind (weekday / weekend): measured and dropped (October 2026).** Each window day was compared only with the null days of its kind. It halves the null for a weekday and raises the floor of the reachable p-values enough that findings which pass with the mixed null no longer pass Benjamini-Hochberg, without changing the order: a weekend scan can hold most of the new baseline logins. The mixed null is the conservative choice for a weekday (the weekend novelty makes it heavier) and a calibration window containing a weekend showed no weekend alarm. The run prints the split ("Day kinds: null 20 weekday and 8 weekend day(s); window 5 weekday and 1 weekend day(s)") so the analyst can see it. A depth rule relative to the panel span instead of the days with data was tried at the same time and dropped too: it discarded a weekend day with years of secure-log reference behind it.
- **Hour of day per account: measured and dropped (October 2026).** The idea was a coordinate for a login outside the account's usual hours, read from the baseline. On LANL the red team works office hours: the quiet source C22409 logs in between 13:00 and 15:00, C19932 between 8:00 and 18:00, and the red team as a whole has no login between 23:00 and 6:00 while the network has 3 % of its logins in each of those hours. On real data the attacker entered in the middle of the working afternoon. The signal would separate nothing, and on a DFIR baseline of one to four weeks most accounts have too few logins for an hourly profile anyway; a coordinate that is almost always zero only dilutes the joint test.
- **Accumulated homes per origin: measured and not added (October 2026).** The number of distinct single-home accounts an origin has used so far (1 for a person on a new machine, growing for an attacker rotating stolen credentials) was measured prequentially on LANL: it would put C22409 among the 1.4 % most unusual origin-days on its third day (2 homes), which under Benjamini-Hochberg over 60,000 connections is not significant; C19932 (one shared account) is invisible to it. Not worth a coordinate.

## Validation

- **Parser:** row-for-row against counts computed independently from the raw logs.
- **Statistics:** each p-value states its counts, which are recomputed independently from the CSV for selected connections.
- **Calibration:** a hunt over a period without the incident should give few significant connections, consistent with the controlled false discovery rate.
- **Synthetic corpus** with ground truth (5M edges, Neo4j database `neo4j`): used for the previous, hand-weighted detectors (May 2026) and retired with them; never re-run with the statistical engine. The public benchmark is LANL ([graph-hunt.md](graph-hunt.md#detection-quality)).
