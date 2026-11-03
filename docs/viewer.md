# The viewer: `masstin -a view`

The lateral-movement graph in a window of masstin's own, read straight from the timeline CSV. No database, no browser. Back to the [README](../README.md).

```bash
# the hunt's findings on a timeline (run graph-hunt-csv first so the rows carry their state)
masstin -a view -f timeline.csv

# open on a host's neighbourhood, inside a window of time
masstin -a view -f timeline.csv --focus SRV01 --start-time "2026-03-15 00:00:00" --end-time "2026-03-16 00:00:00"

# several timelines at once
masstin -a view -f dc01.csv -f srv02.csv
```

## What is drawn

The picture follows Neo4j Browser: a **host** is a circle with its name inside (cyan when it is a name, amber when it is an address the hunt could not tie to a name), a **connection** is a line from origin to destination with an arrowhead and the account written on it. Hosts are the machines graph-hunt sees: upper-case short names, an IP folded into the host name the same-login test gives it (the host lists its addresses in the pane and in the tooltip).

- **Width** of an edge grows with its number of events; **size** of a host with its traffic in the view.
- **Colour** of an edge is its result (logon OK grey, logon FAILED red, connect purple and dotted, logoff grey and dotted), unless the hunt has a word on it: `significant` red and thick, `candidate` orange. A host touched by a significant connection gets a red ring.
- **Halo**: a connection the analyst marked carries a halo (pink for suspicious and confirmed, green for benign).
- Two hosts with more than six accounts between them are drawn as **one edge** that says how many (a spray or a Kerberoast would otherwise be a fan of parallel curves).

Drag a host to move it, drag the background to pan, scroll to zoom, double-click a host to open its neighbourhood. The force layout runs while warm and settles; **Shake** lays it out again, **Fit** frames it.

## Filters

| Control | Meaning |
|---|---|
| View | **Findings**: the connections the hunt marked `significant` or `candidate`. **Neighbourhood**: the hosts within *hops* of the host(s) named in *around*. **Everything**: the other filters alone decide |
| Host / User / Logon type | `contains` by default; `*` wildcards (`adm*`, `*$`); `!` negates; several separated by commas (`ws*,!ws09`) |
| Result, Hunt, Verdict | toggles; in Findings the hunt toggles are fixed to significant + candidate |
| From / To | `YYYY-MM-DD HH:MM:SS` (UTC); a date alone is midnight |
| Limit | connections drawn, the most pressing first (significant, then candidate, then by number of events). The status line says when it was reached |

`--focus HOST` opens in Neighbourhood on that host; `--start-time` / `--end-time` fill From / To.

## The pane

- A **host**: its names, events in and out, every connection it has in the view (click one to open it), *Expand around* and *Only this host*.
- A **connection**: the account(s), result, number of events, first and last time, logon types and event IDs, the hunt's state with its q-value and explanation, and the rows behind it (first 300) with their event columns.

## Marks

On a connection: **suspicious**, **confirmed**, **benign** or **clear**, plus notes, then *Save*. The verdict and the notes are written into the `verdict` and `notes` columns of every row of that connection in the timeline CSV (the file is rewritten through a temporary copy and renamed over the original). A case tool reading the same CSV sees them; the viewer reloads a file another program changed (**Reload** forces it).

## Replay

The bar at the bottom runs the rows of the view in time order: hosts and connections appear when their first event happens. **Play** / **Pause**, the speed in rows per second, the slider to scrub, **All** to show everything again.

## Building without it

The viewer is behind the `ui` feature, on by default. `cargo build --no-default-features` gives a parser-only binary without the window stack.
