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

## Presets, saved views and style

The third row of the bar:

- **View presets**: Findings, Everything, RDP only (type 10), Network logons (type 3), SSH, Admin accounts, Service accounts, Without machine accounts, Failures and touches, Marked by the analyst, Last 24 hours of the timeline. Picking one fills the filters and applies them. **Save view…** keeps the current filter *and* style under a name; a saved view brings its style back when picked; **Delete view** removes it. Saved views and the last style used live in `<timeline>.views.json`, next to the timeline, so they survive sessions and travel with the case.
- **Colour by**: result (the default: logon OK grey, FAILED red, connect purple, logoff grey, with the hunt's red and orange on top), account (one colour per account, Neo4j's palette), logon type, hunt state, verdict. The chips at the top left list the categories in the view with their counts.
- **On edges**: what is written on an edge: the account, the first time, the logon type, account + time, the number of events, or nothing.
- **Shapes by role**: hexagon for a domain controller (it receives Kerberos ticket traffic, 4768 / 4769 / 4770 / 4771), rounded square for a server (mostly a destination), circle for a workstation, diamond for an address outside the private ranges; colours follow.
- **Hosts / Edges / Text**: scales.
- **Rules (n)**: the style rules window. A rule is a field (host, account, logon type, event id, result, hunt, verdict) and a pattern (same syntax as the filters; empty matches everything), then the look it gives: colour, edge width, host size, shape, dashed, glow, hide. The first rule that matches wins; rules on host and hunt also apply to hosts. Buttons add the usual ones: one account in colour, hide machine accounts, fade what was marked benign, domain controllers as hexagons. Rules are saved with the style.

## The pane

- A **host**: its names, events in and out, every connection it has in the view (click one to open it), *Expand around* and *Only this host*.
- A **connection**: the account(s), result, number of events, first and last time, logon types and event IDs, the hunt's state with its q-value and explanation, and the rows behind it (first 300) with their event columns.

## Marks

On a connection: **suspicious**, **confirmed**, **benign** or **clear**, plus notes, then *Save*. The verdict and the notes are written into the `verdict` and `notes` columns of every row of that connection in the timeline CSV (the file is rewritten through a temporary copy and renamed over the original). A case tool reading the same CSV sees them; the viewer reloads a file another program changed (**Reload** forces it).

## Replay

The bar at the bottom runs the rows of the view in time order: hosts and connections appear when their first event happens. **Play** / **Pause**, the speed in rows per second, the slider to scrub, **All** to show everything again.

## Presentation and recording

**Present** plays the view as a story, full window: each connection draws itself from origin to destination in its turn, the host it reaches pops in, a clock shows the moment, a caption at the bottom says what happened (`14:54:24 · admin-hacker · 10.23.123.11 -> ROOTDC1 (+9 more)`), a counter says where you are. Space pauses, Left / Right step, Home restarts, Esc leaves.

**Story…** is the editor, saved as `<timeline>.story.json` next to the timeline:

- a step is one row, or every row within *group rows within* seconds of the first (a spray over twenty hosts in three seconds is one step, not twenty);
- **timing**: the same seconds per step, or the real gaps compressed by a factor and clamped between a minimum and a maximum (so two days between two hops are felt without waiting);
- a **pause on significant** connections, a **hold** at the end, **fade older** edges, the clock, the caption and the counter on or off, a **title**;
- **anonymise**: HOST-01, user-02, 10.x.x.3, consistent through the story, for a talk;
- **per step**: its own seconds, a pause after it, its own caption, skip, emphasis (a glow and a framed caption). Click a step's number to see the graph at that moment.

**Record…** writes the story as it is shown: every frame is a screenshot of the window while the story plays, at 10 to 60 frames per second, in the window's size or at 1280 x 720 / 1920 x 1080 (the window is resized for the recording). Formats: **GIF** (animated), **PNG frames** (a folder), **MP4** when `ffmpeg` is on the PATH (H.264, plays in PowerPoint and Keynote). The file goes next to the timeline. Leave the window alone while it records; the encoding runs afterwards on its own thread.

## Driving it from outside

`MASSTIN_VIEW_AUTO` runs actions one per second once the window is up, for demos and tests: `present`, `story`, `rules`, `fit`, `record=FORMAT:FPS:SIZE` (`gif` / `png` / `mp4`; size `0` the window, `1` 720p, `2` 1080p) and `quit`. `MASSTIN_VIEW_AUTO="record=gif:15:1,quit" masstin -a view -f timeline.csv` records the story at 720p and closes. `MASSTIN_VIEW_DEBUG=1` prints what the viewer does on stderr.

## Building without it

The viewer is behind the `ui` feature, on by default. `cargo build --no-default-features` gives a parser-only binary without the window stack.
