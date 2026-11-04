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

A **host** is a piece of glass: a soft shadow, a gradient from a lit centre to a darker rim, a highlight, a thin bright rim, coloured by what the graph makes of it (slate blue for a workstation, teal for a server, violet for a domain controller, muted amber for an address outside the private ranges, sand for an address the hunt could not tie to a name). Four **node styles** (View > Labels and sizes): **machines** (the default: the host drawn as what it is, a monitor with its screen lit, a laptop, a rack server with its lights, a domain controller with its key badge, an antenna for an address, a globe for an external one, and database, cloud, router and phone from the catalogue; the lights breathe with motion on), **glass**, **icons** (the glass with a glyph in the middle) and **minimal** (a dot in a ring). A host can carry its own icon from a catalogue of twenty-five (right-click > Style of this host), whatever the style. A **connection** is a line from origin to destination with an arrowhead and the account written on it. Hosts are the machines graph-hunt sees: upper-case short names, an IP folded into the host name the same-login test gives it (the host lists its addresses in the pane and in the tooltip).

- **Width** of an edge grows with its number of events; **size** of a host with its traffic in the view.
- **Colour** of an edge is its result (logon OK grey, logon FAILED red, connect purple and dotted, logoff grey and dotted), unless the hunt has a word on it: `significant` red and thick, `candidate` orange. An edge fades in from its origin and is brightest at its destination, so the direction reads even before the arrowhead. A host touched by a significant connection gets a red ring and a slow red pulse; a candidate a faint orange one.
- **Halo**: a connection the analyst marked carries a halo (pink for suspicious and confirmed, green for benign).
- Two hosts with more than six accounts between them are drawn as **one edge** that says how many (a spray or a Kerberoast would otherwise be a fan of parallel curves).
- **Motion** (a checkbox in the bar, saved with the style): bright dots travel along the connections that matter, origin to destination (the findings, the glowing rules, whatever is hovered or selected), the significant hosts breathe, a hovered host gets a pulsing ring. Off, the picture is still; it costs nothing when nothing moves.
- Hovering or selecting something fades everything else out over a fraction of a second; a host that enters the view pops in; the camera glides to where it goes (Fit, zoom, a neighbourhood).

Drag a host to move it, drag the background to pan, scroll to zoom, double-click a host to open its neighbourhood. The force layout runs while warm and settles; when it does, the picture is **stretched to the window's shape** and framed, so a tall graph uses the sides and a flat one the height. **Fill the window** (the corners on the toolbar) does it again at any time; **Lay out again** starts the layout over. Captions that would sit on one another are left out until the view is zoomed in or the edge is lit.

### Many hosts

The layout is d3's: repulsion through a Barnes-Hut quadtree (a far cell counts as its centre of mass), springs on the links weaker on a busy host (1 / the smaller degree, so a hub's five hundred leaves do not crush it), a weak gravity, the picture recentred every tick, overlaps pushed apart on a hash grid. A tick over 3,000 hosts and 47,000 links costs about 8 ms. Drawing adapts to the crowd: beyond 2,500 edges on screen the unlit edges become straight segments in one mesh (findings keep their colour), small hosts become discs in one mesh, captions and halos go, and the detail comes back as you zoom in. Measured on a laptop: the 15 hosts of a lab at the display's rate; 600 hosts with 12,700 edges drawn at 48 frames a second settled and 40 while the layout runs; 3,000 hosts with 47,000 edges at 29 settled and 20 while the layout runs. **F1** shows the frame budget (hosts and edges drawn, layout, geometry, edges, hosts, frame, fps) at the bottom left.

## The window

The logo's dog and the wordmark in its cyan-to-magenta gradient at the top left (click the dog for About); the accent of the window is the logo's cyan. A menu bar (**Evidence**, **Hunt**, **View**, **Tools**, **Help**), a toolbar, the row of applied filters, the filter pane on the left, the canvas, the inspector on the right, the time strip and a status line.

- **Evidence**: open or add timeline CSVs, reload, **Ingest evidence…** (masstin's own parsers run from here: pick what it is, where it is and the CSV to write; the command line is shown and the result opens in the window), **Merge timelines…**.
- **Hunt**: **Run the hunt on this timeline…** (below) and the score threshold.
- **View**: the three views, fit, lay out again, the panes, motion, shapes by role, sizes, colour by, captions, the style rules.
- **Tools**: paths and reach, questions, the story and its recording, **Open the case in agentc00pr**, the log of the last run.
- **Toolbar**: the filter pane toggle, the three views as one control, a quick search (a host name, Enter opens its neighbourhood), fit, lay out again, motion, shapes by role, rules; on the right questions, paths, **Hunt**, agentc00pr, the frame budget, the inspector toggle.
- **Applied filters**: every filter that narrows the view is a chip under the toolbar (`host: SRV*`, `score ≥ 13`, `2026-11-03 20:00 → 2026-11-04 00:19`, `findings only`, `one edge per event`…); the × on a chip removes that filter at once, *clear all* removes them all. No chips, no filters.
- **Right-click** a host: expand around, only this host, paths from or to here, pin, **style of this host** (name position, text size, box, size, colour), hide, a note, copy the name. A connection: open in the inspector, mark suspicious / confirmed / benign, a note, **style of this connection** (colour, width, dashes, glow, hidden, for every connection of that account; a folded edge lets you pick the account), hide the account, only it. The background: fit, lay out again, Findings, Everything, back to the view, clear the selection, a note on the case.

## Filters

The pane on the left (the funnel on the toolbar hides it). **Apply filters** at the bottom applies the pane; *apply as I change them* applies pills at once and text fields when you pause; Enter in a field applies too.

| Section | Meaning |
|---|---|
| View | **Findings**: the connections the hunt marked `significant` or `candidate`. **Neighbourhood**: the hosts within *hops* of the host(s) named. **Everything**: the other filters alone decide |
| Search | hosts, accounts, logon type: `contains` by default; `*` wildcards (`adm*`, `*$`); `=name` exactly that name; `!` negates; several separated by commas (`ws*,!ws09`) |
| Hunt | **score ≥**: `hunt_score` at least this (13 is one in twenty, 30 one in a thousand, 60 one in a million); the state pills (fixed to significant + candidate in Findings) |
| Result, Verdict | pills |
| Grouping | **Group accounts** (one edge per origin, destination, account and result; a pair with more than six accounts becomes one edge that says how many), **One edge per account** (never folded), **One edge per event** (every row its own curve, for a tight window) |
| Limit | connections drawn, the most pressing first (significant, then candidate, then by number of events); the status line and the inspector say when it was reached |
| Saved filters | yours, by name, and the built-in ones (RDP only, network logons, SSH, admin accounts, service accounts, without machine accounts, failures and touches, marked by the analyst, last 24 hours); **Save the current filter…** keeps the filter, the style *and*, when the box is ticked, **the arrangement** (where every host is on the canvas) under a name in `<timeline>.views.json`, next to the timeline; picking the filter puts the hosts back in their places, pinned, and hosts it did not know settle around them (*Lay out again* frees them); the trash on a saved filter asks before deleting |

The time window is the **time strip** at the bottom (below), and the same From / To the chips show.

## Style

In the View menu and on the toolbar:

- **Colour by**: result (the default: logon OK grey, FAILED red, connect purple, logoff grey, with the hunt's red and orange on top), account (one colour per account, Neo4j's palette), logon type, hunt state, verdict. The chips at the top left list the categories in the view with their counts.
- **On edges**: what is written on an edge: the account, the first time, the logon type, account + time, the number of events, or nothing.
- **Shapes by role**: hexagon for a domain controller (it receives Kerberos ticket traffic, 4768 / 4769 / 4770 / 4771), rounded square for a server (mostly a destination), circle for a workstation, diamond for an address outside the private ranges; colours follow.
- **Hosts / Edges / Text**: scales.
- **Account and host colours**: coloured by account, the legend chips over the canvas are buttons: click one to pick that account's colour (a palette, or any colour); right-click a host or a connection for *Colour this host…* / *Colour <account>…*. These are style rules, saved with the style.
- **Labels and sizes** (View menu, or the tag on the toolbar): where every host's name goes (**auto**: inside when it fits readably, under it otherwise; **inside**; **band**: a band across the host, wider than it, like a road sign; **below**; **above**), the text size, a box behind the names and its colour, host size by traffic or not, the host and edge scales. Right-click a host › *Name, size and colour of this host…* sets the same for that host alone (its own name position, text size, box, size and colour), kept as a style rule on its exact name (`=NAME`) that wins over the global setting; *Back to the global settings* removes it.
- **Rules**: the style rules window. A rule is a field (host, account, logon type, event id, result, hunt, verdict) and a pattern (same syntax as the filters; empty matches everything), then the look it gives: colour, edge width, host size, shape, dashed, glow, hide. The first rule that matches wins; rules on host and hunt also apply to hosts. Buttons add the usual ones: one account in colour, hide machine accounts, fade what was marked benign, domain controllers as hexagons. Rules are saved with the style.

## Paths, cones and questions

**Paths…** finds the time-respecting paths between two hosts: a chain of logins where every hop happens after the previous one and no later than the gap allowed (hours; 24 by default), no host entered twice, up to a number of hops, inside the bar's time window. Hops are successful logons by default; failures, touches and logoffs can count too, and machine accounts are left out unless asked. The paths come shortest first, each as `A -(account HH:MM)-> B -(…)-> C`; clicking one draws it alone, the hosts in columns by hop with the time of each arrival. *Reach from origin* draws the earliest-arrival cone (every host a chain of logins could have reached from the origin, with the hop and the time it was first reached); *Ways into destination* the same backwards. *Paths from here* / *Paths to here* on a host fill the form. *Back to the view* returns to the filter's graph.

**Questions…** answers, over the rows of the current view: the origins reaching the most destinations, the destinations reached from the most origins, the accounts used from several origins, the connections where failures were followed by a logon, the hosts and accounts seen latest for the first time, and the centrality of every host (PageRank, betweenness, distinct in / out). Click a host to open its neighbourhood.

These are the questions the Cypher catalogue of the Neo4j export used to answer (`neo4j-resources/cypher_queries.md`), without a database.

## The inspector

Three tabs on the right.

- **Selection**. A **host**: its names, events in and out, its notes, every connection it has in the view (click one to open it), *Expand around*, *Only this host*, *Paths from here*, *Paths to here*. A **connection**: the account(s), result, number of events, first and last time, logon types and event IDs, the hunt's state with its score (0 to 100, how rare: 30 is one in a thousand) and explanation, the mark, and the rows behind it (first 300) with their event columns. Nothing selected: what is in the view, by state and verdict.
- **Notes**: the notes of the case (on a host, on a connection, or free), with the time they were written and a way to delete them, then every row of the timeline that carries a verdict or a note, click to open its connection.
- **Legend**: what the colours, rings, halos and widths mean.

## Subnets

The toolbar's antenna (or View › Subnet regions) groups the hosts of the view by where they sit on the network: **Tools › Subnets…** takes your CIDRs with a name (`10.10.0.0/24  servers VLAN 10`), and, when *auto* is on, every other host with an address gets the group of its /24. A host joins a group through the addresses it is known by (its own names, the address the hunt or you merged into it). Each group pulls its hosts together in the layout and pushes the other groups away, and is drawn as a soft region in its colour behind them with its name on top. The named subnets live in `<timeline>.views.json`.

The layout shares the window out: the distance between hosts comes from the room there is and the number of hosts, and the picture stretches along the window's long side, so a small graph spreads over the canvas instead of huddling in the middle.

## Merging hosts

The same machine often comes as an address in one log and as a name in another. The hunt folds an address into a name by itself when the same-login test allows it; for the rest, **right-click a host › Merge with another host…** (pick the other from the list), or select a host and right-click the other › **Merge with <host>…**. The window asks **which name stays**; the two become one node, every connection follows, the other name stays among the host's names in the inspector (with an undo next to it), and a note in the case says the host is a merge of the two. **Tools › Merged hosts…** lists the pairs, undoes any, adds one by name. The timeline CSV is not changed and keeps both names: the pairs live in `<timeline>.views.json` next to it, so they survive sessions and travel with the case.

## Marks and notes

A **verdict** (suspicious, confirmed, benign, or clear) with notes goes on the rows of a connection, into the `verdict` and `notes` columns of the timeline CSV (the file is rewritten through a temporary copy and renamed over the original). When a drawn edge stands for several rows, **the viewer asks**: the whole block (every row, every account folded into it) or only the rows you tick in the list. A case tool reading the same CSV sees the marks; the viewer reloads a file another program changed (**Reload** forces it).

A **note** on a host, on a connection or on the case itself has no row to live in: it goes to `<timeline>.notes.json` next to the timeline, with its time, where agentc00pr can read it too. Right-click, or the Notes tab.

## The time strip

The strip at the bottom is the whole timeline's events over time (a bar every three pixels, log scale, red where a significant connection falls), with the **window the filter selects as a bright band between two handles**. Drag a handle to narrow the window: that *is* the From / To filter, and the chips and the fields follow. Double-click frees the whole timeline. The white line is the **replay head**: drag anywhere else to scrub, **Play** runs the rows of the view in time order at the chosen speed (hosts and connections appear when their first event happens), **All** shows everything again. Hover for the time under the pointer.

## The hunt, from the window

**Hunt** on the toolbar (or the Hunt menu) runs `graph-hunt-csv` on the timeline(s) open: the start of the investigation (prefilled with the window's From, or the last third of the timeline), an optional end, alpha. It runs as a child masstin with the same command line you would type, its output in a log window, and while it runs the mastiff of the logo is on the scent in the middle of the canvas and a sweep crosses it. When it ends the timeline is read again, the view switches to Findings and **the findings appear one after another in time order, each with a flash**; then **the summary** opens: rows by state, the rarest connections with their scores, the spread of scores, and the score threshold with one-click bars (one in twenty, one in a hundred, one in a thousand) that apply at once. The slider in the filter pane does the same at any time. The verdicts and notes already written are kept. *Tools › Log of the last run…* brings the log back.

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

`MASSTIN_VIEW_AUTO` runs actions one per second once the window is up, for demos and tests: `present`, `story`, `rules`, `fit`, `questions`, `paths=A:B[:gap_h]`, `cone=A`, `record=FORMAT:FPS:SIZE` (`gif` / `png` / `mp4`; size `0` the window, `1` 720p, `2` 1080p), `shot=file.png` (a screenshot of the window), `hunt=YYYY-MM-DD HH:MM:SS` (run the hunt from that start), `all=LIMIT` (the Everything view with that limit), `select=HOST`, `zoom=F`, `hud`, `motion`, `bench=N` (times the next N frames with the layout heated and prints the figures on stderr; `bench=N:cold` as it is), `wait=SECONDS` and `quit`. `MASSTIN_VIEW_AUTO="record=gif:15:1,quit" masstin -a view -f timeline.csv` records the story at 720p and closes; `MASSTIN_VIEW_AUTO="all=5000,wait=5,shot=big.png,bench=120,wait=10,quit"` is how the figures above were taken. `MASSTIN_VIEW_DEBUG=1` prints what the viewer does on stderr; `MASSTIN_VIEW_HUD=1` opens with the frame budget shown.

## Building without it

The viewer is behind the `ui` feature, on by default. `cargo build --no-default-features` gives a parser-only binary without the window stack.
