# Demo recordings

The GIFs in `resources/demo-*.gif` are generated from the files in this folder. Replace `<masstin dir>` and `<evidence dir>` with your paths; the evidence folder holds public data only: the [EVTX-to-MITRE-Attack](https://github.com/mdecrevoisier/EVTX-to-MITRE-Attack) samples, the timeline masstin parsed from the [DFIR Madness "Szechuan sauce"](https://dfirmadness.com/the-stolen-szechuan-sauce/) images, and the [LANL authentication set](https://csr.lanl.gov/data/cyber1/) converted to a timeline (days 0 to 16, 200 sampled hosts plus every red-team machine).

- `demo-parse.tape`: `parse-windows` over the EVTX samples, with [VHS](https://github.com/charmbracelet/vhs) (`vhs demo-parse.tape`).
- `demo-hunt.tape`: `graph-hunt-csv` over the LANL timeline, no seed. Under VHS the run takes about 22 minutes (the recorder slows masstin down); the published GIF keeps the start, the phase change, the summary and the result table.
- `record-memgraph-lab.py`: drives Memgraph Lab (http://localhost:3000, with the Szechuan graph loaded by `load-memgraph --ungrouped`) through [Playwright](https://playwright.dev/python/) and records the session: the hour of the intrusion, the masstin style, and the temporal path between the attacker and the workstation. `pip install playwright && playwright install chromium`, then `python record-memgraph-lab.py`; convert the `.webm` with ffmpeg.
