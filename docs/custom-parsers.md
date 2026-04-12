# Masstin custom parsers — schema specification

Masstin's `parse-custom` action parses arbitrary text logs (VPN, firewall, proxy, etc.) using **YAML rule files** and feeds the results into the same 14-column CSV timeline used by the rest of masstin. This document is the complete reference for the YAML schema.

For the community-contributed rule library, see [`rules/`](../rules/).
For background and a worked example, see the blog post [masstin custom parsers](https://weinvestigateanything.com/en/tools/masstin-custom-parsers/).

---

## Why custom parsers

Masstin ships with native parsers for Windows EVTX, Linux auth/secure, UAL, Winlogbeat, Cortex XDR, MountPoints2 and EVTX carving. Everything else — Fortinet, Palo Alto, Cisco ASA, OpenVPN, Squid, any hardware firewall syslog, any cloud VPN — is out of scope for native code. Instead of writing a module per vendor, `parse-custom` lets you (or the community) describe each format in YAML and masstin does the rest.

One rule file describes one vendor format. Inside that file, a list of **sub-parsers** handles the different line types the same product emits (login success, login failure, logout, session update, tunnel up/down, ...). Each line in the log is tried against each sub-parser in order, and the first one that matches wins.

Lines that nothing matches are counted and reported as *rejected* so you can see what your rule is missing.

---

## Command-line usage

```bash
# Single rule file
masstin -a parse-custom --rules path/to/rule.yaml -f log.log -o out.csv

# Directory of rule files (all .yaml / .yml files are loaded recursively)
masstin -a parse-custom --rules rules/ -f log1.log -f log2.log -o out.csv

# Dry-run: parse and show the first 5 matched records + first 5 rejected lines, no CSV written
masstin -a parse-custom --rules rule.yaml -f log.log --dry-run

# Debug mode: preserves sample rejected lines alongside the output for post-mortem
masstin -a parse-custom --rules rule.yaml -f log.log -o out.csv --debug
```

The output CSV has the same 14 columns as any other masstin timeline, so you can `merge` it with EVTX, UAL or carved data and load the combined timeline into Neo4j/Memgraph.

---

## Schema at a glance

```yaml
meta:              # informative metadata (vendor, version, reference URL, author)
  ...

prefilter:         # optional fast filter applied before per-parser matching
  contains_any: [...]
  contains_all: [...]

parsers:           # ordered list of sub-parsers
  - name: "..."    # required, used in the hits-per-parser summary
    match:         # which lines this sub-parser claims
      contains:     [...]   # all of these substrings must be present
      contains_any: [...]   # any one of these substrings must be present
      regex: "..."          # optional regex that must match
    extract:       # how to pull fields out of the matched line
      type: csv | regex | keyvalue
      ...
    sub_extract:   # optional second-pass extraction on a field extracted above
      field: "..."
      strip_before: "..."   # optional, drop prefix up to first occurrence
      type: csv | regex | keyvalue
      ...
    map:           # fill masstin's 14 LogData columns using ${variable} substitution
      time_created: "${...}"
      event_type:   "..."
      ...
```

---

## `meta` block

Purely informative — masstin doesn't parse it semantically, but it's used in the rules library README and helps future contributors understand the rule's origin.

```yaml
meta:
  vendor: "Palo Alto Networks"
  product: "GlobalProtect (VPN)"
  format: "syslog CSV — SYSTEM log subtype=globalprotect"
  versions_tested: ["PAN-OS 8.1", "PAN-OS 9.0", "PAN-OS 10.x"]
  description: "GlobalProtect VPN authentication and session events"
  author: "masstin community"
  reference_url: "https://docs.paloaltonetworks.com/..."
```

All fields are optional but `vendor`, `product`, `format` and `reference_url` are strongly recommended.

---

## `prefilter` block (optional)

Runs **once per line** before any parser is tried. If the line doesn't pass the prefilter, it's skipped entirely — cheaper than running 5+ sub-parser matches that would all fail. Use it when your input file contains a mix of relevant and irrelevant lines (for example, a syslog stream that mixes GlobalProtect and TRAFFIC logs).

```yaml
prefilter:
  contains_any:
    - "globalprotectgateway-"
    - "globalprotectportal-"
```

- `contains_any` — the line must contain **at least one** of these substrings.
- `contains_all` — the line must contain **all** of these substrings.

If both are specified, both conditions must hold.

---

## `parsers` block

A list, processed in order. The **first parser that matches** a given line wins, produces one `LogData` record, and processing of that line stops. If no parser matches, the line is rejected.

Each parser has a required `name` (used in the summary), a `match` block, an `extract` block, an optional `sub_extract`, and a `map` block.

### `match` block

Declares which lines this parser claims. Any combination of the three criteria can be used; all specified criteria must pass.

```yaml
match:
  contains:     ["type=TRAFFIC", "action=allow"]   # all of these must be in the line
  contains_any: ["srcuser=DOMAIN\\", "srcuser=CORP\\"]   # any one must be in the line
  regex: '^\d{4}-\d{2}-\d{2}T.*user="[^"]+"'   # full-line regex must match
```

If you omit all three, the parser matches nothing. This is intentional — it prevents a forgotten `match:` block from accidentally eating every line.

### `extract` block

Pulls fields out of the matched line. Three extractor types are supported in v1:

#### `type: csv`

Splits the line on a delimiter, optionally respecting a quote character, and assigns selected indices to named variables.

```yaml
extract:
  type: csv
  delimiter: ","          # default ","
  quote: '"'              # optional — enables CSV-style quoting with escaped "" inside
  fields_by_index:
    6: generated_time
    8: event_id_raw
    14: description
```

Indices are **0-based**. Values are trimmed before being stored.

Use for CSV-shaped logs (Palo Alto, many cloud exports) or for space/tab-separated logs (set `delimiter: " "` or `"\t"`).

#### `type: regex`

Applies a single regex with named capture groups. All named captures become context variables.

```yaml
extract:
  type: regex
  pattern: '^(?P<date>\S+ \S+)\s+user=(?P<user>\S+)\s+src=(?P<src>\d+\.\d+\.\d+\.\d+)'
```

Use for free-form text logs (OpenVPN, legacy syslog messages). Rust's `regex` crate supports named captures via `(?P<name>...)` but does **not** support lookaround assertions — keep patterns linear.

#### `type: keyvalue`

Splits the line into pairs and each pair into key/value. Perfect for Fortinet-style `key=value key="some value"` logs.

```yaml
extract:
  type: keyvalue
  pair_separator: " "     # default " "
  kv_separator: "="       # default "="
  trim: true              # trim whitespace around each pair
```

Each parsed key becomes a context variable. Values are stripped of surrounding `"` and `'` quotes.

### `sub_extract` block (optional)

Runs a **second extraction pass on a field already extracted by `extract`**. This is essential when a log has a structured outer format but the interesting data is packed inside one of the outer fields as a narrative or inner key-value list.

Example: Palo Alto GlobalProtect SYSTEM logs are CSV outer, but the interesting user/IP data lives inside field 14 (`description`) as a narrative sentence followed by `Key: value, Key: value, ...`:

```
..., "GlobalProtect gateway user auth OK. Login from: 10.0.0.1, User name: alice, Auth type: profile", ...
```

The outer `extract: csv` pulls `description` out. Then `sub_extract` re-parses it:

```yaml
sub_extract:
  field: description          # name of the variable produced by extract
  strip_before: ". "          # optional: drop everything up to and including the first ". "
  type: keyvalue
  pair_separator: ","
  kv_separator: ":"
  trim: true
```

`strip_before` is a simple but surprisingly useful preprocessor: it removes everything up to and including the first occurrence of the given string. In the Palo Alto case, stripping `". "` drops the leading prose and leaves a clean `Login from: 10.0.0.1, User name: alice, ...` for the keyvalue extractor.

Variables produced by `sub_extract` live in the same context as those produced by `extract`, so the `map` block can use either.

### `map` block

Fills the 14 columns of masstin's `LogData` struct using `${variable}` substitution. Any key in the map that corresponds to a real `LogData` field is kept; unknown keys are ignored.

```yaml
map:
  time_created:       "${generated_time}"
  computer:           "${gateway_name}"
  event_type:         "SUCCESSFUL_LOGON"
  event_id:           "GP-GW-AUTH-SUCC"
  subject_user_name:  "${User name}"
  target_user_name:   "${User name}"
  workstation_name:   "${Login from}"
  ip_address:         "${Login from}"
  logon_type:         "VPN"
  filename:           "${__source_file}"
  detail:             "GlobalProtect gateway auth OK | user=${User name} from=${Login from} auth=${Auth type}"
```

Substitution rules:

- `${foo}` is replaced by the value of the context variable `foo`. Whitespace inside variable names **is allowed** (so `${User name}` works when `keyvalue` produces a key literally called `User name`).
- Unknown variables are replaced by the empty string. This is intentional: a missing field should not crash the parser, it should just produce an empty cell.
- Variable names are case-sensitive.
- Literal text is passed through as-is, so you can build rich `detail` strings.

### Special variables

| Variable | Meaning |
|---|---|
| `${__source_file}` | Basename of the current log file |
| `${__line_number}` | 1-based line number of the current line |

These are always available in the map, regardless of whether `extract` produced them.

---

## The 14 destination fields

These are the columns of masstin's unified `LogData` schema — the same ones you see in any masstin-generated CSV. Fill in the ones that make sense for your vendor; leave the rest empty.

| Field | Typical use |
|---|---|
| `time_created` | Event timestamp, ideally in the vendor's own format (masstin preserves it as-is) |
| `computer` | Destination machine / device the event happened on (e.g. firewall name, gateway name) |
| `event_type` | One of `SUCCESSFUL_LOGON`, `FAILED_LOGON`, `LOGOFF`, `CONNECT` |
| `event_id` | Short identifier of the event flavour (e.g. `GP-GW-AUTH-SUCC`) |
| `subject_user_name` | The authenticating user |
| `subject_domain_name` | The user's domain, if known |
| `target_user_name` | Usually the same as `subject_user_name` for VPN/FW logs |
| `target_domain_name` | Usually empty for VPN/FW logs |
| `logon_type` | A short tag distinguishing the source: `VPN`, `FW`, `PROXY`, `SSH`, `RDP` |
| `workstation_name` | Client hostname if known, otherwise the client IP |
| `ip_address` | Client public IP |
| `logon_id` | Session ID from the vendor, useful for later correlation |
| `filename` | Source log filename — usually `${__source_file}` |
| `detail` | Free-form human-readable summary; you can embed any variables here |

---

## Dry-run mode

Running with `--dry-run` does everything **except** write the output CSV. You get:

- The per-file summary (`lines`, `matched`, `rejected`)
- The per-parser hit counts
- The first 5 matched records, rendered in a short format
- The first 5 rejected lines

Use it while you're iterating on a rule — it takes seconds to run and gives you direct feedback on what's matching and what isn't.

```bash
masstin -a parse-custom --rules my-rule.yaml -f sample.log --dry-run
```

---

## Rejected lines and debug mode

When a line doesn't match any parser, it's counted as rejected. The summary always prints the count; the first 20 rejected lines are shown in dry-run mode.

With `--debug` and an output file, masstin also writes `<output>.rejected.log` alongside the CSV containing file:line:text for the rejected sample. That's your clue for what your rule is still missing.

```bash
masstin -a parse-custom --rules my-rule.yaml -f big.log -o out.csv --debug
# -> out.csv
# -> out.csv.rejected.log
```

---

## Writing your first rule — step by step

1. **Collect 5-10 sample lines** from each event type you care about. Put them in a `.sample.log` file.
2. **Copy an existing rule** from `rules/` that has a similar format. `palo-alto-globalprotect.yaml` is a good template for CSV+keyvalue logs; `fortinet-fortigate.yaml` (when complete) will be a good template for pure keyvalue logs.
3. **Write the `meta` block** with vendor, product, version, and `reference_url`. Future-you will thank past-you when the format changes.
4. **Write a `prefilter`** with 2-3 substrings guaranteed to appear in every relevant line. Skip this if your log file is dedicated to this vendor.
5. **Write ONE parser first** — the one for "login success". Use `contains` or `contains_any` to claim the lines.
6. **Pick an extractor type.** CSV if the format is tabular, keyvalue if it's `key=value` style, regex if it's free-form prose.
7. **Fill in `map`** with the 4-5 fields you actually care about: time, user, src IP, dst host, event_type. Leave the others empty.
8. **Run with `--dry-run` and inspect.** Tune until the first matched record looks right.
9. **Add the other event types** (login fail, logout, session update) one by one, each with its own parser.
10. **Check the rejected lines.** If something important is rejected, add a parser for it or widen an existing `match`.
11. **Contribute it back** — open a PR adding your rule to `rules/`. See [`rules/README.md`](../rules/README.md#contributing-a-new-rule).

---

## Limits of v1

- **No JSON extractor.** Planned for v2. For now, JSON logs need a regex extractor.
- **No lookaround in regex.** Rust's `regex` crate is linear-time by design and doesn't support `(?=...)` or `(?<=...)`. Use capture groups with `?P<name>` and do splitting in the extractor.
- **No chained sub-extracts.** Exactly one `sub_extract` per parser. If you need two-level nesting, write two parsers or split your input differently.
- **No conditional mapping.** The `map` block is pure text substitution. If you need event_type to depend on a captured field's value (e.g. `action=success` → `SUCCESSFUL_LOGON`, `action=fail` → `FAILED_LOGON`), write two parsers with different `match` blocks.

All of these are on the roadmap if there's demand.

---

## Roadmap

- `type: json` extractor with jq-style path selectors
- Conditional `map` with `when: ${var} == "foo"` style predicates
- Multiple `regex_multi` patterns on the same input for logs with optional fields
- Per-rule validation (`masstin -a parse-custom --validate rule.yaml`)
- Namespace prefixes for variables to avoid collisions when merging multiple sub-extracts
