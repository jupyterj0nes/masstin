"""release_notes.py TAG FILE [FILE...]: the text of a release, written to standard output.

The downloads first (one line per system, each a link to its file), how to build from
source, then what changed in this version alone: its section of CHANGELOG.md, not the
whole file. A reader of the Releases page reaches the binary without scrolling.
"""
import re
import sys

REPO = "https://github.com/jupyterj0nes/masstin"


def section(changelog, tag):
    """The lines under `## TAG ...` up to the next `## ` heading."""
    m = re.search(r"^## " + re.escape(tag) + r"(?![\w.]).*?$\n(.*?)(?=^## |\Z)", changelog, re.S | re.M)
    return m.group(1).strip() if m else ""


def downloads(tag, files):
    kinds = [("windows", "Windows", "download it and double-click: the window opens"),
             ("linux", "Linux", "`chmod +x` it and run it"),
             ("macos-arm64", "macOS, Apple silicon", "`chmod +x` it and run it"),
             ("macos-x86_64", "macOS, Intel", "`chmod +x` it and run it")]
    rows, known = [], set()
    for key, system, how in kinds:
        for f in files:
            if key in f.lower() and f not in known:
                known.add(f)
                rows.append(f"| **{system}** | [`{f}`]({REPO}/releases/download/{tag}/{f}) | {how} |")
    for f in files:
        if f not in known:
            rows.append(f"| | [`{f}`]({REPO}/releases/download/{tag}/{f}) | |")
    return rows


def notes(tag, files, changelog):
    out = ["## Download", ""]
    rows = downloads(tag, sorted(files))
    if rows:
        out += ["One file, no installer, no runtime dependencies.", "",
                "| System | File | Then |", "|---|---|---|"] + rows + [""]
    out += ["Or build it from source, on stable Rust: `cargo install masstin`.", "",
            f"First steps: the [README]({REPO}#quick-start).", ""]
    body = section(changelog, tag)
    out += [f"## What changed in {tag}", ""]
    out += [body if body else "No section for this version in the changelog.", ""]
    out += [f"Every version: [CHANGELOG.md]({REPO}/blob/main/CHANGELOG.md)."]
    return "\n".join(out) + "\n"


if __name__ == "__main__":
    tag, files = sys.argv[1], sys.argv[2:]
    sys.stdout.reconfigure(encoding="utf-8", newline="\n")
    sys.stdout.write(notes(tag, files, open("CHANGELOG.md", encoding="utf-8").read()))
