# Contributing

Thanks for wanting to help. Issues, ideas and pull requests are all welcome.

## Reporting a bug

Open an issue with the bug template: the version (`masstin --version`), the system, the command or what you did in the window, and what you expected. If a file triggers it, say what kind of file it is; share a sample only if it holds nothing from a real case.

Questions and ideas go in [Discussions](https://github.com/jupyterj0nes/masstin/discussions).

## Building

```bash
cargo build --release      # stable Rust, no other dependency
cargo test
```

The binary is `target/release/masstin`.

## Pull requests

- One change per pull request, with the reason in the description.
- `cargo test` passes, and a new parser or rule comes with a test on a small sample.
- The timeline's columns are a contract ([docs/csv-format.md](docs/csv-format.md)): a change to them is a discussion first.
- A new log source can often be a YAML rule instead of code ([docs/custom-parsers.md](docs/custom-parsers.md)).

By contributing you agree that your contribution is licensed under the AGPL-3.0 like the rest of the project.
