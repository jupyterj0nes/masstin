<div align="center">
 <p>
  <h1>
   MASSTIN
  </h1>
 </p>
<img style="padding:0;vertical-align:bottom;" height="300" width="300" src="resources/msastin_logo.png"/>
</div>

---


**Masstin** is a Digital Forensic and Incident Response (DFIR) tool that massively parses multiple forensic artifacts (including Windows evtx files and Linux data) and displays them in a graph database. Developed by Toño Díaz (@jupyterjones), Masstin simplifies the analysis of large volumes of forensic data, aiding security professionals in uncovering patterns and insights efficiently.

## Key Features

- **Parse and Load**: Choose to either parse forensic artifacts or load them directly into a graph database.
- **Support for Multiple Files**: Efficiently processes individual files or entire directories.
- **Flexible Output Options**: Outputs can be saved to a file, directly uploaded to a Neo4j database, or printed to stdout.
- **Overwrite Functionality**: Optionally overwrite existing output files.

## Getting Started

### Prerequisites

Before you begin, ensure you have the following installed:
- Latest version of Rust and Cargo (See Rust's [official site](https://www.rust-lang.org/tools/install))
- Access to a Neo4j database

### Installation

Clone the repository to your local machine:

```bash
git clone https://github.com/yourusername/masstin.git
cd masstin
```

Build the project using Cargo:
```bash
cargo build --release
```

The executable can be found in ./target/release/.


### Usage

Run `masstin.exe` from the command line with the following options:

```
masstin.exe [OPTIONS] --action <ACTION>
```

### Options:
- `-a, --action <ACTION>`: Specify the action to perform (`parse` or `load`).
- `-d, --directory <DIRECTORY>`: Specify directory(ies) to use. This argument can be repeated.
- `-f, --file <FILE>`: Specify single evtx files to use. This argument can be repeated.
- `-o, --output <OUTPUT>`: File where parsed output will be stored.
- `--database <DATABASE>`: URL of the Neo4j database where the CSV file will be uploaded.
- `-u, --user <USER>`: User of the Neo4j database.
- `--overwrite`: When specified, if the output file exists, it will be overwritten.
- `--stdout`: When specified, output will be displayed in stdout only.
- `-h, --help`: Print help information.
- `-V, --version`: Print version information.

## Contributing

Contributions are welcome! Please feel free to fork the repository and submit pull requests.

## License

This project is licensed under the GNU General Public License (GPL), which ensures that all distributed adaptations and versions of this project remain free and open source.

## Contact

For any queries or issues, contact Toño Díaz via GitHub or the provided contact links.
