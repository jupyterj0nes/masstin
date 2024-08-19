# MASSTIN

<div align="center">
  <img style="padding:0;vertical-align:bottom;" height="400" width="400" src="resources/masstin_logo.png" alt="Masstin Logo"/>
</div>

---

**Masstin** is a Rust-written Digital Forensic and Incident Response (DFIR) tool designed to efficiently parse and analyze a wide range of forensic artifacts, with a focus on identifying lateral movement. Don't fear investigations without Security.evtx! Masstin collects over 10 different artifacts into a single timeline, initially generating a CSV file with all lateral movements unified and ordered temporally from the provided directories. You also have the option to load this data into a Neo4j database for advanced visualization and analysis using powerful Cypher queries. Ideal for DFIR analysts seeking both precision and speed, Masstin enhances your ability to uncover hidden patterns and insights from complex datasets.

## Table of Contents

- [Background](#background)
- [Key Features](#key-features)
- [Getting Started](#getting-started)
  - [Prerequisites](#prerequisites)
  - [Installation](#installation)
  - [Usage](#usage)
- [Neo4j and Cypher Integration](#neo4j-and-cypher-integration)
- [Contributing](#contributing)
- [License](#license)
- [Contact](#contact)

## Background

Masstin was developed out of the need to handle incidents involving multiple machines with rotated logs, incomplete SIEM log forwarding, and limited SIEM retention. As forensic artifacts became crucial for reconstructing lateral movements across various machines, the need for efficient parsing and visualization tools became apparent.

Originally automated using a Python script (Sabonis: [https://github.com/jupyterj0nes/sabonis](https://github.com/jupyterj0nes/sabonis)), the tool evolved as more artifacts were added, eventually leading to a complete timeline representation similar to Plaso. This evolution highlighted the challenges of normalizing data, managing large volumes, and improving processing speed, especially with EVTX files over 500MB.

The shift to Rust significantly improved performance, achieving a 90% speed increase without additional preprocessing or dependencies. The result is a high-speed, reliable tool capable of processing large forensic datasets and visualizing them in Neo4j.

## Key Features

- **Parse and Load**: Efficiently parse forensic artifacts or load them into a Neo4j graph database.
- **Support for Multiple Files**: Process individual files or entire directories with high efficiency.
- **Flexible Output Options**: Save outputs to files, upload directly to Neo4j, or print to stdout for versatile usage.
- **Cross-Platform Compatibility**: Runs on both Windows and Linux without needing additional dependencies.
- **Fast Processing**: Utilizes Rust's performance to handle large forensic datasets quickly, significantly reducing processing time compared to Python-based tools.
- **Detailed Error Reporting**: Provides comprehensive error messages to aid in troubleshooting and debugging.
- **Cypher Queries**: Includes a set of pre-built Cypher queries to facilitate advanced searching and filtering during investigations.

## Getting Started

### Prerequisites

Before you begin, ensure you have the following installed:
- Latest version of Rust and Cargo ([Rust Installation Guide](https://www.rust-lang.org/tools/install))
- Access to a Neo4j database

### Installation

Clone the repository and build the project:

```bash
git clone https://github.com/yourusername/masstin.git
cd masstin
cargo build --release
```
The executable can be found in ./target/release/.

Alternatively, you can download the latest release directly from the releases page. 

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


## Neo4j and Cypher Integration

Masstin integrates with Neo4j to visualize forensic data. The Cypher query language allows for advanced searching and filtering, making it easier to identify relationships and outliers. Pre-built queries and visualizations enhance the analysis process, providing a comprehensive view of the data.

## Contributing

Contributions are welcome! Please feel free to fork the repository and submit pull requests.

## License

This project is licensed under the GNU General Public License (GPL), which ensures that all distributed adaptations and versions of this project remain free and open source.

## Contact

For any queries or issues, contact Toño Díaz via GitHub or the provided contact links.
