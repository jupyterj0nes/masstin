# Masstin: High-Speed DFIR Tool written in Rust and Graph Visualization in Neo4j for Comprehensive Lateral Movement Analysis

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

**To get started quickly, you can download the latest release directly from the [Releases page](https://github.com/jupyterj0nes/masstin/releases).**

There, you can directly download the pre-built binary for Windows (`.exe`) or Linux and run it without needing to compile from source.

### Prerequisites

Before you begin, ensure you have the following:

- **Access to a Neo4j database**: This is only required if you want to use the graphical visualization features. If you only intend to use the `parse` mode to generate and view CSV files of unified and ordered lateral movements, Neo4j is not necessary. If you do need Neo4j, you can download it from [Neo4j Download Page](https://neo4j.com/download/). You only need to create a database and choose a username and password. Masstin will communicate with the Bolt service, typically offered at `localhost:7687`. You can easily verify this setting in the database properties once Neo4j is running.

- **Rust and Cargo**: These are only necessary if you plan to compile the program from source. If you choose to use the pre-built binaries, you do not need to install Rust or Cargo. If you do need to compile from source, make sure you have the latest version of Rust and Cargo installed ([Rust Installation Guide](https://www.rust-lang.org/tools/install)).


### Installation

**To get started quickly, you can download the latest release directly from the [Releases page](https://github.com/jupyterj0nes/masstin/releases).**

On this page, you will find:
- `masstin-v0.9.0` which is the ELF binary for Linux.
- `masstin-v0.9.0.exe` which is the executable for Windows.
- A ZIP file with the source code.
- A TAR.GZ file with the source code.

Please note that Linux binaries may not work on every kernel version. If you encounter issues, you might need to compile Masstin yourself using Cargo. Instructions for building from source can be found below.

If you choose to compile the program from source, follow these steps:

1. Clone the repository and build the project:

    ```bash
    git clone https://github.com/jupyterj0nes/masstin.git
    cd masstin
    cargo build --release
    ```

    **Note:** After installing Rust, you may need to close and reopen your terminal or manually add Cargo to your PATH for the changes to take effect.

2. The executable can be found in `./target/release/`.



## Usage

Run `masstin` from the command line with the following options:

```
masstin [OPTIONS] --action <ACTION>
```

**Note**: For Windows users, just remember to use `masstin.exe` and backslashes (`\`) for paths. Linux users might find this explanation unnecessary.
 

### Example: Parsing simple Windows Logs folder

To parse a folder of Windows logs, use the following command:

```
masstin.exe -a parse -d '\Velociraptor\ExtractedCollection\C\Windows\System32\winevt\Logs\' -o C:\cases\masstin-output.csv --overwrite
```

### Example: Parsing multiple Windows Logs folders and singles EVTX at once

To parse a folder of Windows logs from multiple machines, as well as an archived Windows log file, use the following command:


```
masstin -a parse -d 'machine1_image/C/Windows/System32/winevt/Logs' -d 'machine2_image/C/Windows/System32/winevt/Logs' -d 'machine3_image/C/Windows/System32/winevt/Logs' -d 'machine4_image/C/Windows/System32/winevt/Logs' -f 'path/to/single_archived_logs.evtx' -o /cases/masstin-output.csv --overwrite
```

### Example: Loading Data into Neo4j

To load the previously parsed data into a Neo4j database, use the following command:

```
masstin.exe -a load -f C:\cases\masstin-output.csv --database localhost:7687 --user neo4j
```

Note: After running the command, you will be prompted to enter the password for the Neo4j database.

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
