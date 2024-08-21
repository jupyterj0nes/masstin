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

#### Windows:
```
masstin.exe -a parse -d '\Velociraptor\ExtractedCollection\C\Windows\System32\winevt\Logs\' -o C:\investigation\masstin-output.csv --overwrite
```

#### Linux:
```
masstin -a parse -d '/Velociraptor/ExtractedCollection/C/Windows/System32/winevt/Logs/' -o /investigation/masstin-output.csv --overwrite
```

#### Output file example

As we can see, events from multiple different EVTX files are merged together. Typically, the initial events come from EVTX files that are not security.evtx. Due to log rotation, security.evtx files cover a limited period—often just a few days—while other EVTX files may span several years. In this example, you can observe when events from security.evtx start to appear, reflecting the rotation of logs that results in shorter log retention for security events compared to other types of logs.

```
time_created,dst_computer,event_id,subject_user_name,subject_domain_name,target_user_name,target_domain_name,logon_type,src_computer,src_ip,log_filename
2024-06-10 17:53:01.545437+00:00,PC-arias,22,,,ucronk,abamp.com,10,PC-agued,192.168.23.34,Microsoft-Windows-TerminalServices-LocalSessionManager%4Operational.evtx
2024-06-10 21:16:39.419230+00:00,PC-arias,24,,,ucronk,abamp.com,10,PC-agued,192.168.23.34,Microsoft-Windows-TerminalServices-LocalSessionManager%4Operational.evtx
2024-06-10 21:18:10.181558+00:00,PC-arias,25,,,ucronk,abamp.com,10,PC-agued,192.168.23.34,Microsoft-Windows-TerminalServices-LocalSessionManager%4Operational.evtx
2024-06-10 21:18:55.645830+00:00,PC-arias,24,,,ucronk,abamp.com,10,PC-agued,192.168.23.34,Microsoft-Windows-TerminalServices-LocalSessionManager%4Operational.evtx
2024-07-08 01:56:37.410372+00:00,PC-arias,1009,ucrudy,,,,3,PC-aedes,PC-10.10.20.23,Microsoft-Windows-SMBServer%4Security.evtx
2024-07-08 01:56:37.410374+00:00,PC-arias,551,ucrudy,,unates,,3,PC-aedes,PC-10.10.20.23,Microsoft-Windows-SMBServer%4Security.evtx
2024-07-08 01:56:38.147178+00:00,PC-arias,1009,ucrudy,,,,3,PC-aedes,PC-10.10.20.23,Microsoft-Windows-SMBServer%4Security.evtx
2024-07-08 01:56:38.147180+00:00,PC-arias,551,ucrudy,,unates,,3,PC-aedes,PC-10.10.20.23,Microsoft-Windows-SMBServer%4Security.evtx
2024-07-08 04:02:23.610180+00:00,PC-arias,1009,ucrudy,,,,3,PC-aedes,PC-10.10.20.23,Microsoft-Windows-SMBServer%4Security.evtx
2024-07-08 04:02:23.610182+00:00,PC-arias,551,ucrudy,,unates,,3,PC-aedes,PC-10.10.20.23,Microsoft-Windows-SMBServer%4Security.evtx
2024-07-08 04:02:48.529051+00:00,PC-arias,1009,ucrudy,,,,3,PC-aedes,PC-10.10.20.23,Microsoft-Windows-SMBServer%4Security.evtx
2024-07-08 04:02:48.529054+00:00,PC-arias,551,ucrudy,,unates,,3,PC-aedes,PC-10.10.20.23,Microsoft-Windows-SMBServer%4Security.evtx
2024-07-30 13:24:48.800497+00:00,PC-arias,21,,,umages,abamp.com,10,PC-amice,PC-amice,Microsoft-Windows-TerminalServices-LocalSessionManager%4Operational.evtx
2024-07-30 13:24:49.208836+00:00,PC-arias,22,,,umages,abamp.com,10,PC-amice,PC-amice,Microsoft-Windows-TerminalServices-LocalSessionManager%4Operational.evtx
2024-07-30 19:48:37.402075+00:00,PC-arias,24,,,umages,abamp.com,10,PC-amice,PC-amice,Microsoft-Windows-TerminalServices-LocalSessionManager%4Operational.evtx
2024-08-02 01:05:09.344144+00:00,PC-arias,24,,,umages,abamp.com,10,PC-amice,PC-amice,Microsoft-Windows-TerminalServices-LocalSessionManager%4Operational.evtx
2024-08-05 01:56:33.513251+00:00,PC-arias,1009,ucrudy,,,,3,PC-altos,PC-altos,Microsoft-Windows-SMBServer%4Security.evtx
2024-08-05 01:56:33.513253+00:00,PC-arias,551,ucrudy,,unates,,3,PC-altos,PC-altos,Microsoft-Windows-SMBServer%4Security.evtx
2024-08-05 01:56:33.984595+00:00,PC-arias,1009,ucrudy,,,,3,PC-altos,PC-altos,Microsoft-Windows-SMBServer%4Security.evtx
2024-08-05 04:34:58.532089+00:00,PC-arias,551,ucrudy,,unates,,3,PC-altos,PC-altos,Microsoft-Windows-SMBServer%4Security.evtx
2024-08-05 04:44:59.137856+00:00,PC-arias,1009,ucrudy,,,,3,PC-altos,PC-altos,Microsoft-Windows-SMBServer%4Security.evtx
2024-08-05 04:44:59.137859+00:00,PC-arias,551,ucrudy,,unates,,3,PC-altos,PC-altos,Microsoft-Windows-SMBServer%4Security.evtx
2024-08-05 04:45:40.590562+00:00,PC-arias,1009,ucrudy,,,,3,PC-altos,PC-altos,Microsoft-Windows-SMBServer%4Security.evtx
2024-08-05 04:45:40.590564+00:00,PC-arias,551,ucrudy,,unates,,3,PC-altos,PC-altos,Microsoft-Windows-SMBServer%4Security.evtx
2024-08-06 19:42:47.918965+00:00,PC-arias,21,,,umages,abamp.com,10,PC-amice,PC-amice,Microsoft-Windows-TerminalServices-LocalSessionManager%4Operational.evtx
2024-08-06 19:42:48.200986+00:00,PC-arias,22,,,umages,abamp.com,10,PC-amice,PC-amice,Microsoft-Windows-TerminalServices-LocalSessionManager%4Operational.evtx
2024-08-07 02:27:09.627182+00:00,PC-arias,24,,,umages,abamp.com,10,PC-amice,PC-amice,Microsoft-Windows-TerminalServices-LocalSessionManager%4Operational.evtx
2024-08-09 22:57:18.508195+00:00,PC-arias,25,,,umages,abamp.com,10,PC-amice,PC-amice,Microsoft-Windows-TerminalServices-LocalSessionManager%4Operational.evtx
2024-08-09 23:01:22.610277+00:00,PC-arias,24,,,umages,abamp.com,10,PC-amice,PC-amice,Microsoft-Windows-TerminalServices-LocalSessionManager%4Operational.evtx
2024-08-12 18:43:04.331929+00:00,PC-arias,4624,-,-,uebons,abamp.com,3,PC-audad,172.31.1.25,Security.evtx
2024-08-12 18:43:04.665159+00:00,PC-arias,4634,,,uebons,abamp.com,3,,,Security.evtx
2024-08-12 18:43:04.750419+00:00,PC-arias,4624,-,-,uebons,abamp.com,3,PC-audad,172.31.1.25,Security.evtx
2024-08-12 18:43:04.816963+00:00,PC-arias,4624,-,-,uebons,abamp.com,3,PC-audad,172.31.1.25,Security.evtx
2024-08-12 18:43:05.152701+00:00,PC-arias,4634,,,uebons,abamp.com,3,,,Security.evtx
2024-08-12 18:43:05.153298+00:00,PC-arias,4634,,,uebons,abamp.com,3,,,Security.evtx
2024-08-12 18:43:07.339480+00:00,PC-arias,4624,-,-,uebons,abamp.com,3,PC-audad,172.31.1.25,Security.evtx
2024-08-12 18:43:07.347172+00:00,PC-arias,4624,-,-,uebons,abamp.com,3,PC-audad,172.31.1.25,Security.evtx
2024-08-12 18:43:07.348558+00:00,PC-arias,4624,-,-,uebons,abamp.com,3,PC-audad,172.31.1.25,Security.evtx
2024-08-12 18:43:07.349305+00:00,PC-arias,4624,-,-,uebons,abamp.com,3,PC-audad,172.31.1.25,Security.evtx
```


### Example: Parsing multiple Windows Logs folders and singles EVTX at once

To parse a folder of Windows logs from multiple machines, as well as an archived Windows log file, use the following command:

#### Windows
```
masstin.exe -a parse -d 'machine1_image\C\Windows\System32\winevt\Logs' -d 'machine2_image\C\Windows\System32\winevt\Logs' -d 'machine3_image\C\Windows\System32\winevt\Logs' -d 'machine4_image\C\Windows\System32\winevt\Logs' -f 'path\to\single_archived_logs.evtx' -o C:\investigation\masstin-output.csv --overwrite

```

#### Linux
```
masstin -a parse -d 'machine1_image/C/Windows/System32/winevt/Logs' -d 'machine2_image/C/Windows/System32/winevt/Logs' -d 'machine3_image/C/Windows/System32/winevt/Logs' -d 'machine4_image/C/Windows/System32/winevt/Logs' -f 'path/to/single_archived_logs.evtx' -o /investigation/masstin-output.csv --overwrite
```

#### Output file example

In this example, multiple EVTX files from different machines are being merged into a single timeline. This is extremely helpful in investigations when it comes to identifying what happened and which accounts were involved within a very specific time frame.

```
time_created,dst_computer,event_id,subject_user_name,subject_domain_name,target_user_name,target_domain_name,logon_type,src_computer,src_ip,log_filename
time_created,dst_computer,event_id,subject_user_name,subject_domain_name,target_user_name,target_domain_name,logon_type,src_computer,src_ip,log_filename
2020-10-28 18:17:49.979945+00:00,PC-breys,21,,,ulaldy,abamp.com,10,PC-bania,10.2.23.12,Microsoft-Windows-TerminalServices-LocalSessionManager%4Operational.evtx
2020-10-28 18:17:50.239635+00:00,PC-breys,22,,,ulaldy,abamp.com,10,PC-bania,10.2.23.12,Microsoft-Windows-TerminalServices-LocalSessionManager%4Operational.evtx
2020-10-28 18:45:24.611805+00:00,PC-breys,21,,,ulaldy,abamp.com,10,PC-bania,10.2.23.12,Microsoft-Windows-TerminalServices-LocalSessionManager%4Operational.evtx
2020-10-28 18:45:24.837268+00:00,PC-breys,22,,,ulaldy,abamp.com,10,PC-bania,10.2.23.12,Microsoft-Windows-TerminalServices-LocalSessionManager%4Operational.evtx
2020-10-28 19:27:52.146888+00:00,PC-breys,21,,,ulaldy,abamp.com,10,PC-bania,10.2.23.12,Microsoft-Windows-TerminalServices-LocalSessionManager%4Operational.evtx
2020-10-28 19:27:52.423019+00:00,PC-breys,22,,,ulaldy,abamp.com,10,PC-bania,10.2.23.12,Microsoft-Windows-TerminalServices-LocalSessionManager%4Operational.evtx
2020-11-28 02:24:45.974671+00:00,PC-breys,21,,,ulaldy,abamp.com,10,PC-bania,10.2.23.12,Microsoft-Windows-TerminalServices-LocalSessionManager%4Operational.evtx
2020-11-28 02:24:46.631128+00:00,PC-breys,22,,,ulaldy,abamp.com,10,PC-bania,10.2.23.12,Microsoft-Windows-TerminalServices-LocalSessionManager%4Operational.evtx
2020-11-28 02:29:26.895803+00:00,PC-bezil,30804,,,,,3,PC-arias,10.2.23.8,Microsoft-Windows-SmbClient%4Connectivity.evtx
2020-11-28 02:29:26.895941+00:00,PC-bezil,30805,,,,,3,PC-arias,10.2.23.8,Microsoft-Windows-SmbClient%4Connectivity.evtx
2020-11-28 02:29:26.895945+00:00,PC-antre,30807,,,,,3,PC-arias,10.2.23.8,Microsoft-Windows-SmbClient%4Connectivity.evtx
2020-11-28 02:29:26.895981+00:00,PC-buats,30804,,,,,3,PC-arias,10.2.23.8,Microsoft-Windows-SmbClient%4Connectivity.evtx
2020-11-28 02:29:26.895987+00:00,PC-buats,30805,,,,,3,PC-arias,10.2.23.8,Microsoft-Windows-SmbClient%4Connectivity.evtx
2020-11-28 02:29:26.895988+00:00,PC-algin,30807,,,,,3,PC-arias,10.2.23.8,Microsoft-Windows-SmbClient%4Connectivity.evtx
2020-11-28 02:29:38.117348+00:00,PC-arias,21,,,ulaldy,abamp.com,10,PC-bania,10.2.23.12,Microsoft-Windows-TerminalServices-LocalSessionManager%4Operational.evtx
2020-11-28 02:29:38.392536+00:00,PC-arias,22,,,ulaldy,abamp.com,10,PC-bania,10.2.23.12,Microsoft-Windows-TerminalServices-LocalSessionManager%4Operational.evtx
2020-11-28 02:31:28.457567+00:00,PC-arias,21,,,ulaldy,abamp.com,10,PC-bania,10.2.23.12,Microsoft-Windows-TerminalServices-LocalSessionManager%4Operational.evtx
2020-11-28 02:31:28.701927+00:00,PC-arias,22,,,ulaldy,abamp.com,10,PC-bania,10.2.23.12,Microsoft-Windows-TerminalServices-LocalSessionManager%4Operational.evtx
2020-11-28 02:39:37.394987+00:00,PC-arias,21,,,ulaldy,abamp.com,10,PC-bania,10.2.23.12,Microsoft-Windows-TerminalServices-LocalSessionManager%4Operational.evtx
2020-11-28 02:39:37.650984+00:00,PC-arias,22,,,ulaldy,abamp.com,10,PC-bania,10.2.23.12,Microsoft-Windows-TerminalServices-LocalSessionManager%4Operational.evtx
2020-11-28 02:50:59.155238+00:00,PC-arias,24,,,ulaldy,abamp.com,10,PC-bania,10.2.23.12,Microsoft-Windows-TerminalServices-LocalSessionManager%4Operational.evtx
2020-11-28 02:51:00.327632+00:00,PC-arias,25,,,ulaldy,abamp.com,10,PC-basts,192.168.23.34,Microsoft-Windows-TerminalServices-LocalSessionManager%4Operational.evtx
2020-11-28 23:56:48.582896+00:00,PC-arias,24,,,ulaldy,abamp.com,10,PC-basts,192.168.23.34,Microsoft-Windows-TerminalServices-LocalSessionManager%4Operational.evtx
2020-11-30 08:16:27.168203+00:00,PC-arias,551,ucrudy,,,,3,PC-bucks,10.2.23.99,Microsoft-Windows-SMBServer%4Security.evtx
2020-11-30 08:16:27.171364+00:00,PC-arias,551,ucrudy,,,,3,PC-bucks,10.2.23.99,Microsoft-Windows-SMBServer%4Security.evtx
2020-12-02 11:01:27.532930+00:00,PC-arias,551,ucrudy,,,,3,PC-bucks,10.2.23.99,Microsoft-Windows-SMBServer%4Security.evtx
2020-12-02 11:01:27.534189+00:00,PC-arias,551,ucrudy,,,,3,PC-bucks,10.2.23.99,Microsoft-Windows-SMBServer%4Security.evtx
2020-12-02 19:53:11.546058+00:00,PC-arias,21,,,uduros,abamp.com,10,PC-bitos,172.10.23.32,Microsoft-Windows-TerminalServices-LocalSessionManager%4Operational.evtx
2020-12-02 19:53:11.868937+00:00,PC-arias,22,,,uduros,abamp.com,10,PC-bitos,172.10.23.32,Microsoft-Windows-TerminalServices-LocalSessionManager%4Operational.evtx
2020-12-02 19:58:17.653812+00:00,PC-arias,21,,,uminis,abamp.com,10,PC-bezes,10.2.23.55,Microsoft-Windows-TerminalServices-LocalSessionManager%4Operational.evtx
2020-12-02 19:58:17.980578+00:00,PC-arias,22,,,uminis,abamp.com,10,PC-bezes,10.2.23.55,Microsoft-Windows-TerminalServices-LocalSessionManager%4Operational.evtx
2020-12-02 21:03:39.690134+00:00,PC-arias,24,,,uduros,abamp.com,10,PC-bitos,172.10.23.32,Microsoft-Windows-TerminalServices-LocalSessionManager%4Operational.evtx
2020-12-03 03:36:03.896190+00:00,PC-arias,24,,,uminis,abamp.com,10,PC-bezes,10.2.23.55,Microsoft-Windows-TerminalServices-LocalSessionManager%4Operational.evtx
2020-12-05 20:58:14.319364+00:00,PC-arias,551,ucrudy,,,,3,PC-bucks,10.2.23.99,Microsoft-Windows-SMBServer%4Security.evtx
2020-12-05 20:58:14.322492+00:00,PC-arias,551,ucrudy,,,,3,PC-bucks,10.2.23.99,Microsoft-Windows-SMBServer%4Security.evtx
2020-12-06 08:01:28.263622+00:00,PC-acros,30804,,,,,3,PC-arias,10.2.23.8,Microsoft-Windows-SmbClient%4Connectivity.evtx
2020-12-06 08:01:28.263714+00:00,PC-acros,30804,,,,,3,PC-arias,10.2.23.8,Microsoft-Windows-SmbClient%4Connectivity.evtx
2020-12-06 08:01:28.264039+00:00,PC-acros,30804,,,,,3,PC-arias,10.2.23.8,Microsoft-Windows-SmbClient%4Connectivity.evtx
2020-12-06 08:01:28.264054+00:00,PC-acros,30804,,,,,3,PC-arias,10.2.23.8,Microsoft-Windows-SmbClient%4Connectivity.evtx
2020-12-06 08:01:28.264057+00:00,PC-acros,30805,,,,,3,PC-arias,10.2.23.8,Microsoft-Windows-SmbClient%4Connectivity.evtx
2020-12-06 08:01:28.264060+00:00,PC-ashes,30807,,,,,3,PC-arias,10.2.23.8,Microsoft-Windows-SmbClient%4Connectivity.evtx
```


### Example: Loading Data into Neo4j

To load the previously parsed data into a Neo4j database, use the following command:


#### Windows
```
masstin.exe -a load -f C:\investigation\masstin-output.csv --database localhost:7687 --user neo4j
```

#### Linux
```
masstin -a load -f /investigation/masstin-output.csv --database localhost:7687 --user neo4j
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

For detailed tips, explanations, and Cypher queries, refer to the [Neo4j and Cypher Resources](neo4j-resources/cypher_queries.md) page.


## Contributing

Contributions are welcome! Please feel free to fork the repository and submit pull requests.

## License

This project is licensed under the GNU General Public License (GPL), which ensures that all distributed adaptations and versions of this project remain free and open source.

## Contact

For any queries or issues, contact Toño Díaz via GitHub or the provided contact links.
