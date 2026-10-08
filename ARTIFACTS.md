# Supported Artifacts

Masstin parses the following forensic artifacts to extract lateral movement data. For in-depth analysis of each artifact, see the linked articles at [weinvestigateanything.com](https://weinvestigateanything.com).

## Windows Event Logs (EVTX)

### Security.evtx

[Full article →](https://weinvestigateanything.com/en/artifacts/security-evtx-lateral-movement/)

| Event ID | Description | Logon Type |
|----------|-------------|------------|
| 4624 | Successful logon | as logged (3 Network and 10 RDP are the lateral ones) |
| 4625 | Failed logon | as logged |
| 4634 | Logoff (origin and logon type taken from the 4624 with the same logon ID on that machine) | as its logon |
| 4647 | User-initiated logoff | — |
| 4648 | Logon with explicit credentials (RunAs) | — |
| 4768 | Kerberos TGT request | — |
| 4769 | Kerberos service ticket request | — |
| 4770 | Kerberos service ticket renewed | — |
| 4771 | Kerberos pre-authentication failed | — |
| 4776 | NTLM authentication (domain controller) | — |
| 4778 | RDP session reconnected | 10 |
| 4779 | RDP session disconnected | 10 |
| 5140 | Network share accessed | 3 |

### Terminal Services

[Full article →](https://weinvestigateanything.com/en/artifacts/terminal-services-evtx/)

| Log Source | Event ID | Description |
|------------|----------|-------------|
| LocalSessionManager/Operational | 21 | RDP session logon |
| LocalSessionManager/Operational | 22 | RDP shell start |
| LocalSessionManager/Operational | 24 | RDP session logoff |
| LocalSessionManager/Operational | 25 | RDP session disconnect |
| RDPClient/Operational | 1024 | RDP client session initiation |
| RDPClient/Operational | 1102 | RDP client connection |
| RemoteConnectionManager/Operational | 1149 | Incoming RDP connection accepted |
| RdpCoreTS/Operational | 131 | RDP transport security negotiation |

### SMB (Server Message Block)

[Full article →](https://weinvestigateanything.com/en/artifacts/smb-evtx-events/)

| Log Source | Event ID | Description |
|------------|----------|-------------|
| SMBServer/Security | 1009 | Server denied anonymous access to the client (FAILED_LOGON); client from `ClientName` (UNC stripped) or the `ClientAddress` socket dump |
| SMBServer/Security | 551 | SMB session authentication failure (FAILED_LOGON); client as above, `UserName` split into user and domain, NT status in `detail` (`Status 0xc000006d` = wrong password, `0xc000006e` = account restriction, `0xc0000022` = access denied) |
| SMBClient/Security | 31001 | Client failed to authenticate to the server (FAILED_LOGON); written on the client: the local computer is the source, `ServerName` (UNC stripped) the destination, the share in `detail` |
| SMBClient/Connectivity | 30803 | Failed to establish a network connection to the server (CONNECT, client side) |
| SMBClient/Connectivity | 30804 | A network connection was disconnected (CONNECT, client side) |
| SMBClient/Connectivity | 30805 | The client lost its session to the server (CONNECT, client side) |
| SMBClient/Connectivity | 30806 | The client re-established its session to the server (CONNECT, client side) |
| SMBClient/Connectivity | 30807 | The connection to the share was lost (CONNECT, client side; `ServerName` carries `\server\share`, the share goes to `detail`) |
| SMBClient/Connectivity | 30808 | SMB share access |

### PowerShell Remoting & WMI

[Full article →](https://weinvestigateanything.com/en/artifacts/winrm-wmi-schtasks-lateral-movement/)

| Log Source | Event ID | Description |
|------------|----------|-------------|
| WinRM/Operational | 6 | WSMan session initiation on the source host (destination in `connection` field) |
| WMI-Activity/Operational | 5858 | WMI client failure with `ClientMachine` field identifying remote origin |

### Sysmon

| Log Source | Event ID | Description |
|------------|----------|-------------|
| Sysmon/Operational | 3 | Network connection on a lateral-movement service port (22, 135, 139, 445, 1433, 3306, 3389, 5900, 5985, 5986). The Sysmon host is the local endpoint; `Initiated` sets the direction. One `CONNECT` edge origin → destination with the process and protocol in `detail`. Other Sysmon events (process, pipe, file, registry) are out of scope |

## Linux Artifacts

[Full article →](https://weinvestigateanything.com/en/artifacts/linux-forensic-artifacts/)

| Source | Type | What it captures |
|--------|------|-----------------|
| `/var/log/auth.log` | Text | SSH success, failure, PAM (Debian/Ubuntu) |
| `/var/log/secure` | Text | SSH success, failure, PAM (RHEL/CentOS/Rocky) |
| `/var/log/messages` | Text | SSH events (alternative to secure) |
| `/var/log/audit/audit.log` | Text | `USER_LOGIN` / `USER_AUTH` from auditd — primary signal on Ubuntu with SSSD + AD |
| `/var/log/journal/<machine-id>/*.journal[~]` | Binary (zstd) | systemd-journald — SSH `sshd` events on modern distros where `auth.log` is empty (Ubuntu 18+, RHEL 8+, Debian 11+). Pure-Rust reader, handles compact mode + zstd, **works on Windows analyst hosts without libsystemd**. |
| `utmp` | Binary | Active user sessions |
| `wtmp` | Binary | Historical login/logout/boot records |
| `btmp` | Binary | Failed login attempts |
| `lastlog` | Binary | Last login per user |
| `uac-<host>-<os>-<stamp>.tar.gz` | Archive | UAC (Unix-like Artifacts Collector) triages, streamed selectively; nested zip / tar.gz combinations walked |

What `parse-linux` writes, per row: `SSH_SUCCESS` / `SSH_FAILED` (sshd lines, journald, auditd `USER_LOGIN`), `LOGIN` / `FAILED_LOGIN` (wtmp / btmp), `LASTLOG`, `SSH_PREAUTH` (`CONNECT` rows for connections that ended before authenticating), `SSH_CONNECT` (`CONNECT` rows for sshd started by xinetd) and `LOGOUT` (`LOGOFF` rows paired with their login). `logon_id` carries the sshd process id on every row that has one, the same on a login and on its LOGOFF. RFC3164 syslog timestamps are converted from the host's local zone to UTC; auditd records of a connection already in the sshd log are dropped, paired by pid.

> **Domain-joined Linux (SSSD / Active Directory):** on Ubuntu 22 + SSSD hosts, `/var/log/auth.log` is often nearly empty because PAM routes auth through the systemd journal. Masstin reads `.journal` / `.journal~` files directly and applies the same `Accepted (password|publickey)` / `Failed password` regexes as on text logs, so SSH logins from AD users surface in the timeline with no extra configuration. Combined with the audit.log `USER_LOGIN` path, this recovers the full lateral-movement picture on modern enterprise Linux.

## macOS Artifacts

The macOS Unified Log, read by `parse-mac`. A `.logarchive` bundle (`sudo log collect` or a Console.app export) is the binary `tracev3` store; masstin decodes it directly with the pure-Rust `macos-unifiedlogs` crate, so an archive acquired from a Mac is parsed on a Windows or Linux analyst host with no Mac in the loop. A `log show --style ndjson` / `json` export carries the same events already resolved to text.

| Source | Type | What it captures |
|--------|------|-----------------|
| `*.logarchive` (`Persist/*.tracev3` + `dsc` / `uuidtext` + `timesync`) | Binary (Unified Log) | `sshd` / `sshd-session` / `sshd-auth` SSH logons and `screensharingd` Screen Sharing / Apple Remote Desktop logons. Validated on real Sonoma and Sequoia bundles (`mac-evidence.yml`) |
| `log show --style ndjson` / `json` export | Text (JSON) | The same `sshd` and `screensharingd` events, resolved off the host |

What `parse-mac` writes, per row: `SUCCESSFUL_LOGON` (sshd `Accepted`, screensharingd `Authentication: SUCCEEDED` or, on Sonoma / Sequoia, a viewer address paired with `authResult = 0`, account `uid:<n>`), `FAILED_LOGON` (sshd `Failed` including `invalid user` and `not allowed because`, screensharingd `Authentication: FAILED` or `authResult = 1`), `LOGOFF` (sshd `Disconnected from user`) and `CONNECT` (sshd pre-authentication touches, a screensharingd viewer whose outcome was not logged). `logon_type` is `SSH` or `ScreenSharing`; the destination is the Mac being analysed, the source address goes to `src_ip` (or `src_computer` for a resolved name). Unified Log timestamps (nanoseconds since the epoch) and `log show` timestamps are converted to ISO UTC. Console logins (`loginwindow`), `sudo` and `su` are host-local, not lateral movement, and are dropped.

> **Not yet read:** `smbd` share connections (the Unified Log message format is not documented reliably enough to parse without guessing), `/var/log/system.log` / ASL text, the `utmpx` / `wtmpx` login databases, and APFS disk images — these are the documented roadmap for `parse-mac`.

## Winlogbeat JSON

[Full article →](https://weinvestigateanything.com/en/artifacts/winlogbeat-elastic-artifacts/)

Parses the Windows Event IDs listed above from Winlogbeat JSON (`winlog.channel`, `winlog.event_id` as a number or, from Winlogbeat 8, a string, `winlog.event_data.*` and `winlog.user_data.*`) through the same per-event mapping as `parse-windows`, so an event gives the same row from an EVTX or from Elastic. Elastic Agent's Windows integration writes the same documents and is read too.

## Cortex XDR

[Full article →](https://weinvestigateanything.com/en/artifacts/cortex-xdr-artifacts/)

### Network Events (via API)

Default admin port list queried by `parse-cortex`:

| Port | Protocol | Logon Type |
|------|----------|------------|
| 22   | SSH  | SSH |
| 445  | SMB  | 3   |
| 3389 | RDP  | 10  |
| 5985 | WinRM (HTTP)  | 3 |
| 5986 | WinRM (HTTPS) | 3 |

`--admin-ports` widens the set further to 135, 139, 1433, 3306, 5900 for RPC, NetBIOS, SQL and VNC pivoting visibility.

### EVTX Forensics (via XQL)

Queries the Cortex XDR `forensics_event_log` dataset, which backs both the XDR forensic collection agent and the offline collector (triage packages uploaded to the tenant land in the same dataset). The query asks for the event IDs of `parse-windows` from Security, TerminalServices-LocalSessionManager, SMBServer/Security, SmbClient/Security, SmbClient/Connectivity, RDPClient, RemoteConnectionManager, RdpCoreTS, WinRM/Operational and WMI-Activity/Operational, and drops rows without an origin server side. Logoffs 4634/4647 (no origin in the message, no logon id in the dataset) and Sysmon 3 are not covered. Regex extraction currently ships with EN / ES / DE / FR / IT keyword variants and auto-paginates via time bisection if a window saturates the 1M API cap.

---

**Total:** 33 Windows Event IDs across 12 EVTX sources + 9 Linux artifact types + macOS Unified Log (`.logarchive` and `log show` JSON) + Winlogbeat JSON + Cortex XDR + YAML custom parsers (VPN, firewall, proxy, JSON)
