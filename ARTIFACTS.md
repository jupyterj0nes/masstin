# Supported Artifacts

Masstin parses the following forensic artifacts to extract lateral movement data. For in-depth analysis of each artifact, see the linked articles at [weinvestigateanything.com](https://weinvestigateanything.com).

## Windows Event Logs (EVTX)

### Security.evtx

[Full article →](https://weinvestigateanything.com/en/artifacts/security-evtx-lateral-movement/)

| Event ID | Description | Logon Type |
|----------|-------------|------------|
| 4624 | Successful logon | 3 (Network), 10 (RDP) |
| 4625 | Failed logon | 3, 10 |
| 4634 | Logoff | — |
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
| SMBServer/Security | 1009 | SMB server connection attempt |
| SMBServer/Security | 551 | SMB authentication |
| SMBClient/Security | 31001 | SMB client connection to share |
| SMBClient/Connectivity | 30803 | SMB connectivity event |
| SMBClient/Connectivity | 30804 | SMB connectivity event |
| SMBClient/Connectivity | 30805 | SMB connectivity event |
| SMBClient/Connectivity | 30806 | SMB connectivity event |
| SMBClient/Connectivity | 30807 | SMB connectivity event |
| SMBClient/Connectivity | 30808 | SMB share access |

### PowerShell Remoting & WMI

[Full article →](https://weinvestigateanything.com/en/artifacts/winrm-wmi-schtasks-lateral-movement/)

| Log Source | Event ID | Description |
|------------|----------|-------------|
| WinRM/Operational | 6 | WSMan session initiation on the source host (destination in `connection` field) |
| WMI-Activity/Operational | 5858 | WMI client failure with `ClientMachine` field identifying remote origin |

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

> **Domain-joined Linux (SSSD / Active Directory):** on Ubuntu 22 + SSSD hosts, `/var/log/auth.log` is often nearly empty because PAM routes auth through the systemd journal. Masstin reads `.journal` / `.journal~` files directly and applies the same `Accepted (password|publickey)` / `Failed password` regexes as on text logs, so SSH logins from AD users surface in the timeline with no extra configuration. Combined with the audit.log `USER_LOGIN` path, this recovers the full lateral-movement picture on modern enterprise Linux.

## Winlogbeat JSON

[Full article →](https://weinvestigateanything.com/en/artifacts/winlogbeat-elastic-artifacts/)

Parses all 32 Windows Event IDs listed above from Winlogbeat JSON format (`@timestamp`, `winlog.event_id`, `winlog.event_data.*`).

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

Queries the Cortex XDR `forensics_event_log` dataset, which backs both the XDR forensic collection agent and the offline collector (triage packages uploaded to the tenant land in the same dataset). The query mirrors the event ID and source set of `parse-windows` exactly, including Security, TerminalServices-LocalSessionManager, SMBServer/Security, SmbClient/Security, RDPClient, RemoteConnectionManager, RdpCoreTS, WinRM/Operational and WMI-Activity/Operational. Regex extraction currently ships with EN / ES / DE / FR / IT keyword variants and auto-paginates via time bisection if a window saturates the 1M API cap.

---

**Total:** 32 Windows Event IDs across 10 EVTX sources + 7 Linux artifact types + Winlogbeat JSON + Cortex XDR
