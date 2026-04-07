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

## Linux Artifacts

[Full article →](https://weinvestigateanything.com/en/artifacts/linux-forensic-artifacts/)

| Source | Type | What it captures |
|--------|------|-----------------|
| `/var/log/secure` | Text | SSH success, failure, connection attempts |
| `/var/log/messages` | Text | SSH events (alternative to secure) |
| `/var/log/audit/audit.log` | Text | Authentication events via audit subsystem |
| `utmp` | Binary | Active user sessions |
| `wtmp` | Binary | Historical login/logout/boot records |
| `btmp` | Binary | Failed login attempts |
| `lastlog` | Binary | Last login per user |

## Winlogbeat JSON

[Full article →](https://weinvestigateanything.com/en/artifacts/winlogbeat-cortex-xdr-artifacts/)

Parses all 28 Windows Event IDs listed above from Winlogbeat JSON format (`@timestamp`, `winlog.event_id`, `winlog.event_data.*`).

## Cortex XDR

[Full article →](https://weinvestigateanything.com/en/artifacts/winlogbeat-cortex-xdr-artifacts/)

### Network Events (via API)

| Port | Protocol | Logon Type |
|------|----------|------------|
| 3389 | RDP | 10 |
| 445 | SMB | 3 |
| 22 | SSH | SSH |

### EVTX Forensics (via XQL)

Queries Cortex XDR for forensic event logs from: Security, TerminalServices-LocalSessionManager, SMBServer/Security, SMBClient/Security, RDPClient, RemoteConnectionManager.

---

**Total:** 28 Windows Event IDs across 9 EVTX sources + 7 Linux artifact types + Winlogbeat JSON + Cortex XDR
