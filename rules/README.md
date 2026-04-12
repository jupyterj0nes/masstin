# Masstin custom parser rules library

This directory holds community-contributed YAML rule files for masstin's `parse-custom` action. Each rule teaches masstin how to parse the logs of a specific VPN, firewall or proxy vendor into the unified lateral-movement CSV timeline.

**Full schema specification:** see [`docs/custom-parsers.md`](../docs/custom-parsers.md).

## Status legend

- ✅ **complete** — researched, tested against real sample lines, ready to use
- 🚧 **stub** — file exists, structure in place, but `parsers: []` — needs someone to write it
- 📝 **planned** — not started yet, listed here as a roadmap item

## Current rules

| Category | Rule | Status | Parsers | Vendor format |
|----------|------|--------|---------|---------------|
| VPN | [`vpn/palo-alto-globalprotect.yaml`](vpn/palo-alto-globalprotect.yaml) | ✅ complete | 5 | SYSTEM log subtype=globalprotect (legacy CSV syslog) |
| VPN | [`vpn/cisco-anyconnect.yaml`](vpn/cisco-anyconnect.yaml) | ✅ complete | 4 | ASA syslog `%ASA-<level>-<msgid>` (113039/722022/722023/113019) |
| VPN | [`vpn/fortinet-ssl-vpn.yaml`](vpn/fortinet-ssl-vpn.yaml) | ✅ complete | 3 | FortiGate `type=event subtype=vpn` key=value (tunnel-up/down/ssl-login-fail) |
| VPN | [`vpn/openvpn.yaml`](vpn/openvpn.yaml) | ✅ complete | 4 | OpenVPN free-form syslog (Peer Connection / AUTH_FAILED / SIGTERM) |
| Firewall | [`firewall/palo-alto-traffic.yaml`](firewall/palo-alto-traffic.yaml) | ✅ complete | 2 | PAN-OS TRAFFIC log CSV — authenticated sessions with User-ID |
| Firewall | [`firewall/cisco-asa.yaml`](firewall/cisco-asa.yaml) | ✅ complete | 6 | ASA syslog (113004/113005/605004/605005/716001/716002) |
| Firewall | [`firewall/fortinet-fortigate.yaml`](firewall/fortinet-fortigate.yaml) | ✅ complete | 4 | FortiGate `type=event subtype=system\|user` (admin login, user auth) |
| Proxy | [`proxy/squid.yaml`](proxy/squid.yaml) | ✅ complete | 3 | Squid access.log native (CONNECT tunnel, HTTP, TCP_DENIED) |

**Totals:** 8 rules, 31 parsers, all researched against vendor documentation and validated against sample log lines in [`*/samples/`](./).

## References

Every rule in this library was written from the vendor's official log format documentation and then validated against real sample log lines. The references below are the primary sources used:

| Rule | Vendor docs / format reference |
|------|-------------------------------|
| `vpn/palo-alto-globalprotect.yaml` | [GlobalProtect Log Fields (Palo Alto official)](https://docs.paloaltonetworks.com/ngfw/administration/monitoring/use-syslog-for-monitoring/syslog-field-descriptions/globalprotect-log-fields) · [Event Descriptions for GlobalProtect](https://docs.paloaltonetworks.com/globalprotect/10-1/globalprotect-admin/logging-for-globalprotect-in-pan-os/event-descriptions-for-the-globalprotect-logs-in-pan-os) · [Sample log lines (Palo Alto Splunk Data Generator)](https://github.com/PaloAltoNetworks/Splunk-App-Data-Generator/blob/master/bin/data/pan_globalprotect.txt) |
| `vpn/cisco-anyconnect.yaml` | [Cisco ASA Series Syslog Messages](https://www.cisco.com/c/en/us/td/docs/security/asa/syslog/b_syslog.html) · [ManageEngine — ASA Event 113039 format](https://www.manageengine.com/products/eventlog/cisco-asa-events-auditing/cisco-anyconnect-parent-session-started-113039.html) |
| `vpn/fortinet-ssl-vpn.yaml` | [FortiOS Log Message Reference](https://docs.fortinet.com/document/fortigate/latest/fortios-log-message-reference) · [Understanding VPN related logs (FortiGate cookbook)](https://docs.fortinet.com/document/fortigate/6.2.0/cookbook/834425/understanding-vpn-related-logs) · [LOG_ID_EVENT_SSL_VPN_USER_SSL_LOGIN_FAIL 39426](https://docs.fortinet.com/document/fortigate/7.6.6/fortios-log-message-reference/39426/39426-log-id-event-ssl-vpn-user-ssl-login-fail) |
| `vpn/openvpn.yaml` | [OpenVPN 2.6 Reference Manual](https://openvpn.net/community-resources/reference-manual-for-openvpn-2-6/) · [OpenVPN Access Server logging docs](https://openvpn.net/as-docs/logging.html) |
| `firewall/palo-alto-traffic.yaml` | [Traffic Log Fields (PAN-OS 11.0)](https://docs.paloaltonetworks.com/pan-os/11-0/pan-os-admin/monitoring/use-syslog-for-monitoring/syslog-field-descriptions/traffic-log-fields) · [Syslog Field Descriptions index](https://docs.paloaltonetworks.com/ngfw/administration/monitoring/use-syslog-for-monitoring/syslog-field-descriptions) |
| `firewall/cisco-asa.yaml` | [ASA Syslog Messages 101001–199021](https://www.cisco.com/c/en/us/td/docs/security/asa/syslog/b_syslog/syslogs1.html) · [ASA Syslog Messages 715001–721019](https://www.cisco.com/c/en/us/td/docs/security/asa/syslog/asa-syslog/syslog-messages-715001-to-721019.html) · [Messages by Severity Level](https://www.cisco.com/c/en/us/td/docs/security/asa/syslog/b_syslog/syslogs-sev-level.html) |
| `firewall/fortinet-fortigate.yaml` | [FortiOS Log Message Reference](https://docs.fortinet.com/document/fortigate/latest/fortios-log-message-reference) |
| `proxy/squid.yaml` | [Squid LogFormat feature reference](https://wiki.squid-cache.org/Features/LogFormat) · [Squid FAQ — Log Files](https://wiki.squid-cache.org/SquidFaq/SquidLogs) · [logformat directive](https://www.squid-cache.org/Doc/config/logformat/) |

If you're writing a new rule or updating an existing one, add your primary sources to this table in the same PR.

## Using a rule

```bash
# Single rule file
masstin -a parse-custom --rules rules/vpn/palo-alto-globalprotect.yaml -f vpn.log -o timeline.csv

# Whole directory (all .yaml files in subdirectories)
masstin -a parse-custom --rules rules/ -f vpn.log -f firewall.log -o timeline.csv

# Dry-run: show first matches + rejected lines, no CSV written
masstin -a parse-custom --rules rules/vpn/palo-alto-globalprotect.yaml -f vpn.log --dry-run
```

## Contributing a new rule

1. **Pick a target product.** Prefer vendors with public documentation and stable log formats.
2. **Collect real sample lines.** At least 5-10 lines per event type you want to cover. Put them in `rules/<category>/samples/<rule>.sample.log`.
3. **Read the schema.** [`docs/custom-parsers.md`](../docs/custom-parsers.md) has the full reference for `meta`, `prefilter`, `match`, `extract`, `sub_extract`, `map`, and the 14 destination fields of `LogData`.
4. **Write the rule.** Start from an existing rule as a template — `palo-alto-globalprotect.yaml` is a good reference for the `csv` + `sub_extract: keyvalue` pattern.
5. **Iterate with `--dry-run`.** Run against your sample file; inspect the matched records and the rejected lines; tune `match` and `map` until everything you care about is covered.
6. **Add a `reference_url`** in the `meta` block pointing to the official log format documentation.
7. **Update this README** — move your rule from 🚧 to ✅ in the table above.
8. **Open a pull request.** Include the sample file (anonymised: replace real usernames, IPs, hostnames with `user1`, `10.0.0.1`, etc.).

## Design principles

- **One file per vendor+format combination.** Don't mix Palo Alto SYSTEM logs and PAN-OS 9.1+ dedicated `globalprotect` logs in the same file — they are different formats.
- **Prefer narrow matches over broad regex.** `contains: ["globalprotectgateway-auth-succ"]` is cheaper and safer than `regex: '.*globalprotectgateway-.*-succ.*'`.
- **Every matched line should produce one `LogData` record.** The 14 columns are a fixed schema; map your vendor's fields into them.
- **Non-logon events are OK to reject.** If a log line isn't a logon, logoff, or remote connection relevant to lateral movement, let it fall through to the rejected log — masstin is a lateral movement tracker, not a generic log aggregator.
- **Use `logon_type: "VPN"`, `"FW"`, `"PROXY"`** or a similar short tag so the downstream graph can distinguish sources.
