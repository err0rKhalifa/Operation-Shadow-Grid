# Detection rule catalog

All 15 Splunk detection rules with full SPL, MITRE ATT&CK mapping, severity, log source, and tuning notes.

Common alert configuration for every rule:

| | |
|---|---|
| Saved as | Splunk Alert |
| Permissions | Shared in App |
| Schedule | `*/15 * * * *` (every 15 minutes) |
| Time range | -15m to now |
| Trigger condition | Number of results > 0 |
| Trigger frequency | Once per search run |
| Trigger action | Add to Triggered Alerts |

12 of 15 rules have real attack data. Detections 3, 5, and 7 return no data because PowerShell payloads, password brute-force, and RDP were not exercised in this engagement. The rules are saved as forward coverage.

---

## Summary matrix

| # | Detection | MITRE | Severity | Index / Sourcetype | Status |
|---|-----------|-------|----------|--------------------|--------|
| 1 | Port scan | T1046 | High | idx_network / zeek:conn | Active |
| 2 | Web application exploit | T1190 | Critical | idx_network / zeek:http | Active (tuned) |
| 3 | PowerShell abuse | T1059.001 | Critical | idx_windows / Sysmon | Staged (no data) |
| 4 | Cron persistence | T1053.003 | Critical | idx_firewall / syslog | Active |
| 5 | Brute force | T1110 | High | idx_windows / Security 4625 | Staged (no data) |
| 6 | Credential abuse (multi-host logon) | T1078 | High | idx_windows / Security 4624 | Active |
| 7 | RDP lateral movement | T1021.001 | High | idx_windows / Security 4624 | Staged (no data) |
| 8 | PsExec / SMBExec remote admin | T1021.002 | Critical | idx_windows / Security 4624 | Active |
| 9 | Kerberoasting | T1558.003 | Critical | idx_windows / Security 4769 | Active |
| 10 | DCSync | T1003.006 | Critical | idx_windows / Security 4662 | Active |
| 11 | LSASS credential access | T1003.001 | Critical | idx_windows / Sysmon | Active (tuned) |
| 12 | Golden Ticket (RC4 TGT) | T1558.001 | Critical | idx_windows / Security 4768 | Active |
| 13 | DNS tunneling exfiltration | T1048.003 | Critical | idx_network / zeek:dns | Active (tuned) |
| 14 | Attack chain correlation | Multiple | Critical | Multiple | Active |
| 15 | Reverse shell outbound | TA0010 | Critical | idx_firewall / syslog | Active |

---

## Detection 1 — Port scan

| | |
|---|---|
| MITRE | T1046 — Network Service Scanning |
| Severity | High |
| Log source | idx_network / zeek:conn |

```spl
index=idx_network sourcetype="zeek:conn" conn_state="S0"
| stats count as scan_count dc(id_resp_p) as unique_ports by id_orig_h, id_resp_h
| where scan_count > 50 AND unique_ports > 20
| eval severity="High", mitre="T1046", description="Port scan detected"
| table id_orig_h, id_resp_h, scan_count, unique_ports, severity, mitre
```

`conn_state="S0"` captures SYN-sent-no-reply connections (the half-open scan fingerprint). `dc(id_resp_p)` counts distinct destination ports. Dual threshold (scan_count > 50 AND unique_ports > 20) requires both volume and breadth to suppress false positives.

Note: in this engagement, the actual scan traffic appeared as `conn_state=REJ` (129,038 events) because pfSense answered with RST rather than silently dropping. The rule covers the S0 case; a production deployment should alert on both S0 and REJ from a single source.

---

## Detection 2 — Web application exploit (tuned)

| | |
|---|---|
| MITRE | T1190 — Exploit Public-Facing Application |
| Severity | Critical |
| Log source | idx_network / zeek:http |

```spl
index=idx_network sourcetype="zeek:http"
  (uri="*UNION*" OR uri="*SELECT*" OR uri="*../*" OR uri="*cmd=*"
   OR uri="*<script>*" OR uri="*exec*")
  NOT uri="*splunkd*" NOT uri="*en-US*" NOT uri="*servicesNS*"
| stats count by id_orig_h, id_resp_h, uri, method
| eval severity="Critical", mitre="T1190"
```

The NOT clauses were added because Splunk's own web UI paths (splunkd, en-US, servicesNS) contain substrings like "select" and "exec" and were causing false positives. Diagnosed with `| stats count by uri` before adding the exclusions.

---

## Detection 3 — PowerShell abuse (staged)

| | |
|---|---|
| MITRE | T1059.001 — PowerShell |
| Severity | Critical |
| Log source | idx_windows / Sysmon EventCode 1 |
| Status | Staged — no PowerShell attacks were executed in this engagement |

```spl
index=idx_windows sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=1
  Image="*powershell*"
  (CommandLine="*-enc*" OR CommandLine="*-nop*" OR CommandLine="*IEX*"
   OR CommandLine="*Invoke-*" OR CommandLine="*DownloadString*" OR CommandLine="*bypass*")
| table _time, host, User, CommandLine
```

`-enc` = Base64-encoded command, `-nop` = NoProfile, `bypass` = execution-policy bypass, `IEX`/`Invoke-`/`DownloadString` = fileless download cradles.

---

## Detection 4 — Cron persistence

| | |
|---|---|
| MITRE | T1053.003 — Scheduled Task/Job: Cron |
| Severity | Critical |
| Log source | idx_firewall / syslog (host 10.10.10.50) |

```spl
index=idx_firewall host="10.10.10.50" (crontab OR CRON)
  (python OR socket OR connect OR "/bin/bash")
| stats count by host, _raw
| eval severity="Critical", mitre="T1053.003"
```

`(crontab OR CRON)` catches both installation and execution. The second group narrows to reverse-shell-looking jobs, filtering out legitimate cron (backups, log rotation). Fires every cycle because the planted cron calls back every 5 minutes.

---

## Detection 5 — Brute force (staged)

| | |
|---|---|
| MITRE | T1110 — Brute Force |
| Severity | High |
| Log source | idx_windows / WinEventLog:Security EventCode 4625 |
| Status | Staged — no brute-force attacks were executed in this engagement |

```spl
index=idx_windows sourcetype="WinEventLog:Security" EventCode=4625
| stats count as fail_count values(Account_Name) as accounts by IpAddress
| where fail_count > 5
| eval severity="High", mitre="T1110"
```

EventCode 4625 = failed logon. Grouping by source IP with `values(Account_Name)` reveals whether the pattern is brute force (one account) or password spraying (many accounts). The threshold of fail_count > 5 filters out normal typos.

---

## Detection 6 — Credential abuse / multi-host logon

| | |
|---|---|
| MITRE | T1078 — Valid Accounts |
| Severity | High |
| Log source | idx_windows / WinEventLog:Security EventCode 4624 Logon_Type 3 |

```spl
index=idx_windows sourcetype="WinEventLog:Security" EventCode=4624 Logon_Type=3
  Account_Name IN ("Administrator","j.smith","localadmin")
| stats dc(host) as unique_hosts values(host) as hosts by Account_Name
| where unique_hosts > 1
| eval severity="High", mitre="T1078"
```

Detects one privileged account authenticating across multiple hosts over the network. Originally used `NOT Account_Name="*$"` to exclude machine accounts, but it returned nothing due to field-matching behavior. Switched to an explicit allow-list after diagnosing with `| stats count by Account_Name`. Allow-lists are often more reliable than wildcard deny-lists.

---

## Detection 7 — RDP lateral movement (staged)

| | |
|---|---|
| MITRE | T1021.001 — Remote Desktop Protocol |
| Severity | High |
| Log source | idx_windows / WinEventLog:Security EventCode 4624 Logon_Type 10 |
| Status | Staged — SMBExec was used instead of RDP in this engagement |

```spl
index=idx_windows sourcetype="WinEventLog:Security" EventCode=4624 Logon_Type=10
| table _time, host, Account_Name, IpAddress
| eval severity="High", mitre="T1021.001"
```

Logon_Type=10 = RemoteInteractive (RDP). Completes coverage of the lateral-movement tactic alongside Detection 8.

---

## Detection 8 — PsExec / SMBExec remote admin

| | |
|---|---|
| MITRE | T1021.002 — SMB/Windows Admin Shares |
| Severity | Critical |
| Log source | idx_windows / WinEventLog:Security EventCode 4624 Logon_Type 3 |

```spl
index=idx_windows sourcetype="WinEventLog:Security" EventCode=4624 Logon_Type=3
  Account_Name IN ("Administrator","localadmin")
| stats count by _time, host, Account_Name, IpAddress
| eval severity="Critical", mitre="T1021.002"
```

SMBExec and PsExec authenticate over SMB producing Logon_Type=3. Filtering on admin accounts focuses on the high-impact case. Pairs with Event 7045 (service creation) — the smbexec service was visible in the Windows Security dashboard.

---

## Detection 9 — Kerberoasting

| | |
|---|---|
| MITRE | T1558.003 — Kerberoasting |
| Severity | Critical |
| Log source | idx_windows / WinEventLog:Security EventCode 4769 (DC01) |

```spl
index=idx_windows host="DC01" EventCode=4769 Ticket_Encryption_Type="0x17"
| table _time, Account_Name, Service_Name, Client_Address, Ticket_Encryption_Type
| eval severity="Critical", mitre="T1558.003"
```

EventCode 4769 = TGS requested (routine on a DC). Ticket_Encryption_Type="0x17" = RC4. Modern Windows uses AES (0x12); an RC4 request is the attacker choosing weak crypto to crack offline. The stored field format was confirmed with `| stats count by Ticket_Encryption_Type`.

---

## Detection 10 — DCSync

| | |
|---|---|
| MITRE | T1003.006 — DCSync |
| Severity | Critical |
| Log source | idx_windows / WinEventLog:Security EventCode 4662 (DC01) |

```spl
index=idx_windows host="DC01" EventCode=4662 Access_Mask="0x100"
  Object_Type="*1131f6aa-9c07-11d1-f79f-00c04fc2dcd2*"
  NOT Account_Name="*$"
| table _time, Account_Name, Object_Type, Access_Mask
| eval severity="Critical", mitre="T1003.006"
```

Access_Mask="0x100" = Control Access right used by replication. The GUID 1131f6aa-9c07-11d1-f79f-00c04fc2dcd2 is DS-Replication-Get-Changes. `NOT Account_Name="*$"` excludes legitimate DC machine accounts — a user account replicating is the anomaly.

Note: the live evidence also showed the DS-Replication-Get-Changes-All GUID (1131f6ad) in Event 4662 for the same Administrator account. Both GUIDs indicate DCSync; the -All variant is what secretsdump specifically requests.

---

## Detection 11 — LSASS credential access (tuned)

| | |
|---|---|
| MITRE | T1003.001 — LSASS Memory |
| Severity | Critical |
| Log source | idx_windows / Sysmon EventCode 1 |

```spl
index=idx_windows sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=1
  (CommandLine="*lsass*" OR CommandLine="*mimikatz*" OR CommandLine="*sekurlsa*"
   OR CommandLine="*procdump*" OR CommandLine="*comsvcs*" OR CommandLine="*MiniDump*")
  NOT Image="*lsass.exe"
| eval severity="Critical", mitre="T1003.001"
```

`NOT Image="*lsass.exe"` was added because legitimate lsass.exe self-references caused false positives. Excluding the real process keeps the alert focused on other processes touching LSASS.

---

## Detection 12 — Golden Ticket (RC4 TGT)

| | |
|---|---|
| MITRE | T1558.001 — Golden Ticket |
| Severity | Critical |
| Log source | idx_windows / WinEventLog:Security EventCode 4768 (DC01) |

```spl
index=idx_windows host="DC01" EventCode=4768 Ticket_Encryption_Type="0x17"
| table _time, Account_Name, Client_Address, Ticket_Encryption_Type
| eval severity="Critical", mitre="T1558.001"
```

EventCode 4768 = TGT request (the master ticket), compared to 4769 = per-service TGS. An RC4 (0x17) TGT is suspicious because forged Golden Tickets often use RC4.

---

## Detection 13 — DNS tunneling exfiltration (tuned)

| | |
|---|---|
| MITRE | T1048.003 — Exfiltration Over Unencrypted Non-C2 Protocol |
| Severity | Critical |
| Log source | idx_network / zeek:dns |

```spl
index=idx_network sourcetype="zeek:dns"
| eval query_length=len(query)
| where query_length > 50 AND (rcode_name="NXDOMAIN" OR rcode_name="SERVFAIL")
| stats count as query_count avg(query_length) as avg_len by id_orig_h, query
| where query_count > 10
| eval severity="Critical", mitre="T1048.003"
```

Three stacked indicators: query_length > 50 (long subdomains), NXDOMAIN/SERVFAIL (tunneling domains don't resolve), and query_count > 10 (tunneling is high-volume). The original length-only rule was too noisy; the failure-code and volume conditions sharpened it.

---

## Detection 14 — Attack chain correlation

| | |
|---|---|
| MITRE | Multiple (cross-phase) |
| Severity | Critical |
| Log source | Multiple (zeek:conn, zeek:http, zeek:dns) |

```spl
index=idx_network sourcetype="zeek:conn" conn_state="S0"
| stats dc(id_resp_p) as ports by id_orig_h | where ports > 20 | eval phase="1-Recon"
| append [ search index=idx_network sourcetype="zeek:http" uri="*UNION*"
    | stats count by id_orig_h | eval phase="2-Exploit" ]
| append [ search index=idx_network sourcetype="zeek:conn" id_resp_p=445
    | stats count by id_orig_h | eval phase="5-Lateral" ]
| append [ search index=idx_network sourcetype="zeek:dns"
    | eval ql=len(query) | where ql>50 | stats count by id_orig_h | eval phase="7-Exfil" ]
| stats values(phase) as phases dc(phase) as phase_count by id_orig_h
| where phase_count >= 2
| eval severity="Critical", description="Multi-phase attack from single source"
```

Each `append` runs an independent per-phase sub-search and tags results with a phase label. The final stats counts how many distinct phases each IP touched. phase_count >= 2 almost certainly indicates an attacker rather than a false positive. Correlation drastically reduces noise compared to single-phase rules.

---

## Detection 15 — Reverse shell outbound (host-based)

| | |
|---|---|
| MITRE | TA0010 — Exfiltration / C2 callback |
| Severity | Critical |
| Log source | idx_firewall / syslog (host 10.10.10.50) |

```spl
index=idx_firewall host="10.10.10.50"
  (connect OR socket OR SOCK_STREAM)
  ("192.168." OR "10.0." OR "172.16.")
  ("4444" OR "5555" OR "6666" OR "1337" OR "9001")
| eval severity="Critical", mitre="TA0010", description="Reverse shell callback"
| table _time, host, _raw, severity
```

Socket/connect activity logged on the host (via auditd/syslog), to a private IP range, on a common C2/reverse-shell port (4444 = Metasploit default, 5555 = the cron callback). This is the compensating control for the NAT detection gap: when network visibility fails, host telemetry fills the gap.

---

## Detection-engineering notes

1. Put thresholds in the search, trigger on > 0. The SPL encodes the logic (where unique_ports > 20), so any result means a real hit.
2. Diagnose before tuning. When a rule is noisy or empty, run `| stats count by <field>` to see the actual data. Never guess.
3. Stack weak signals into strong ones. Detection 13 (length + failure code + volume) and Detection 14 (multi-phase) demonstrate high-fidelity through correlation.
4. Allow-lists beat wildcard deny-lists for account filtering (Detection 6).
5. Host telemetry covers network blind spots (Detection 15 vs the NAT gap).
6. Permissions matter. A Private alert is invisible to the team. Everything must be Shared in App.

---

*Operation Shadow Grid — Detection Rule Catalog*
*Ahmed Ali Khalifa — Cybersecurity Technology Engineering, Middle Technical University, Baghdad*
