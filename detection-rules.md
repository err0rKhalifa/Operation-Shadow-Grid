# Detection rules catalog

Operation Shadow Grid — 15 Splunk SPL detection rules mapped to MITRE ATT&CK. 12 fired on real attack data from this engagement. 3 are staged for techniques not exercised.

For the full attack narrative and evidence screenshots, see the [README](README.md).

---

## Detection 1 — Network port scan

| | |
|---|---|
| MITRE | T1046 — Network Service Scanning |
| Phase | 1 — Reconnaissance |
| Status | Active — fired on real data |

```spl
index=idx_network sourcetype="zeek:conn" id_resp_h="10.10.10.50" id_orig_h="10.10.10.1" proto=tcp conn_state="REJ"
```

Detects a high volume of rejected TCP connections (conn_state=REJ) from a single source to a single destination. 129,038 events in this engagement. Closed ports answer with RST, producing the REJ signature rather than S0 (which appears only against filtered ports).

Key fields: conn_state, id_orig_h, id_resp_h, proto.
Threshold: more than 1,000 REJ connections from a single source within 10 minutes.

---

## Detection 2 — Directory brute-force

| | |
|---|---|
| MITRE | T1046 — Network Service Scanning |
| Phase | 1 — Reconnaissance |
| Status | Active — fired on real data |

```spl
index=idx_network sourcetype="zeek:http" id_resp_h="10.10.10.50" status_code=404
| stats count by id_orig_h, user_agent
| where count > 50
```

Detects a burst of HTTP 404 responses from a single source — the pattern of a directory brute-force tool probing for hidden paths. User-agent gobuster/3.8 confirmed the tool.

Key fields: status_code, id_orig_h, user_agent.
Threshold: more than 50 404 responses from a single source within 5 minutes.

---

## Detection 3 — SQL injection (UNION-based)

| | |
|---|---|
| MITRE | T1190 — Exploit Public-Facing Application |
| Phase | 2 — Initial Access |
| Status | Active — fired on real data |

```spl
index=idx_network sourcetype="zeek:http" id_resp_h="10.10.10.50" uri="*UNION*SELECT*"
```

Detects SQL injection payloads in HTTP request URIs. The UNION SELECT pattern in a URI parameter is a reliable indicator of credential-extraction attempts via union-based SQLi.

Key fields: uri, id_resp_h, status_code.
Tuning: combine with status_code=200 to isolate successful injections.

---

## Detection 4 — Command injection

| | |
|---|---|
| MITRE | T1059.004 — Unix Shell |
| Phase | 2 — Initial Access |
| Status | Active — fired on real data |

```spl
index=idx_firewall host="10.10.10.50" sourcetype="syslog" "vulnerabilities/exec"
```

Detects POST requests to the DVWA command-injection endpoint via Apache access log. The injected commands travel in the POST body, which Apache does not record. The endpoint access pattern (repeated POST to /vulnerabilities/exec/ with status 200) is a reliable indicator. Full command visibility requires auditd or Sysmon process auditing.

Key fields: host, request URI, HTTP method, status code.

---

## Detection 5 — Web shell access

| | |
|---|---|
| MITRE | T1505.003 — Web Shell |
| Phase | 3 — Persistence |
| Status | Active — fired on real data |

```spl
index=idx_firewall host="10.10.10.50" sourcetype="syslog" "uploads/info.php"
```

Detects HTTP access to a PHP file in an upload directory with a cmd parameter. The curl/8.17.0 user-agent and cmd=whoami in the URI confirm the shell is being exercised.

Key fields: request URI (info.php?cmd=), user-agent, status code.
Tuning: alert on any .php file accessed in /uploads/ or /hackable/ directories.

---

## Detection 6 — Cron job persistence

| | |
|---|---|
| MITRE | T1053.003 — Cron |
| Phase | 3 — Persistence |
| Status | Active — fired on real data |

```spl
index=idx_firewall host="10.10.10.50" sourcetype="syslog" cron
```

Detects cron-job execution events in Linux syslog. The 5-minute cycle of the reverse-shell cron job is self-announcing — each execution produces a syslog entry.

Key fields: host, cron user, command, execution interval.
Tuning: baseline normal cron jobs and alert on new entries for www-data or other web-service accounts.

---

## Detection 7 — Privilege escalation: su and sudo chain

| | |
|---|---|
| MITRE | T1078.003 — Valid Accounts: Local, T1548.003 — Sudo |
| Phase | 4 — Privilege Escalation |
| Status | Active — fired on real data |

```spl
index=idx_firewall host="10.10.10.50" sourcetype="syslog" (su OR sudo)
```

Detects the escalation chain in Linux auth syslog: www-data to sysadmin via su (password reuse), then sysadmin to root via sudo su -. The sequence of session-opened messages with uid transitions (33 to 1000 to 0) reconstructs the complete path.

Key fields: su/sudo keywords, session opened, uid values, COMMAND.
Tuning: alert on any su session opened by a web-service account (uid below 100).

---

## Detection 8 — SMBExec lateral movement

| | |
|---|---|
| MITRE | T1021.002 — SMB/Windows Admin Shares |
| Phase | 5 — Lateral Movement |
| Status | Active — fired on real data |

```spl
index=idx_windows host="WS01" sourcetype="WinEventLog:Security" EventCode=4624 Logon_Type=3 Account_Name="Administrator"
```

Detects network logon (Type 3) on a workstation using the domain Administrator account via NTLM authentication. Corroborated by Event 4672 (special privileges assigned) and Zeek conn.log showing SMB traffic to port 445.

Key fields: EventCode, Logon_Type, Account_Name, Authentication_Package, Source_Network_Address.

Supporting queries:
```spl
index=idx_windows host="WS01" sourcetype="WinEventLog:Security" EventCode=4672
```
```spl
index=idx_network sourcetype="zeek:conn" id_resp_h="10.10.10.20" id_resp_p=445
```

---

## Detection 9 — Kerberoasting

| | |
|---|---|
| MITRE | T1558.003 — Kerberoasting |
| Phase | 6 — Domain Compromise |
| Status | Active — fired on real data |

```spl
index=idx_windows host="DC01" sourcetype="WinEventLog:Security" EventCode=4769 Ticket_Encryption_Type=0x17
```

Detects a TGS ticket request using RC4 encryption (0x17). Modern Kerberos negotiates AES (0x11/0x12), so an RC4 TGS request for a service account is a high-fidelity Kerberoasting indicator.

Key fields: EventCode, Ticket_Encryption_Type, Service_Name, Account_Name, Client_Address.
Evidence: Service_Name=svc_web, requested by j.smith@SHADOWGRID.LOCAL, Client_Address=::ffff:10.10.10.1.

---

## Detection 10 — DCSync

| | |
|---|---|
| MITRE | T1003.006 — DCSync |
| Phase | 6 — Domain Compromise |
| Status | Active — fired on real data |

```spl
index=idx_windows host="DC01" sourcetype="WinEventLog:Security" EventCode=4662 Account_Name="Administrator"
```

Detects directory replication requests (Event 4662) from a non-machine account. The presence of the DS-Replication-Get-Changes-All GUID ({1131f6ad-9c07-11d1-f79f-00c04fc2dcd2}) in the Properties field is the definitive DCSync indicator.

Key fields: EventCode, Account_Name, Properties (GUID), Object_Type.
Tuning: exclude machine accounts (*$) to reduce noise from legitimate DC replication.

---

## Detection 11 — Explicit credential use (DCSync corroboration)

| | |
|---|---|
| MITRE | T1003.006 — DCSync |
| Phase | 6 — Domain Compromise |
| Status | Active — fired on real data |

```spl
index=idx_windows host="DC01" sourcetype="WinEventLog:Security" EventCode=4648
```

Detects explicit-credential logon events on DC01. Corroborates DCSync by showing Account_Name: Administrator with Process: lsass.exe.

Key fields: EventCode, Account_Name, Process_Name.

---

## Detection 12 — Special privileges assigned

| | |
|---|---|
| MITRE | T1021.002 — SMB/Windows Admin Shares |
| Phase | 5 — Lateral Movement |
| Status | Active — fired on real data |

```spl
index=idx_windows host="WS01" sourcetype="WinEventLog:Security" EventCode=4672
```

Detects assignment of special privileges (SeDebugPrivilege, SeImpersonatePrivilege, SeTakeOwnershipPrivilege) to a logon session. When paired with a Type 3 logon (Detection 8), confirms an administrative remote session.

Key fields: EventCode, Account_Name, privilege list.

---

## Detection 13 — DNS tunneling exfiltration

| | |
|---|---|
| MITRE | T1048.003 — Exfiltration Over Unencrypted Non-C2 Protocol |
| Phase | 7 — Data Exfiltration |
| Status | Active — fired on real data |

```spl
index=idx_network sourcetype="zeek:dns" query="*evil-corp.com*"
```

Detects DNS tunneling by identifying abnormally long base64-encoded subdomains in DNS queries. 116 queries from 10.10.10.50 to 10.10.10.1:53, all returning SERVFAIL, with subdomain labels exceeding 40 characters.

Key fields: query, id_orig_h, rcode_name, query length.

Advanced version (query-length analytics):
```spl
index=idx_network sourcetype="zeek:dns"
| eval query_length=len(query)
| where query_length > 50
| stats count by id_orig_h, query
| sort - count
```

---

## Detection 14 — SMB lateral movement (network layer)

| | |
|---|---|
| MITRE | T1021.002 — SMB/Windows Admin Shares |
| Phase | 5 — Lateral Movement |
| Status | Active — fired on real data |

```spl
index=idx_network sourcetype="zeek:conn" id_resp_h="10.10.10.20" id_resp_p=445
```

Detects SMB connections at the network layer via Zeek conn.log. Corroborates the Windows Security log detections (Detections 8 and 12) by showing the network session to port 445 with service gssapi/smb/ntlm.

Key fields: id_orig_h, id_resp_h, id_resp_p, service, orig_bytes, resp_bytes.

---

## Detection 15 — Reverse shell outbound (host-based)

| | |
|---|---|
| MITRE | T1059.004 — Unix Shell |
| Phase | 2 — Initial Access / 3 — Persistence |
| Status | Active — compensating control for Gap 1 |

```spl
index=idx_firewall host="10.10.10.50" sourcetype="syslog" "vulnerabilities/exec"
```

Compensating control for the NAT detection gap. The reverse shell egresses over the NAT segment (192.168.119.x) where the Zeek sensor has no visibility. This host-based detection catches the shell delivery at the Apache layer rather than the wire. Every POST to the command-injection endpoint that delivered the shell payload is captured.

Key fields: request URI, HTTP method, status code.

---

## Staged rules

The following rules were written and tuned but did not fire during this engagement because the corresponding techniques were not exercised.

### Staged rule A — PowerShell abuse

| | |
|---|---|
| MITRE | T1059.001 — PowerShell |
| Status | Staged — technique not exercised |

```spl
index=idx_windows sourcetype="WinEventLog:Microsoft-Windows-PowerShell/Operational" EventCode=4104
| search ScriptBlockText="*Invoke-Mimikatz*" OR ScriptBlockText="*Invoke-Expression*" OR ScriptBlockText="*-EncodedCommand*" OR ScriptBlockText="*Net.WebClient*"
```

Detects suspicious PowerShell script-block content including encoded commands, known offensive tool invocations, and download cradles.

### Staged rule B — Brute force

| | |
|---|---|
| MITRE | T1110 — Brute Force |
| Status | Staged — technique not exercised |

```spl
index=idx_windows sourcetype="WinEventLog:Security" EventCode=4625
| stats count by Account_Name, Source_Network_Address
| where count > 5
```

Detects repeated failed logon attempts (Event 4625) from a single source, indicative of password spraying or brute-force attacks.

### Staged rule C — RDP lateral movement

| | |
|---|---|
| MITRE | T1021.001 — Remote Desktop Protocol |
| Status | Staged — technique not exercised |

```spl
index=idx_windows sourcetype="WinEventLog:Security" EventCode=4624 Logon_Type=10
```

Detects RDP logon (Type 10) on domain-joined machines. SMBExec was used instead of RDP in this engagement.

---

*Operation Shadow Grid — Detection Rules Catalog*
*Ahmed Ali Khalifa — Cybersecurity Technology Engineering, Middle Technical University, Baghdad*
