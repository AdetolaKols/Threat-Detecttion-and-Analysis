# SIGNALS BEFORE THE NOISE

----
### Incident Reference: IR-2025-1209-01
**Analyst:** Adetola Kols | Cybersecurity Analyst  
**Platform:** Microsoft Sentinel | Workspace: law-cyber-range  
**Report Written:** 01 May 2026  
**Investigation Window:** 09 December 2025 00:00 UTC to 23 December 2025 23:59 UTC  
**Severity:** HIGH  
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

On 11 December 2025, PHTG deployed an internal endpoint health service called HealthCloud. The following day, a cloud engineer (Sarah Chen) posted a LinkedIn update celebrating the rollout. The photo accompanying the post inadvertently exposed a live Azure Virtual Machine's public IP address (74.249.82.162), internal IP (10.0.0.152), VM name (azwks-phtg-02), subscription ID, OS details, and network topology — sufficient for an external actor to begin targeted reconnaissance immediately. This proactive hunt was initiated to determine whether that exposure had been acted upon.

Telemetry confirmed it had. Within hours of the LinkedIn post, the VM's exposed RDP port (3389) drew 194 inbound connection events from 173 unique public IP addresses across 11 countries. Of those, 57 IPs progressed from probe to accepted connection. An actor operating from Uruguay (173.244.55.131 and 173.244.55.128) successfully authenticated via RDP using the account `vmadminusername` on 12 December 2025, achieving 23 successful logon events across the investigation window. Following initial access, the actor opened sensitive internal documents, downloaded and executed a Meterpreter payload (classified as `Trojan:Win32/Meterpreter.gen!E`), disabled Microsoft Defender by switching it to Passive Mode to bypass repeated quarantine actions, and established persistence by disguising the payload as a HealthCloud service binary (`PHTG.exe`) inside the legitimate service directory. Command and control beacons were directed to `173.244.55.130` on port 4444 — part of the same Uruguayan subnet as the RDP source IPs, indicating a coordinated attacker-controlled infrastructure. This attack bears the hallmarks of a targeted operation: the actor demonstrably leveraged the specific infrastructure details exposed in the LinkedIn post, chose a victim within the same organisation, and deliberately camouflaged persistence inside a newly deployed internal service that would appear routine to defenders.

---

### Key Findings at a Glance

| Item | Detail |
|---|---|
| Compromised User | vmadminusername |
| Attack Type | RDP Brute Force → Meterpreter Post-Exploitation |
| Hosts Compromised | azwks-phtg-02 |
| Data Exfiltrated | Internal PHTG notes; notes_sarah.txt (security-relevant content) |
| Exfiltration Destination | 173.244.55.130:4444 (Uruguay, South America) |
| Credentials Compromised | vmadminusername (local admin account) |
| Backdoor Account Created | Not confirmed |
| C2 Infrastructure | 173.244.55.130 — Port 4444 — Meterpreter |
| Staging Server | 173.244.55.131 / 173.244.55.128 (RDP source, Uruguay) |
| Attacker Email | Not identified |
| Persistence Mechanisms | PHTG.exe in C:\ProgramData\PHTG\HealthCloud\ via Launch.bat |
| Evidence Gaps | Defender state change logs incomplete; Q30 defender mode not fully confirmed in telemetry |

---

## Environment Overview

| Field | Value |
|---|---|
| SIEM Platform | Microsoft Sentinel |
| Workspace | law-cyber-range |
| Log Tables | DeviceNetworkEvents, DeviceLogonEvents, DeviceProcessEvents, DeviceFileEvents, DeviceEvents |
| Log Sources | Microsoft Defender for Endpoint (MDE) |
| Domain | PHTG |
| Key Fields | Timestamp, DeviceName, RemoteIPType, LocalPort, LogonType, ActionType, SHA256, AdditionalFields |

### Hosts in Scope

| Role | Hostname | IP Address |
|---|---|---|
| Target VM (Cloud Workstation) | azwks-phtg-02 | Public: 74.249.82.162 / Private: 10.0.0.152 |
| Attacker RDP Source | Unknown | 173.244.55.131 (Uruguay) |
| Attacker RDP Source | Unknown | 173.244.55.128 (Uruguay) |
| Attacker C2 Server | Unknown | 173.244.55.130 (Uruguay) |

---

## Incident Trigger

This was a proactive, hypothesis-driven hunt with no prior alert. The trigger was an OSINT review of employee social media. A cloud engineer at PHTG posted a photo on LinkedIn celebrating the rollout of the HealthCloud service. Analysis of the visible screen in the photo revealed a live Azure portal session displaying full VM configuration details for `azwks-phtg-02`, including its public IP address `74.249.82.162`. The hunt lead directed the analyst to determine whether the exposed information had been leveraged by a threat actor, and to follow the telemetry wherever it led.

---

## MITRE ATT&CK Mapping

| Tactic | Technique | ID | Evidence |
|---|---|---|---|
| Initial Access | Valid Accounts — Local Accounts | T1078.003 | vmadminusername authenticated successfully via RDP from Uruguay |
| Initial Access | External Remote Services | T1133 | RDP (port 3389) exposed directly to internet on public IP |
| Execution | User Execution — Malicious File | T1204.002 | Sarah_Chen_Notes.exe executed manually by attacker post-logon |
| Execution | Command and Scripting Interpreter — PowerShell | T1059.001 | powershell.exe spawned from explorer.exe during attacker session |
| Persistence | Boot or Logon Autostart — Scheduled Task | T1053.005 | Launch.bat in HealthCloud directory configured for persistent execution |
| Defence Evasion | Masquerading — Match Legitimate Name | T1036.005 | Payload renamed PHTG.exe and placed in HealthCloud service directory |
| Defence Evasion | Obfuscated Files — Double Extension | T1027 | Sarah_Chen_Notes.exe.Txt used to bypass file type inspection |
| Defence Evasion | Impair Defences — Disable or Modify Tools | T1562.001 | Microsoft Defender switched to Passive Mode to allow payload execution |
| Credential Access | Brute Force — Password Guessing | T1110.001 | 646 LogonFailed events with InvalidUserNameOrPassword before success |
| Discovery | File and Directory Discovery | T1083 | Attacker opened Notes 12122025.txt and notes_sarah.txt via notepad.exe |
| Collection | Data from Local System | T1005 | Internal PHTG notes and security-relevant content accessed |
| Command and Control | Non-Standard Port | T1571 | Meterpreter beacon to 173.244.55.130 on port 4444 |
| Command and Control | Remote Access Software | T1219 | Meterpreter (Trojan:Win32/Meterpreter.gen!E) used as C2 framework |
| Exfiltration | Exfiltration Over C2 Channel | T1041 | Data exfiltration path via established Meterpreter session |

---

## Investigation Findings

### Phase 1: Initial Access

**Who:** Unknown threat actor operating from Uruguay (173.244.55.131 and 173.244.55.128)  
**What:** RDP brute force against `vmadminusername` resulting in 23 successful authentications  
**Where:** azwks-phtg-02 — Port 3389 — exposed directly to the internet  
**When:** First successful authentication: 12 December 2025; activity continued through 13 December 2025  

The attacker identified the target through OSINT — specifically the LinkedIn post by Sarah Chen which exposed the VM's public IP address `74.249.82.162`. Between 9 December and 23 December 2025, port 3389 on the VM received 194 inbound connection events from 173 unique public IPs across 11 countries. Of those, 57 IPs progressed from probe to accepted connection, indicating a broad automated scanning wave followed by targeted follow-up. The Uruguayan actor distinguished themselves by achieving successful authentication — 23 successful RDP logons using the account `vmadminusername` across two source IPs (`173.244.55.131` and `173.244.55.128`). Of 675 total RDP authentication events, 646 were failures with reason `InvalidUserNameOrPassword`, confirming a sustained brute force campaign before the correct credential was identified. Successful authentications originated from only 2 countries — the United States and Uruguay — with Uruguay representing the anomalous and unrecognised access.

---

### Phase 2: Execution

**What:** Download, staging, and execution of a Meterpreter payload disguised as a text file  
**Where:** C:\Users\vmAdminUsername\Documents\PHTG\ and C:\ProgramData\PHTG\HealthCloud\  
**When:** 12 December 2025, beginning approximately 14:11 UTC  

Following successful RDP authentication, the attacker downloaded a file identified initially as `Sarah_Chen_Notes.Txt.crdownload` — a Chrome partial download — which completed and was renamed to `Sarah_Chen_Notes.Txt`. The attacker then renamed it to `Sarah_Chen_Notes.exe.Txt` (double-extension evasion) before stripping the false `.Txt` extension to produce `Sarah_Chen_Notes.exe`. Microsoft Defender detected and quarantined the payload three times between approximately 14:11 and 14:17. The attacker responded by switching Defender to Passive Mode, which allowed subsequent execution to proceed unblocked. The payload was classified by MDE as `Trojan:Win32/Meterpreter.gen!E` with SHA256 `224462ce5e3304e3fd0875eeabc829810a894911e3d4091d4e60e67a2687e695`. First execution ran under the name `Sarah_Chen_Notes.exe`. A C2 beacon was directed to `173.244.55.130:4444` — part of the same Uruguayan /24 subnet as the attacker's RDP sources, confirming shared infrastructure. The initial C2 connection returned `ConnectionFailed`, suggesting the listener was not yet active at the time of first execution.

---

### Phase 3: Privilege Escalation

**What:** Attacker operated with a local administrative account throughout  
**Where:** azwks-phtg-02  
**When:** Throughout 12–13 December 2025  

No additional privilege escalation technique was observed beyond the initial use of `vmadminusername` — a local account with administrative rights. The account name itself (`vmadminusername`) is a generic placeholder that suggests default or misconfigured credential hygiene. The attacker leveraged this account for all subsequent file, process, and persistence activity without needing to escalate further, indicating the initial brute-forced account already carried sufficient privileges for the attacker's objectives.

---

### Phase 4: Lateral Movement

**What:** RDP used as the primary remote access mechanism; no confirmed lateral movement to additional hosts  
**Where:** External → azwks-phtg-02 via public RDP  
**When:** 12–13 December 2025  

Lateral movement beyond the initial target host was not confirmed within the investigation window. The attacker's access remained focused on `azwks-phtg-02`. However, the VM sits on the `Cyber-Range-VNet / Cyber-Range-Subnet` with private IP `10.0.0.152`, meaning internal network access was available to the attacker through the compromised session. The presence of `azwks-phtg-01` in the same subnet warrants follow-on investigation to confirm no lateral movement occurred that fell outside the current telemetry scope.

---

### Phase 5: Collection and Exfiltration

**What:** Internal PHTG documents accessed; Meterpreter C2 channel established for data exfiltration  
**Where:** C:\Users\vmAdminUsername\Documents\PHTG\  
**When:** 12 December 2025, starting approximately 04:08 UTC  

The first notable operator-initiated action after session startup was the opening of `Notes 12122025.txt` via `notepad.exe` at approximately 04:08 UTC on 12 December 2025. Minutes later, `notes_sarah.txt` was opened — a file containing internal security-relevant content linked to Sarah Chen, the engineer whose LinkedIn post triggered this hunt. The review of `notes_sarah.txt` is particularly significant as it would have provided the attacker with insider knowledge about PHTG's infrastructure, reducing the effort required for further compromise. Data exfiltration through the Meterpreter C2 channel on port 4444 to `173.244.55.130` was established as the attacker's outbound path, though full confirmation of data volume exfiltrated was not possible within available telemetry.

---

### Phase 6: Persistence and Defence Evasion

**What:** Payload staged in legitimate HealthCloud service directory; renamed to blend with legitimate binaries; Defender bypassed via Passive Mode  
**Where:** C:\ProgramData\PHTG\HealthCloud\  
**When:** 13 December 2025, approximately 10:14–10:19 UTC  

On 13 December 2025, the attacker moved the payload from the user's Documents folder into `C:\ProgramData\PHTG\HealthCloud\` — the directory belonging to the legitimate HealthCloud service rolled out just two days prior on 11 December 2025. The payload was renamed from `Sarah_Chen_Notes.exe` to `PHTG.exe`, deliberately matching the naming convention of the legitimate service to blend with expected baseline activity. A batch file wrapper (`Launch.bat`, renamed from `Launch.txt`) was created in the same directory to provide a launch mechanism. This approach exploited the recency of HealthCloud's deployment — defenders and detection rules would not yet have established a behavioural baseline for the service, making malicious binaries within its directory difficult to distinguish from legitimate components. Microsoft Defender was previously switched to Passive Mode to allow execution, and this state persisted across subsequent payload runs. A PowerShell script (`_ps1`, renamed from `_txt`) was also observed, suggesting additional scripted activity not fully recovered within the investigation window.

---

## Attack Timeline

```
12 Dec 2025 — azwks-phtg-02

~02:06 UTC   azwks-phtg-02   -   First successful RDP authentication from 173.244.55.131 (Uruguay) — vmadminusername
~02:11 UTC   azwks-phtg-02   -   Sarah_Chen_Notes.Txt.crdownload appears in Downloads (payload delivery begins)
~02:13 UTC   azwks-phtg-02   -   File renamed from .crdownload to Sarah_Chen_Notes.Txt
~02:14 UTC   azwks-phtg-02   -   File renamed to Sarah_Chen_Notes.exe.Txt (double-extension evasion)
~02:18 UTC   azwks-phtg-02   -   File created/renamed to Sarah_Chen_Notes.exe (weaponised)
~02:19 UTC   azwks-phtg-02   -   First C2 beacon attempt to 173.244.55.130:4444 — ConnectionFailed
~04:08 UTC   azwks-phtg-02   -   notepad.exe opens Notes 12122025.txt (first operator-initiated action)
~04:15 UTC   azwks-phtg-02   -   notepad.exe opens notes_sarah.txt (sensitive internal document accessed)
~04:26 UTC   azwks-phtg-02   -   powershell.exe spawned from explorer.exe

13 Dec 2025 — azwks-phtg-02

~09:34 UTC   azwks-phtg-02   -   _txt renamed to _ps1 (PowerShell script staged)
~10:13 UTC   azwks-phtg-02   -   Sarah_Chen_Notes.exe C2 beacon to 173.244.55.130:4444 — ConnectionFailed
~10:14 UTC   azwks-phtg-02   -   Sarah_Chen_Notes.exe moved to C:\ProgramData\PHTG\HealthCloud\
~10:16 UTC   azwks-phtg-02   -   Payload renamed from Sarah_Chen_Notes.exe to PHTG.exe (masquerading)
~10:19 UTC   azwks-phtg-02   -   Launch.txt renamed to Launch.bat (persistence wrapper created)
~10:22 UTC   azwks-phtg-02   -   PHTG.exe C2 beacon to 173.244.55.130:4444 — ConnectionFailed
```

> Note: All timestamps are derived from the `Timestamp` field in Microsoft Sentinel MDE tables. `TimeGenerated` and `Timestamp` behave differently in this workspace — `Timestamp` was used for all confirmed KQL results. Some events may reflect ingestion delay between endpoint activity and SIEM availability.

---

## Indicators of Compromise

### Network IOCs

| Type | Value | Context |
|---|---|---|
| IP | 173.244.55.131 | RDP source — Uruguay — first confirmed attacker IP |
| IP | 173.244.55.128 | RDP source — Uruguay — second confirmed attacker IP |
| IP | 173.244.55.130 | C2 server — Uruguay — Meterpreter listener |
| IP | 74.249.82.162 | Victim public IP — azwks-phtg-02 — exposed via LinkedIn OSINT |
| Port | 4444/TCP | Meterpreter C2 port — non-standard, used to avoid 80/443 inspection |
| Network | 173.244.55.128/25 | Attacker-controlled Uruguayan subnet (all three IPs fall within range) |

### Host IOCs

| Type | Value | Context |
|---|---|---|
| File | Sarah_Chen_Notes.exe | Initial payload filename — first execution phase |
| File | Sarah_Chen_Notes.exe.Txt | Double-extension evasion filename used during staging |
| File | PHTG.exe | Final payload filename — masquerading as HealthCloud binary |
| File | Launch.bat | Persistence batch wrapper in HealthCloud directory |
| File | _ps1 | PowerShell script staged during attacker session |
| File | notes_sarah.txt | Sensitive internal document accessed by attacker |
| SHA256 | 224462ce5e3304e3fd0875eeabc829810a894911e3d4091d4e60e67a2687e695 | Meterpreter payload hash — consistent across all rename events |
| Malware | Trojan:Win32/Meterpreter.gen!E | MDE classification of payload |
| Path | C:\ProgramData\PHTG\HealthCloud\ | Attacker persistence staging directory |
| Path | C:\Users\vmAdminUsername\Documents\PHTG\ | Initial payload drop location |
| Account | vmadminusername | Brute-forced local admin account used throughout |
| Service | HealthCloud | Legitimate service abused for payload masquerading |

---

## Investigative Challenges

**Q07 — Network Event Count (RDP Exposure Volume):** The most significant investigative challenge of this hunt was resolving the total network event count for port 3389. Multiple KQL combinations across `DeviceName`, `LocalIP`, `RemoteIP`, `LocalPort`, `RemotePort`, `TimeGenerated`, and `Timestamp` returned inconsistent and conflicting results over an extended investigation. The correct answer (194) was only recoverable by combining the `Timestamp` field (not `TimeGenerated`), `RemoteIPType == "Public"`, and `LocalPort == 3389` — a combination that required iterative elimination of every other approach. The root cause was that `InboundInternetScanInspected` events log port information inside `AdditionalFields` as `PublicScannedPort` rather than in the structured `LocalPort` column, and `RemoteIPType` tagging is inconsistently applied across ActionTypes. This is a documented quirk of how MDE streams data into Sentinel and is not immediately apparent from schema inspection alone.

**Q12 — RDP Auth Volume:** Identifying the correct LogonType combination for RDP authentication required over 30 investigative queries. The answer (`LogonType in ("Network", "RemoteInteractive")`) was non-obvious because RDP NLA authentication produces `Network` logon events (not `RemoteInteractive`) for the pre-authentication handshake, while the actual session produces `RemoteInteractive` events. `Unknown`, `Unlock`, and `Network` combinations all produced plausible but incorrect results before the correct pairing was confirmed.

**Timestamp vs TimeGenerated:** This workspace indexes MDE data on `Timestamp` for the core event time, while `TimeGenerated` reflects Sentinel ingestion time. The difference caused silent record drops across multiple queries until this distinction was identified. All future KQLs in this environment should use `Timestamp` with ISO 8601 format: `datetime(YYYY-MM-DDThh:mm:ssZ)`.

**Defender State Change:** The mechanism by which Defender was switched to Passive Mode was not fully recoverable in available telemetry. `AntivirusStateChange` events were absent or insufficiently logged. This represents a defensive gap — Defender configuration changes should generate durable, queryable alerts.

**C2 ConnectionFailed:** All three observed C2 beacon attempts returned `ConnectionFailed`. This may indicate the C2 listener was not configured at the time of beacon, the port was filtered at network level, or the attacker was using a staged approach. Full C2 session establishment cannot be confirmed from available telemetry, though the payload, infrastructure, and protocol are consistent with active Meterpreter deployment.

---

## Recommendations

**Immediate (0-24 hours)**

1. Isolate `azwks-phtg-02` from the network immediately. Revoke all active sessions and reset credentials for `vmadminusername`. Assume full host compromise.
2. Block all traffic from the Uruguayan /24 subnet (`173.244.55.128/25`) at the perimeter firewall and cloud NSG level. Add `173.244.55.130`, `173.244.55.131`, and `173.244.55.128` to threat intelligence blocklists.
3. Quarantine and submit the payload SHA256 (`224462ce5e3304e3fd0875eeabc829810a894911e3d4091d4e60e67a2687e695`) to Microsoft and internal AV platforms. Scan all hosts in the same subnet for `PHTG.exe`, `Launch.bat`, and the associated SHA256.

**Short Term (1-7 days)**

4. Disable public RDP access across all Azure VMs. Enforce RDP access exclusively via Azure Bastion or a VPN-gated jump host. No VM should expose port 3389 directly to the internet.
5. Enforce a social media and OSINT policy for technical staff. Any post referencing infrastructure, cloud services, or tooling must be reviewed before publication. Sarah Chen's post was not malicious — the failure was a process gap, not a personnel failure.
6. Review all accounts on `azwks-phtg-02` and across the PHTG estate for default or weak credentials. `vmadminusername` is a generic placeholder name that should never exist in production. Enforce a minimum password complexity and account naming policy.

**Strategic (7-30 days)**

7. Implement Microsoft Defender for Cloud with Just-In-Time VM access. RDP should only be accessible for approved time windows from approved IPs — never persistently open to the internet.
8. Establish a HealthCloud behavioural baseline in Sentinel using DeviceProcessEvents and DeviceFileEvents. Any binary executed from `C:\ProgramData\PHTG\HealthCloud\` that does not match a known hash allowlist should trigger an automated alert. New internal service deployments should always be accompanied by a detection engineering task to define expected behaviour.
9. Build a proactive OSINT monitoring programme for PHTG staff social media and public posts. Tools such as automated LinkedIn monitoring or a responsible disclosure workflow for staff can provide early warning when infrastructure details are inadvertently exposed before a threat actor acts on them.

---

## KQL Reference

**Standard time filter (this workspace):**
```kql
| where Timestamp between (datetime(2025-12-09T00:00:00Z) .. datetime(2025-12-23T23:59:59Z))
```
> Note: Use `Timestamp` not `TimeGenerated` in this workspace. `TimeGenerated` reflects ingestion time and may drop records. Use ISO 8601 format with Z suffix.

---

### Scanning Activity — Strongest Port by ScanScore (Q06)
```kql
DeviceNetworkEvents
| where Timestamp between (datetime(2025-12-09T00:00:00Z) .. datetime(2025-12-23T23:59:59Z))
| where DeviceName == "azwks-phtg-02"
| summarize
    TotalHits = count(),
    UniqueRemoteIPs = dcount(RemoteIP),
    FirstSeen = min(TimeGenerated),
    LastSeen = max(TimeGenerated)
    by LocalPort
| extend ScanScore = TotalHits * UniqueRemoteIPs
| sort by ScanScore desc
| project LocalPort, TotalHits, UniqueRemoteIPs, ScanScore, FirstSeen, LastSeen
```

---

### Network Events Targeting RDP Port (Q07)
```kql
DeviceNetworkEvents
| where Timestamp between (datetime(2025-12-09T00:00:00Z) .. datetime(2025-12-23T23:59:59Z))
| where DeviceName == "azwks-phtg-02"
| where RemoteIPType == "Public"
| where LocalPort == 3389
| count
```

---

### Unique Public Source IPs Targeting RDP (Q08)
```kql
DeviceNetworkEvents
| where Timestamp between (datetime(2025-12-09T00:00:00Z) .. datetime(2025-12-23T23:59:59Z))
| where DeviceName == "azwks-phtg-02"
| where RemoteIPType == "Public"
| where LocalPort == 3389
| summarize dcount(RemoteIP)
```

---

### IPs with Both Probe and Accepted Connection (Q09)
```kql
DeviceNetworkEvents
| where Timestamp between (datetime(2025-12-09T00:00:00Z) .. datetime(2025-12-23T23:59:59Z))
| where DeviceName == "azwks-phtg-02"
| where LocalPort == 3389
| where ActionType in ("ConnectionAttempt", "InboundConnectionAccepted")
| summarize ActionTypes = make_set(ActionType) by RemoteIP
| where ActionTypes has "ConnectionAttempt" and ActionTypes has "InboundConnectionAccepted"
| count
```

---

### Geographic Enrichment of RDP Sources (Q10)
```kql
let GeoTable =
    externaldata(network:string, geoname_id:long, continent_code:string,
                continent_name:string, country_iso_code:string, country_name:string)
    [@"https://raw.githubusercontent.com/datasets/geoip2-ipv4/main/data/geoip2-ipv4.csv"]
    with (format="csv");
DeviceNetworkEvents
| where Timestamp between (datetime(2025-12-09T00:00:00Z) .. datetime(2025-12-23T23:59:59Z))
| where DeviceName == "azwks-phtg-02"
| where LocalPort == 3389
| where ActionType in ("ConnectionAttempt", "InboundConnectionAccepted")
| summarize ActionTypes = make_set(ActionType) by RemoteIP
| where ActionTypes has "ConnectionAttempt" and ActionTypes has "InboundConnectionAccepted"
| evaluate ipv4_lookup(GeoTable, RemoteIP, network)
| summarize dcount(country_name)
```

---

### Total External Authentication Events (Q11)
```kql
DeviceLogonEvents
| where Timestamp between (datetime(2025-12-09T00:00:00Z) .. datetime(2025-12-23T23:59:59Z))
| where DeviceName == "azwks-phtg-02"
| where RemoteIPType == "Public"
| count
```

---

### RDP-Specific Authentication Events (Q12)
```kql
DeviceLogonEvents
| where Timestamp between (datetime(2025-12-09T00:00:00Z) .. datetime(2025-12-23T23:59:59Z))
| where DeviceName == "azwks-phtg-02"
| where RemoteIPType == "Public"
| where LogonType in ("Network", "RemoteInteractive")
| count
```

---

### Auth Outcome Breakdown (Q13)
```kql
DeviceLogonEvents
| where Timestamp between (datetime(2025-12-09T00:00:00Z) .. datetime(2025-12-23T23:59:59Z))
| where DeviceName == "azwks-phtg-02"
| where RemoteIPType == "Public"
| where LogonType in ("Network", "RemoteInteractive")
| summarize count() by ActionType
| sort by count_ desc
```

---

### Countries with RDP Auth Activity (Q15)
```kql
let GeoTable =
    externaldata(network:string, geoname_id:long, continent_code:string,
                continent_name:string, country_iso_code:string, country_name:string)
    [@"https://raw.githubusercontent.com/datasets/geoip2-ipv4/main/data/geoip2-ipv4.csv"]
    with (format="csv");
DeviceLogonEvents
| where Timestamp between (datetime(2025-12-09T00:00:00Z) .. datetime(2025-12-23T23:59:59Z))
| where DeviceName == "azwks-phtg-02"
| where RemoteIPType == "Public"
| where LogonType in ("Network", "RemoteInteractive")
| evaluate ipv4_lookup(GeoTable, RemoteIP, network)
| summarize dcount(country_name)
```

---

### Countries with Successful RDP Auth (Q16/Q17)
```kql
let GeoTable =
    externaldata(network:string, geoname_id:long, continent_code:string,
                continent_name:string, country_iso_code:string, country_name:string)
    [@"https://raw.githubusercontent.com/datasets/geoip2-ipv4/main/data/geoip2-ipv4.csv"]
    with (format="csv");
DeviceLogonEvents
| where Timestamp between (datetime(2025-12-09T00:00:00Z) .. datetime(2025-12-23T23:59:59Z))
| where DeviceName == "azwks-phtg-02"
| where RemoteIPType == "Public"
| where LogonType in ("Network", "RemoteInteractive")
| where ActionType == "LogonSuccess"
| evaluate ipv4_lookup(GeoTable, RemoteIP, network)
| summarize dcount(RemoteIP) by country_name
```

---

### Successful Logons from Uruguay — Account and IP (Q19/Q20)
```kql
let GeoTable =
    externaldata(network:string, geoname_id:long, continent_code:string,
                continent_name:string, country_iso_code:string, country_name:string)
    [@"https://raw.githubusercontent.com/datasets/geoip2-ipv4/main/data/geoip2-ipv4.csv"]
    with (format="csv");
DeviceLogonEvents
| where Timestamp between (datetime(2025-12-09T00:00:00Z) .. datetime(2025-12-23T23:59:59Z))
| where DeviceName == "azwks-phtg-02"
| where RemoteIPType == "Public"
| where LogonType in ("Network", "RemoteInteractive")
| where ActionType == "LogonSuccess"
| evaluate ipv4_lookup(GeoTable, RemoteIP, network)
| where country_name == "Uruguay"
| project AccountName, RemoteIP, TimeGenerated
| sort by TimeGenerated asc
```

---

### Attacker Process Activity Post-Logon (Q23)
```kql
DeviceProcessEvents
| where Timestamp between (datetime(2025-12-12T00:00:00Z) .. datetime(2025-12-23T23:59:59Z))
| where DeviceName == "azwks-phtg-02"
| where InitiatingProcessAccountName == "vmadminusername"
| sort by TimeGenerated asc
| project TimeGenerated, FileName, ProcessCommandLine, InitiatingProcessFileName
```

---

### Payload Rename Chain (Q25/Q26/Q28)
```kql
DeviceFileEvents
| where Timestamp between (datetime(2025-12-12T00:00:00Z) .. datetime(2025-12-23T23:59:59Z))
| where DeviceName == "azwks-phtg-02"
| where ActionType == "FileRenamed"
| where InitiatingProcessAccountName == "vmadminusername"
| where FileName endswith ".exe" or FileName endswith ".dll" or FileName endswith ".bat" or FileName endswith ".ps1"
| sort by TimeGenerated asc
| project TimeGenerated, FileName, PreviousFileName, FolderPath
```

---

### Payload Tracking by SHA256 (Q27/Q28)
```kql
DeviceFileEvents
| where Timestamp between (datetime(2025-12-12T00:00:00Z) .. datetime(2025-12-23T23:59:59Z))
| where DeviceName == "azwks-phtg-02"
| where SHA256 == "224462ce5e3304e3fd0875eeabc829810a894911e3d4091d4e60e67a2687e695"
| sort by TimeGenerated desc
| project TimeGenerated, FileName, PreviousFileName, FolderPath, ActionType
```

---

### MDE Antivirus Detection — Malware Family (Q29)
```kql
DeviceEvents
| where Timestamp between (datetime(2025-12-09T00:00:00Z) .. datetime(2025-12-23T23:59:59Z))
| where DeviceName == "azwks-phtg-02"
| where ActionType == "AntivirusDetection"
| extend ThreatName = tostring(parse_json(AdditionalFields).ThreatName)
| project TimeGenerated, ThreatName, AdditionalFields
```

---

### C2 Network Connections by Payload (Q34)
```kql
DeviceNetworkEvents
| where Timestamp between (datetime(2025-12-12T00:00:00Z) .. datetime(2025-12-23T23:59:59Z))
| where DeviceName == "azwks-phtg-02"
| where InitiatingProcessSHA256 == "224462ce5e3304e3fd0875eeabc829810a894911e3d4091d4e60e67a2687e695"
| where RemoteIPType == "Public"
| project TimeGenerated, RemoteIP, RemotePort, InitiatingProcessFileName, ActionType
| sort by TimeGenerated asc
```

---

### C2 IP Geolocation (Q35)
```kql
let GeoTable =
    externaldata(network:string, geoname_id:long, continent_code:string,
                continent_name:string, country_iso_code:string, country_name:string)
    [@"https://raw.githubusercontent.com/datasets/geoip2-ipv4/main/data/geoip2-ipv4.csv"]
    with (format="csv");
print ip = "173.244.55.130"
| evaluate ipv4_lookup(GeoTable, ip, network)
| project country_name, continent_name
```

---

*Report authored by Adetola Kols | Cybersecurity Analyst*  
*Threat Hunt: SIGNALS BEFORE THE NOISE | IR-2025-1209-01*  
*Platform: Microsoft Sentinel | law-cyber-range*
