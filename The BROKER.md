#  The Broker - Hands-on-Keyboard Attack
**Classification:** CONFIDENTIAL  
**Date of Incident:** 15 January 2026  
**Report Date:** 28 February 2026  
**Analyst:** Adetola Kolawole  
**Environment:** Cyber Range Microsoft Sentinel — Log Analytics Workspace  

---

## 1. Summary of Events

On 15 January 2026, a threat actor compromised endpoint **AS-PC1** via a socially engineered email lure containing a malicious executable disguised as a CV (`daniel_richardson_cv.pdf.exe`). Following initial execution, the attacker established persistent remote access using AnyDesk, conducted credential harvesting, performed lateral movement across three hosts, accessed sensitive payroll data, and staged files for exfiltration — all under the compromised identity of **sophie.turner**.

The attack demonstrated a high level of operational maturity, making use of Living-off-the-Land (LOLBin) techniques, in-memory execution, legitimate remote access tooling, and deliberate log clearing to hinder forensic investigation.

---

## 2. Who

| Entity | Detail |
|---|---|
| **Compromised User** | `sophie.turner` (AS-PC1\Sophie.Turner) |
| **Attacker Backdoor Account** | `svc_backup` (created by attacker, elevated to local admin) |
| **Lateral Movement Account** | `david.mitchell` (activated via `/active:yes`) |
| **Server Admin Account Abused** | `as.srv.administrator` |
| **C2 Infrastructure** | `cdn.cloud-endpoint.net` |
| **Staging Infrastructure** | `sync.cloud-endpoint.net` |

---

## 3. What — Attacker Actions & Malicious Artifacts

### Malicious Files
| Filename | SHA256 | Location |
|---|---|---|
| `daniel_richardson_cv.pdf.exe` | `48b97fd91946e81e3e7742b3554585360551551cbf9398e1f34f4bc4eac3a6b5` | AS-PC1 — User Downloads |
| `AnyDesk.exe` | `f42b635d93720d1624c74121b83794d706d4d064bee027650698025703d20532` | `C:\Users\Public\AnyDesk.exe` (all 3 hosts) |
| `RuntimeBroker.exe` | `48b97fd91946e81e3e7742b3554585360551551cbf9398e1f34f4bc4eac3a6b5` | `C:\Users\Public\RuntimeBroker.exe` (AS-PC2, AS-SRV) |
| `Shares.7z` | `6886c0a2e59792e69df94d2cf6ae62c2364fda50a23ab44317548895020ab048` | `C:\Shares\Clients\Shares.7z` (AS-SRV) |
| `sam.hiv` | — | `C:\Users\Public\sam.hiv` (AS-PC1) |
| `system.hiv` | — | `C:\Users\Public\system.hiv` (AS-PC1) |

### Attacker Actions
- Social engineering via fake CV lure (double extension technique)
- Process injection into `notepad.exe` via `CreateRemoteThreadApiCall`
- In-memory credential theft via `SharpChrome` (`ClrUnbackedModuleLoaded`)
- C2 communication to `cdn.cloud-endpoint.net`
- AnyDesk deployment with hardcoded password (`intrud3r!`) for unattended access
- Credential dumping of SAM and SYSTEM registry hives
- Backdoor account creation (`svc_backup`) with local admin privileges
- Lateral movement to AS-PC2 and AS-SRV via `mstsc.exe` (RDP)
- Sensitive payroll file access (`BACS_Payments_Dec2025.ods`)
- Data archiving via 7-Zip (`Shares.7z`)
- Event log clearing (System and Security logs)
- Scheduled task persistence (`MicrosoftEdgeUpdateCheck`)

---

## 4. When — Unified Attack Timeline

| Time (UTC) | Host | Event |
|---|---|---|
| 03:46:55 AM | AS-PC1 | Malicious DLL `3gfdjnio.dll` compiled in memory via `csc.exe` |
| 03:47:10 AM | AS-PC1 | First C2 beacon to `cdn.cloud-endpoint.net` |
| 03:58:55 AM | AS-PC1 | `whoami` executed — attacker confirms identity |
| 04:01:09 AM | AS-PC1 | Network enumeration — `net user`, `net localgroup administrators`, `net view` |
| 04:08:29 AM | AS-PC1 | `certutil.exe` downloads AnyDesk from `download.anydesk.com` |
| 04:09:27 AM | AS-PC1 | Payload reads AnyDesk config — `system.conf` accessed |
| 04:10:06 AM | AS-PC1 | AnyDesk launched — `cmd.exe /c start C:\Users\Public\AnyDesk.exe` |
| 04:11:47 AM | AS-PC1 | AnyDesk password set — `intrud3r!` |
| 04:13:32 AM | AS-PC1 | Registry credential dump — `HKLM\SAM` and `HKLM\SYSTEM` saved to `C:\Users\Public` |
| 04:17:00 AM | AS-PC1 | Failed lateral movement attempts via `WMIC` and `PsExec` against AS-PC2 |
| 04:24:26 AM | AS-PC1 | Successful RDP lateral movement to AS-PC2 via `mstsc.exe` |
| 04:40:03 AM | AS-PC2 | `david.mitchell` logs in via RemoteInteractive (RDP) |
| 04:40:58 AM | AS-PC2 | AnyDesk deployed on AS-PC2 |
| 04:46:20 AM | AS-PC2 | `BACS_Payments_Dec2025.ods` accessed from `\\AS-SRV\Payroll\` |
| 04:52:22 AM | AS-PC2 | `certutil.exe` downloads payload from `sync.cloud-endpoint.net` |
| 04:55:58 AM | AS-SRV | RDP session established on AS-SRV |
| 04:57:07 AM | AS-SRV | AnyDesk deployed on AS-SRV |
| 04:57:47 AM | AS-PC1 | Backdoor account `svc_backup` created and added to local Administrators |
| 04:59:04 AM | AS-SRV | Sensitive files accessed — `Rate_Card_2025_CONFIDENTIAL.pdf`, `Terms_of_Business_SIGNED.pdf` |
| 04:59:47 AM | AS-SRV | `Shares.7z` archive created — data staged for exfiltration |
| 05:09:53 AM | AS-PC1 | `SharpChrome` loaded into memory via `notepad.exe` — browser credential theft |
| 05:13:00 AM | AS-PC1/AS-SRV | Event logs cleared — System and Security logs wiped |

---

## 5. Where — Affected Assets

| Hostname | Role | Impact |
|---|---|---|
| **AS-PC1** | User workstation (Sophie.Turner) | Initial compromise, C2 beacon, credential dump, AnyDesk installed |
| **AS-PC2** | User workstation (david.mitchell) | Lateral movement target, AnyDesk installed, payroll file accessed |
| **AS-SRV** | File server | AnyDesk installed, sensitive files accessed, data archived for exfiltration |

### Network Infrastructure Abused
| Domain | Purpose |
|---|---|
| `cdn.cloud-endpoint.net` | C2 communication |
| `sync.cloud-endpoint.net` | Payload staging |
| `download.anydesk.com` | AnyDesk delivery |
| `live.sysinternals.com` | PsExec delivery |

---

## 6. Why — Root Cause Analysis

The root cause of this incident was a combination of technical and human factors:

**Human Factor:** A user (`sophie.turner`) executed a malicious file (`daniel_richardson_cv.pdf.exe`) delivered via social engineering. The double-extension filename disguised the executable as a PDF document, exploiting a common cognitive bias where users trust familiar file type names.

**Technical Gaps:**
- The endpoint was not fully onboarded to Microsoft Defender at the time of initial payload delivery, resulting in a gap in telemetry coverage.
- No application whitelisting or execution controls prevented the unsigned executable from running.
- Legitimate remote administration tools (AnyDesk) were not restricted, allowing the attacker to establish persistent access without triggering alerts.
- Disabled accounts (`david.mitchell`) could be reactivated without automated detection.
- The SAM and SYSTEM registry hives were accessible to a standard user account, enabling offline credential attacks.
- No detection rule existed for LOLBin abuse patterns (`certutil` downloading executables, `reg.exe` saving hives).

---

## 7. How — The Kill Chain

```
[1] INITIAL ACCESS
    └─ sophie.turner executes daniel_richardson_cv.pdf.exe
       (double-extension lure, delivered pre-Defender onboarding)

[2] EXECUTION
    └─ Payload spawns notepad.exe via CreateRemoteThreadApiCall
       └─ SharpChrome loaded in-memory (ClrUnbackedModuleLoaded)
          └─ Browser credentials stolen from Chrome

[3] PERSISTENCE
    ├─ AnyDesk installed with password intrud3r! (unattended access)
    ├─ Backdoor account svc_backup created → added to local Admins
    ├─ david.mitchell account re-enabled (/active:yes)
    └─ Scheduled task MicrosoftEdgeUpdateCheck created on AS-PC2 and AS-SRV
       └─ Payload: RuntimeBroker.exe (renamed daniel_richardson_cv.pdf.exe)

[4] CREDENTIAL ACCESS
    ├─ HKLM\SAM saved → C:\Users\Public\sam.hiv
    ├─ HKLM\SYSTEM saved → C:\Users\Public\system.hiv
    └─ SharpChrome → Chrome saved credentials stolen

[5] DISCOVERY
    ├─ whoami (user context confirmation)
    ├─ net user (local account enumeration)
    ├─ net localgroup administrators (privilege enumeration)
    └─ net view (network share enumeration)

[6] LATERAL MOVEMENT
    ├─ WMIC → AS-PC2 (FAILED)
    ├─ PsExec → AS-PC2 (FAILED)
    └─ mstsc.exe (RDP) → AS-PC2 → AS-SRV (SUCCESS)
       Path: AS-PC1 > AS-PC2 > AS-SRV

[7] COLLECTION
    ├─ BACS_Payments_Dec2025.ods accessed (\\AS-SRV\Payroll\)
    ├─ Rate_Card_2025_CONFIDENTIAL.pdf read
    ├─ Terms_of_Business_SIGNED.pdf read
    └─ Shares.7z archive created (C:\Shares\Clients\)

[8] COMMAND & CONTROL
    ├─ C2 beacon → cdn.cloud-endpoint.net (port 443)
    └─ Staging → sync.cloud-endpoint.net (certutil download)

[9] DEFENCE EVASION
    ├─ LOLBin abuse (certutil, reg, net, wmic, mstsc, schtasks)
    ├─ Process injection into notepad.exe
    ├─ In-memory tool execution (SharpChrome, 3gfdjnio.dll)
    ├─ Renamed payload (RuntimeBroker.exe)
    ├─ Legitimate tool abuse (AnyDesk)
    └─ Event log clearing (System + Security logs)
```

---

## 8. Recommendations

### Immediate Actions (0–24 Hours)
- Isolate **AS-PC1, AS-PC2, AS-SRV** from the network pending full forensic investigation
- Disable and investigate accounts: `sophie.turner`, `david.mitchell`, `svc_backup`, `as.srv.administrator`
- Block C2 and staging domains at firewall/proxy level: `cdn.cloud-endpoint.net`, `sync.cloud-endpoint.net`
- Reset all passwords for affected accounts and any accounts whose credentials may have been stored in Chrome on AS-PC1
- Remove scheduled task `MicrosoftEdgeUpdateCheck` from AS-PC2 and AS-SRV
- Delete malicious files: `RuntimeBroker.exe`, `AnyDesk.exe`, `Shares.7z`, `sam.hiv`, `system.hiv` from all affected hosts
- Uninstall AnyDesk from all three affected hosts
- Notify affected parties regarding potential exposure of `BACS_Payments_Dec2025.ods` payroll data

### Short-Term Actions (1–4 Weeks)
- Ensure **all endpoints are fully onboarded** to Microsoft Defender — eliminate telemetry gaps
- Implement **application whitelisting** to prevent unsigned executables from running
- Block `certutil.exe` from making outbound internet connections via AppLocker or WDAC
- Enable **file extension visibility** in Windows Explorer across all endpoints to prevent double-extension attacks
- Implement **LAPS (Local Administrator Password Solution)** to prevent lateral movement using shared local admin credentials
- Deploy detection rules for:
  - `certutil` downloading remote files
  - `reg.exe` saving SAM/SYSTEM hives
  - `net user /add` and `net localgroup administrators` commands
  - `CreateRemoteThreadApiCall` events
  - `ClrUnbackedModuleLoaded` events in unexpected processes
- Review and restrict access to `\\AS-SRV\Payroll\` share — enforce least privilege

### Long-Term Actions (1–3 Months)
- Implement **Security Awareness Training** focusing on phishing and social engineering — specifically double-extension file lures
- Deploy **Privileged Access Workstations (PAW)** for administrator accounts
- Implement **Just-in-Time (JIT) access** for administrative accounts to reduce standing privilege
- Deploy **Endpoint Detection and Response (EDR)** with behavioural analytics across all endpoints
- Implement **network segmentation** — workstations should not be able to RDP directly to file servers
- Enable **PowerShell Constrained Language Mode** and script block logging
- Conduct regular **threat hunting exercises** focused on LOLBin abuse patterns
- Implement **Credential Guard** to protect LSASS from memory scraping
- Review AnyDesk and other remote access tools — whitelist approved tools only and require MFA for all remote sessions
- Conduct a full **Active Directory audit** — identify and remove stale/disabled accounts that could be reactivated

---

*Report prepared by Adetola | Microsoft Sentinel Threat Analysis | 28 February 2026*
