#  Akira Ransomware Attack - Ashford Sterling Recruitment


- **Classification:** CONFIDENTIAL  
- **Date of Incident:** 27 January 2026
- **Report Date:** 30 March 2026 
- **Analyst:** Adetola Kolawole  
- **Severity:** 🔴 CRITICAL
- **Environment:** Cyber Range Microsoft Sentinel - Log Analytics Workspace  

---

## 📋 Table of Contents

1. [Summary](#1-summary)
2. [Who](#2-who)
3. [What](#3-what)
4. [When](#4-when)
5. [Where](#5-where)
6. [Why](#6-why)
7. [How](#7-how)
8. [Recommendations](#8-recommendations)

---

## 1. Summary

Ashford Sterling Recruitment, a UK-based recruitment firm employing 45 staff, suffered a double-extortion ransomware attack on 27 January 2026. The Akira ransomware group deployed their payload across the network, encrypting all files in `C:\Shares\` and exfiltrating sensitive data including financial records, employee PII, client databases, and candidate information.

This was **not a fresh intrusion**. The threat actor reused pre-staged access established during a prior compromise investigated as **"The Broker"**, returning to an environment where AnyDesk and a backdoor account had already been planted. The attack resulted in full encryption of shared network resources with a ransom demand of **£65,000**.

| Field | Detail |
|-------|--------|
| **Incident Type** | Ransomware / Double Extortion |
| **Threat Actor** | Akira Ransomware Group |
| **Initial Access** | Pre-staged (The Broker compromise reused) |
| **Compromised Hosts** | as-pc2, as-srv |
| **Encryption Time** | 22:18:29 UTC, 27 January 2026 |
| **Ransom Demand** | £65,000 (victim countered £11,000) |
| **Data Exfiltrated** | Confirmed — exfil_data.zip |

---

## 2. Who

### Threat Actor

The Akira ransomware group, first observed in March 2023, operates a Ransomware-as-a-Service (RaaS) model targeting Windows and Linux environments. The group employs double extortion — stealing data before encrypting systems — and has claimed over $244 million USD in ransomware proceeds as of late 2025.

| Attribute | Detail |
|-----------|--------|
| **Group** | Akira Ransomware |
| **Victim ID** | `813R-QWJM-XKIJ` |
| **Negotiation Portal** | `akiral2iz6a7qgd3ayp3l6yub7xx2uep76idk3u2kollpj5z3z636bad.onion` |
| **Chat Portal** | `akiralkzxzq2dsrzsrvbr2xgbbu2wgsmxryd4csgfameg52n7efvr2id.onion` |
| **Attacker IP** | `88.97.164.155` |
| **Encryption Algorithm** | AES-256 (claimed) |
| **File Extension** | `.akira` |

### Compromised Accounts

| Account | Role |
|---------|------|
| `david.mitchell` | Primary compromised user on as-pc2 |
| `as.srv.administrator` | Used for lateral movement to as-srv |
| `svc_backup` | Backdoor account created during The Broker compromise |

---

## 3. What

### Attack Overview

The attacker returned to the Ashford Sterling environment using pre-staged AnyDesk access from The Broker investigation. They conducted reconnaissance, harvested credentials, moved laterally, disabled defences, exfiltrated data, and deployed Akira ransomware — all within a single evening.

### Malicious Tools & Files

| File | Location |
|------|----------|
| `wsync.exe` | C2 beacon — `C:\ProgramData\wsync.exe` |
| `updater.exe` | Ransomware binary — `C:\ProgramData\updater.exe` |
| `kill.bat` | Security disabling script — `C:\ProgramData\kill.bat` |
| `clean.bat` | Anti-forensics cleanup script — `C:\ProgramData\clean.bat` |
| `st.exe` | Data compression/staging tool — `C:\ProgramData\st.exe` |
| `scan.exe` | Advanced IP Scanner installer — `C:\Users\david.mitchell\Downloads\` |
| `AnyDesk.exe` | Remote access tool — `C:\Users\Public\AnyDesk.exe` |
| `SenseIR.exe` | Masquerading process — Windows Defender ATP path |
| `exfil_data.zip` | Exfiltration archive — `C:\Users\Public\exfil_data.zip` |

### File Hashes (SHA256)

| File | SHA256 |
|------|--------|
| `wsync.exe` (original) | `66b876c52946f4aed47dd696d790972ff265b6f4451dab54245bc4ef1206d90b` |
| `wsync.exe` (replacement) | `0072ca0d0adc9a1b2e1625db4409f57fc32b5a09c414786bf08c4d8e6a073654` |
| `kill.bat` | `0e7da57d92eaa6bda9d0bbc24b5f0827250aa42f295fd056ded50c6e3c3fb96c` |
| `updater.exe` | `e609d070ee9f76934d73353be4ef7ff34b3ecc3a2d1e5d052140ed4cb9e4752b` |
| `st.exe` | `512a1f4ed9f512572608c729a2b89f44ea66a40433073aedcd914bd2d33b7015` |
| `scan.exe` | `26d5748ffe6bd95e3fee6ce184d388a1a681006dc23a0f08d53c083c593c193b` |
| `akira_readme.txt` | `b9f1a9fc272c6fb5bca46de75b77a06a647aac2a0c6a1eca9a3a06c9cbdea191` |

---

## 4. When

### Attack Timeline — 27 January 2026 (UTC)

| Time (UTC) | Event |
|------------|-------|
| `19:15` | AnyDesk reconnection from `88.97.164.155` — attacker regains access to as-pc2 |
| `19:17` | `wsync.exe` (original beacon) deployed to `C:\ProgramData\` by PowerShell |
| `19:44` | `wsync.exe` replacement beacon deployed — 25 second swap |
| `20:02` | `advanced_ip_scanner.exe` launched — subnet reconnaissance begins |
| `20:14` | `bitsadmin.exe` begins staging tool downloads from `sync.cloud-endpoint.net` |
| `20:22` | `wsync.exe` first C2 contact with `cdn.cloud-endpoint.net` |
| `21:00` | `kill.bat` written to `C:\ProgramData\` |
| `21:03` | `kill.bat` executes — Windows Defender disabled via registry |
| `21:06` | `net stop` commands executed — AV and backup services killed |
| `21:09` | Shadow copies deleted — `vssadmin`, `wmic`, `bcdedit` executed |
| `21:11` | `tasklist \| findstr lsass` — credential theft begins |
| `21:42` | `\Device\NamedPipe\lsass` accessed — credentials harvested |
| `22:10` | `net view \\10.1.0.154` and `\\10.1.0.183` — share enumeration on as-srv |
| `22:17` | `updater.exe` staged to `C:\ProgramData\` on as-srv by PowerShell |
| **`22:18:29`** | **ENCRYPTION BEGINS** — `updater.exe` executes on as-srv |
| `22:18:33` | `akira_readme.txt` dropped across Desktop, Documents, Downloads |
| `22:20` | `wevtutil` clears Security, System, Application, Defender logs |
| `22:20:27` | `clean.bat` executes — `updater.exe` deleted from disk |
| `22:22` | Victim opens `akira_readme.txt` — encryption discovered |
| `22:24` | `st.exe` creates `exfil_data.zip` — `C:\Users\Public\exfil_data.zip` |

---

## 5. Where

### Compromised Infrastructure

| Host | Role | IP |
|------|------|----|
| `as-pc2` | Primary attack workstation — david.mitchell's machine | `10.1.0.183` |
| `as-srv` | File server — target of encryption | `10.1.0.203` |
| `C:\Shares\` | Encrypted directory — Backups, Clients, Compliance, Contractors, Payroll | — |
| `C:\ProgramData\` | Primary attacker staging directory on both hosts | — |
| `C:\Users\Public\` | AnyDesk staging location and exfil archive location | — |

### Network Infrastructure (IOCs)

| Domain / IP | Purpose |
|-------------|---------|
| `sync.cloud-endpoint.net` | Payload staging domain |
| `cdn.cloud-endpoint.net` | C2 communications domain |
| `relay-0b975d23.net.anydesk.com` | AnyDesk relay server |
| `88.97.164.155` | Attacker direct IP — AnyDesk sessions |
| `104.21.30.237` | Cloudflare C2 IP |
| `172.67.174.46` | Cloudflare C2 IP |
| `89.187.179.132` | AnyDesk relay IP |

---

## 6. Why

### Attacker Motivation

Financial extortion via double-extortion ransomware. The attacker targeted Ashford Sterling specifically because of their access to sensitive candidate and client PII — a recruitment firm holds highly valuable personal data including CVs, financial information, and identity documents that can be leveraged for public exposure pressure.

The attacker demonstrated knowledge of the environment from The Broker investigation, suggesting either the same threat actor returned or the initial access was sold/shared with the Akira affiliate. The deliberate selection of `C:\Shares\` as the encryption target shows targeted intent rather than opportunistic encryption.

### Why Ashford Sterling Was Vulnerable

- Pre-staged access from The Broker compromise was **never fully remediated**
- AnyDesk remained installed in `C:\Users\Public\` — a non-standard, unwatched path
- Backdoor account `svc_backup` was not removed after The Broker investigation
- No MFA on RDP or remote access tools
- Shadow copy deletion executed without triggering automated alerts
- Windows Defender disabled without automated response or tamper protection

---

## 7. How

### Attack Chain

#### Phase 1 — Re-entry via Pre-staged Access
The attacker reconnected using AnyDesk from `88.97.164.155`, leveraging the persistent installation at `C:\Users\Public\AnyDesk.exe` left from The Broker compromise. No new vulnerability was exploited — the environment was already owned.

#### Phase 2 — Beacon Replacement
The original AnyDesk beacon showed instability. `wsync.exe` was deployed as a replacement C2 beacon, communicating with Cloudflare-proxied infrastructure at `cloud-endpoint.net`. The beacon was replaced once within 25 seconds when the first version failed, demonstrating operational agility.

#### Phase 3 — Reconnaissance
Advanced IP Scanner was deployed via `scan.exe` (portable mode) to map the `10.1.0.x` subnet. Targeted share enumeration followed using `net view` against `10.1.0.154` and `10.1.0.183` to identify encryption targets.

#### Phase 4 — Credential Theft
The attacker used `tasklist | findstr lsass` to locate the LSASS process, then accessed `\Device\NamedPipe\lsass` to harvest credentials from memory. The stolen `as.srv.administrator` credentials enabled authenticated lateral movement to the file server.

#### Phase 5 — Defence Evasion
`kill.bat` systematically disabled Windows Defender via `Set-MpPreference` and registry modifications (`DisableAntiSpyware`, `DisableBehaviorMonitoring`, `DisableIOAVProtection`). The firewall was disabled via `netsh`, shadow copies were destroyed three ways, and backup services were stopped.

#### Phase 6 — Data Exfiltration
`st.exe` compressed sensitive data into `exfil_data.zip` at `C:\Users\Public\`, completing the double extortion setup before encryption began. The archive contained financial records, PII, client data, and business documents.

#### Phase 7 — Ransomware Deployment & Cleanup
`updater.exe` was staged to `C:\ProgramData\` on as-srv and executed at `22:18:29 UTC`. Disguised as a legitimate updater process, it encrypted `C:\Shares\` and dropped `akira_readme.txt` across user directories. Event logs were cleared and `clean.bat` deleted the ransomware binary as a final anti-forensics measure.

---

### MITRE ATT&CK Mapping

| TTP ID | Technique | Evidence |
|--------|-----------|----------|
| `T1133` | External Remote Services | AnyDesk reused from prior compromise |
| `T1219` | Remote Access Software | AnyDesk in `C:\Users\Public\` |
| `T1046` | Network Service Discovery | `advanced_ip_scanner.exe` — subnet scan |
| `T1135` | Network Share Discovery | `net view \\10.1.0.154` and `\\10.1.0.183` |
| `T1003.001` | LSASS Memory | Named pipe `\Device\NamedPipe\lsass` accessed |
| `T1055` | Process Injection | `SenseIR.exe` masquerading |
| `T1562.001` | Disable Security Tools | `kill.bat` — Defender disabled via registry |
| `T1070.001` | Clear Windows Event Logs | `wevtutil cl Security/System/Application` |
| `T1490` | Inhibit System Recovery | `vssadmin`/`wmic` shadow copy deletion |
| `T1486` | Data Encrypted for Impact | `updater.exe` — `.akira` extension |
| `T1041` | Exfiltration Over C2 | `exfil_data.zip` via `cloud-endpoint.net` |
| `T1105` | Ingress Tool Transfer | `bitsadmin.exe` staging from `sync.cloud-endpoint.net` |
| `T1036` | Masquerading | `updater.exe` disguised as legitimate process |
| `T1572` | Protocol Tunneling | Cloudflare proxying C2 traffic |

---

## 8. Recommendations

###  Immediate Actions (0–24 Hours)

- Isolate `as-pc2` and `as-srv` from the network immediately if not already done
- Reset all credentials for `david.mitchell`, `as.srv.administrator`, and `svc_backup`
- Remove `svc_backup` backdoor account from all systems
- Uninstall AnyDesk from all hosts — verify no instances remain in non-standard paths
- Preserve all Sentinel logs and endpoint telemetry for forensic investigation
- Notify ICO within 72 hours of breach discovery — GDPR obligation given PII exposure
- Do **NOT** pay the ransom without first consulting law enforcement and legal counsel

###  Short Term (1–2 Weeks)

- Deploy MFA across all VPN, RDP, and remote access services without exception
- Implement application whitelisting to block unapproved executables in `C:\ProgramData\` and `C:\Users\Public\`
- Enable tamper protection on Windows Defender — prevents `kill.bat` style disabling
- Block `bitsadmin.exe` and `certutil.exe` outbound connections via firewall rules
- Restore `C:\Shares\` from clean backups — validate backup integrity before restoration
- Conduct full environment sweep for `wsync.exe`, `senseir.exe`, and AnyDesk remnants
- Implement network segmentation — workstations should not have direct SMB access to file servers

### Long Term (1–3 Months)

- Implement EDR solution with real-time alerting for shadow copy deletion, LSASS access, and LOLBin abuse
- Deploy honeypot shares to detect ransomware encryption activity early
- Conduct Purple Team exercise simulating Akira TTPs to validate detection coverage
- Implement a formal Incident Response plan — The Broker findings should have triggered full remediation
- Deploy Privileged Access Workstations (PAWs) for administrator accounts
- Implement Just-In-Time (JIT) access for administrative accounts
- Regular threat hunting exercises focusing on LOLBin abuse and lateral movement patterns
- Employee security awareness training — focus on phishing and social engineering

---

### ⚡ Key Lesson

> The most critical finding of this investigation is that this attack was **entirely preventable**. The Broker investigation identified persistent access mechanisms that were not fully remediated. AnyDesk remained installed, the backdoor account `svc_backup` was not removed, and no enhanced monitoring was deployed following the initial compromise. The Akira affiliate walked back in through the front door.
>
> **Incomplete remediation is not remediation.**

---

