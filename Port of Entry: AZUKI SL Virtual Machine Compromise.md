#  Port of Entry - Azuki-SL Virtual Machine Compromise 
<img width="740" height="1110" alt="image" src="https://github.com/user-attachments/assets/175e509e-a948-4788-8507-5e7c0d30ce74" />

| **Date of Report** |21st November 2025|
|--------------------|--------------------|
| **Severity Level** | **CRITICAL**       |
| **Report Status**  | Open               |
| **Escalated To**   | Joshua Makador – LOG(N) Pacific |
| **Incident Date**  | 16th November 2025 |
| **Analyst**        | Adetola Kolawole  |


## Summary of Events

This investigation confirmed that the compromise of the **AZUKI-SL** administrator workstation on *19 November 2025* was not routine activity, but a coordinated intrusion that leveraged valid credentials, trusted Windows components, and staged automation.

The threat hunt uncovered a structured, multi-phase operation that followed a clear attack lifecycle:

- **Initial foothold** gained through successful RDP authentication using a compromised account.  
- **System and network reconnaissance** conducted through native utilities disguised as normal troubleshooting.  
- **Defense evasion** via Microsoft Defender tampering, file-extension and folder exclusions, and the creation of a hidden staging directory.  
- **Persistent access** established through a scheduled task masquerading as a system update and a secondary administrator-level account.  
- **Credential access** achieved using a renamed Mimikatz binary targeting LSASS memory.  
- **Data staging and exfiltration** carried out inside a concealed ProgramData folder and uploaded over HTTPS to a Discord webhook.  
- **Anti-forensics activity** including targeted clearing of the Security event log to obscure the attacker’s trail.

This activity demonstrates a deliberate compromise aimed at harvesting credentials, staging sensitive files, and moving deeper into the network. All relevant indicators are listed in the **IoCs** section of this report.

---

## Hunt Scope
- **Lab Environment:** `LOG(N) Pacific - Cyber Range 1` 
- **Platform:** Microsoft Defender for Endpoint + Azure Sentinel (Log Analytics Workspace)  
- **Host Monitored:** `azuki-sl` (IT administrator workstation)  
- **Data Sources:**  
  - `DeviceProcessEvents`  
  - `DeviceFileEvents`  
  - `DeviceNetworkEvents`  
  - `DeviceLogonEvents`  
- **Timeframe:** 2025-11-19 to 2025-11-20
- **Frameworks Applied:** *MITRE ATT&CK*, *NIST 800-61*
- **Objective:** Identify initial access, reconnaissance activity, defense evasion, credential dumping, persistence mechanisms, lateral movement attempts, and data exfiltration.

📌 Timeline of Events (UTC) & MITRE ATTACK

| Time (UTC) | Flag | Tactic           | Key Event Details / Evidence                                                                                      | MITRE ID                   |
|-----------|------|-----------------------------|----------------------------------------------------------------------------------------------------------|----------------------------------------|
|  **Nov 19, 2025 6:36:21 PM**    | 1    | Initial Access              | RDP login to `azuki-sl` using compromised account `kenji.sato`                                          | T1021.001, T1078                       |
| **Nov 19, 2025 6:36:21 PM**  | 2    | Initial Access              | Valid account leveraged to gain interactive access                                                       | T1078                                  |
|  **Nov 19, 2025 7:04:01 PM** | 3    | Execution                   | Recon commands executed (`arp -a`, `ipconfig /all`)                                                      | T1059.003, T1016                       |
| **Nov 19, 2025 6:49:21 PM**   | 4    | Execution                   | PowerShell execution from Downloads / Temp directories                                                   | T1059.001                              |
| **Nov 19, 2025 6:49:21 PM**  | 5    | Persistence                 | Scheduled task created for long-term persistence                                                         | T1564, TA0005                              |
|  **Nov 19, 2025 6:49:21 PM**    | 6    | Defense Evasion             | Temp folder excluded from Defender scanning: `C:\Users\KENJI~1.SAT\AppData\Local\Temp`                   | T1562.001 T1564                             |
| **Nov 19, 2025 7:06:58 PM**   | 7    | Defense Evasion             | `certutil.exe` abused to download malicious tools                                                        | T1105                                 |
| **Nov 19, 2025 7:07:46 PM**   | 8    | Persistence                 | Scheduled task name created:  “Windows Update Check” → runs attacker payload                                                      | T1053.005                              |
| **Nov 19, 2025 7:07:46 PM**   | 9    | Persistence                 | Scheduled task executes malicious payload: `C:\ProgramData\WindowsCache\svchost.exe`                     | T1053.005                              |
| **Nov 19, 2025 7:06:58 PM**    | 10   | Command & Control           | Outbound connection to C2 server: **78.141.196.6**                                                       | T1071.001, T1105                       |
| **Nov 19, 2025 7:11:04 PM**   | 11   | Command & Control           | C2 communications over port **443**                                                                     | T1071.001                              |
| **Nov 19, 2025 7:07:22 PM**   | 12   | Credential Access           | Credential dumping tool identified: `mm.exe`                                                            | T1003.001                              |
| **Nov 19, 2025 7:08:22 PM**   | 13   | Credential Access           | Mimikatz module used: `sekurlsa::logonpasswords`                                                        | T1003.001                              |
| **Nov 19, 2025 7:08:58 PM**   | 14   | Collection                  | Data compressed into archive: `export-data.zip`                                                        | T1560.001                              |
| **Nov 19, 2025 7:09:58 PM**   | 15   | Exfiltration                | Data exfiltrated via HTTPS Discord webhook (`curl.exe`)                                                 | T1567.002                              |
| **Nov 19, 2025 7:11:39 PM**   | 16   | Anti-Forensics              | Security event log cleared via `wevtutil.exe cl Security`                                               | T1070.001                              |
| **Nov 19, 2025 7:11:39 PM**  | 17   | Persistence                 | Hidden administrator account created: `support`                                                       | T1136.001                              |
| **Nov 19, 2025 6:49:48 PM**   | 18   | Execution                   | Malicious PowerShell automation script executed: `wupdate.ps1`                                        | T1059.001                              |
| **Nov 19, 2025 7:10:39 PM**    | 19   | Lateral Movement            | Attacker targets RDP host **10.1.0.188** using stored credentials                                       | T1550.002, T1021.001                   |
| **Nov 19, 2025 7:10:39 PM**   | 20   | Lateral Movement            | Built-in RDP client (`mstsc.exe`) used for pivot attempt                                                 | T1021.001                              |

## Remediation & Hardening Plan

### **Long-Term (1–3 Months)**

- Deploy MFA everywhere, remove public RDP, implement EDR full telemetry.
- Introduce Defender Tamper Protection and Attack Surface Reduction (ASR) rules.
- Begin SIEM log centralisation with immutable storage.
- Apply least-privilege access for sensitive data and restrict ZIP/archiving in ProgramData/Temp.
- Roll out security awareness for admins on script abuse, LOLBins, and suspicious RDP use.

### **Detection Engineering (Ongoing)**

- Deploy full Privileged Access Management (PAM).
-  Perform regular red/purple-team exercises to test resilience.
- Move toward password-less authentication for all admins.
- Refine monitoring rules to alert on creation of hidden ProgramData folders, Temp-based execution, new local admin accounts or priviledge changes
- Alert on outbound HTTPS uploads to non-business services.

##  Lessons Learned

- RDP without MFA exposes organizations to high-risk credential compromise.
- LOLBins and renamed binaries make detection harder; deep telemetry is essential.
- Defender exclusions can quietly weaken protection for months if not monitored.
- Scheduled tasks and local accounts remain high-value persistence vectors.
- Strong logging, segmentation, and privileged identity controls reduce long-term risk.

## IOCs

##  Starting Point – Initial Access

**Objective:**
Determine the origin  and source IP address of the Remote Desktop Protocol connection

- **KQL Query Used:**
```
DeviceLogonEvents
| where Timestamp between (datetime(2025-11-19) .. datetime(2025-11-22))
| where DeviceName == "azuki-sl"
| where ActionType in ("LogonSuccess", "LogonFailed")
| where isnotempty(RemoteIP)
| where RemoteIP !in ("127.0.0.1", "::1", "-")
| where not(ipv4_is_private(RemoteIP))
| project Timestamp, DeviceName, AccountName, LogonType, ActionType, RemoteIP
| order by Timestamp asc
```
<img width="1107" height="507" alt="image" src="https://github.com/user-attachments/assets/c7a813e7-23a3-4ed1-a2ea-a2a74ebdca6c" />

## Compromised User Account

**Objective:**
Identify which credentials were compromised and determine the scope of unauthorised access.

**Hypothesis** - Attackers often enumerate network topology to identify lateral movement opportunities and high-value target.


- **KQL Query Used:**
```
DeviceLogonEvents
| where Timestamp between (datetime(2025-11-19) .. datetime(2025-11-22))
| where DeviceName == "azuki-sl"
| where ActionType in ("LogonSuccess", "LogonFailed")
| where isnotempty(RemoteIP)
| where RemoteIP !in ("127.0.0.1", "::1", "-")
| where not(ipv4_is_private(RemoteIP))
| project Timestamp, DeviceName, AccountName, LogonType, ActionType, RemoteIP
| order by Timestamp asc
```
<img width="1262" height="375" alt="flag 2" src="https://github.com/user-attachments/assets/1d5311b9-553f-493f-8262-06ae650466ef" />

## Network Reconnaissance

**Objective:**
Determine the command and argument used to enumerate network neighbours
**Hypothesis** - Attackers often enumerate network topology to identify lateral movement opportunities and high-value targets.

- **KQL Query Used:**
```
DeviceProcessEvents
| where Timestamp between (datetime(2025-11-19) .. datetime(2025-11-22))
| where DeviceName == "azuki-sl"
| where AccountName contains "kenji.sato"
| where ProcessCommandLine has_any ("arp", "getmac", "ipconfig", "netsh", "route print")
| where FileName in~ ("cmd.exe", "powershell.exe", "arp.exe", "getmac.exe", "ipconfig.exe", "netsh.exe")
| project Timestamp, FileName, ProcessCommandLine, InitiatingProcessAccountName
| order by Timestamp asc
```
<img width="1082" height="136" alt="flag 3" src="https://github.com/user-attachments/assets/a4566c62-bc70-4125-b56e-fe6a271fb7a6" />

- **Evidence Collected:** `"ARP.EXE" -a` in CLI
- **Final Finding:** `-Arp.exe` is used to check IP addresses of devices the system recently communicated with

## Malware Staging Directory

**Objective:**
Determine the PRIMARY staging directory where malware was stored

**Hypothesis** - Attackers establish staging locations to organise tools and stolen data. Identifying these directories reveals the scope of compromise and helps locate additional malicious artefacts.

- **KQL Query Used:**
```
DeviceProcessEvents
| where DeviceName == "azuki-sl"
| where AccountName contains "kenji.sato"
| where Timestamp between (datetime(2025-11-19) .. datetime(2025-11-19))
| project Timestamp, FileName, ProcessCommandLine, InitiatingProcessAccountName, FolderPath
| order by Timestamp asc
```
<img width="1827" height="443" alt="flag 4" src="https://github.com/user-attachments/assets/74ab11cd-2c7a-49a1-a185-443e7baab397" />

- **Evidence Collected:** `C:\ProgramData\WindowsCache` in CLI
- **Final Finding:** -  The attacker created/used `C:\ProgramData\WindowsCache`; hid it, stored tools and stolen data inside it then zipped and exfiltrated data from this exact directory

## File Extension Exclusions

**Objective:**
Identify how many file extensions were excluded from Windows Defender

**Hypothesis** - Attackers add file extension exclusions to Windows Defender to prevent scanning of malicious files. By excluding them, the attacker can drop new malware without Defender noticing 

- **KQL Query Used:**
```
DeviceRegistryEvents
| where DeviceName == "azuki-sl"
| where Timestamp between (datetime(2025-11-19) .. datetime(2025-11-21))
| where RegistryKey has @"Windows Defender\Exclusions\Extensions"
| project Timestamp, RegistryKey, RegistryValueName, RegistryValueData, ActionType
| order by Timestamp asc
```
<img width="1227" height="245" alt="flag 5" src="https://github.com/user-attachments/assets/edc476fa-d678-49f8-8e53-24d64e3fd591" />

- **Evidence Collected:** 3 file extension exclusions were added `.bat; .psi; .exe` 
- **Final Finding:** -  The attacker intends to use these later,  These exclusions set the stage for the next phases to deploy more toolinng into `C:\ProgramData\WindowsCache`; run credential dumping, file collection and lateral movement scripts freely.
Execute exfiltration binaries without Defender interference.

                                                                                                      
## Download Utility Abuse

**Objective:**
Determine the Windows-native binary the attacker abused to download files

**Hypothesis** - Legitimate system utilities are often weaponized to download malware while evading detection. 

- **KQL Query Used:**
```
DeviceRegistryEvents
| where DeviceName == "azuki-sl"
| where Timestamp between (datetime(2025-11-19) .. datetime(2025-11-21))
| project Timestamp, RegistryKey, RegistryValueName, RegistryValueData, ActionType, InitiatingProcessFolderPath
| order by Timestamp asc
```
<img width="1845" height="462" alt="Flag 6" src="https://github.com/user-attachments/assets/40b602c3-9bda-4d0a-8e46-4ef7c041435b" />

- **Evidence Collected:** : `C:\Users\KENJI~1.SAT\AppData\Local\Temp` 
- **Final Finding:** - Temp folder was excluded from Defender scanning

## Temporary Folder Exclusion

**Objective:**
Determine the temporary folder path was excluded from Windows Defender scanning

**Hypothesis** - Attackers add folder path exclusions to Windows Defender to prevent scanning of directories used for downloading and executing malicious tools.

- **KQL Query Used:**
```
DeviceProcessEvents
| where Timestamp between (datetime(2025-11-19) .. datetime(2025-11-20))
| where DeviceName == "azuki-sl" 
| where AccountName contains "kenji.sato"
| project Timestamp, ProcessCommandLine, ActionType, AccountName, FileName
```
<img width="1632" height="485" alt="Flag 7" src="https://github.com/user-attachments/assets/2af1ac61-f2e7-4ad2-82a7-52eddfbeeaa6" />

- **Evidence Collected:** : `certutil.exe` 
- **Final Finding:** - `certutil.exe` abused to download malicious files.


## Scheduled Task Name

**Objective:**
Identify the Windows-native binary the attacker abused to download files

**Hypothesis**  Scheduled tasks provide reliable persistence across system reboots, blends in with legitimate Windows maintenanace routines and it keep control even if the initial access is removed

- **KQL Query Used:**
```
DeviceProcessEvents
| where Timestamp between (datetime(2025-11-19) .. datetime(2025-11-20))
| where DeviceName == "azuki-sl" 
| where AccountName contains "kenji.sato"
| project Timestamp, ProcessCommandLine, ActionType, AccountName, FileName
```
<img width="1508" height="466" alt="Flag 8" src="https://github.com/user-attachments/assets/ace7b5b6-5745-4e35-a6d8-3bfc151e8d1a" />

- **Evidence Collected:**  `Windows Update Check` 
- **Final Finding:** Persistence established via scheduled task 

## Scheduled Task Target

**Objective:**
Identify the executable path configured in the scheduled task

**Hypothesis** The scheduled task action defines what executes at runtime; this reveals the exact persistence mechanism and the malware location

- **KQL Query Used:**
```
DeviceProcessEvents
| where Timestamp between (datetime(2025-11-19) .. datetime(2025-11-20))
| where DeviceName == "azuki-sl" 
| where AccountName contains "kenji.sato"
| project Timestamp, ProcessCommandLine, ActionType, AccountName, FileName
```
<img width="1555" height="512" alt="flag 9" src="https://github.com/user-attachments/assets/9f7ee038-06c2-43ef-8259-a37b84d3ffb3" />

- **Evidence Collected:**  `C:\ProgramData\WindowsCache\svchost.exe` 
- **Final Finding:** Task configured to execute malicious file

## C2 Server Address

**Objective:**
Determine the IP address of the command and control server

**Hypothesis** Attackers often use  external command-and-control infrastructure to remotely manage the compromised host. If we identify the C2 server involved, we can block its traffic and trace the attacker’s wider infrastructure.
- **KQL Query Used:**
```
DeviceNetworkEvents
| where Timestamp between (datetime(2025-11-19) .. datetime(2025-11-20))
| where DeviceName == "azuki-sl" 
| where InitiatingProcessAccountName contains "kenji.sato"
| project Timestamp, RemoteIP, RemoteUrl, RemotePort, RemoteIPType, InitiatingProcessFileName, InitiatingProcessCommandLine
```
<img width="1555" height="667" alt="image" src="https://github.com/user-attachments/assets/ef6af943-a4dc-4334-8989-18dfb2b88617" />

- **Evidence Collected:**  `78.141.196.6` 
- **Final Finding:** Outbound C2 connection made

## C2 Communication Port

**Objective:**
Determine the destination port used for command and control communications

**Hypothesis** C2 communication ports can indicate the framework or protocol used. This information supports network detection rules and threat intelligence correlation

- **KQL Query Used:**
```
DeviceNetworkEvents
| where Timestamp between (datetime(2025-11-19) .. datetime(2025-11-20))
| where DeviceName == "azuki-sl" 
| where InitiatingProcessAccountName contains "kenji.sato"
| project Timestamp, RemoteIP, RemoteUrl, RemotePort, RemoteIPType, InitiatingProcessFileName, InitiatingProcessCommandLine
```
<img width="1555" height="667" alt="image" src="https://github.com/user-attachments/assets/d3b8ae05-8ce2-48ee-84db-c1711b46e9fd" />

- **Evidence Collected:**  `443` 
- **Final Finding:** C2 traffic sent over port 443
-  web traffic to avoid detection/network filtering by blending in with existing traffic.


## Credential Theft Tool

**Objective:**
Identify the filename of the credential dumping tool

**Hypothesis** Credential dumping tools extract authentication secrets from system memory. These tools are typically renamed to avoid signature-based detection.

- **KQL Query Used:**
```
DeviceFileEvents
| where Timestamp between (datetime(2025-11-19) .. datetime(2025-11-20))
| where DeviceName == "azuki-sl" 
| where InitiatingProcessAccountName contains "kenji.sato"
| project Timestamp, FileName, FolderPath, InitiatingProcessFileName, InitiatingProcessCommandLine, InitiatingProcessFolderPath
```
<img width="1656" height="692" alt="image" src="https://github.com/user-attachments/assets/4441caea-5ba3-4b00-85b9-d550c9caf066" />

- **Evidence Collected:**  `mm.exe` 
- **Final Finding:** The attacker downloaded a renamed credential dumper into the staging directory. It executed commands consistent with Mimikatz usage.

## Credential Access; Memory Extraction Module

**Objective:**
Identify tthe module used to extract logon passwords from memory

**Hypothesis** Credential dumping tools use specific modules to extract passwords from security subsystems. Documenting the exact technique used aids in detection engineering.

- **KQL Query Used:**
```
DeviceProcessEvents
| where Timestamp between (datetime(2025-11-19) .. datetime(2025-11-20))
| where DeviceName == "azuki-sl" 
| where AccountName contains "kenji.sato"
| project Timestamp, ProcessCommandLine, ActionType, AccountName, FileName
```
<img width="1656" height="692" alt="image" src="https://github.com/user-attachments/assets/4441caea-5ba3-4b00-85b9-d550c9caf066" />

- **Evidence Collected:**  `sekurlsa::logonpasswords` 
- **Final Finding:** OS Credential Dumping: LSASS MemorySub-technique rationale:sekurlsa module interacts with Security Support Provider (SSP) data inside LSASS.logonpasswords extracts plaintext credentials, NTLM hashes, Kerberos keys.

## Data Staging Archive

**Objective:**
 Identify the compressed archive filename used for data exfiltration

**Hypothesis** Attackers compress stolen data for efficient exfiltration. The archive filename often includes dates or descriptive names for the attacker's organisation.

- **KQL Query Used:**
```
DeviceFileEvents
| where Timestamp between (datetime(2025-11-19) .. datetime(2025-11-20))
| where DeviceName == "azuki-sl" 
| where InitiatingProcessAccountName contains "kenji.sato"
| project Timestamp, FileName, FolderPath, InitiatingProcessFileName, InitiatingProcessCommandLine, InitiatingProcessFolderPath
```
<img width="1517" height="441" alt="image" src="https://github.com/user-attachments/assets/587e52e6-9c8b-41fb-ba2f-9d6654491308" />

- **Evidence Collected:**  `export-data.zip` 
- **Final Finding:** Stolen data was compressed into `export-data.zip` within staging folder.


##  Exfiltration Channel

**Objective:**
 Determine the cloud service used to exfiltrate stolen data

**Hypothesis** Attackers compress stolen data for efficient exfiltration. The archive filename often includes dates or descriptive names for the attacker's organisation.

- **KQL Query Used:**
```
DeviceNetworkEvents
| where Timestamp between (datetime(2025-11-19) .. datetime(2025-11-20))
| where DeviceName == "azuki-sl" 
| where InitiatingProcessAccountName contains "kenji.sato"
| project Timestamp, InitiatingProcessFileName, InitiatingProcessCommandLine, InitiatingProcessFolderPath, RemoteIPType, RemoteIP
```
<img width="1506" height="432" alt="image" src="https://github.com/user-attachments/assets/a6293442-345c-4c93-a39f-499b39933cfb" />

- **Evidence Collected:**  `discord` 
- **Final Finding:** Data exfiltrated using `curl.exe` an HTTPS POST to a Discord webhook endpoint

## Anti-Forensics; Log Tampering
**Objective:**
 Determine the first log cleared by the attacker

**Hypothesis** Clearing event logs destroys forensic evidence and impedes investigation efforts. The order of log clearing usually indicates the attacker's priorities and sophistication

- **KQL Query Used:**
```
DeviceNetworkEvents
| where Timestamp between (datetime(2025-11-19) .. datetime(2025-11-20))
| where DeviceName == "azuki-sl" 
| where InitiatingProcessAccountName contains "kenji.sato"
| project Timestamp, InitiatingProcessFileName, InitiatingProcessCommandLine, InitiatingProcessFolderPath, RemoteIPType, RemoteIP
```
<img width="1510" height="446" alt="flag 16" src="https://github.com/user-attachments/assets/0ffaed59-953e-4440-95a0-a3470659cea0" />

- **Evidence Collected:**  `Security` 
- **Final Finding:** Security event log cleared using `wevtutil cl Security`. This is usually the first log attackers target because it holds the most incriminating activity.

## Persistence Account
**Objective:**
 Determine the first log cleared by the attacker

**Hypothesis** Hidden administrator accounts provide alternative access for future operations. These accounts are often configured to avoid appearing in normal user interfaces

- **KQL Query Used:**
```
DeviceProcessEvents
| where DeviceName == "azuki-sl"
| where AccountName contains "kenji.sato"
| where Timestamp between (datetime(2025-11-19) .. datetime(2025-11-20))
| project Timestamp, ProcessCommandLine, FolderPath, InitiatingProcessAccountName
| order by Timestamp asc
```
<img width="1527" height="237" alt="flag 17" src="https://github.com/user-attachments/assets/ec0abb76-b7b7-4c0d-9be6-7af4f6f9d6ad" />

- **Evidence Collected:**  `support` 
- **Final Finding:** The attacker created a new local user and added it to the Administrators group to maintain privileged access even if other entry points are removed.

## Malicious Script
**Objective:**
Identify the PowerShell script file used to automate the attack chain

**Hypothesis** Attackers often use scripting languages to automate their attack chain. Identifying the initial attack script will reveal the entry point and automation method used in the compromise.

- **KQL Query Used:**
```
DeviceFileEvents
| where Timestamp between (datetime(2025-11-19) .. datetime(2025-11-20))
| where DeviceName == "azuki-sl" 
| where InitiatingProcessAccountName contains "kenji.sato"
| project Timestamp, FileName, FolderPath, InitiatingProcessFileName, InitiatingProcessCommandLine, InitiatingProcessFolderPath
```
<img width="1552" height="505" alt="image" src="https://github.com/user-attachments/assets/102cac9a-9500-4853-ae06-f51cf3410812" />

- **Evidence Collected:**  `wupdate.ps1` 
- **Final Finding:** The attacker used wupdate.ps1 as a staged PowerShell script that automates key steps in their attack chain, such as pulling payloads, running commands, and modifying system settings without user interaction.
By disguising it as a harmless update script, they run it quietly to maintain control, deploy persistence, and prepare the system for later actions like data staging or exfiltration.

## Secondary Target
**Objective:**
Identify the PowerShell script file used to automate the attack chain

**Hypothesis** Lateral movement targets are selected based on their access to sensitive data or network privileges. Identifying these targets reveals attacker objectives.

- **KQL Query Used:**
```
DeviceNetworkEvents
| where Timestamp between (datetime(2025-11-19) .. datetime(2025-11-20))
| where DeviceName == "azuki-sl" 
| where InitiatingProcessAccountName contains "kenji.sato"
| project Timestamp, RemoteIP, RemoteUrl, RemotePort, RemoteIPType, InitiatingProcessFileName, InitiatingProcessCommandLine
```
<img width="1501" height="451" alt="flag 19" src="https://github.com/user-attachments/assets/878e9232-acf2-45d7-a810-fd157425daa0" />

- **Evidence Collected:**  `10.1.0.188 ` 
- **Final Finding:** Target internal private address used to pivot deeper into the network identified

## Remote Access Tool
**Objective:**
Determine the remote access tool used for lateral movement

**Hypothesis** Built-in remote access tools are preferred for lateral movement as they blend with legitimate administrative activity. This technique is harder to detect than custom tools.

- **KQL Query Used:**
```
DeviceNetworkEvents
| where Timestamp between (datetime(2025-11-19) .. datetime(2025-11-20))
| where DeviceName == "azuki-sl" 
| where InitiatingProcessAccountName contains "kenji.sato"
| project Timestamp, RemoteIP, RemoteUrl, RemotePort, RemoteIPType, InitiatingProcessFileName, InitiatingProcessCommandLine
```
<img width="1422" height="357" alt="image" src="https://github.com/user-attachments/assets/893d5f7f-350d-4683-9222-00840442757d" />

- **Evidence Collected:**  `mstsc.exe` 
- **Final Finding:** Native RDP client `mstsc.exe` used for pivot attempt
