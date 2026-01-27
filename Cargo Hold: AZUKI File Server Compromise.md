# Cargo Hold - Azuki File Server Compromise 

<img width="1024" height="1536" alt="cargoholdct2" src="https://github.com/user-attachments/assets/f8ccdba8-4ba8-40aa-af2b-415a309b2d31" />


|  Date of Report | 14-Dec-25         |
|-----------------|------------------|
| Severity Level  | CRITICAL         |
| Escalated To   | Joshua Makador – LOG(N) Pacific |
| Analyst         | Adetola Kolawole  |


## Summary of Events

About **72 hours** after the initial compromise of **AZUKI-SL**, the threat actor **reconnected to the existing foothold** using new external infrastructure, marking the start of a second operational phase.

The attacker performed **lateral movement** via **RDP** to the corporate file server **azuki-fileserver01**, leveraging **stolen administrative credentials**. Once on the file server, a structured **discovery** phase followed, including **network mapping**, **share enumeration**, and **permission analysis**.

A **hidden CBS staging directory** was created to support operations. The attacker then deployed tooling using **certutil** to download **ex.ps1**, followed by **credential acquisition** through the creation of **IT-Admin-Passwords.csv**. High-value data was collected via **xcopy** from the **IT-Admin file share** and prepared for exfiltration using **tar.exe** compression.

Further **credential access** was achieved using **pd.exe** to dump **LSASS** memory. The collected data was **exfiltrated** using **curl** to the anonymous file-sharing service **file.io**.

To maintain access, **persistence** was established through a **Windows Run key** pointing to a **masqueraded script**. Finally, **defense evasion** activity was observed through **PowerShell history deletion**, indicating deliberate anti-forensics behavior.

## WHO
### Threat Actor Architecture

| IP / Domain        | Purpose                                   |
|--------------------|-------------------------------------------|
| 159.26.106.98      | Return connection after dwell time         |
| 78.141.196.6       | Malware / script hosting (`ex.ps1`)        |
| file.io            | Anonymous cloud exfiltration endpoint     |
| fileadmin  | Administrative file server account used for lateral movement and staging |

##  WHAT
The attacker carried out these actions on **azuki-fileserver01**:

- Re-established access using newly rotated infrastructure  
- Performed RDP-based lateral movement with compromised credentials  
- Enumerated local and remote shares alongside privilege details  
- Identified network configuration and routing information  
- Created and concealed a staging directory within a Windows system path  
- Retrieved a malicious PowerShell payload  
- Generated exported credential spreadsheets  
- Recursively copied the IT-Admin file share  
- Archived all collected data into compressed files  
- Dumped LSASS memory using a renamed utility  
- Exfiltrated compressed archives to **file.io**  
- Established Run-key persistence referencing a masqueraded script  
- Removed PowerShell command history to limit forensic visibility

  ### Malicious Artifacts

| Artifact                   | Description                                      |
|----------------------------|--------------------------------------------------|
| ex.ps1                     | Downloaded PowerShell payload                   |
| IT-Admin-Passwords.csv     | Extracted credential file                       |
| credentials.tar.gz         | Compressed archive of staged data               |
| pd.exe                     | Renamed credential-dumping utility              |
| lsass.dmp                  | Full memory dump of LSASS                       |
| svchost.ps1                | Persistence beacon script                       |
| ConsoleHost_history.txt    | Deleted PowerShell history log                  |

##  WHEN
###   Incident Window
- **Start:** November 22, 2025, 12:27 AM UTC  
  *(Threat actor reconnected to azuki-sl via RDP)*
- **End:** November 22, 2025, 2:26 AM UTC  
  *(PowerShell activity traces removed by deleting `ConsoleHost_history.txt`)*

###   Exfiltration Window
- **Time:** November 22, 2025, 1:59:54 AM UTC  
  *(Data transferred using `curl.exe` to `file.io`)*
  

###  Unified Attacker Timeline & MITRE ATT&CK Mapping

This table provides a comprehensive log of the attack events, summarizing the action, and mapping it to the corresponding MITRE ATT&CK Tactic and Technique for structured analysis.

| Flag # | Time (UTC) | Event Description (Paraphrased) | MITRE Tactic | ATT&CK ID | Technique Name |
| :----: | :--------: | :------------------------------------------- | :-----------: | :-------------: | :----------------------------------------------- |
| 1 | 12:27:53 AM | Initial access to **azuki-sl** via RDP from `159.26.106.98`. | Initial Access | T1133 | External Remote Services |
| 2 | 12:38:47 AM | Lateral Movement to **azuki-fileserver01** via RDP. | Lateral Movement | T1021.001 | Remote Services: RDP |
| 3 | 12:38:49 AM | Use of the compromised `fileadmin` account. | Credential Access | T1078.003 | Valid Accounts |
| 4 | 12:40:54 AM | Local shared resources enumeration (`net.exe share`). | Discovery | T1135 | Network Share Discovery |
| 5 | 12:42:01 AM | Remote share enumeration (`net.exe view \\10.1.0.188`). | Discovery | T1135 | Network Share Discovery |
| 6 | 12:42:24 AM | Detailed privilege information gathered (`whoami.exe /all`). | Discovery | T1033 | System Owner/User Discovery |
| 7 | 12:42:46 AM | Full network configuration inspection (`ipconfig.exe /all`). | Discovery | T1016 | System Network Configuration Discovery |
| 8 & 9 | 12:55:43 AM | Staging directory `C:\Windows\Logs\CBS` was created and hidden (`attrib.exe +h +s`). | Defense Evasion | T1564.001 | Hidden Files and Directories |
| 10 | 12:56:47 AM | Malicious PowerShell script downloaded via `certutil.exe -urlcache`. | Execution | T1105 | Ingress Tool Transfer |
| 11 | 1:07:53 AM | Credentials harvested and saved to `IT-Admin-Passwords.csv`. | Collection | T1552.001 / T1555 | Credentials from Storage / OS Credential Dumping |
| 12 | 1:07:53 AM | Recursive data copying into the hidden staging directory (`xcopy.exe`). | Collection | T1119 | Automated Collection |
| 13 | 1:30:10 AM | Stolen data compressed into `credentials.tar.gz` using `tar.exe`. | Collection | T1560.001 | Archive Collected Data: Compression |
| 14 | 2:03:19 AM | Credential dumping tool deployed, renamed to `pd.exe`. | Credential Access | T1036.003 | Masquerading: Rename System Utility |
| 15 | 2:24:44 AM | LSASS process memory dumped using `pd.exe`. | Credential Access | T1003.001 | OS Credential Dumping: LSASS Memory |
| 16 & 17 | 1:59:54 AM | Compressed file exfiltrated to cloud service **file.io** using `curl.exe`. | Exfiltration | T1567.002 | Exfiltration to Cloud Storage |
| 18 | 2:10:50 AM | Persistence established by setting `FileShareSync` in a Registry Run key. | Persistence | T1547.001 | Registry Run Keys / Startup Folder |
| 19 | 2:04:45 AM | Persistent beacon script created (`svchost.ps1`), designed for process masquerading. | Defense Evasion | T1036.005 | Masquerading: Match Legitimate Name or Location |
| 20 | 2:26:01 AM | Anti-forensics performed by deleting the PowerShell command history file. | Defense Evasion | T1070.003 | Indicator Removal: Clear Command History |

##  WHERE
###  Primary Target
| System | Role |
| :--- | :--- |
| `azuki-fileserver01` | Corporate file server containing administrative, operational, and contract data. |

###   Key Directories
| Path | Purpose |
| :--- | :--- |
| `C:\Windows\Logs\CBS` | Hidden directory used for **staging** stolen data and deploying malware. |
| `C:\FileShares\IT-Admin` | Source file share containing the **stolen data** copied via `xcopy.exe`. |

###   Network Destinations (Indicators of Compromise)
| Type | Target | Purpose |
| :--- | :--- | :--- |
| **Script Download IP** | `78.141.196.6` | External host used to **download** the malicious PowerShell script (`ex.ps1`). |
| **Exfiltration Domain** | `file.io` | **Exfiltration** destination for the compressed archive (`credentials.tar.gz`). |
| **Internal Enumeration** | `10.1.0.188` | Internal host targeted for **network enumeration** (`net.exe view`). |


##   WHY
###   Root Causes
| Root Cause | Description |
| :--- | :--- |
| **Compromised Foothold Reuse** | The attacker leveraged an existing compromise on the `AZUKI-SL` system, indicating inadequate remediation or monitoring of previously affected assets. |
| **Lack of Multi-Factor Authentication (MFA)** | Absence of MFA on administrative accounts allowed the attacker to use stolen credentials freely for lateral movement and access. |
| **Insufficient Monitoring** | The file server lacked sufficient logging and behavioral monitoring, preventing timely detection of file access, staging activity, and tool execution. |
| **Broad Access Structure** | A wide, non-segmented administrative share structure simplified the attacker's discovery phase and accelerated data collection. |

###   Attacker Objectives
| Objective | Detail |
| :--- | :--- |
| **Credential Theft** | Extract highly privileged account credentials for future operations. |
| **Data Exfiltration** | Steal sensitive administrative and contractual data from the corporate file share. |
| **Maintaining Access** | Establish long-term persistence within the network for future unauthorized access. |
| **Network Expansion** | Enable subsequent, deeper lateral movement to other critical segments of the network. |

##   HOW (Kill Chain)
- Reconsolidation – Threat actor reconnects to foothold
- Lateral Movement – RDP to file server using stolen admin credentials
- Discovery – Shares, permissions, network mapping
- Staging Setup – Hidden CBS directory created
- Tool Deployment – certutil download of ex.ps1
- Credential Acquisition – Creation of IT-Admin-Passwords.csv
- Collection – xcopy of IT-Admin file share
- Preparation – tar.exe compression of collected data.
- Credential Access – pd.exe + LSASS dump
- Exfiltration – curl upload to file.io
- Persistence – Run key points to masqueraded script
- Defense Evasion – PowerShell history deletion

##   RECOMMENDATIONS
###  Immediate Remediation

These actions must be executed immediately to mitigate active unauthorized access and prevent further intrusion.

| Action Category | Specific Task | Rationale |
| :--- | :--- | :--- |
| **Credential Management** | Reset `fileadmin` and associated privileged credentials. | Mitigates current unauthorized access risks. |
| **Persistence Removal** | Remove the `FileShareSync` Registry Run key. | Eliminates the attacker's unauthorized persistence mechanism. |
| **Artifact Removal** | Delete the staging directory and all malicious artifacts. | Erases attacker files and conceals intrusion tracks. |
| **Network Blockade** | Block all outbound connections to `file.io` and related external infrastructure. | Prevents any subsequent data exfiltration attempts. |
| **Mandatory Rotation** | Trigger mandatory password rotation for all local and server administrators. | Enforces broad security across all critical administrative accounts. |


###  Short-Term Actions

| Action Category | Specific Task | Rationale |
| :--- | :--- | :--- |
| **Identity Protection** | **Enforce MFA** for all privileged and remote-access accounts. | Significantly enhances security against stolen credentials. |
| **Access Control** | **Harden permissions** on sensitive file shares. | Minimizes exposure of crucial data by restricting unnecessary access. |
| **Detection & Logging** | **Enable advanced auditing** for process, file, and network events. | Ensures capture of critical telemetry for timely detection and analysis. |
| **Detection Engineering** | Deploy specific **detection rules** for: `certutil` misuse, `xcopy` staging, `tar` archive creation, `curl` exfiltration, and unauthorized Run keys. | Directly addresses the attack techniques used, improving anomalous behavior identification. |

###  Long-Term Strategy (Subject to Operational and Budgetary Constraints)

| Action Category | Specific Task | Rationale / Implementation Plan |
| :--- | :--- | :--- |
| **Access Architecture** | **Segment administrative file shares.** | Phased restructuring to implement structured segmentation, reducing unauthorized access risk. |
| **Endpoint Security** | **Implement Privileged Access Workstations (PAWs).** | Prioritize dedicated, secure workstations for administrative tasks, requiring hardware, software investment, and administrator training. |
| **Forensics & Monitoring** | **Increase SIEM retention and telemetry granularity.** | Devise a phased budget-conscious upgrade plan to enhance long-term monitoring and forensic capabilities. |
| **Threat Hunting** | **Create baseline deviation alerts** for command-line execution patterns. | Integrate alerts into the security monitoring framework to detect suspicious deviations from typical system behavior. |

##   IMPACT 

Risk Assessment A successful attack would result in total administrative control, the loss of critical business data, and a long-term breach of the domain via stolen credentials.

Observed Incident Details The threat actor successfully exfiltrated sensitive credential archives and performed memory dumps (LSASS) to harvest further access. They secured long-term access through registry persistence and took active steps to evade forensic detection. Currently, the attack appears limited to data theft and unauthorized access, as no destructive malware or ransomware has been identified.

##  EVIDENCE COLLECTED AND KQL USED

### Flag 1: Return Connection Source 
<img width="1513" height="418" alt="Flag 1" src="https://github.com/user-attachments/assets/6708c083-eb09-4b4f-897b-55e66a8c8e45" />

**KQL Query Used:**
```
DeviceLogonEvents
| where DeviceName contains "azuki" 
| where Timestamp between (datetime(2025-11-20) .. datetime(2025-11-25))
| where isnotempty(RemoteIP)
| where ActionType in ("LogonSuccess", "LogonFailed")
| project Timestamp, DeviceName, AccountName, LogonType, ActionType, RemoteIP
| order by Timestamp asc
```

### Flag 2: Compromised File Server Device
<img width="1432" height="512" alt="Flag 2" src="https://github.com/user-attachments/assets/9d37cca5-2516-4451-a30a-ea089aa8011e" />

**KQL Query Used:** 
```
1st 
DeviceProcessEvents
| where DeviceName contains "azuki" 
| where Timestamp between (datetime(2025-11-22) .. datetime(2025-11-25)) 
| where FileName contains "mstsc.exe"
| project Timestamp, DeviceName, ProcessCommandLine, FolderPath, FileName, InitiatingProcessCommandLine, ActionType
| order by Timestamp asc
```
```
2nd
DeviceNetworkEvents
| where RemoteIP == "10.1.0.188" or LocalIP == "10.1.0.188"
| where Timestamp between (datetime(2025-11-20) .. datetime(2025-11-25)) 
| project Timestamp, DeviceName, LocalIP, RemoteIP, InitiatingProcessAccountName
| order by Timestamp asc
```
### Flag 3: Compromised Administrator Account
<img width="1432" height="512" alt="Flag 2" src="https://github.com/user-attachments/assets/3936d717-ae60-48fb-8166-9594a8f1ea06" />

**KQL Query Used:**
Same as above

### Flag 4: Share Enumeration Command
<img width="1387" height="412" alt="Flag 4" src="https://github.com/user-attachments/assets/4cc0527c-39d3-4f3f-826c-7c3dcf598906" />

**KQL Query Used:**

```
DeviceProcessEvents
| where DeviceName == "azuki-fileserver01"
| where Timestamp between (datetime(2025-11-22) .. datetime(2025-11-25)) 
| where ProcessCommandLine contains "net" or ProcessCommandLine contains "share" or ProcessCommandLine contains "view"
| project Timestamp, ProcessCommandLine
| order by Timestamp asc
```

### Flag 5: Remote Share Enumeration
<img width="1422" height="412" alt="Flag 5 " src="https://github.com/user-attachments/assets/886adabe-552c-4258-831a-fd3ad9b09845" />

**KQL Query Used:**
Same as above

### Flag 6: Privilege Enumeration
<img width="983" height="351" alt="Flag 6" src="https://github.com/user-attachments/assets/99e02150-c8e5-4cd0-9a34-94d20ed19679" />

**KQL Query Used:**
```
DeviceProcessEvents
| where DeviceName == "azuki-fileserver01"
| where Timestamp between (datetime(2025-11-22) .. datetime(2025-11-25)) 
| where ProcessCommandLine contains "whoami" 
    or ProcessCommandLine contains "net user"
    or ProcessCommandLine contains "localgroup"
    or ProcessCommandLine contains "priv"
| project Timestamp, InitiatingProcessAccountName, ProcessCommandLine
| order by Timestamp asc
```

### Flag 7:  Network Configuration Enumeration
<img width="972" height="241" alt="Flag 7" src="https://github.com/user-attachments/assets/db1a81c2-c3a4-41ab-a5a5-d7a851209503" />

**KQL Query Used:**
```
DeviceProcessEvents
| where DeviceName == "azuki-fileserver01"
| where Timestamp between (datetime(2025-11-22) .. datetime(2025-11-25)) 
| where ProcessCommandLine contains "ipconfig"
    or ProcessCommandLine contains "netstat"
    or ProcessCommandLine contains "arp"
    or ProcessCommandLine contains "route"
| project Timestamp, InitiatingProcessAccountName, ProcessCommandLine
| order by Timestamp asc
```

### Flag 8:  Directory Hiding Command
<img width="1841" height="525" alt="flag 8" src="https://github.com/user-attachments/assets/3fd6498c-3ba0-4e20-87f1-1d37e77cb873" />

**KQL Query Used:**

```
DeviceProcessEvents
DeviceProcessEvents
| where DeviceName contains "azuki-fileserver01"
| where Timestamp between (datetime(2025-11-22) .. datetime(2025-11-25)) 
| project Timestamp, DeviceName, ProcessCommandLine, FolderPath, FileName, InitiatingProcessCommandLine, ActionType
| order by Timestamp asc
```

### Flag 9: Staging Directory Path
<img width="1841" height="525" alt="Flag 9" src="https://github.com/user-attachments/assets/5aa0ee97-a4a9-4e89-8e1c-c57154291ddb" />

**KQL Query Used:**
Same as above

### Flag 10: Script Download Command
<img width="1892" height="441" alt="flag 10" src="https://github.com/user-attachments/assets/4ffb6211-b313-4149-8534-1cafe87dff83" />

**KQL Query Used:**

```
DeviceProcessEvents
| where DeviceName contains "azuki-fileserver01"
| where Timestamp between (datetime(2025-11-22) .. datetime(2025-11-25)) 
| project Timestamp, DeviceName, ProcessCommandLine, FolderPath, FileName, InitiatingProcessCommandLine, ActionType
| order by Timestamp asc
```

### Flag 11: Credential File Discovery
<img width="1248" height="737" alt="Flag 11" src="https://github.com/user-attachments/assets/b32775f8-2096-4bad-89ec-b3c037c9525c" />

**KQL Query Used:**

```
DeviceFileEvents
| where DeviceName == "azuki-fileserver01"
| where Timestamp between (datetime(2025-11-22) .. datetime(2025-11-25))  
| where ActionType == "FileCreated"
| where FileName contains "pass"
    or FileName contains "cred"
    or FileName contains "pwd"
    or FileName endswith ".txt"
    or FileName endswith ".zip"
| project Timestamp, FileName, FolderPath
```

### Flag 12: Recursive Copy Command
<img width="1902" height="262" alt="flag 12" src="https://github.com/user-attachments/assets/45f2786c-77bc-439e-b605-02633294b992" />

**KQL Query Used:**

```
KQL 
DeviceProcessEvents
| where DeviceName contains "azuki-fileserver01"
| where Timestamp between (datetime(2025-11-22) .. datetime(2025-11-25)) 
| project Timestamp, DeviceName, ProcessCommandLine, FolderPath, FileName, InitiatingProcessCommandLine, ActionType
| order by Timestamp asc
```

### Flag 13: Compression Command
<img width="1918" height="553" alt="Flag 13" src="https://github.com/user-attachments/assets/36cd0df1-17b9-4356-b5a1-3ba9a041cad4" />

**KQL Query Used:**
Same as above

### Flag 14: Renamed Credential Dump Tool
<img width="1427" height="233" alt="flag 14" src="https://github.com/user-attachments/assets/53e24bb4-845e-495e-a2cb-c97b04e1d3ca" />

**KQL Query Used:**

```
DeviceFileEvents
| where DeviceName == "azuki-fileserver01"
| where Timestamp between (datetime(2025-11-22) .. datetime(2025-11-25))
| where ActionType == "FileCreated"
| where FileName endswith ".exe"
| project Timestamp, DeviceName, FolderPath, FileName, InitiatingProcessFileName, InitiatingProcessCommandLine, SHA1
```

### Flag 15: Memory Dump Command
<img width="1918" height="567" alt="Flag 15" src="https://github.com/user-attachments/assets/7e952aa9-7b4a-4df6-8f29-c78149fc3965" />

**KQL Query Used:**

```
DeviceProcessEvents
| where DeviceName contains "azuki-fileserver01"
| where Timestamp between (datetime(2025-11-22) .. datetime(2025-11-25)) 
| project Timestamp, DeviceName, ProcessCommandLine, FolderPath, FileName, InitiatingProcessCommandLine, ActionType
| order by Timestamp asc
```

### Flag 16 & 17: Exfiltration Upload Command & Cloud Exfiltration Service
<img width="1868" height="585" alt="flag 16 and 17 " src="https://github.com/user-attachments/assets/b3cf05a9-3a1a-4fc2-b3eb-d5abc1d397b5" />

**KQL Query Used:**
Same as above

### Flag 18: Registry Value Name (Persistence)
<img width="1523" height="377" alt="flag 18" src="https://github.com/user-attachments/assets/dc2ac48f-0072-4443-ba5c-1e407e57b0e4" />

**KQL Query Used:**
```
DeviceRegistryEvents
| where DeviceName == "azuki-fileserver01"
| where Timestamp between (datetime(2025-11-22) .. datetime(2025-11-25)) 
| where ActionType == "RegistryValueSet" or ActionType == "RegistryKeyCreate"
| where RegistryKey has_any (
    @"\Software\Microsoft\Windows\CurrentVersion\Run",
    @"\Software\Microsoft\Windows\CurrentVersion\RunOnce")
| project Timestamp, RegistryKey, InitiatingProcessCommandLine, RegistryValueType, RegistryValueName
| order by Timestamp asc
```

### Flag 19: Persistence Beacon Filename
<img width="1413" height="420" alt="Flag 19" src="https://github.com/user-attachments/assets/7c7a8672-05bc-4ba8-ad74-9015c0af68b4" />

**KQL Query Used:**
```
DeviceRegistryEvents
| where DeviceName == "azuki-fileserver01"
| where Timestamp between (datetime(2025-11-22) .. datetime(2025-11-25)) 
| where ActionType =~ "RegistryValueSet"
| where RegistryValueData contains ".exe"
    or RegistryValueData contains ".ps1"
    or RegistryValueData contains ".bat"
    or RegistryValueData contains ".vbs"
| extend BeaconFile = extract(@"([^\\]+)$", 1, RegistryValueData)
| project Timestamp, RegistryKey, RegistryValueData, BeaconFile
| order by Timestamp asc
```
### Flag 20: PowerShell History File Deleted
<img width="1281" height="382" alt="flag 20" src="https://github.com/user-attachments/assets/c76092da-aed6-46ab-802d-d1efbe244f51" />

**KQL Query Used:**
```
DeviceFileEvents
| where DeviceName == "azuki-fileserver01"
| where Timestamp between (datetime(2025-11-22) .. datetime(2025-11-25)) 
| where ActionType == "FileDeleted"
| project Timestamp, FileName, FolderPath
| order by Timestamp asc
```















