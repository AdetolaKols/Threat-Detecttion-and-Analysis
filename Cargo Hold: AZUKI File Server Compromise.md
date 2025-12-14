# Cargo Hold - Azuki File Server Compromise 

<img width="740" height="1110" alt="image" src="https://github.com/user-attachments/assets/175e509e-a948-4788-8507-5e7c0d30ce74" />

|  Date of Report | 14-Dec-25         |
|-----------------|------------------|
| Severity Level  | CRITICAL         |
| Escalated To   | Joshua Makador – LOG(N) Pacific |
| Analyst         | Adetola Kolawole  |


## Summary of Events

Approximately **72 hours** after the initial compromise of **AZUKI-SL (Part 1)**, the threat actor **reconnected to the existing foothold** using new external infrastructure, marking the start of a second operational phase.

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
