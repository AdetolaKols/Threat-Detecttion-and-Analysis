# Cargo Hold - Azuki File Server Compromise 

<img width="740" height="1110" alt="image" src="https://github.com/user-attachments/assets/175e509e-a948-4788-8507-5e7c0d30ce74" />

## Report Metadata

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
### Threat Actor Archutecture

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


