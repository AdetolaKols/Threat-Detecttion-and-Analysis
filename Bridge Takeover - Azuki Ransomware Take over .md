# Bridge Takeover - AZUKI Import/Export

<img width="1536" height="1024" alt="ChatGPT Image Jan 11, 2026, 07_06_07 PM" src="https://github.com/user-attachments/assets/dd066846-059d-4ca5-820f-e1d68508fc4c" />


|  Date of Report | 25-Dec-25         |
|-----------------|------------------|
| Severity Level  | CRITICAL         |
| Escalated To   | Joshua Makador – LOG(N) Pacific |
| Analyst         | Adetola Kolawole  |


## Summary of Events

Five days after the initial compromise of AZUKI-SL, the threat actor re-entered the environment using newly rotated infrastructure. This marked the start of a second, more deliberate operational phase focused on credential theft, data collection, and exfiltration.
The attacker pivoted laterally to a high-value administrative workstation (azuki-adminpc), established persistence, harvested credentials from multiple sources, staged sensitive business data, and exfiltrated it to anonymous cloud storage services.

## WHO
### Threat Actor Architecture

| IP / Domain        | Purpose                                   |
|--------------------|-------------------------------------------|
| 159.26.106.98      | Initial reconnection after dwell time        |
| litter.catbox.moe      | Tool and archive hosting       |
| store1.gofile.io         | Anonymous cloud exfiltration endpoint   |
| 45.112.123.227  | Exfiltration destination server IP |
| yuki.tanaka  | Compromised user account |
| yuki.tanaka  | Backdoor administrator account |

###  WHAT  - Attacker Actions
- The attacker performed the following actions on azuki-adminpc:
- Re-established access using rotated infrastructure
- Conducted RDP-based lateral movement
- Enumerated users, sessions, domain trusts, and network configuration
- Downloaded credential theft tooling and supporting utilities
- Extracted browser credentials using DPAPI
- Located KeePass databases and extracted the master password
- Discovered plaintext password files on disk
- Staged sensitive business data in a masqueraded system directory
- Compressed collected data into multiple archives
- Exfiltrated data using HTTPS POST uploads
- Established persistence and performed defense evasion

### Malicious Artifacts

| Artifact                   | Description                                      |
|----------------------------|--------------------------------------------------|
| meterpreter.exe             | C2 implant                  |
| m.exe     |  Credential theft tool                      |
| silentlynx.exe             | Supporting malicious utility               |
| KB5044273-x64.7z           | Renamed credential-dumping utility              |
| credentials.tar.gz         | Staged credential archive                       |
| tax-documents.tar.gz       | Staged business data                      |
| contracts-data.tar.gz      | Staged contractual data                  |
| KeePass-Master-Password.txt | Extracted password manager master key                 |
| OLD-Passwords.txt | Plaintext credential file                |
| ConsoleHost_history.txt | Deleted PowerShell history                 |

## ⏱️ WHEN — Timeline

### Incident Window

- **Start:** Nov 25, 2025 – 04:06:52 UTC  
- **End:** Nov 25, 2025 – Post-exfiltration and cleanup  

### Exfiltration Window

- **First upload:** Nov 25, 2025 – 04:49 UTC  
- **Method:** `curl.exe` POST uploads to `gofile.io`

---

##  Unified Attack Timeline & MITRE ATT&CK Mapping

| Flag | Time (UTC) | Activity | MITRE Tactic | ATT&CK ID |
|-----:|------------|----------|--------------|-----------|
| 1 | 04:06 | Lateral movement to azuki-adminpc | Lateral Movement | T1021.001 |
| 4 | 04:21 | Tool download via curl | Execution | T1105 |
| 6 | 04:21 | Archive extraction via 7z | Defense Evasion | T1140 |
| 7 | 04:24 | C2 implant execution | Persistence | T1059 |
| 8 | 04:24 | Named pipe creation | Command and Control | T1090.001 |
| 9 | 04:51 | Encoded account creation | Credential Access | T1027 |
| 12 | 04:10 | Session enumeration | Discovery | T1033 |
| 16 | 04:15 | Plaintext password discovery | Credential Access | T1552.001 |
| 17 | 04:40 | Data staging directory created | Collection | T1074.001 |
| 18 | 04:42 | Automated data copying | Collection | T1119 |
| 19 | 04:48 | Data archived (8 files) | Collection | T1560.001 |
| 20 | 04:21 | Credential tool download | Ingress Tool Transfer | T1105 |
| 21 | 04:52 | Browser credential theft | Credential Access | T1555.003 |
| 22 | 04:49 | Data exfiltration via POST | Exfiltration | T1567 |
| 25 | 05:06 | Master password extraction | Credential Access | T1555.005 |

##  WHERE - Affected Assets

### Primary Target

| System | Role |
|--------|------|
| `azuki-adminpc` | Administrative workstation containing credentials and business data |

### Key Directories

| Path | Purpose |
|------|---------|
| `C:\ProgramData\Microsoft\Crypto\staging` | Data staging directory |
| `C:\Windows\Temp\cache` | Payload extraction location |

##  WHY 
### Root Cause Analysis

| Root Cause | Description |
|------------|-------------|
| Reused foothold | Previous compromise not fully remediated |
| No MFA | Allowed reuse of stolen credentials |
| Poor credential hygiene | Plaintext password storage |
| Excessive privileges | Broad access to sensitive shares |
| Insufficient detection | Limited alerting for living-off-the-land tools |

###  Attacker Objectives

| Objective | Description |
|-----------|-------------|
| Credential Theft | Extract reusable credentials |
| Data Exfiltration | Steal sensitive administrative and contract data |
| Persistence | Maintain long-term access |
| Expansion | Enable future lateral movement |


##  HOW - Kill Chain Summary

- Re-entry using existing foothold  
- Lateral movement to administrative workstation  
- Discovery and enumeration  
- Tool deployment  
- Credential harvesting  
- Data staging and compression  
- Exfiltration via HTTPS  
- Persistence and anti-forensics  

## Recommendations

### Immediate Actions

- Reset all compromised credentials  
- Remove backdoor accounts  
- Delete staging directories and malicious artifacts  
- Block outbound traffic to `gofile.io`  

### Short-Term Actions

- Enforce MFA on all privileged accounts  
- Harden file share permissions  
- Enable detailed process, file, and network auditing  
- Deploy detections for `curl`, `robocopy`, `tar`, `7z`, and encoded PowerShell  

### Long-Term Strategy

- Implement Privileged Access Workstations (PAWs)  
- Segment administrative access paths  
- Increase SIEM telemetry retention  
- Establish routine threat-hunting playbooks  

##  Conclusion

This incident demonstrates how attackers leverage legitimate tools, weak credential hygiene, and limited monitoring to conduct structured, low-noise intrusions. Each phase reinforced the next, culminating in credential compromise and successful data exfiltration.

The hunt highlights the importance of **behavior-based detection**, **defense in depth**, and **strong credential hygiene** in modern enterprise environments.


