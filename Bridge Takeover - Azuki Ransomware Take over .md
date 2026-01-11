# Bridge Takeover - AZUKI Import/Export

<img width="740" height="1110" alt="image" src="https://github.com/user-attachments/assets/175e509e-a948-4788-8507-5e7c0d30ce74" />

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




