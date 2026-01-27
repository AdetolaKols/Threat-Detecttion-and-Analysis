## Dead in the Water - Azuki Ransomeware

<img width="1024" height="1536" alt="dead in the water" src="https://github.com/user-attachments/assets/bcc750e6-175e-42c3-af61-04dcd9cace1a" />



|  Date of Report | 09-Jan-26      |
|-----------------|------------------|
| Severity Level  | CRITICAL         |
| Escalated To   | Joshua Makador – LOG(N) Pacific |
| Analyst         | Adetola Kolawole  |

## Summary of Events
A multi-stage ransomware attack targeted Azuki Import/Export by first compromising a Windows workstation, pivoting to a Linux backup server, destroying backups, stealing credentials, and later deploying ransomware across Windows systems. The attacker systematically disabled recovery mechanisms, established persistence, removed forensic artefacts, and dropped a ransom note to confirm impact.

## WHO
### Threat Actor Architecture

| IP / Domain        | Purpose                                   |
|--------------------|-------------------------------------------|
|  10.1.0.108      | Initial reconnection after dwell time        |
| PsExec64.exe      | Ransomeqare Deployment Tool  |
| wbadmin delete catalog -quiet     | Backup Deletion       |
| backup-admin  | Backdoor administrator account |
| SILENTLYNX_README.txt  | Payload Deployed |

##  WHAT  - Attacker Actions
- Used SSH for lateral movement from a compromised workstation
- Enumerated backup directories, files, users, and schedules
- Searched for and accessed credential files
- Destroyed backup archives
- Downloaded external tooling
- Deployed ransomware using PsExec
- Disabled Windows and Linux recovery mechanisms
- Established persistence via registry and scheduled tasks
- Deleted forensic evidence
- Dropped a ransom note after encryption

## UNIFIED TIMELINE / MITRE ATT&CK

| Time (UTC) | Action | Command / Evidence | MITRE ID |
|------------|--------|-------------------|----------|
| 11/25 05:39 | SSH lateral movement | `ssh.exe backup-admin@10.1.0.189` | T1021 |
| 11/25 05:47 | Directory enumeration | `ls --color=auto -la /backups/` | T1083 |
| 11/25 05:47 | Scheduled job reconnaissance | `cat /etc/crontab` | T1053 |
| 11/25 05:45 | Tool download | `curl -L -o destroy.7z ...` | T1105 |
| 11/24 14:14 | Credential access | `cat /backups/configs/all-credentials.txt` | T1552.001 |
| 11/25 05:47 | Backup destruction | `rm -rf /backups/archives` | T1485 |
| 11/25 05:47 | Service stopped | `systemctl stop cron` | T1489 |
| 11/25 05:47 | Service disabled | `systemctl disable cron` | T1489 |
| 11/25 06:03 | Lateral movement (Windows) | `PsExec64.exe ... silentlynx.exe` | T1021.002 |
| 11/25 06:04 | Shadow copy stopped | `net stop VSS /y` | T1490 |
| 11/25 06:04 | Backup engine stopped | `net stop wbengine /y` | T1490 |
| 11/25 06:04 | Recovery points deleted | `vssadmin delete shadows /all /quiet` | T1490 |
| 11/25 06:05 | Storage limited | `vssadmin resize shadowstorage ...` | T1490 |
| 11/25 06:04 | Recovery disabled | `bcdedit /set {default} recoveryenabled No` | T1490 |
| 11/25 06:07 | Registry persistence | `WindowsSecurityHealth` | T1547.001 |
| 11/25 06:07 | Scheduled task created | `Microsoft\Windows\Security\SecurityHealthService` | T1053.005 |
| 11/25 06:10 | Journal deletion | `fsutil usn deletejournal /D C:` | T1070.004 |
| 11/25 06:05 | Ransom note dropped | `SILENTLYNX_README.txt` | T1486 |

## MALICIOUS ARTIFACTS

- `destroy.7z`
- `silentlynx.exe`
- `SILENTLYNX_README.txt`
- Registry value: `WindowsSecurityHealth`
- Scheduled task: `\Microsoft\Windows\Security\SecurityHealthService`

---

## HOW (ATTACK FLOW)

1. **Initial Access & Lateral Movement**
   - SSH used from a compromised Windows host to a Linux backup server.

2. **Discovery**
   - Enumerated directories, backup archives, local users, and cron jobs.

3. **Credential Access**
   - Retrieved plaintext credentials from backup configuration files.

4. **Impact on Backups**
   - Deleted backup archives.
   - Stopped and disabled `cron` to prevent future backups.

5. **Ransomware Deployment**
   - Used PsExec to deploy the payload across Windows systems.

6. **Recovery Inhibition**
   - Disabled VSS, Windows Backup, system recovery, and shadow storage.

7. **Persistence**
   - Created registry autorun entry and scheduled task disguised as legitimate services.

8. **Anti-Forensics**
   - Deleted the NTFS USN journal to hide file system activity.

9. **Ransomware Success**
   - Dropped ransom note confirming successful encryption.

---

## RECOMMENDATIONS

### Short-Term

- Isolate all affected systems.
- Revoke and rotate exposed credentials.
- Rebuild the backup server from trusted media.
- Restore data from offline or immutable backups.
- Remove malicious registry keys and scheduled tasks.

### Long-Term

- Treat backup servers as Tier-0 assets.
- Enforce immutable and offline backup strategies.
- Alert on destructive commands:
  - `rm -rf`
  - `vssadmin`
  - `bcdedit`
  - `fsutil`
- Monitor access to credential files on Linux systems.
- Restrict PsExec usage and administrative shares.
- Enable Linux audit logging.
- Regularly test ransomware recovery scenarios.

---

## CONCLUSION

This incident represents a **backup-aware ransomware operation**.

The attacker deliberately targeted backups, credentials, recovery services, and forensic artefacts before deploying ransomware. This approach maximised impact and limited recovery options.

The activity shows mature tradecraft across both Linux and Windows environments and highlights the need to secure backup infrastructure as a high-risk asset.

##  EVIDENCE COLLECTED AND KQL USED

### Flag 1 : LATERAL MOVEMENT
<img width="1826" height="256" alt="Flag 1 " src="https://github.com/user-attachments/assets/58342948-00cc-46f2-90d7-e7c79196e650" />

**KQL Query Used:**
```
DeviceProcessEvents
| where TimeGenerated between (datetime(2025-11-25) .. datetime(2025-11-30))
| where DeviceName =~ "AZUKI-AdminPC"
| where FileName in~ ("ssh.exe","plink.exe","putty.exe","scp.exe","sftp.exe")
| project TimeGenerated, DeviceName, AccountName, FileName, ProcessCommandLine, FolderPath
| order by TimeGenerated desc
```

### Flag 2-3 : LATERAL MOVEMENT
<img width="1816" height="250" alt="Flag 2" src="https://github.com/user-attachments/assets/1054544b-a6b3-4b44-bc9e-40d5b783fba6" />

<img width="1715" height="420" alt="Flag 3" src="https://github.com/user-attachments/assets/85243aa0-ff7a-4e0e-a6cd-7dca6e88a823" />

**KQL Query Used:**
```
DeviceNetworkEvents
| where TimeGenerated between (datetime(2025-11-25) .. datetime(2025-11-30))
| where DeviceName =~ "AZUKI-AdminPC"
| where InitiatingProcessFileName =~ "ssh.exe"
| where RemotePort == 22
| project TimeGenerated, DeviceName, InitiatingProcessAccountName, InitiatingProcessFileName,
          LocalIP, LocalPort, RemoteIP, RemotePort, RemoteUrl, InitiatingProcessCommandLine
| order by TimeGenerated desc
```

### Flag 4 : DISCOVERY - Directory Enumeration

<img width="1582" height="401" alt="Flag 4" src="https://github.com/user-attachments/assets/97a9bb02-a232-4de1-bc21-8bdd9be46526" />

**KQL Query Used:**
```
DeviceProcessEvents
| where TimeGenerated between (datetime(2025-11-25) .. datetime(2025-11-30))
| where ProcessCommandLine has_any ("ls -", "ls --")
| where ProcessCommandLine has_any ("/backup", "/backups", "/var/backups", "/mnt", "/srv", "/data", "/exports", "/opt")
| project TimeGenerated, DeviceName, AccountName, FileName, ProcessCommandLine
| order by TimeGenerated asc
```

### Flag 5 : DISCOVERY - File Search

<img width="1314" height="413" alt="Flag 5" src="https://github.com/user-attachments/assets/35f67eaa-c077-4bc2-815a-924993046552" />

**KQL Query Used:**
```
DeviceProcessEvents
| where TimeGenerated between (datetime(2025-11-20) .. datetime(2025-12-02))
| where DeviceName has "backupsrv"
| where FileName == "find"
| summarize Hits=count(), FirstSeen=min(TimeGenerated), LastSeen=max(TimeGenerated) by ProcessCommandLine
| order by Hits desc, FirstSeen asc
```

### Flag 6: DISCOVERY - File Search
<img width="1602" height="382" alt="flag 6" src="https://github.com/user-attachments/assets/a34a16e3-292e-4172-a298-d371467bf01c" />

**KQL Query Used:**
```
DeviceProcessEvents
| where DeviceName == "azuki-adminpc"
| where Timestamp >= datetime(2025-11-25 04:00:00)
| where FileName has_any ("7z.exe","7za.exe","winrar.exe","rar.exe","tar.exe","unzip.exe")
| where ProcessCommandLine has_any ("x","extract","-p","-password")
| project Timestamp, AccountName, FileName, ProcessCommandLine
| order by Timestamp asc
```
### Flag 7: DISCOVERY - Scheduled Job Reconnaissance
<img width="1527" height="210" alt="Flag 7 but needs to be changed" src="https://github.com/user-attachments/assets/938edba9-4d9e-4880-b0fa-b673926dd994" />


**KQL Query Used:**
```
DeviceFileEvents
| where TimeGenerated between (datetime(2025-11-25) .. datetime(2025-11-30))
| where FileName == "crontab"
| project TimeGenerated, DeviceName, ActionType, InitiatingProcessFileName, InitiatingProcessCommandLine, FolderPath, FileName
| order by TimeGenerated asc
```

### Flag 8: DISCOVERY - Scheduled Job Reconnaissance
<img width="1610" height="228" alt="Flag 8" src="https://github.com/user-attachments/assets/6051f928-fef8-43c2-b361-338342f7b8c9" />

**KQL Query Used:**
```
DeviceProcessEvents
| where TimeGenerated between (datetime(2025-11-25) .. datetime(2025-11-30))
| where FileName in ("curl","wget","ftp","python","bash","sh")
| where ProcessCommandLine has_any ("http://","https://")
| project TimeGenerated,
          DeviceName,
          AccountName,
          FileName,
          ProcessCommandLine
| order by TimeGenerated asc
```

### Flag 9: CREDENTIAL ACCESS - Credential Theft
<img width="1316" height="388" alt="flag 9" src="https://github.com/user-attachments/assets/3b94c0ba-2563-48bd-9378-bf3bff4f929f" />

**KQL Query Used:**
```
DeviceProcessEvents
| where TimeGenerated between (datetime(2025-11-24) .. datetime(2025-11-28))
| where FileName contains "cat"
| where AccountDomain contains "azuki"
| project TimeGenerated, DeviceName, AccountName, FileName, ProcessCommandLine
```

### Flag 10: IMPACT - Data Destruction
<img width="1035" height="231" alt="Flag10" src="https://github.com/user-attachments/assets/93be84ff-92d9-4928-a989-bea9ec8e6dc6" />

**KQL Query Used:**
```
DeviceProcessEvents
| where TimeGenerated between (datetime(2025-11-25) .. datetime(2025-11-30))
| where FileName == "rm"
| where ProcessCommandLine has "-rf"
| project TimeGenerated,
          DeviceName,
          AccountName,
          ProcessCommandLine
| order by TimeGenerated asc
```

### Flag 11: IMPACT - Service Stopped
<img width="1818" height="518" alt="Flag11" src="https://github.com/user-attachments/assets/a13bc70d-b204-4145-ac1b-eafe2354636c" />

**KQL Query Used:**
```
DeviceProcessEvents
| where TimeGenerated between (datetime(2025-11-25) .. datetime(2025-11-30))
| where FileName == "rm"
| where ProcessCommandLine has "-rf"
| project TimeGenerated,
          DeviceName,
          AccountName,
          ProcessCommandLine
| order by TimeGenerated asc
```

### Flag 12: : IMPACT - Service Disabled Disabling a service prevents it from starting at boot - this SURVIVES a reboot.

**KQL Query Used:**
```
DeviceProcessEvents
| where TimeGenerated between (datetime(2025-11-25) .. datetime(2025-11-30))
| where FileName == "rm"
| where ProcessCommandLine has "-rf"
| project TimeGenerated,
          DeviceName,
          AccountName,
          ProcessCommandLine
| order by TimeGenerated asc
```
 
