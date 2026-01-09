# Dead In the Water - Azuki Ransomware Take over

<img width="740" height="1110" alt="image" src="https://github.com/user-attachments/assets/175e509e-a948-4788-8507-5e7c0d30ce74" />

|  Date of Report | 25-Dec-25         |
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
