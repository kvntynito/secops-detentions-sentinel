## 1. Learn the common attack technique categories (so you know what to hunt).
These are the ones you’ll see most often and will build most of your early detections around:
- Initial Access — how adversaries get in (phishing, exploited RDP, malicious downloads).
- Execution — running code on a host (PowerShell, cmd, scripts, macros).
- Persistence — ways attackers stay after initial access (services, scheduled tasks, registry run keys).
- Privilege Escalation — methods to gain higher privileges (credential dumping, exploiting local bugs).
- Defense Evasion — hiding from security (obfuscated scripts, disabling logging).
- Credential Access — stealing passwords/tokens (Mimikatz, keyloggers, LSASS access).
- Discovery — figuring out the environment (netstat, whoami, AD enumeration).
- Lateral Movement — moving across network (PsExec, SMB, RDP).
- Collection — gathering important files/data.
- Exfiltration — moving the data out (HTTP uploads, DNS tunneling, cloud storage).
- Command & Control (C2) — remote control channels (HTTP beaconing, DNS, custom protocols).

A practical framework you’ll run into is MITRE ATT&CK; it maps techniques to categories.

## 2. Pick easy, high-value techniques to detect first.

## 3. Use the template to create a detection file.

## 4. Test it later in a VM with Sysmon + Windows logs when you’re ready.
