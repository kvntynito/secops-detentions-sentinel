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

## 2. Select techniques that make good first detections (high ROI, low complexity).
Start with things that are (a) common, (b) noisy when malicious, and (c) visible in logs:

**1. PowerShell abuse / encoded commands (Execution)** — easy to spot strings like -EncodedCommand or long Base64 command lines.

**2. Suspicious process spawning (e.g., rundll32/Regsvr32 launching scripts)** (Execution / Defense Evasion).

**3. Multiple failed logons / brute force (RDP, SSH)** (Initial Access / Lateral Movement).

**4. New service creation or suspicious scheduled task** (Persistence).

**5. Credential dumping indicators (LSASS access/Suspicious processes)** (Credential Access).

I recommend starting with **PowerShell abuse** — it’s common in labs and real attacks, easy to simulate, and gives you immediate wins.



## 3. Data sources (what logs to monitor)
You’ll need these standard sources to detect the techniques above:
- **Windows Security Event Logs** (e.g., 4624 success logons, 4625 failures, 4688 process creation).
- **Sysmon** (if you can deploy it): process create, network connect, file create, image load. Highly valuable.
- **PowerShell Operational logs** (Windows Event Log: Microsoft-Windows-PowerShell/Operational) — shows executed commands and transcripts.
- **Endpoint logs/EDR telemetry** — process lineage, parent-child, command line.
- **Network logs** (firewall, proxy, IDS) — for C2/beacon and exfiltration.
- **SIEM logs** (Splunk/Elastic/Sentinel) where you’ll actually run queries.

You don’t need all of these right away — prioritize process creation logs and PowerShell logs.

## For the 1st detection idea: Suspicious PowerShell EncodedCommand
Use the template to create the detection file.

*NOTE - do not overwite Detection_Rule_TEMPLATE - its used to make copies for more rules to be made.

- rename the Detection_Rule2_TEMPLATE to Detection: Suspicious PowerShell EncodedCommand



## 4. Test it later in a VM with Sysmon + Windows logs when you’re ready.
