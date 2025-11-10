# Rule Name
Detection: Suspicious PowerShell EncodedCommand Usage

# Description
Detects executions of PowerShell (Windows PowerShell `powershell.exe` or PowerShell Core `pwsh.exe`) invoked with the `-EncodedCommand`, `-enc`, or unusually long Base64-like command-line arguments. Encoded commands are commonly used to obfuscate malicious scripts and bypass simple signature inspection.

# MITRE ATT&CK Mapping
- Command and Scripting Interpreter: PowerShell — T1059.001

# Severity
High — escalate quickly when observed on sensitive systems or when parent process is a non-admin service or unusual process.

# Data Sources
- Sysmon (Event ID 1: Process Create) with command-line capture enabled  
- Windows Security Event Log (4688) when process creation auditing with command line is enabled  
- PowerShell Operational logs (Microsoft-Windows-PowerShell/Operational) and Script Block Logging if available (Event IDs related to script block logging)  
- Endpoint/EDR command-line telemetry and process tree

# Detection Logic (plain language)
Alert when a PowerShell process runs with `-EncodedCommand`, `-enc`, or when the command-line contains a long Base64-like token (many contiguous Base64 chars, e.g. 80+ characters, optionally ending with `=` padding). Exclude known automation systems and signed scripts after initial tuning.

# False Positives
- Legitimate administrative automation and deployment tools that intentionally use `-EncodedCommand`.  
- Some installers or patching systems may use encoded commands.  
Mitigation: whitelist approved hosts, service accounts, or fingerprint known benign command-lines.

# Response Playbook (triage + quick actions)
1. Enrich: collect host, user, parent process, full command-line, timestamp, and recent process tree.  
2. If host is high-value (domain controller, file server) — isolate network or move to investigation VLAN.  
3. Retrieve process memory and any available EDR artifacts (child processes, network connections).  
4. Search for follow-up actions: new service creation, scheduled tasks, suspicious network connections, credential dumping indicators.  
5. If confirmed malicious: contain (isolate), eradicate (kill processes, remove persistence), recover (restore from clean image or rebuild), and document timeline. Notify stakeholders as per Incident Response policy.

# Example Detection Queries

## Sigma-style (conceptual)
title: Suspicious PowerShell EncodedCommand Usage
id: e3f7b1d2-0000-4000-8000-000000000001
status: experimental
description: Detects invocation of PowerShell with -EncodedCommand or long Base64 command lines
logsource:
  product: windows
  service: sysmon
detection:
  selection1:
    Image|endswith: ['\\powershell.exe', '\\pwsh.exe']
    CommandLine|contains: ['-EncodedCommand', '-enc', '-e']
  selection2:
    Image|endswith: ['\\powershell.exe', '\\pwsh.exe']
    CommandLine|contains_regex: '[A-Za-z0-9+/]{80,}={0,2}'
  condition: selection1 or selection2
falsepositives:
  - Admin deployment tools, signed maintenance scripts.
level: high

## Splunk SPL (example)
index=winevent OR index=sysmon (Image="*\\powershell.exe" OR Image="*\\pwsh.exe")
| where match(CommandLine, "-EncodedCommand|-enc|-e") OR match(CommandLine, "[A-Za-z0-9+/]{80,}={0,2}")
| stats count by host, user, Image, ParentImage, CommandLine, _time

## Elastic / KQL (example)
(process.name: "powershell.exe" or process.name: "pwsh.exe")
and (process.command_line: "*-EncodedCommand*" or process.command_line: "* -enc *" or process.command_line: /[A-Za-z0-9+/]{80,}={0,2}/)

# Regex notes for Base64-like detection
Use a regex to catch long Base64 strings:  
`[A-Za-z0-9+/]{80,}={0,2}`  
- `80` is a tunable threshold; shorter values increase false positives.  
- `={0,2}` accounts for Base64 padding.  
Tune by scanning historical logs for occurrences before alerting.

# Test / Validation Plan (safe)
1. Make a disposable Windows VM (snapshot before testing).  
2. Generate a benign encoded command:
   - Open PowerShell and run:
     ```powershell
     $bytes = [System.Text.Encoding]::Unicode.GetBytes('Write-Output "test-encoded"')
     $b64 = [Convert]::ToBase64String($bytes)
     Write-Output $b64
     ```
   - Then run:
     ```powershell
     powershell.exe -EncodedCommand <paste-the-b64-string-here>
     ```
   - Expected: Process creation logged with command-line containing `-EncodedCommand <long-string>` in Sysmon (Event ID 1) and SIEM.
3. Confirm detection fires in your SIEM using provided queries.  
4. Tune regex threshold and whitelists based on observed benign matches.

# Mitigations / Recommendations
- Enable Sysmon with ProcessCreate (Event ID 1) and include command line capture.  
- Enable PowerShell Script Block Logging and Module Logging on endpoints for richer telemetry.  
- Keep EDR agents updated and enable process ancestry collection.

# Author / Date
Author: Kevin Nito 
Date: 2025-11-10
