# Detection Rule – <Suspicious Behavior Name>

**Category:** (Auth, Lateral Movement, Persistence, Exfiltration)  
**Platform:** (Azure Sentinel KQL / Wazuh / Sigma)  
**Use Case ID:** DET-<NNN>

## Query / Rule
```kql
// Example KQL
SecurityEvent
| where EventID == 4688
| where CommandLine has_any ("-enc", "IEX", "System.Net.WebClient")
| summarize count() by Account, Computer, bin(TimeGenerated, 5m)
```

## Rationale
What this catches and why it matters.

## Test Procedure
How to safely generate test events.

## Response Guidance
What to check next, quick triage steps, escalation criteria.

## False Positives / Tuning
Common benign cases, exclusions.

## References
Links, MITRE ATT&CK mappings.
