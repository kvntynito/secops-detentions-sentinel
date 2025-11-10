# Architecture Diagram

```mermaid
flowchart LR
User -->|HTTPS| WAF --> App[Web App]
App --> DB[(Database)]
App --> SIEM[[Sentinel]]
Endpoint --> EDR[[EDR]]
SIEM --> SOAR[[Automation]]
Firewall --- VLAN1
Firewall --- VLAN2
```
