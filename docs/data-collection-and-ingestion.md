# Data Collection and Ingestion

## 1. Overview

This document describes the Windows security telemetry collection pipeline implemented in the Microsoft Sentinel lab.

The pipeline uses Azure Monitor Agent (AMA) and a Data Collection Rule (DCR) to collect selected Windows event logs and forward them to a dedicated Azure Log Analytics workspace.

## 2. Telemetry Pipeline

1. Windows generates Security and operational events.
2. Azure Monitor Agent collects configured events.
3. The Data Collection Rule defines the collection configuration.
4. AMA forwards the collected records to the destination workspace.
5. Microsoft Sentinel accesses the workspace data for threat hunting and detection.

## 3. Azure Monitor Agent

| Property | Configuration |
|---|---|
| Agent | Azure Monitor Agent |
| Extension version | 1.45.0.0 |
| Source | Windows Server lab VM |

The agent was installed as a virtual machine extension.

During verification, the agent successfully downloaded and parsed the assigned Data Collection Rule.

The following diagnostic message was observed:

`The data collection rules downloaded from AMCS were successfully parsed and executed. Marking them last-known-good.`

## 4. Data Collection Rule

| Property | Configuration |
|---|---|
| Source | Windows Server lab VM |
| Destination | Dedicated Log Analytics workspace |
| Stream | `Microsoft-SecurityEvent` |
| Collection configuration | Windows Security event collection plus a custom XPath selection for PowerShell Operational Event ID 4104 |

The DCR was associated with the Windows Server virtual machine. Exact Azure resource names are intentionally omitted from this public document.

## 5. Configured Event Sources

### 5.1 Windows Security Event Log

The DCR collects configured Windows Security events.

Important event identifiers examined in this lab include:

| Event ID | Description |
|---|---|
| 4624 | Successful account logon |
| 4625 | Failed account logon |
| 4673 | A privileged service was called |
| 4688 | A new process was created |
| 4702 | A scheduled task was updated |
| 4798 | A user's local group membership was enumerated |
| 4799 | A security-enabled local group membership was enumerated |

These IDs are documented because they were examined in the lab. This list does not claim that each ID was individually configured as a separate DCR XPath filter.

### 5.2 PowerShell Operational Event Log

PowerShell Script Block Logging was enabled through the Windows registry policy:

`HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging`

The configured value:

`EnableScriptBlockLogging = 1`

The DCR includes the following XPath selection:

```text
Microsoft-Windows-PowerShell/Operational!*[System[(EventID=4104)]]
```

Event ID 4104 records PowerShell script block activity.

## 6. Log Analytics Ingestion Verification

The destination table used for the collected records was:

`SecurityEvent`

Example query to inspect event volume:

```kusto
SecurityEvent
| where TimeGenerated > ago(24h)
| summarize EventCount = count() by EventID
| order by EventCount desc
```

PowerShell Event ID 4104 was also confirmed in the `SecurityEvent` table.

The event record contained XML data in the `EventData` field, including the `ScriptBlockText` value.

## 7. Agent and DCR Verification

The following checks were performed:
- AMA extension installation was confirmed.
- Agent processes were active.
- DCR association with the VM was confirmed.
- Successful DCR download and parsing were observed in agent diagnostics.
- Network connectivity to Azure Monitor endpoints was tested.
- Security event ingestion was confirmed in Log Analytics.
- PowerShell Event ID 4104 ingestion was confirmed.

## 8. Troubleshooting Observations

**Agent installation is not the same as successful ingestion.**

The agent, DCR association, event generation and destination workspace must all be checked.

Another important observation was that PowerShell Event ID 4104 records were available in the `SecurityEvent` table in this environment, rather than the initially expected `WindowsEvent` table.

## 9. Limitations

- The lab collects selected Windows event sources rather than every available Windows event.
- Event collection depends on the Windows audit and logging configuration.
- Event availability does not automatically establish malicious activity.
- Event volume and ingestion costs depend on the configured collection scope.

## 10. Evidence to Be Added

Screenshots should demonstrate:
- AMA extension status.
- DCR data source configuration.
- DCR destination configuration.
- DCR association.
- PowerShell Script Block Logging configuration.
- Log Analytics event ingestion.
- Event ID 4104 verification.

---

**Project note:** Event IDs listed here represent the events examined during the lab. They should not be interpreted as a claim that every event was explicitly configured as an individual DCR filter.
