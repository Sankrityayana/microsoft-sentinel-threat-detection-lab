
# KQL-03 — PowerShell Script Activity Analysis

## 1. Objective

Analyze PowerShell Script Block Logging events to identify script execution activity, establish an activity baseline and support investigations involving potentially suspicious PowerShell behavior.

## 2. Data Source

| Property | Value |
|---|---|
| Workspace table | `SecurityEvent` |
| Windows Event ID | 4104 |
| Event channel | Microsoft-Windows-PowerShell/Operational |
| Event description | PowerShell script block logging |
| Execution window | Last 24 hours |
| Monitored host | `windows-lab-vm` |

## 3. KQL Query

```kusto
SecurityEvent
| where TimeGenerated > ago(24h)
| where EventID == 4104
| extend ScriptBlockText = extract(
    '<Data Name="ScriptBlockText">([^<]*)</Data>',
    1,
    EventData
)
| where isnotempty(ScriptBlockText)
| summarize
    EventCount = count(),
    FirstSeen = min(TimeGenerated),
    LastSeen = max(TimeGenerated),
    SampleScripts = make_set(ScriptBlockText, 5)
    by Computer, Account
| order by EventCount desc
```

## 4. Query Logic

| Operation | Purpose |
|---|---|
| Time filter | Selects the previous 24 hours |
| Event ID filter | Selects PowerShell Event ID 4104 |
| `extract()` | Extracts ScriptBlockText from EventData XML |
| `isnotempty()` | Excludes records without extracted script content |
| `count()` | Counts script block events |
| `min()` and `max()` | Establish the observed activity period |
| `make_set()` | Retrieves up to five distinct sample scripts |
| `order by` | Sorts results by event volume |

## 5. Observed Results

The query returned:

| Field | Observed result |
|---|---|
| Computer | `windows-lab-vm` |
| Event count | 727 |
| First observed event | 2026-11-24 02:27:53.632 UTC |
| Last observed event | 2026-11-24 12:43:23.526 UTC |
| Sample scripts | 5 |

The sampled script blocks included:

- AMA diagnostic operations
- File and directory inspection
- Diagnostic log searches
- PowerShell execution and inspection activity

These are sample observations, not a complete classification of all 727 events.

## 6. Security Interpretation

PowerShell is a legitimate Windows administration and automation tool. However, attackers may also abuse it for execution, discovery, downloading payloads and other activities.

Script Block Logging provides visibility into executed PowerShell script content.

During analysis, consider:

- Script content and intent
- Execution account
- Parent process
- Encoded commands
- Network-related operations
- File and registry modifications
- Execution time and frequency
- Related Windows Security events

A high volume of PowerShell activity does not independently indicate malicious behavior.

## 7. Investigation Use Cases

- Identify unusual PowerShell scripts.
- Examine encoded or obfuscated commands.
- Investigate suspicious download operations.
- Correlate PowerShell execution with process creation events.
- Establish normal administrative and monitoring activity.

## 8. Limitations

- The query returns only five distinct sample scripts.
- Aggregated output does not provide a complete event-by-event investigation.
- Script Block Logging must be configured and operational.
- XML extraction depends on the observed EventData format.
- The sampled scripts do not establish that every collected event is benign.

## 9. Validation Status

**Execution status:** Executed successfully.

**Observed output:** 727 Event ID 4104 records during the queried period.

**Interpretation:** PowerShell telemetry ingestion and query extraction were confirmed. The sampled activity provided an initial baseline; full event-level review remains necessary for definitive classification.

---

**Project:** Microsoft Sentinel Threat Detection and Incident Investigation Lab
