
# KQL-05 — Privileged Group Enumeration Analysis

## 1. Objective

Identify and analyze Windows Security Event ID 4799 records involving enumeration of selected privileged local groups.

This query helps establish which processes enumerate sensitive local groups and provides context for investigating potential permission-group discovery activity.

## 2. Data Source

| Property | Value |
|---|---|
| Workspace table | `SecurityEvent` |
| Windows Event ID | 4799 |
| Event description | A security-enabled local group membership was enumerated |
| Execution window | Last 7 days |
| Monitored host | `windows-lab-vm` |
| Target groups | Administrators, Remote Desktop Users |

## 3. KQL Query

```kusto
SecurityEvent
| where TimeGenerated > ago(7d)
| where EventID == 4799
| extend TargetGroup = extract(
    '<Data Name="TargetUserName">([^<]*)</Data>',
    1,
    EventData
)
| extend CallerProcess = extract(
    '<Data Name="CallerProcessName">([^<]*)</Data>',
    1,
    EventData
)
| where TargetGroup in ("Administrators", "Remote Desktop Users")
| summarize
    EnumerationCount = count(),
    FirstSeen = min(TimeGenerated),
    LastSeen = max(TimeGenerated)
    by Computer, TargetGroup, CallerProcess
| order by EnumerationCount desc
```

## 4. Query Logic

| Operation | Purpose |
|---|---|
| Time filter | Selects the previous seven days |
| Event ID filter | Selects local security-enabled group enumeration |
| `extract()` | Retrieves the target group and caller process |
| Group filter | Limits analysis to selected privileged groups |
| `count()` | Counts enumeration events |
| `min()` and `max()` | Establish first and last observed timestamps |
| `summarize` | Aggregates activity by computer, group and process |

## 5. Observed Results

The query returned the following groups:

| Target Group | Caller Process | Enumeration Count |
|---|---|---:|
| Administrators | `WaAppAgent.exe` | 168 |
| Remote Desktop Users | `WaAppAgent.exe` | 168 |
| Administrators | `powershell.exe` | 4 |

## 6. Security Interpretation

### Azure Guest Agent activity

The `WaAppAgent.exe` process was responsible for the majority of observed enumeration events.

The process was located under the Azure Guest Agent installation directory:

`C:\WindowsAzure\GuestAgent_2.7.41491.1243_2026-10-26_022945\WaAppAgent.exe`

The observed activity was associated with the VM's computer account:

`LAB\windows-lab-vm$`

This activity was treated as part of the observed Azure VM management baseline.

### Controlled PowerShell activity

Four enumeration events were associated with `powershell.exe`.

The seven-day exploratory query returned four PowerShell-associated records. The DET-03 incident report documents two matching records examined for CASE-29 within the incident investigation; the counts represent different query/investigation scopes. The controlled test command was:

```powershell
Get-LocalGroupMember -Group "Administrators"
```

The command was used to inspect local Administrators group membership.

## 7. Investigation Use Cases

- Detect enumeration of privileged local groups.
- Identify the process responsible for group discovery.
- Establish expected Azure management-agent behavior.
- Investigate unexpected processes accessing privileged group information.
- Correlate enumeration activity with process creation and authentication events.

## 8. Limitations

- Event ID 4799 identifies enumeration, not membership modification.
- The query examines only two selected local groups.
- Process names alone do not establish executable legitimacy.
- Aggregated results do not replace individual event inspection.
- Legitimate administration and management software can generate these events.

## 9. Validation Status

**Execution status:** Executed successfully.

**Observed output:** Three process-and-group combinations.

**Interpretation:** The query identified recurring Azure Guest Agent enumeration and the four controlled PowerShell enumeration events.

---

**Project:** Microsoft Sentinel Threat Detection and Incident Investigation Lab
