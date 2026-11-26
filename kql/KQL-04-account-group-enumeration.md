
# KQL-04 — Local Account and Group Enumeration Analysis

## 1. Objective

Analyze Windows Security events associated with local account and group enumeration.

The query examines Event IDs 4798 and 4799 to identify which processes and accounts are performing enumeration activity and which users or groups are being examined.

## 2. Data Source

| Property | Value |
|---|---|
| Workspace table | `SecurityEvent` |
| Event IDs | 4798, 4799 |
| Execution window | Last 7 days |
| Monitored host | `windows-lab-vm` |

### Relevant Windows Events

| Event ID | Description |
|---|---|
| 4798 | A user's local group membership was enumerated |
| 4799 | A security-enabled local group membership was enumerated |

## 3. KQL Query

```kusto
SecurityEvent
| where TimeGenerated > ago(7d)
| where EventID in (4798, 4799)
| extend CallerProcess = extract(
    '<Data Name="CallerProcessName">([^<]*)</Data>',
    1,
    EventData
)
| extend TargetName = extract(
    '<Data Name="TargetUserName">([^<]*)</Data>',
    1,
    EventData
)
| summarize
    EventCount = count(),
    FirstSeen = min(TimeGenerated),
    LastSeen = max(TimeGenerated),
    TargetNames = make_set(TargetName, 10)
    by EventID, Computer, Account, CallerProcess
| order by EventCount desc
```

## 4. Query Logic

| Operation | Purpose |
|---|---|
| Time filter | Selects the previous seven days |
| Event ID filter | Selects account and group enumeration events |
| `extract()` | Extracts caller process and target name from EventData XML |
| `count()` | Counts matching events |
| `min()` and `max()` | Establish the observed activity period |
| `make_set()` | Lists up to ten distinct target names |
| `summarize` | Groups activity by event, host, account and process |

## 5. Observed Results

The query returned five distinct activity groups.

| Event ID | Caller Process | Event Count | Observed Targets |
|---|---|---:|---|
| 4798 | `WmiPrvSE.exe` | 672 | lab-user, DefaultAccount, Guest, WDAGUtilityAccount |
| 4798 | `WaAppAgent.exe` | 336 | lab-user |
| 4799 | `WaAppAgent.exe` | 336 | Remote Desktop Users, Administrators |
| 4798 | Caller process unavailable | 168 | lab-user |
| 4799 | `powershell.exe` | 4 | Administrators |

## 6. Security Interpretation

The results revealed two broad activity patterns.

### System and Azure Guest Agent activity

The observed `WmiPrvSE.exe` and `WaAppAgent.exe` activity was associated with Windows and Azure VM management operations.

The `WaAppAgent.exe` process was observed enumerating the Administrators and Remote Desktop Users groups.

This activity formed part of the lab's observed baseline.

### Controlled PowerShell activity

Four Event ID 4799 records were associated with `powershell.exe` and the Administrators group.

The seven-day exploratory query returned four PowerShell-associated Event ID 4799 records. The DET-03 incident report documents two matching records examined for CASE-29 within the detection investigation. These figures refer to different query/investigation scopes and should not be treated as the same count.

### Missing caller process information

One result group contained no extracted caller process name.

This represents missing process information in the available event data. It should not automatically be classified as malicious.

## 7. Investigation Use Cases

- Identify processes enumerating local accounts.
- Examine enumeration of privileged groups.
- Establish expected system and management-agent behavior.
- Identify unusual enumeration processes.
- Compare activity against controlled testing records.

## 8. Limitations

- The query depends on event XML fields being present and extractable.
- Aggregated counts do not expose every individual event.
- Missing caller information reduces investigation context.
- Event frequency alone does not establish malicious behavior.
- Baseline activity can change with operating system and agent updates.

## 9. Validation Status

**Execution status:** Executed successfully.

**Observed output:** Five activity groups across Event IDs 4798 and 4799.

**Interpretation:** The query established a baseline of system-related enumeration and identified the controlled PowerShell test activity.

---

**Project:** Microsoft Sentinel Threat Detection and Incident Investigation Lab
