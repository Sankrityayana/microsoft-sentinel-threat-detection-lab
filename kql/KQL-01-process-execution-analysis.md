
# KQL-01 — Process Execution Analysis

## 1. Objective

Analyze Windows process creation events to understand process execution patterns and parent-child process relationships on the monitored virtual machine.

This query helps establish a baseline of process activity and provides a starting point for investigating unusual process execution.

## 2. Data Source

| Property | Value |
|---|---|
| Workspace table | `SecurityEvent` |
| Windows Event ID | 4688 |
| Event description | A new process was created |
| Execution window | Last 24 hours |
| Monitored host | `windows-server-lab-vm` |

## 3. KQL Query

```kusto
SecurityEvent
| where TimeGenerated > ago(24h)
| where EventID == 4688
| where isnotempty(NewProcessName)
| summarize
    ExecutionCount = count(),
    FirstSeen = min(TimeGenerated),
    LastSeen = max(TimeGenerated)
    by Computer, NewProcessName, ParentProcessName
| order by ExecutionCount desc
```

## 4. Query Logic

| Operation | Purpose |
|---|---|
| `where TimeGenerated > ago(24h)` | Restricts analysis to the previous 24 hours |
| `where EventID == 4688` | Selects Windows process creation events |
| `isnotempty(NewProcessName)` | Excludes records without a process name |
| `summarize` | Aggregates process execution activity |
| `count()` | Counts executions for each process-parent combination |
| `min()` and `max()` | Identifies first and last observed timestamps |
| `order by` | Displays the most frequent combinations first |

## 5. Observed Results

The query returned 44 process-parent combinations.

Selected results:

| Process | Parent Process | Execution Count |
|---|---|---:|
| `conhost.exe` | `cmd.exe` | 171 |
| `WmiPrvSE.exe` | `svchost.exe` | 100 |
| `BfeToolWin8.exe` | `WindowsAzureGuestAgent.exe` | 96 |
| `conhost.exe` | `BfeToolWin8.exe` | 96 |
| `sppsvc.exe` | `services.exe` | 68 |
| `cmd.exe` | `WindowsAzureGuestAgent.exe` | 61 |
| `cmd.exe` | `cmd.exe` | 58 |

## 6. Security Interpretation

The query provides visibility into process execution frequency and parent-child relationships.

Several high-frequency combinations were consistent with Windows operating system and Azure Guest Agent activity in the lab environment.

However, process frequency alone does not establish whether an execution is benign or malicious.

Further investigation should consider:

- Full executable path
- Command-line arguments
- Parent process legitimacy
- Execution account
- File signature and hash
- Process execution time
- Related network and authentication events

## 7. Investigation Use Cases

This query can support investigations involving:

- Unexpected parent-child process relationships
- Unusual command interpreter execution
- Suspicious process spawning
- Repeated execution of unfamiliar binaries
- Potential abuse of legitimate Windows utilities

## 8. Limitations

- The query aggregates events and does not display individual command lines.
- High-frequency processes may be legitimate system activity.
- The result is specific to the selected 24-hour window.
- Additional context is necessary before identifying suspicious execution.

## 9. Validation Status

**Execution status:** Executed successfully.

**Observed output:** 44 process-parent combinations.

**Interpretation:** Initial process activity baseline established. Individual process combinations require contextual validation before being classified as benign or suspicious.

---

**Project:** Microsoft Sentinel Threat Detection and Incident Investigation Lab
