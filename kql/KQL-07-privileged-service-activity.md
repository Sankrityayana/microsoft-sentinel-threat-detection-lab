
# KQL-07 — Privileged Service Activity Analysis

## 1. Objective

Analyze Windows privileged service call events to understand activity involving privileged operations and identify the accounts and processes associated with these events.

This query helps establish a baseline for investigating potentially unusual privileged service activity.

## 2. Data Source

| Property | Value |
|---|---|
| Workspace table | `SecurityEvent` |
| Windows Event ID | 4673 |
| Event description | A privileged service was called |
| Execution window | Last 7 days |
| Monitored host | `windows-lab-vm` |

## 3. KQL Query

```kusto
SecurityEvent
| where TimeGenerated > ago(7d)
| where EventID == 4673
| summarize
    EventCount = count(),
    FirstSeen = min(TimeGenerated),
    LastSeen = max(TimeGenerated),
    Accounts = make_set(Account, 10),
    Processes = make_set(Process, 10)
    by Computer, Activity
| order by EventCount desc
```

## 4. Query Logic

| Operation | Purpose |
|---|---|
| Time filter | Selects the previous seven days |
| Event ID filter | Selects privileged service call events |
| `count()` | Counts matching events |
| `min()` and `max()` | Establish the first and last observed timestamps |
| `make_set()` | Collects distinct accounts and process values |
| `summarize` | Aggregates events by computer and activity |
| `order by` | Sorts results by event count |

## 5. Observed Results

The query returned the following result:

| Field | Observed value |
|---|---|
| Computer | `windows-lab-vm` |
| Event count | 479 |
| Account | `LAB\windows-lab-vm$` |
| Process | `lsass.exe` |
| Activity | 4673 - A privileged service was called |

## 6. Security Interpretation

Event ID 4673 provides visibility into attempts to invoke privileged services.

The observed events were associated with the VM computer account and `lsass.exe`.

LSASS is a Windows security subsystem process involved in authentication and security policy enforcement.

The observed pattern is consistent with Windows security and authentication-related activity. However, the aggregated result alone does not establish that every event was legitimate.

Further investigation should examine:

- Individual event records
- Privileges requested
- Process context
- Subject account
- Event timestamps
- Related authentication and process events

## 7. Investigation Use Cases

- Establish a baseline of privileged service calls.
- Identify accounts associated with privileged operations.
- Examine processes generating privileged service events.
- Investigate unusual privileged activity.
- Correlate privileged service events with other Windows security events.

## 8. Limitations

- The query aggregates events and does not expose every privilege requested.
- Process and account names alone are insufficient to establish legitimacy.
- High event counts do not independently indicate malicious behavior.
- Additional event-level investigation is required.

## 9. Validation Status

**Execution status:** Executed successfully.

**Observed output:** 479 Event ID 4673 records.

**Interpretation:** The query established an initial privileged service activity baseline associated with the VM computer account and LSASS. Individual event-level review is required for deeper conclusions.

---

**Project:** Microsoft Sentinel Threat Detection and Incident Investigation Lab
