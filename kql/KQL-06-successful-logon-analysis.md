
# KQL-06 — Successful Logon Analysis

## 1. Objective

Analyze successful Windows authentication events to understand logon patterns, identify the accounts involved and examine the types of logon activity occurring on the monitored system.

This query helps establish an authentication baseline that can support investigations involving unusual access patterns.

## 2. Data Source

| Property | Value |
|---|---|
| Workspace table | `SecurityEvent` |
| Windows Event ID | 4624 |
| Event description | An account was successfully logged on |
| Execution window | Last 7 days |
| Monitored host | `windows-lab-vm` |

## 3. KQL Query

```kusto
SecurityEvent
| where TimeGenerated > ago(7d)
| where EventID == 4624
| summarize
    LogonCount = count(),
    FirstSeen = min(TimeGenerated),
    LastSeen = max(TimeGenerated),
    Accounts = make_set(Account, 10),
    SourceIPs = make_set(IpAddress, 10)
    by Computer, LogonType
| order by LogonCount desc
```

## 4. Query Logic

| Operation | Purpose |
|---|---|
| Time filter | Selects the previous seven days |
| Event ID filter | Selects successful logon events |
| `count()` | Counts successful logons |
| `min()` and `max()` | Establish the observed activity period |
| `make_set()` | Collects unique accounts and source IP addresses |
| `summarize` | Groups activity by computer and logon type |
| `order by` | Sorts results by logon count |

## 5. Observed Results

The query returned 22 successful logon events.

| Field | Observed result |
|---|---|
| Computer | `windows-lab-vm` |
| Total events | 22 |
| Account | `NT AUTHORITY\SYSTEM` |
| Logon type | 5 |
| Source IP | `-` |

## 6. Security Interpretation

All 22 observed successful logon events were associated with the SYSTEM account and Logon Type 5.

Logon Type 5 represents a service logon.

This pattern is consistent with Windows service activity in the observed lab environment.

However, the result represents only the events captured during the selected seven-day period. It does not establish that all authentication activity on the host is represented by these records.

## 7. Investigation Use Cases

- Establish a baseline of successful authentication activity.
- Identify accounts performing successful logons.
- Examine logon types.
- Investigate unexpected interactive or remote logon activity.
- Correlate successful logons with preceding failed authentication attempts.

## 8. Limitations

- The query aggregates events by computer and logon type.
- It does not display individual logon sessions.
- The result depends on the available Windows audit telemetry.
- Source IP information may be unavailable for some logon types.
- Logon type and account context must be considered before classifying activity.

## 9. Validation Status

**Execution status:** Executed successfully.

**Observed output:** 22 successful logon events.

**Interpretation:** The observed authentication baseline consisted of SYSTEM service logons (Logon Type 5). No broader conclusion about all host authentication activity is made.

---

**Project:** Microsoft Sentinel Threat Detection and Incident Investigation Lab
