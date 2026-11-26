
# KQL-02 — Failed Logon Analysis

## 1. Objective

Analyze failed Windows authentication attempts to identify unsuccessful login activity, repeated failures and potential password-guessing behavior.

## 2. Data Source

| Property | Value |
|---|---|
| Workspace table | `SecurityEvent` |
| Windows Event ID | 4625 |
| Event description | An account failed to log on |
| Execution window | Last 24 hours |
| Monitored host | `windows-lab-vm` |

## 3. KQL Query

```kusto
SecurityEvent
| where TimeGenerated > ago(24h)
| where EventID == 4625
| summarize
    FailedAttempts = count(),
    FirstSeen = min(TimeGenerated),
    LastSeen = max(TimeGenerated),
    SourceIPs = make_set(IpAddress, 10),
    Workstations = make_set(WorkstationName, 10)
    by Computer, Account
| order by FailedAttempts desc
```

## 4. Query Logic

| Operation | Purpose |
|---|---|
| Time filter | Restricts analysis to the previous 24 hours |
| Event ID filter | Selects failed logon events |
| `count()` | Counts failed attempts |
| `min()` | Identifies the first observed failure |
| `max()` | Identifies the last observed failure |
| `make_set()` | Collects unique source IP addresses and workstation names |
| `order by` | Prioritizes accounts with the highest failure counts |

## 5. Observed Results

### Initial baseline

The initial 24-hour query returned zero Event ID 4625 records.

A seven-day event distribution also showed zero failed logon events before the controlled test.

### Controlled authentication test

A failed authentication attempt was generated using an intentionally incorrect password against the local IPC$ share.

Test command:

```powershell
$computer = $env:COMPUTERNAME
$user = "lab-user"
net use \\localhost\IPC$ /user:$computer\$user InvalidPassword9281
```

The command returned:

`System error 1326 has occurred. The user name or password is incorrect.`

### Observed event

The resulting Windows Security event contained:

| Field | Observed value |
|---|---|
| Event ID | 4625 |
| Computer | `windows-lab-vm` |
| Account | `windows-lab-vm\lab-user` |
| IP address | `::1` |
| Logon type | 3 |
| Activity | An account failed to log on |

A separate controlled test used for Detection DET-01 generated seven failed logon events for a dedicated test account.

## 6. Security Interpretation

Event ID 4625 provides visibility into unsuccessful authentication attempts.

Repeated failures may indicate:

- Password guessing
- Brute-force attempts
- Incorrect stored credentials
- Misconfigured services
- Legitimate user authentication errors

The source address, account, logon type, frequency and surrounding activity should be examined before classifying an event as malicious.

The observed `::1` address represents the IPv6 loopback address, consistent with the local test.

## 7. Investigation Use Cases

- Identify accounts experiencing repeated authentication failures.
- Examine potential password-guessing activity.
- Compare source IP addresses across failed attempts.
- Investigate unusual workstation-to-account relationships.
- Correlate failed attempts with subsequent successful logons.

## 8. Limitations

- The query aggregates by account and computer.
- It does not independently distinguish malicious attempts from user mistakes.
- The 24-hour execution window can exclude older activity.
- The controlled test results do not establish detection against all brute-force techniques.

## 9. Validation Status

**Execution status:** Executed and inspected.

**Initial baseline:** Zero failed logons in the initial 24-hour window.

**Controlled test:** Failed authentication event successfully generated and confirmed in Log Analytics.

**Interpretation:** Failed authentication telemetry was verified using controlled testing.

---

**Project:** Microsoft Sentinel Threat Detection and Incident Investigation Lab
