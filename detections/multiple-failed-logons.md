
# DET-01 — Multiple Failed Logons

## 1. Detection Overview

| Property | Value |
|---|---|
| Detection ID | DET-01 |
| Rule name | SOC Lab - Multiple Failed Logons |
| Detection type | Scheduled analytics rule |
| Severity | Medium |
| Data source | Windows Security Events |
| Event ID | 4625 |
| MITRE ATT&CK tactic | Credential Access |
| MITRE ATT&CK technique | T1110.001 — Password Guessing (relevant behavior) |
| Execution frequency | 5 minutes |
| Lookup period | 5 minutes |

## 2. Objective

Detect repeated unsuccessful Windows authentication attempts against the same account on the same computer within a five-minute interval.

Repeated failed logons can indicate password guessing, brute-force attempts or other suspicious authentication behavior.

## 3. Detection Logic

The rule:

1. Queries the `SecurityEvent` table.
2. Restricts events to the previous five minutes.
3. Filters for Windows Event ID 4625.
4. Groups events by computer, account and five-minute time bin.
5. Counts failed authentication attempts.
6. Returns groups with five or more failures.

## 4. KQL Detection Query

```kusto
SecurityEvent
| where TimeGenerated > ago(5m)
| where EventID == 4625
| summarize FailedAttempts = count()
    by Computer, TargetAccount = Account, bin(TimeGenerated, 5m)
| where FailedAttempts >= 5
```

## 5. Detection Threshold

| Parameter | Configuration |
|---|---|
| Minimum failed attempts | 5 |
| Time window | 5 minutes |
| Alert condition | Query returns one or more results |
| Severity | Medium |

The threshold is a basic lab configuration and should be tuned according to the authentication patterns of the monitored environment.

## 6. Analytics Rule Configuration

| Setting | Configured value |
|---|---|
| Rule name | SOC Lab - Multiple Failed Logons |
| Rule type | Scheduled |
| Run query every | 5 minutes |
| Lookup data from last | 5 minutes |
| Alert threshold | Greater than 0 |
| Event grouping | Group all events into a single alert |
| Incident creation | Enabled |

## 7. Controlled Testing

A controlled authentication test was performed by generating repeated failed logon attempts using an intentionally incorrect password.

The test generated seven failed logon events for the account:

`windows-lab-vm\SOC_Lab_InvalidUser_9281`

The observed events included:

| Field | Observed value |
|---|---|
| Event ID | 4625 |
| Computer | `windows-lab-vm` |
| Test account | `SOC_Lab_InvalidUser_9281` |
| Failed attempts | 7 |
| Source IP | `::1` |
| Logon type | 3 |

The analytics rule generated a Sentinel incident.

## 8. Incident Investigation

| Property | Value |
|---|---|
| Incident ID | 136680 |
| Case reference | 14 |
| Classification | Informational, expected activity |
| Determination | Security testing |
| Final status | Resolved |

The underlying Windows Security events were examined and correlated with the controlled invalid-password test.

The activity was identified as intentional testing rather than unauthorized authentication.

## 9. Investigation Conclusion

The detection successfully identified repeated failed authentication attempts exceeding the configured threshold.

The generated incident was investigated and classified as expected security testing activity.

This validates the basic detection workflow:

**Windows event generation → AMA collection → Log Analytics ingestion → KQL analytics rule → Sentinel incident → Investigation and resolution.**

## 10. Limitations

- The rule uses a fixed threshold.
- It groups events by account, computer and five-minute time bin.
- It does not independently establish malicious intent.
- Legitimate authentication errors can trigger the rule.
- More advanced detection would correlate source addresses, account context and successful logons.

## 11. MITRE ATT&CK Mapping

- Tactic: Credential Access
- Relevant technique for password guessing: T1110.001 — Password Guessing

The mapping describes the behavior the detection may help identify. It does not establish that a brute-force attack occurred during the controlled test.

---

**Project:** Microsoft Sentinel Threat Detection and Incident Investigation Lab
