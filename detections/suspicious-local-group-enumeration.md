# DET-03 — Suspicious Local Group Enumeration

## 1. Detection Overview

| Property | Value |
|---|---|
| Detection ID | DET-03 |
| Rule name | SOC Lab - Suspicious Local Group Enumeration |
| Detection type | Scheduled analytics rule |
| Severity | Medium |
| Data source | Windows Security Events |
| Event ID | 4799 |
| MITRE ATT&CK tactic | Discovery |
| MITRE ATT&CK technique | T1069.001 — Permission Groups Discovery: Local Groups |
| Execution frequency | 5 minutes |
| Lookup period | 5 minutes |

## 2. Objective

Detect PowerShell-based enumeration of selected privileged local groups.

Attackers may enumerate local group membership to identify privileged accounts and understand the security configuration of a compromised system.

This detection focuses on Event ID 4799 and selected privileged local groups.

## 3. Detection Logic

The rule:
1. Queries the `SecurityEvent` table.
2. Filters for Event ID 4799.
3. Extracts the caller process name.
4. Extracts the target group name.
5. Filters for PowerShell processes.
6. Restricts results to Administrators and Remote Desktop Users.
7. Returns the matching event details.

## 4. KQL Detection Query

```kusto
SecurityEvent
| where TimeGenerated > ago(5m)
| where EventID == 4799
| extend CallerProcess = extract(
    '<Data Name="CallerProcessName">([^<]*)</Data>',
    1,
    EventData
)
| extend TargetGroup = extract(
    '<Data Name="TargetUserName">([^<]*)</Data>',
    1,
    EventData
)
| where CallerProcess endswith @"\powershell.exe"
    or CallerProcess endswith @"\pwsh.exe"
| where TargetGroup in ("Administrators", "Remote Desktop Users")
| project
    TimeGenerated,
    Computer,
    Account,
    EventRecordId,
    CallerProcess,
    TargetGroup
```

## 5. Detection Configuration

| Setting | Configured value |
|---|---|
| Rule type | Scheduled |
| Run query every | 5 minutes |
| Lookup data from last | 5 minutes |
| Alert threshold | Greater than 0 |
| Event grouping | Group all events into a single alert |
| Incident creation | Enabled |
| Severity | Medium |

## 6. Controlled Testing

The following PowerShell command was executed on the Windows Server lab VM:

```powershell
Write-Output "SOC_LAB_GROUP_ENUM_TEST_START"

Get-LocalGroupMember -Group "Administrators" |
    Select-Object Name, ObjectClass, PrincipalSource

Write-Output "SOC_LAB_GROUP_ENUM_TEST_END"
```

Observed output identified the local `lab-user` account.

The test generated Windows Security Event ID 4799 records.

### Observed event details

| Field | Observed value |
|---|---|
| Event ID | 4799 |
| Computer | Windows Server lab VM |
| Caller process | PowerShell |
| Target group | Administrators |
| Matching events | 2 |

## 7. Alert and Incident Investigation

| Property | Value |
|---|---|
| Incident ID | 136695 |
| Case reference | 29 |
| Severity | Medium |
| Classification | Informational, expected activity |
| Determination | Security testing |
| Current incident workflow status | Closed |

Two related events were examined. Both recorded PowerShell enumeration of the local Administrators group.

The activity was correlated with the controlled `Get-LocalGroupMember` test.

## 8. Investigation Conclusion

The detection successfully identified the controlled local group enumeration activity and generated a Sentinel incident.

The incident was investigated, classified as expected security testing and closed.

No evidence of unauthorized group modification or account compromise was identified in the investigated activity.

## 9. False Positives and Limitations

- Legitimate administrators may enumerate local groups.
- Security and inventory tools may perform group enumeration.
- Event ID 4799 represents enumeration, not group membership modification.
- The detection covers only selected groups.
- Process names alone do not establish the legitimacy of an executable.
- Additional context is required before classifying activity as malicious.

## 10. MITRE ATT&CK Mapping

- Tactic: Discovery
- Technique: T1069.001 — Permission Groups Discovery: Local Groups

The mapping represents the behavior monitored by the detection. The controlled test demonstrated benign group enumeration, not an actual attack.

---

**Project:** Microsoft Sentinel Threat Detection and Incident Investigation Lab
