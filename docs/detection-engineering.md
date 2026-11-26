
# Detection Engineering

## 1. Overview

This document describes the scheduled analytics detections implemented in the Microsoft Sentinel Threat Detection and Incident Investigation Lab.

Three detection rules were created to identify selected Windows security activities.

| Detection ID | Detection Name | Windows Event ID | Severity |
|---|---|---:|---|
| DET-01 | Multiple Failed Logons | 4625 | Medium |
| DET-02 | Suspicious PowerShell Activity | 4104 | Medium |
| DET-03 | Suspicious Local Group Enumeration | 4799 | Medium |

All three detections use KQL and scheduled analytics rules.

## 2. Detection 01 — Multiple Failed Logons

### Objective

Identify repeated failed Windows logon attempts against the same account and computer within a five-minute window.

### Detection logic

- Event ID: 4625
- Threshold: At least 5 failed attempts
- Time window: 5 minutes
- Severity: Medium
- MITRE tactic: Credential Access
- Relevant MITRE technique: T1110.001 — Password Guessing

### KQL

```kusto
SecurityEvent
| where TimeGenerated > ago(5m)
| where EventID == 4625
| summarize FailedAttempts = count()
    by Computer, TargetAccount = Account, bin(TimeGenerated, 5m)
| where FailedAttempts >= 5
```

### Scheduled rule configuration

- Run frequency: Every 5 minutes
- Lookup period: 5 minutes
- Alert threshold: Greater than 0
- Event grouping: Group all events into a single alert
- Incident creation: Enabled

### Controlled test

Multiple failed authentication attempts were generated using an invalid password against the local IPC$ administrative share.

The resulting events were inspected in Sentinel.

The test generated seven failed logon events for the controlled test account.

## 3. Detection 02 — Suspicious PowerShell Activity

### Objective

Identify selected suspicious PowerShell script-block indicators recorded through Windows PowerShell Event ID 4104.

### Detection logic

The rule examines script-block text for:

- DownloadString
- EncodedCommand
- FromBase64String
- Net.WebClient
- Start-BitsTransfer

Configuration:

- Event ID: 4104
- Severity: Medium
- MITRE tactic: Execution
- MITRE technique: T1059.001 — PowerShell

### KQL

```kusto
SecurityEvent
| where TimeGenerated > ago(5m)
| where EventID == 4104
| extend ScriptBlockText = extract(
    '<Data Name="ScriptBlockText">([^<]*)</Data>',
    1,
    EventData
)
| where isnotempty(ScriptBlockText)
| extend MatchedIndicator = case(
    ScriptBlockText contains "DownloadString", "DownloadString",
    ScriptBlockText contains "EncodedCommand", "EncodedCommand",
    ScriptBlockText contains "FromBase64String", "FromBase64String",
    ScriptBlockText contains "Net.WebClient", "Net.WebClient",
    ScriptBlockText contains "Start-BitsTransfer", "Start-BitsTransfer",
    "No match"
)
| where MatchedIndicator != "No match"
| project TimeGenerated, Computer, EventRecordId, MatchedIndicator, ScriptBlockText
```

### Scheduled rule configuration

- Run frequency: Every 5 minutes
- Lookup period: 5 minutes
- Alert threshold: Greater than 0
- Event grouping: Group all events into a single alert
- Incident creation: Enabled

### Controlled test

A PowerShell script used `System.Convert.FromBase64String()` to decode a benign Base64 value.

The decoded output was:

`Hello`

The corresponding Event ID 4104 record was confirmed in Log Analytics, and the detection generated an incident.

The activity was classified as expected security testing.

## 4. Detection 03 — Suspicious Local Group Enumeration

### Objective

Identify PowerShell-based enumeration of selected privileged local groups.

### Detection logic

- Event ID: 4799
- Target groups: Administrators and Remote Desktop Users
- Process indicators: powershell.exe and pwsh.exe
- Severity: Medium
- MITRE tactic: Discovery
- MITRE technique: T1069.001 — Permission Groups Discovery: Local Groups

### KQL

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

### Scheduled rule configuration

- Run frequency: Every 5 minutes
- Lookup period: 5 minutes
- Alert threshold: Greater than 0
- Event grouping: Group all events into a single alert
- Incident creation: Enabled

### Controlled test

The following command was executed on the Windows VM:

```powershell
Get-LocalGroupMember -Group "Administrators" |
    Select-Object Name, ObjectClass, PrincipalSource
```

The command returned the local `lab-user` account.

Two corresponding Event ID 4799 records were confirmed with PowerShell as the caller process and Administrators as the target group.

The activity was classified as expected security testing.

## 5. Detection Validation Summary

| Detection | Controlled activity | Result |
|---|---|---|
| DET-01 | Repeated invalid-password attempts | Alert and incident generated |
| DET-02 | Benign Base64 decoding script | Alert and incident generated |
| DET-03 | PowerShell local group enumeration | Alert and incident generated |

## 6. Detection Engineering Considerations

### False positives

These rules use behavioral indicators and event attributes. Their matches are not proof of malicious activity.

For example:

- Failed logons can result from legitimate authentication mistakes.
- Base64 decoding can be used in benign administrative scripts.
- Local group enumeration can be performed by legitimate system administration tools.

### Limitations

- The PowerShell detection uses a limited set of string indicators.
- The group enumeration rule focuses on selected groups and PowerShell processes.
- The failed-logon rule aggregates by account, computer and five-minute time bin.
- The rules require tuning before use in a production environment.

## 7. Future Improvements

- Add allowlists for known administrative activity.
- Improve account and source IP correlation.
- Enrich detections with threat intelligence.
- Add entity mapping and alert enrichment.
- Evaluate detection coverage against additional ATT&CK techniques.
- Test detection behavior against a broader range of benign and malicious simulations.
