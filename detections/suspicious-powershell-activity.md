
# DET-02 — Suspicious PowerShell Activity

## 1. Detection Overview

| Property | Value |
|---|---|
| Detection ID | DET-02 |
| Rule name | SOC Lab - Suspicious PowerShell Activity |
| Detection type | Scheduled analytics rule |
| Severity | Medium |
| Data source | Windows PowerShell Operational |
| Event ID | 4104 |
| MITRE ATT&CK tactic | Execution |
| MITRE ATT&CK technique | T1059.001 — PowerShell |
| Execution frequency | 5 minutes |
| Lookup period | 5 minutes |

## 2. Objective

Identify selected suspicious indicators in PowerShell script block content.

PowerShell is a legitimate Windows administration tool, but it can also be abused to execute commands, retrieve remote content, decode payloads and perform other potentially malicious activities.

This detection searches for a defined set of indicators rather than attempting to classify every PowerShell script as malicious.

## 3. Detection Indicators

| Indicator | Investigation relevance |
|---|---|
| `DownloadString` | May indicate retrieval of remote content |
| `EncodedCommand` | May indicate encoded PowerShell command execution |
| `FromBase64String` | May indicate Base64 decoding |
| `Net.WebClient` | May indicate network-related operations |
| `Start-BitsTransfer` | May indicate file transfer activity |

These indicators can also appear in legitimate administrative scripts. Contextual investigation is required.

## 4. KQL Detection Query

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

## 5. Analytics Rule Configuration

| Setting | Configured value |
|---|---|
| Rule name | SOC Lab - Suspicious PowerShell Activity |
| Rule type | Scheduled |
| Run query every | 5 minutes |
| Lookup data from last | 5 minutes |
| Alert threshold | Greater than 0 |
| Event grouping | Group all events into a single alert |
| Incident creation | Enabled |
| Severity | Medium |

## 6. Controlled Testing

A benign PowerShell script was executed to test Base64 decoding visibility.

```powershell
$encoded = "SGVsbG8="
$decoded = [System.Text.Encoding]::UTF8.GetString(
    [Convert]::FromBase64String($encoded)
)
Write-Output "SOC_LAB_BASE64_TEST: $decoded"
```

Expected and observed output:

`SOC_LAB_BASE64_TEST: Hello`

The corresponding Windows PowerShell Event ID 4104 record was confirmed in Log Analytics.

Observed event details:

| Field | Observed value |
|---|---|
| Event ID | 4104 |
| Computer | `windows-lab-vm` |
| EventRecordId | 1649 |
| Matched indicator | FromBase64String |
| Event timestamp | 2026-11-24 10:06:36.573 UTC |

## 7. Alert and Incident Investigation

| Property | Value |
|---|---|
| Incident ID | Omitted from public record |
| Case reference | 28 |
| Alert ID | Omitted from public record |
| Severity | Medium |
| Analyst assessment | Expected security testing activity |
| Alert details: Classification | Informational, expected activity |
| Alert activity history: Determination | Security testing |
| Current incident workflow status | New |

The underlying event was examined separately from the Sentinel incident.

The matched `FromBase64String` indicator corresponded to the controlled test script.

The test value decoded to `Hello`. No evidence of malicious download activity or external network communication was identified in the investigated test.

## 8. Investigation Conclusion

The detection successfully identified the controlled PowerShell script block containing a configured indicator and generated a Sentinel incident.

The alert details page confirmed Classification = Informational, expected activity. The alert activity history recorded Determination = Security testing. These are alert-level fields; keep them distinct from case-level summary metadata.

This demonstrates how PowerShell Script Block Logging can support detection engineering and incident investigation.

## 9. False Positives and Limitations

- Base64 decoding is not inherently malicious.
- Download-related methods may be used by legitimate administration scripts.
- String matching does not establish command intent.
- The extraction logic depends on the observed EventData XML structure.
- The rule examines only five selected indicators.
- A matching indicator should trigger investigation, not an automatic compromise conclusion.

## 10. MITRE ATT&CK Mapping

- Tactic: Execution
- Technique: T1059.001 — PowerShell

The mapping describes the behavior the rule is designed to monitor. The controlled test did not demonstrate malicious execution.

---

**Project:** Microsoft Sentinel Threat Detection and Incident Investigation Lab
