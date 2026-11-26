# Monitoring and Data Collection Configuration

## Log Analytics workspace

| Property | Value |
|---|---|
| Workspace | Azure Log Analytics workspace (resource name omitted) |
| Resource group | Omitted from the public record |
| Region | Central India |
| Purpose | Central log destination queried by Microsoft Sentinel |

## Azure Monitor Agent

| Property | Value |
|---|---|
| VM extension | `AzureMonitorWindowsAgent` |
| Version observed | `1.45.0.0` |
| Provisioning state | Succeeded |
| Handler state | Ready |
| Automatic upgrade | Disabled at review |
| Update shown as available | `1.47.1.0` |

The available update was observed but not applied during the 26 November 2026 verification. The version and update availability are point-in-time observations, not a recommendation to defer updates indefinitely.

## Data Collection Rule

| Property | Value |
|---|---|
| DCR name | Omitted from the public record |
| Resource group | Omitted from the public record |
| Region | Central India |
| Destination type | Log Analytics workspace |
| Destination workspace | Same lab workspace described above |

The DCR's Data Sources page showed a Windows Event Logs source configured in Custom mode. The reviewed configuration included Windows Security event collection and a PowerShell Operational channel filter for Script Block Logging Event ID 4104:

```text
Microsoft-Windows-PowerShell/Operational!*[System[(EventID=4104)]]
```

AppLocker event channels were also visible in the source configuration. This document does not reproduce every Security channel XPath expression because not all individual expressions were captured in the verification record.

The DCR Resources view showed the monitored VM with one associated DCR. The DCR configuration and VM resource association were reviewed in the portal; the resource count alone should not be treated as proof of every association detail.

## PowerShell Script Block Logging

PowerShell Script Block Logging was enabled on the Windows VM using the policy registry value:

```powershell
HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
EnableScriptBlockLogging = 1
```

Event ID 4104 was observed in the Log Analytics `SecurityEvent` table. In this environment, do not assume that Event ID 4104 is stored in the `WindowsEvent` table.

## Ingestion verification — 26 November 2026

Fresh queries against the `SecurityEvent` table confirmed recent Windows telemetry from the lab VM.

Examples from the reviewed 24-hour aggregation:

| Event ID | Count in query result |
|---:|---:|
| 4702 | 144 |
| 4688 | 688 |
| 4798 | 168 |
| 4799 | 48 |
| 4673 | 71 |
| 4662 | 478 |
| 4672 | 2 |
| 4624 | 2 |

The query result indicated nine event-ID groups; only the eight rows above are transcribed here.

A separate query showed 21 Event ID 4104 records in the 24-hour window.

A controlled invalid-password test was then run on the VM. The command returned Windows error 1326, and a fresh 30-minute query confirmed the resulting Event ID 4625. The public record omits the host, account, IP address, exact timestamp and event-record identifier.

This validates fresh ingestion of the controlled 4625 event and current 4104 telemetry at the time of testing. It does not prove complete coverage of every configured event channel or uninterrupted ingestion over time.

## Operational caveats

- AMA was healthy at the time of the portal review; this is not a guarantee of future agent health.
- Automatic extension upgrade was disabled and an update was available. Review and manage agent updates as part of ongoing maintenance.
- The DCR overview displayed a Data Sources count of zero while its Data Sources page showed a configured Windows Event Logs source. The detailed Data Sources page was used for the configuration description.
- Event counts are time-window-specific snapshots, not fixed expected baselines.
- The lab has one monitored Windows host and limited event coverage. Do not generalize these results to a production fleet.

## Related documentation

- [Data Collection and Ingestion](../data-collection-and-ingestion.md)
- [Validation and Evidence Matrix](../validation-matrix.md)
- [Detection Engineering](../detection-engineering.md)
