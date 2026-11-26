# KQL-08 — Scheduled Task Modification Analysis

## 1. Objective

Investigate Windows scheduled task update events to establish an activity baseline and examine whether selected task changes are consistent with expected operating-system maintenance.

Event ID 4702 records a scheduled task being updated. Scheduled tasks are used for legitimate Windows maintenance and can also be abused for persistence or recurring execution. A task name or a high event count alone is not sufficient to classify an update as benign or malicious.

## 2. Data Source and Scope

| Property | Value |
|---|---|
| Workspace table | `SecurityEvent` |
| Windows Event ID | 4702 |
| Event description | A scheduled task was updated |
| Investigation window | Rolling 7 days |
| Host | Lab Windows VM |
| Query type | Exploratory investigation / hunting |

## 3. Baseline Query

```kusto
SecurityEvent
| where TimeGenerated > ago(7d)
| where EventID == 4702
| summarize
    EventCount = count(),
    FirstSeen = min(TimeGenerated),
    LastSeen = max(TimeGenerated),
    Accounts = make_set(Account, 10),
    Activities = make_set(Activity, 10)
    by Computer
| order by EventCount desc
```

The initial execution returned 966 events. A later execution returned 953 events. These are separate executions over a rolling seven-day window; the counts are not treated as a fixed total.

## 4. Task Inventory

A task-name aggregation identified nine distinct task groups. The following counts are the values displayed by the inventory query during the investigation:

| Scheduled task | Event 4702 count |
|---|---:|
| `\Microsoft\Windows\SoftwareProtectionPlatform\SvcRestartTask` | 502 |
| `\Microsoft\Windows\Flighting\OneSettings\RefreshCache` | 327 |
| `\Microsoft\Windows\Windows Defender\Windows Defender Cache Maintenance` | 18 |
| `\Microsoft\Windows\Windows Defender\Windows Defender Verification` | 18 |
| `\Microsoft\Windows\Windows Defender\Windows Defender Cleanup` | 18 |
| `\Microsoft\Windows\WindowsUpdate\Scheduled Start` | 16 |
| `\Microsoft\Windows\UpdateOrchestrator\Schedule Scan` | 14 |
| `\Microsoft\Windows\Data Integrity Scan\Data Integrity Check And Scan` | 14 |
| `\Microsoft\Windows\Device Information\Device` | 14 |

The displayed per-task counts sum to 941, while the separate aggregate query returned 953 during a nearby execution. Because the queries were run at different times against a rolling window, this report preserves both observed outputs rather than forcing them into a single reconciled total. The inventory is a point-in-time observation, not a permanent baseline.

### Inventory query

```kusto
SecurityEvent
| where TimeGenerated > ago(7d)
| where EventID == 4702
| extend TaskName = extract(
    '<Data Name="TaskName">([^<]+)</Data>',
    1,
    EventData
)
| summarize EventCount = count() by TaskName
| order by TaskName asc
```

## 5. Selected Event-Level Findings

### 5.1 Software Protection Platform — SvcRestartTask

Observed task definition:

- Task path: `\Microsoft\Windows\SoftwareProtectionPlatform\SvcRestartTask`
- Source and author fields reference `sppc.dll`.
- Task principal: Network Service.
- Task action: COM handler with a timer-related data value; class identifier omitted.
- Daily calendar trigger; task is marked hidden.
- Two inspected records contained client and parent process identifiers; numeric values are omitted.

Process investigation found Event ID 4688 records where PID 684 (hex `0x2ac`) was associated with `C:\Windows\System32\sppsvc.exe`, parented by `C:\Windows\System32\services.exe`. However, a client-PID join restricted to the two minutes before task updates returned no matches. The process-identifier-only results cannot establish a direct causal relationship because Windows reuses PIDs.

**Assessment:** The task metadata is consistent with Software Protection Platform functionality. Direct attribution of the task updates to `sppsvc.exe` was not established.

### 5.2 Flighting — OneSettings — RefreshCache

Observed task definition:

- Task path: `\Microsoft\Windows\Flighting\OneSettings\RefreshCache`.
- Task principal: LocalSystem.
- Client and parent process identifiers were present in inspected records; numeric values are omitted.
- Time trigger with a 283-minute repetition interval and a WNF state-change trigger.
- Action: COM handler; class identifier omitted.
- Task is not hidden and requires network availability.

A search for the observed client process identifier in Event ID 4688 within the available seven-day window returned no process-creation records.

**Assessment:** The configuration is consistent with a Windows background task, but the registering executable could not be identified from the available process-creation telemetry.

### 5.3 Windows Defender maintenance tasks

Three task groups were observed:

- Windows Defender Cache Maintenance — 18 events
- Windows Defender Verification — 18 events
- Windows Defender Cleanup — 18 events

Time-window PID correlations associated sampled task updates with `MpCmdRun.exe` under the Windows Defender platform directory, with `MsMpEng.exe` as parent. Other sampled correlations included `DismHost.exe` processes under temporary GUID directories, also recorded with `MsMpEng.exe` as parent.

These are time-window correlations, not proof that every task update was initiated by those processes. The historical temporary `DismHost.exe` files were not available for signature or hash verification during the investigation.

**Assessment:** The sampled relationships are consistent with Defender-associated maintenance activity. Binary integrity was not independently verified.

### 5.4 Device Information — Device

Observed task definition:

- Task path: `\Microsoft\Windows\Device Information\Device`.
- Subject SID / task principal: `S-1-5-18` (LocalSystem).
- Configured task action: `%windir%\system32\devicecensus.exe SystemCxt`.
- Daily time trigger with a two-hour random delay.
- Task is not hidden.
- Inspected records contained client and parent process identifiers; numeric values are omitted.

The configured action is consistent with Windows Device Census functionality. The action executable is not necessarily the process that registered the task. The client PID was not reliably attributed: a PID-only search returned multiple process creations over seven days, and the stricter time-window query returned no results.

A later aggregation showed 14 updates and multiple distinct client process identifiers associated with a recurring parent process identifier.

**Assessment:** The task definition is consistent with a Windows device-information task. The registering process remains unconfirmed.

### 5.5 Windows Update — Scheduled Start

Observed task definition:

- Task path: `\Microsoft\Windows\WindowsUpdate\Scheduled Start`.
- Source and author: Microsoft Corporation.
- Subject SID / task principal: `S-1-5-18` (LocalSystem).
- Configured action: `C:\Windows\system32\sc.exe start wuauserv`.
- Task description says it starts the Windows Update service for scheduled operations such as scans.
- Task is not hidden.
- Inspected records contained client and parent process identifiers; numeric values are omitted.

A reused process identifier appeared in Event ID 4688 records with several different executables, including `sc.exe`, `UsoClient.exe`, `DeviceCensus.exe`, `MpCmdRun.exe`, `wermgr.exe` and `wsqmcons.exe`. This demonstrates why process-identifier-only correlation across a seven-day window is unsafe. The two-minute time-window join returned no matches for the Scheduled Start updates.

**Assessment:** The task configuration is consistent with Windows Update service-start functionality. The registering executable was not established.

### 5.6 UpdateOrchestrator — Schedule Scan

Observed task definition:

- Task path: `\Microsoft\Windows\UpdateOrchestrator\Schedule Scan`.
- Subject SID / task principal: `S-1-5-18` (LocalSystem).
- Configured action: `%systemroot%\system32\usoclient.exe StartScan`.
- Time trigger repeats every 420 minutes with a 105-minute random delay.
- Task is not hidden.
- Two inspected records had different client and parent process identifiers; numeric values are omitted.

**Assessment:** The configuration is consistent with scheduled Windows Update scanning. The configured action is not evidence of which process registered the task; registering-process attribution was not completed.

### 5.7 Data Integrity Check And Scan

Observed task definition:

- Task path: `\Microsoft\Windows\Data Integrity Scan\Data Integrity Check And Scan`.
- Source and author fields reference `discan.dll`.
- Subject SID / task principal: `S-1-5-18` (LocalSystem).
- Action: COM handler; class identifier omitted.
- Daily calendar trigger; a boot trigger was disabled in one inspected version and enabled in another.
- Task is not hidden.
- Inspected records contained client and parent process identifiers; numeric values are omitted.

A seven-day aggregation showed 14 updates with recurring client and parent process identifiers. Similar identifiers appeared in another task group, but this does not establish executable identity or prove a shared registering process.

**Assessment:** The task metadata is consistent with a Windows data-integrity task. The registering executable was not identified.

## 6. Process-Correlation Method and Caveats

Event ID 4702 records contain `ClientProcessId` and `ParentProcessId` in the event data. Event ID 4688 provides process-creation telemetry. PID correlation was attempted using the client PID and a two-minute lookback before the task update.

Example correlation approach:

```kusto
let TaskUpdates =
    SecurityEvent
    | where TimeGenerated > ago(7d)
    | where EventID == 4702
    | extend ClientPID = tolong(toint(extract(
        '<Data Name="ClientProcessId">([^<]+)</Data>',
        1,
        EventData
    )))
    | project TaskTime = TimeGenerated,
        TaskEventRecordId = EventRecordId,
        ClientPID;
let ProcessCreations =
    SecurityEvent
    | where TimeGenerated > ago(7d)
    | where EventID == 4688
    | extend CreatedPID = tolong(toint(ProcessId))
    | project ProcessTime = TimeGenerated,
        ProcessEventRecordId = EventRecordId,
        CreatedPID,
        NewProcessName,
        ParentProcessName;
TaskUpdates
| join kind=inner ProcessCreations
    on $left.ClientPID == $right.CreatedPID
| where ProcessTime between (TaskTime - 2m .. TaskTime)
| project TaskTime, TaskEventRecordId, ClientPID,
    ProcessTime, ProcessEventRecordId, NewProcessName, ParentProcessName
| order by TaskTime desc
```

The correlation is only a lead. It does not prove causation. PIDs are reused, process-creation events may be outside the retention window or absent from collected telemetry, and the event's configured task action is distinct from the client process that registered or updated the task.

## 7. Overall Security Assessment

The investigation identified nine task groups and inspected selected task definitions and process relationships. Several configurations are consistent with Windows maintenance components, including Software Protection Platform, Windows Update, Defender maintenance, Device Census and Data Integrity Scan.

**No confirmed malicious scheduled-task modification was established by this investigation.** This is not equivalent to proving that all observed updates were benign. The review was selective and did not validate every event, task action, binary signature or hash.

The high event volume for `SvcRestartTask` (502) and `RefreshCache` (327) warrants retaining them as baseline items for future comparison, rather than treating volume alone as an indicator of compromise.

## 8. Limitations and Follow-up

- Event ID 4702 indicates a task update; it does not by itself show that the task executed.
- The rolling seven-day aggregate counts changed between executions. The task inventory counts and separate aggregate totals are preserved as observed, not forced into an artificial reconciliation.
- Only selected records from each task group were inspected; not all 953/966 aggregate events were individually reviewed.
- Process-identifier reuse limits attribution. Some client PIDs had no corresponding Event ID 4688 record in the available time window.
- The configured task action is not necessarily the executable that registered the task.
- Executable signatures and hashes were not verified for all observed binaries.
- Temporary `DismHost.exe` files were no longer present when checked, preventing retrospective signature/hash verification.
- The investigation did not establish whether every task definition matched a known-good baseline for this exact Windows Server image.

Recommended follow-up:
1. Capture task definitions and file metadata from the live VM at the time of a future update.
2. Collect and correlate Task Scheduler Operational logs and process-creation telemetry with adequate retention.
3. Verify signatures and hashes of task action binaries and relevant COM-handler registrations.
4. Baseline expected task paths, principals, triggers and actions for the specific Windows Server build.
5. Investigate deviations from that baseline, especially unexpected executable paths, script interpreters, user-writable directories or newly introduced tasks.

## 9. Validation Status

**Query execution:** Executed successfully against the `SecurityEvent` table.

**Inventory result:** Nine task groups identified in the seven-day inventory query.

**Investigation result:** Selected task definitions reviewed; selected process correlations attempted.

**Conclusion:** Exploratory scheduled-task investigation completed with unresolved process-attribution and binary-integrity limitations. No confirmed malicious modification was identified; benignity of every event was not established.

---

**Project:** Microsoft Sentinel Threat Detection and Incident Investigation Lab
