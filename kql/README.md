# KQL Threat Hunting Library

## Overview

This directory contains eight Kusto Query Language (KQL) queries developed and executed during the Microsoft Sentinel Threat Detection and Incident Investigation Lab.

The queries examine Windows security telemetry collected from the lab virtual machine. They are exploratory and investigative queries, not eight independently validated production detections.

## Query Index

| ID | Query | Primary Event Source | Focus | Documentation |
|---|---|---|---|---|
| KQL-01 | Process Execution Analysis | 4688 | Process creation and parent-child relationships | [Open](KQL-01-process-execution-analysis.md) |
| KQL-02 | Failed Logon Analysis | 4625 | Authentication failures | [Open](KQL-02-failed-logon-analysis.md) |
| KQL-03 | PowerShell Script Activity Analysis | 4104 | PowerShell script block activity | [Open](KQL-03-powershell-script-activity.md) |
| KQL-04 | Local Account and Group Enumeration | 4798, 4799 | Account and group enumeration | [Open](KQL-04-account-group-enumeration.md) |
| KQL-05 | Privileged Group Enumeration | 4799 | Enumeration of privileged local groups | [Open](KQL-05-privileged-group-enumeration.md) |
| KQL-06 | Successful Logon Analysis | 4624 | Successful authentication activity | [Open](KQL-06-successful-logon-analysis.md) |
| KQL-07 | Privileged Service Activity | 4673 | Privileged service calls | [Open](KQL-07-privileged-service-activity.md) |
| KQL-08 | Scheduled Task Modification | 4702 | Scheduled task updates and selected task-level investigation | [Open](KQL-08-scheduled-task-modification.md) |

## Query Documentation Standard

Each query document records:
1. Objective
2. Data source and event identifiers
3. Complete KQL query
4. Query logic explanation
5. Execution window
6. Observed results
7. Security interpretation
8. Limitations and validation status

## Execution

The query files are Markdown documents containing fenced `kusto` code blocks. Open the relevant document, copy the query from its code block, and execute it in Microsoft Sentinel Logs or the associated Log Analytics workspace.

## Important Notes

- These queries were executed against the lab's `SecurityEvent` table.
- Results reflect the lab environment and the query time window.
- Observed activity is not automatically malicious.
- Baseline activity, controlled test activity and potentially suspicious activity must be distinguished.
- Query results should be validated against event-level evidence before conclusions are drawn.
- KQL-08 includes a selected event-level review of nine scheduled-task groups. Process attribution and binary-integrity verification remain incomplete; the investigation did not establish that every observed update was benign.

---

**Scope:** Eight exploratory and investigative queries. These are not eight independently validated production detections.
