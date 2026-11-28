# Screenshot Evidence Collection

## Purpose

This directory stores original screenshots demonstrating the actual implementation and validation of the Microsoft Sentinel lab.

The directory contains committed evidence screenshots. Each checklist item below is tracked separately; an uploaded supporting screenshot does not automatically complete an entire investigation.

## Azure Infrastructure — documented, no screenshot required

Azure infrastructure configuration is documented in [Azure Infrastructure Reference](../../docs/azure-infrastructure/README.md), including the VM, networking, AMA, DCR and workspace details. The four planned infrastructure screenshots have therefore been removed from this capture checklist.

## 1. Data Collection

| ID | Screenshot filename | What it should demonstrate | Status |
|---|---|---|---|
| EV-01 | `ama-extension-status.png` | AMA extension installation | Pending capture |
| EV-02 | `dcr-data-source.png` | Windows event collection configuration | Pending capture |
| EV-03 | `dcr-destination.png` | Workspace destination and stream | Pending capture |
| EV-04 | `dcr-vm-association.png` | DCR association with VM | Pending capture |
| EV-05 | `security-event-ingestion.png` | Windows Security events in Log Analytics | Pending capture |
| EV-06 | `powershell-event-4104.png` | PowerShell Script Block Logging ingestion | Pending capture |

Additional supporting evidence: `case-28-powershell-scriptblock.png` captures four Event ID 4104 records containing the controlled marker `SOC_LAB_POWERSHELL_DETECTION_TEST_2026` on `win-soc-lab-01` (24 Nov 2026). This demonstrates controlled script-block test activity; it does not independently prove alert correlation.

## 2. KQL Threat Hunting

| ID | Screenshot filename | What it should demonstrate | Status |
|---|---|---|---|
| EV-07 | `kql-process-execution.png` | KQL-01 execution | Pending capture |
| EV-08 | `kql-failed-logons.png` | KQL-02 execution | Pending capture |
| EV-09 | `kql-powershell-activity.png` | KQL-03 execution | Pending capture |
| EV-10 | `kql-account-group-enumeration.png` | KQL-04 execution | Pending capture |
| EV-11 | `kql-privileged-group-enumeration.png` | KQL-05 execution | Pending capture |
| EV-12 | `kql-successful-logons.png` | KQL-06 execution | Pending capture |
| EV-13 | `kql-privileged-service-activity.png` | KQL-07 execution | Pending capture |
| EV-14 | `kql-scheduled-task-modification.png` | KQL-08 execution | Pending capture |

## 3. Detection Engineering

| ID | Screenshot filename | What it should demonstrate | Status |
|---|---|---|---|
| EV-15 | `detection-multiple-failed-logons.png` | DET-01 configuration | Pending capture |
| EV-16 | `detection-suspicious-powershell.png` | DET-02 configuration | Pending capture |
| EV-17 | `detection-local-group-enumeration.png` | DET-03 configuration | Pending capture |

## 4. Incident Investigations

| ID | Screenshot filename | What it should demonstrate | Status |
|---|---|---|---|
| EV-18 | `case-14-attack-graph.png`, `case-14-activities.png` | CASE-14 attack graph and activity history | Partial — 2 screenshots uploaded; alert/event evidence pending |
| EV-19 | `case-28-investigation.png` | CASE-28 case overview and alert-list status (Closed); a separate incident-detail capture is still pending | Pending capture |
| EV-20 | `case-29-investigation.png` | CASE-29 incident showing Closed status | Pending capture |
| EV-21 | `incident-classification-resolution.png` | Classification and incident workflow evidence | Pending capture |

## 5. Screenshot Standards

- Capture the actual Azure or Sentinel interface.
- Keep relevant query results and configuration values readable.
- Use the filenames listed above.
- Avoid unnecessary browser tabs and unrelated interface elements.
- Redact personal information, subscription identifiers, workspace identifiers and sensitive details.
- Do not alter screenshots to misrepresent results.
- Only mark an evidence item complete after the screenshot has been captured, added to the repository and reviewed.

## 6. Evidence Status

**Current status: 5 screenshots committed.** The repository contains `analytics-rules-overview.png`, `case-14-attack-graph.png`, `case-14-activities.png`, `case-28-powershell-scriptblock.png`, and `case-28-alert-list.png`.

The CASE-28 alert-list screenshot supports the case overview and alert-list state (Closed, Medium severity, Resolved alert, Execution category). The PowerShell ScriptBlock marker screenshot supports the controlled Event ID 4104 test. Together they provide supporting evidence for the case, but do not independently prove every alert-to-event correlation step or replace the remaining incident-detail, alert-classification and closure-note captures.

CASE-14's original Event ID 4625 telemetry was not retrievable for 25–28 October 2026. Update each checklist item only after the corresponding evidence has been committed and reviewed.
