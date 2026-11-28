
# Project Evidence

## 1. Overview

This directory contains the evidence inventory and, as screenshots are captured, supporting screenshots from implementation, testing and investigation of the Microsoft Sentinel Threat Detection and Incident Investigation Lab.

The evidence is intended to demonstrate the actual configurations, telemetry ingestion, detection execution and incident investigation activities performed during the project.

## 2. Evidence Categories

| Category | Evidence |
|---|---|
| Azure Infrastructure | Resource groups, VM configuration and workspace |
| Microsoft Sentinel | Sentinel workspace and analytics configuration |
| Azure Monitor Agent | AMA installation and extension status |
| Data Collection Rules | DCR data sources, destinations and VM association |
| Telemetry Ingestion | Windows Security events and PowerShell Event ID 4104 |
| KQL Threat Hunting | Execution results of the eight hunting queries |
| Detection Engineering | Three scheduled analytics rule configurations |
| Alert Generation | Alerts generated during controlled testing |
| Incident Investigation | Investigation findings and event evidence |
| Incident Workflow | Classification, analyst notes and current incident status |

## 3. Investigation Evidence

### CASE-14 — Multiple Failed Logons

- Sentinel incident overview
- Event ID 4625 query results
- Failed authentication test output
- Incident classification and resolution

### CASE-28 — Suspicious PowerShell Activity

- Sentinel incident overview
- Event ID 4104 query results
- Controlled Base64 decoding test
- Detection indicator match
- Incident classification and final status

### CASE-29 — Suspicious Local Group Enumeration

- Sentinel incident overview
- Event ID 4799 query results
- Controlled PowerShell enumeration output
- Incident classification and resolution

## 4. Screenshot Directory

Screenshots will be organized under:

`screenshots/`

Five screenshots are currently committed: the analytics-rules overview, two CASE-14 screenshots, and two CASE-28 screenshots. See the [screenshot evidence checklist](screenshots/README.md) for current capture status.

Use descriptive filenames that identify the component or activity.

Examples:

- `azure-resource-groups.png`
- `log-analytics-workspace.png`
- `windows-vm-configuration.png`
- `ama-extension-status.png`
- `dcr-configuration.png`
- `security-event-ingestion.png`
- `powershell-event-4104.png`
- `detection-det-01.png`
- `detection-det-02.png`
- `detection-det-03.png`
- `case-14-investigation.png`
- `case-28-investigation.png`
- `case-29-investigation.png`

## 5. Evidence Handling

Before publishing screenshots:

- Remove subscription IDs and personal account information.
- Hide credentials, tokens and sensitive identifiers.
- Check that the screenshot supports the associated documentation.
- Preserve enough context to understand what is being demonstrated.
- Avoid editing screenshots in a way that changes the underlying evidence.

## 6. Current Evidence Status

Azure infrastructure details are documented in [Azure Infrastructure Reference](../docs/azure-infrastructure/README.md), so infrastructure screenshots are not required. Five screenshots are currently committed: the analytics-rules overview, two CASE-14 screenshots, and two CASE-28 screenshots. Additional planned captures across data collection, KQL, detection configuration and incident investigations remain pending. Do not describe the screenshot evidence collection as complete until each planned item has been captured, committed and reviewed.

## 7. Evidence Integrity

Screenshots are supporting evidence, not substitutes for technical documentation.

Each screenshot should correspond to an actual configuration, query execution or investigation result.

Do not include fabricated, recreated or misleading screenshots.
