
# Detection Engineering Library

## Overview

This directory contains the three scheduled analytics detection rules implemented in the Microsoft Sentinel Threat Detection and Incident Investigation Lab.

The detections use Windows Security telemetry collected from the monitored Windows Server virtual machine.

## Detection Index

| ID | Detection | Event ID | Severity | MITRE ATT&CK |
|---|---|---:|---|---|
| DET-01 | Multiple Failed Logons | 4625 | Medium | Credential Access — T1110.001 |
| DET-02 | Suspicious PowerShell Activity | 4104 | Medium | Execution — T1059.001 |
| DET-03 | Suspicious Local Group Enumeration | 4799 | Medium | Discovery — T1069.001 |

## Detection Documentation

| Document | Description |
|---|---|
| [Multiple Failed Logons](multiple-failed-logons.md) | Detect repeated failed Windows authentication attempts |
| [Suspicious PowerShell Activity](suspicious-powershell-activity.md) | Detect selected suspicious PowerShell script-block indicators |
| [Suspicious Local Group Enumeration](suspicious-local-group-enumeration.md) | Detect PowerShell enumeration of selected privileged local groups |

## Common Configuration

The three rules were configured as scheduled analytics rules with:

- Execution frequency: 5 minutes
- Lookup period: 5 minutes
- Alert threshold: Greater than zero
- Event grouping: Group all events into a single alert
- Incident creation: Enabled
- Severity: Medium

## Validation

Each detection generated an alert and an associated Sentinel incident during controlled lab testing. Current workflow statuses: CASE-14 — Resolved; CASE-28 — New; CASE-29 — Closed.

The corresponding incident investigations are documented separately in the `investigations/` directory.

## Important

These detections demonstrate basic SIEM detection engineering. They are not production-ready rules and require tuning, broader testing and false-positive evaluation before deployment in an enterprise environment.
