
# Incident Investigation Reports

## 1. Overview

This directory contains investigation reports for three incidents generated during controlled testing of the Microsoft Sentinel analytics detection rules.

Each report documents the alert, underlying Windows security telemetry, investigation findings, analyst classification and incident status.

The investigations demonstrate the workflow from alert generation and triage through evidence examination, classification and incident handling.

## 2. Investigation Index

| Case | Detection | Investigation Focus | Current Status |
|---|---|---|---|
| CASE-14 | DET-01 — Multiple Failed Logons | Repeated failed authentication attempts | Resolved |
| CASE-28 | DET-02 — Suspicious PowerShell Activity | PowerShell Base64 decoding activity | Closed |
| CASE-29 | DET-03 — Suspicious Local Group Enumeration | Privileged local group enumeration | Closed |

## 3. Investigation Reports

| Report | Description |
|---|---|
| [CASE-14 — Multiple Failed Logons](case-14-multiple-failed-logons.md) | Investigation of seven controlled failed authentication attempts |
| [CASE-28 — Suspicious PowerShell Activity](case-28-suspicious-powershell.md) | Investigation of a PowerShell script-block detection involving Base64 decoding |
| [CASE-29 — Local Group Enumeration](case-29-local-group-enumeration.md) | Investigation of controlled PowerShell enumeration of the local Administrators group |

## 4. Common Investigation Methodology

The investigations follow a structured workflow:

1. Identify the generated Sentinel incident.
2. Review alert severity and detection context.
3. Retrieve the underlying Windows Security events.
4. Examine relevant event attributes.
5. Correlate the events with the activity performed during testing.
6. Determine whether the activity was expected or requires further investigation.
7. Record the classification and determination.
8. Document the investigation findings and incident status.

## 5. Investigation Summary

### CASE-14 — Multiple Failed Logons

- Windows Event ID: 4625
- Controlled activity: Repeated invalid-password authentication attempts
- Observed events: 7
- Classification: Informational, expected activity
- Determination: Security testing
- Status: Resolved

### CASE-28 — Suspicious PowerShell Activity

- Windows Event ID: 4104
- Controlled activity: Base64 decoding using PowerShell
- Matched indicator: `FromBase64String`
- Decoded value: `Hello`
- Classification: Informational, expected activity
- Determination: Security testing
- Status: Closed

The Defender case was verified Closed on 2026-11-26. The alert details page confirms Classification = Informational, expected activity, and the alert activity history records Determination = Security testing. These are alert-level values; distinguish them from case-level summary fields.

### CASE-29 — Suspicious Local Group Enumeration

- Windows Event ID: 4799
- Controlled activity: PowerShell enumeration of the local Administrators group
- Observed matching events: 2
- Classification: Informational, expected activity
- Determination: Security testing
- Status: Closed

## 6. Investigation Principles

- An alert is an investigative lead, not proof of compromise.
- Controlled testing must be distinguished from real attacks.
- Conclusions must be supported by observed evidence.
- Missing evidence must not be interpreted as proof of absence.
- Classification, determination and incident workflow status are separate attributes.
- Incident status must reflect the actual Sentinel record.
- Investigation notes should be understandable to another analyst.

## 7. Scope and Limitations

These reports document controlled investigations performed against a single Windows Server lab virtual machine.

They demonstrate a basic SIEM alert triage and investigation workflow.

They do not establish enterprise incident response experience, forensic certainty or actual compromise of a production system.

## 8. Supporting Evidence

Supporting screenshots will be maintained in:

[`../evidence/screenshots/`](../evidence/screenshots/)

Screenshots should be actual captures from Microsoft Sentinel, Log Analytics and the Windows lab environment, with sensitive information redacted.

---

**Project:** Microsoft Sentinel Threat Detection and Incident Investigation Lab
