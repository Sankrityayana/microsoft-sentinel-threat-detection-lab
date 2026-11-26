# Technical Walkthrough and Interview Guide

## Project Summary

This lab demonstrates a basic end-to-end Windows security monitoring workflow using Microsoft Sentinel, Azure Monitor Agent (AMA), a Data Collection Rule (DCR), Log Analytics and Kusto Query Language (KQL).

It is a single-endpoint learning environment. The controlled tests validate selected telemetry and detection paths; they are not real intrusions or proof of enterprise-scale detection coverage.

## 1. Architecture Walkthrough

1. A Windows Server 2022 virtual machine generates Windows Security and PowerShell Operational events.
2. Azure Monitor Agent collects the configured event sources.
3. The associated DCR defines the collection configuration and Log Analytics destination.
4. Events arrive in the workspace's `SecurityEvent` table.
5. Microsoft Sentinel uses the workspace data for hunting and scheduled analytics.
6. Three scheduled rules generate alerts and incidents from controlled test activity.
7. The analyst retrieves underlying events, correlates them with the test, records classification/determination and tracks workflow status.

## 2. Telemetry and Collection

Explain the distinction between an installed agent and verified ingestion. In this lab, AMA extension installation, active processes, DCR association, successful DCR download/parsing, endpoint connectivity tests and event arrival in Log Analytics were separately checked.

PowerShell Script Block Logging was enabled, and the DCR selected PowerShell Operational Event ID 4104. In this environment, 4104 records were observed in `SecurityEvent`, not `WindowsEvent`. On 2026-11-26, the live portal showed AMA 1.45.0.0 Provisioning succeeded / Handler Ready, the DCR's Windows Event Logs source and 4104 XPath, a Log Analytics destination in Central India, and one DCR association on the VM. A fresh query returned 21 Event ID 4104 records in the preceding 24 hours.

The Windows Security event IDs in the KQL library are events examined during the lab; they are not a claim that every listed ID was individually configured as a DCR XPath filter.

## 3. Detection Engineering

### DET-01 — Multiple Failed Logons

- Source: Event ID 4625 in `SecurityEvent`.
- Logic: Count failures by computer, account and five-minute bin; return groups with at least five failures.
- Test: Seven intentionally failed authentication attempts.
- Outcome: Alert and incident generated; controlled activity classified as Informational / expected activity, determination Security testing.
- MITRE mapping: T1110.001 — Password Guessing (relevant behavior).

### DET-02 — Suspicious PowerShell Activity

- Source: Event ID 4104 in `SecurityEvent`.
- Logic: Extract ScriptBlockText and match selected strings including `FromBase64String`, `DownloadString`, `EncodedCommand`, `Net.WebClient` and `Start-BitsTransfer`.
- Test: Benign Base64 decoding of the value `SGVsbG8=`, producing `Hello`.
- Outcome: Event 4104 and matching indicator confirmed; incident generated. Alert classification was Informational / expected activity and alert activity history recorded Security testing. A closing note was submitted and CASE-28 was verified Closed in the Defender Cases list on 2026-11-26.
- MITRE mapping: T1059.001 — PowerShell (behavior monitored, not proof of malicious execution).

### DET-03 — Suspicious Local Group Enumeration

- Source: Event ID 4799 in `SecurityEvent`.
- Logic: Extract caller process and target group; filter PowerShell processes and selected privileged local groups.
- Test: `Get-LocalGroupMember -Group "Administrators"`.
- Outcome: Two matching 4799 records; incident generated and closed as expected security testing activity.
- MITRE mapping: T1069.001 — Permission Groups Discovery: Local Groups.

## 4. Hunting Query Library

Eight exploratory queries were executed: process creation (4688), failed logons (4625), PowerShell script blocks (4104), account/group enumeration (4798/4799), privileged group enumeration (4799), successful logons (4624), privileged service activity (4673) and scheduled task updates (4702).

These are hunting and investigation queries, not eight production detections. In particular, the 727 PowerShell records were sampled rather than all individually classified.

### KQL-08 — Scheduled Task Modification

Event ID 4702 was examined at both aggregate and selected task level. A task-name inventory identified nine groups spanning Windows security, update, maintenance and device-management tasks.

Selected task definitions were inspected. Several configurations were consistent with Windows maintenance functions. Process correlation was attempted using ClientProcessId and Event ID 4688, including a narrow time-window join. PID reuse and missing process-creation matches prevented reliable attribution for several tasks.

The investigation did not confirm a malicious task modification. It also did not prove that every update was benign: not every event was reviewed, and binary signatures/hashes were not verified for all relevant executables. See [KQL-08 investigation notes](../kql/KQL-08-scheduled-task-modification.md) for observed task metadata and limitations.

## 5. Incident Investigation

For each alert, explain:
- What rule fired and why.
- Which Windows event supported the alert.
- What controlled action generated the event.
- Which event attributes were examined.
- Why the activity was classified as expected testing.
- The distinction between alert classification, determination and case workflow status.

Recorded cases:
- CASE-14 — Multiple Failed Logons; Resolved.
- CASE-28 — Suspicious PowerShell; Closed (verified 2026-11-26). Alert-level classification and determination were verified separately.
- CASE-29 — Local Group Enumeration; Closed.

Cloud incident identifiers are omitted from this public walkthrough.

## 6. Known Limitations to State Clearly

- One Windows Server endpoint only.
- Three scheduled detections.
- Controlled positive tests only; no broad adversary simulation.
- String matching in the PowerShell rule can produce false positives and false negatives.
- The failed-logon threshold requires environment-specific tuning.
- Group enumeration is not group modification.
- KQL-03 sampled five scripts, not every 4104 event.
- KQL-08 reviewed selected task definitions, not every Event ID 4702 record; registering-process attribution and binary-integrity verification remain incomplete.
- No automated response, SOAR playbooks, multi-endpoint coverage or production false-positive measurement.

## 7. Reproduction Sequence

1. Provision the Azure resources and Windows Server VM using the environment guide.
2. Configure AMA and the DCR.
3. Enable PowerShell Script Block Logging and collect Event ID 4104.
4. Verify DCR association and agent diagnostics.
5. Confirm SecurityEvent ingestion before writing analytics.
6. Execute the KQL hunting queries and inspect results.
7. Configure the three scheduled analytics rules.
8. Run the controlled tests in an isolated lab.
9. Verify each underlying event, alert and incident.
10. Record classification, determination and actual workflow status.
11. Recheck live ingestion with fresh KQL queries; on 2026-11-26, Event ID 4104 and a controlled Event ID 4625 were confirmed in `SecurityEvent`.
12. Capture redacted screenshots separately; never fabricate evidence.

## Interview Positioning

Describe this as a hands-on SIEM engineering and incident investigation lab. Do not present it as corporate SOC experience, a production deployment, or evidence that real attacks were detected. Explain the exact controlled tests, telemetry path, query logic, investigation decisions and limitations.
