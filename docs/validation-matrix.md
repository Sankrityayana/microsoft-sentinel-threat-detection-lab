# Validation and Evidence Matrix

## Purpose

This matrix separates implementation and test results that have been recorded from work that still requires live-environment confirmation or screenshot evidence. It is a documentation status register, not a claim that every test has been independently reproduced during this review.

## 1. Infrastructure and Telemetry

| Component | Recorded validation | Remaining evidence or follow-up |
|---|---|---|
| Windows Server VM | VM provisioned; no public IP assigned directly; no custom inbound NSG allow rules in the reviewed state; system-assigned managed identity enabled | Screenshot capture only; live-state recheck if configuration has changed |
| Azure Monitor Agent | Live portal check on 2026-11-26: extension 1.45.0.0; Provisioning succeeded; Handler Ready; automatic upgrade disabled; 1.47.1.0 update offered | Screenshot capture only; update intentionally not applied |
| Data Collection Rule | Live portal check on 2026-11-26: Windows Event Logs source in Custom mode; multiple Security XPath filters; PowerShell Operational Event ID 4104 XPath; Log Analytics destination in Central India; VM resource view showed one associated DCR | Screenshot capture only; association count observed, not an exported ARM configuration |
| Connectivity | Network tests to Azure Monitor endpoints passed during setup | Screenshot capture only if output is retained |
| Log ingestion | Live query on 2026-11-26: recent SecurityEvent records including 4688, 4798, 4799, 4673, 4662, 4672, 4624 and 4702; 21 Event ID 4104 records in prior 24h; fresh controlled Event ID 4625 ingested after invalid-password test | Screenshot capture only; 4625 was not present in initial 24h query before the controlled test |

## 2. KQL Query Validation

| ID | Query | Recorded execution result | Remaining limitation |
|---|---|---|---|
| KQL-01 | Process Execution Analysis | Executed; 44 process-parent combinations returned | Individual process legitimacy was not fully established |
| KQL-02 | Failed Logon Analysis | Executed; initial baseline returned zero; controlled Event ID 4625 generated and confirmed | The separate single-event validation test and seven-event DET-01 test must remain distinct |
| KQL-03 | PowerShell Script Activity | Executed; 727 Event ID 4104 records returned | Five samples were inspected; all 727 events were not individually classified |
| KQL-04 | Account and Group Enumeration | Executed; five activity groups returned | Missing caller-process data requires contextual review |
| KQL-05 | Privileged Group Enumeration | Executed; three process/group combinations returned | Aggregated results do not replace event-level review |
| KQL-06 | Successful Logon Analysis | Executed; 22 Event ID 4624 records returned, all SYSTEM / Logon Type 5 | Baseline is limited to the selected seven-day window |
| KQL-07 | Privileged Service Activity | Executed; 479 Event ID 4673 records returned | Individual privilege details were not fully reviewed |
| KQL-08 | Scheduled Task Modification | Executed; nine task groups identified in a task-name inventory; selected task definitions and process correlations investigated | Not every Event ID 4702 record was reviewed; registering-process attribution and binary integrity remain incomplete |

### KQL-08 count interpretation

The initial aggregate query returned 966 events, and a later execution returned 953 events over a rolling seven-day window. The task-name inventory displayed nine groups whose counts summed to 941. These were separate executions/snapshots; the counts are retained as observed and are not treated as a reconciled fixed total.

## 3. Scheduled Detection Validation

| Detection | Controlled test | Recorded outcome | Current incident |
|---|---|---|---|
| DET-01 — Multiple Failed Logons | Seven failed logons using an intentionally incorrect password | Detection generated an alert and incident; controlled activity investigated | CASE-14 — Resolved |
| DET-02 — Suspicious PowerShell Activity | Benign Base64 decoding script using `FromBase64String` | Event ID 4104 confirmed; detection generated an incident; closing note submitted and case closure verified on 2026-11-26 | CASE-28 — Closed |
| DET-03 — Suspicious Local Group Enumeration | `Get-LocalGroupMember -Group "Administrators"` | Two matching Event ID 4799 records examined; detection generated an incident | CASE-29 — Closed |

These are controlled positive tests. They do not establish detection coverage for all attack variations or production false-positive rates. Cloud incident identifiers are omitted from this public matrix.

## 4. Incident Record Consistency

| Case | Analyst assessment | Recorded workflow status | Metadata caveat |
|---|---|---|---|
| CASE-14 | Informational, expected activity; Security testing | Resolved | Recorded in the investigation report |
| CASE-28 | Alert Classification: Informational, expected activity; Determination recorded in alert activity history: Security testing; analyst closing note submitted | Closed (verified in Defender Cases list on 2026-11-26) | Case-level summary Classification and Determination columns remained Unknown in the list; alert-level metadata is distinct |
| CASE-29 | Informational, expected activity; Security testing | Closed | Recorded in the investigation report |

Classification, determination and workflow status are separate incident attributes. Do not infer one from another.

## 5. Screenshot Evidence

The screenshot inventory currently contains 21 planned evidence items. No actual screenshot files were present in the repository at the time of the latest repository review.

| Evidence group | Planned items | Status |
|---|---:|---|
| Data collection | 6 | Pending capture and security review |
| KQL query results | 8 | Pending capture and security review |
| Detection configuration | 3 | Pending capture and security review |
| Incident investigations | 4 | Pending capture and security review |
| **Total** | **21** | **0 captured in repository** |

See [Screenshot Evidence Collection](../evidence/screenshots/README.md) for filenames and capture requirements.

## 6. Completion Criteria

Non-screenshot implementation and documentation work recorded in this repository is substantially complete. The following items remain outside repository-only work:

- Capture and review the 21 planned screenshots, with sensitive information redacted.
- Perform a dedicated GitHub secret-scanning/history review; the earlier targeted search was not comprehensive.

KQL-08's selected task-level investigation is documented. Its remaining process-attribution and binary-integrity limitations are explicit; this is not represented as a complete forensic review.

---

**Status:** Implementation, controlled testing, CASE-28 closure, live AMA/DCR/analytics-rule checks and fresh ingestion validation were confirmed on 2026-11-26. Screenshot evidence remains pending; repository secret/history assurance remains limited.
