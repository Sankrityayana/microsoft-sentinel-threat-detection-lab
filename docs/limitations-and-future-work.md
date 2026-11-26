
# Limitations and Future Work

## 1. Overview

This document records the current limitations of the Microsoft Sentinel Threat Detection and Incident Investigation Lab and identifies opportunities for further development.

The project demonstrates Windows security telemetry collection, KQL threat hunting, scheduled analytics detections and incident investigation in a controlled Azure environment.

It is a learning and demonstration environment, not a production SOC deployment.

## 2. Current Limitations

### 2.1 Infrastructure Scope

- The lab uses a single Windows Server virtual machine.
- It does not represent a multi-host enterprise environment.
- The VM uses a constrained compute configuration.
- No enterprise identity infrastructure or domain controller is included.

### 2.2 Telemetry Coverage

- Collection is limited to configured Windows event sources.
- The lab does not collect telemetry from multiple operating systems.
- Network traffic analysis and endpoint detection telemetry are outside the current implementation.
- Event availability depends on Windows audit and logging configuration.

### 2.3 Detection Coverage

- Only three scheduled analytics detections were implemented.
- PowerShell detection relies on selected string-based indicators.
- Group enumeration detection focuses on selected privileged groups and PowerShell processes.
- Failed-logon detection uses a fixed threshold and time window.
- Production environments would require tuning, contextual enrichment and false-positive evaluation.

### 2.4 Investigation Scope

- Investigations were performed on controlled lab activity.
- The project does not demonstrate a complete enterprise incident response process.
- No automated remediation or SOAR playbooks were implemented.
- Evidence collection is limited to available Windows events and Sentinel incident information.

### 2.5 Testing Scope

- Detection testing used controlled activity.
- The project does not establish comprehensive attack simulation coverage.
- Benign test results should not be interpreted as proof of detection against every malicious technique.

## 3. Future Improvements

### 3.1 Infrastructure Expansion

- Introduce additional Windows endpoints.
- Add a Windows domain environment.
- Explore Linux telemetry collection.
- Evaluate centralized identity and endpoint monitoring.

### 3.2 Detection Engineering

- Develop additional authentication detections.
- Add suspicious process execution analytics.
- Improve PowerShell detection logic.
- Add persistence and scheduled-task investigation detections.
- Introduce entity mapping and alert enrichment.
- Measure false-positive rates using repeatable test datasets.

### 3.3 Threat Intelligence

- Integrate external threat intelligence sources.
- Enrich suspicious IP addresses, domains and file hashes.
- Develop correlation between endpoint events and threat intelligence.

### 3.4 Incident Response

- Develop structured investigation playbooks.
- Explore Microsoft Sentinel automation rules.
- Evaluate Logic Apps-based response workflows.
- Document containment and recovery procedures in an isolated test environment.

### 3.5 Reporting and Visualization

- Build incident and detection dashboards.
- Track alert volume and detection performance.
- Document detection coverage against MITRE ATT&CK.
- Create repeatable validation reports.

## 4. Project Learning Outcomes

The implementation provided practical experience with:

- Azure security monitoring infrastructure.
- Microsoft Sentinel and Log Analytics.
- Azure Monitor Agent and Data Collection Rules.
- Windows Security Event Logs.
- PowerShell Script Block Logging.
- Kusto Query Language.
- Scheduled analytics rule configuration.
- MITRE ATT&CK technique mapping.
- Alert triage and incident investigation.
- Evidence-based security analysis.

## 5. Conclusion

This project establishes a foundation for further SOC and SIEM engineering work.

Its primary value is the practical implementation of a complete basic monitoring workflow, from Windows event generation and collection through detection and incident investigation.

Future development should focus on broader telemetry coverage, stronger detection logic, repeatable testing and improved investigation workflows.
