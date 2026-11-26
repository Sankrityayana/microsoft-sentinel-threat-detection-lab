# Azure Deployment Guide

## 1. Overview

This guide documents the deployment sequence used to establish the Microsoft Sentinel lab environment.

The deployment consists of:
1. Creating an Azure Log Analytics workspace.
2. Enabling Microsoft Sentinel on the workspace.
3. Provisioning a Windows Server virtual machine.
4. Configuring the virtual machine's managed identity.
5. Installing Azure Monitor Agent.
6. Creating a Data Collection Rule.
7. Associating the DCR with the virtual machine.
8. Verifying telemetry ingestion.

## 2. Create the Log Analytics Workspace

Create a dedicated Log Analytics workspace in Azure.

Recorded lab characteristics:

| Setting | Value |
|---|---|
| Region | Central India |
| Pricing tier | Pay-as-you-go |

The workspace acts as the central destination for collected monitoring data. Its exact resource name is intentionally omitted from this public guide.

## 3. Enable Microsoft Sentinel

1. Open Microsoft Sentinel in the Azure portal.
2. Select the Log Analytics workspace.
3. Enable Microsoft Sentinel on the workspace.
4. Verify that the workspace appears in the Sentinel environment.

## 4. Provision the Windows Virtual Machine

Create a Windows Server virtual machine.

| Setting | Recorded configuration |
|---|---|
| Operating system | Windows Server 2022 Datacenter Azure Edition Core |
| Region | Central India |
| Size | Standard B2ats v2 |
| vCPUs | 2 |
| Memory | 1 GiB |
| Public IP | None |
| System-assigned managed identity | Enabled |

The VM acts as the Windows security event source. The deployed VM size is a constrained lab configuration, not a production sizing recommendation.

## 5. Configure Azure Monitor Agent

Install the Azure Monitor Agent extension on the virtual machine.

The deployed extension version was:

`1.45.0.0`

Verify that the extension installation succeeds and that the agent is running.

## 6. Create the Data Collection Rule

Create a Data Collection Rule for the lab VM.

Configure it to:
- Collect configured Windows Security events.
- Collect PowerShell Operational Event ID 4104.
- Use the custom XPath event collection configuration for the PowerShell Operational event.
- Send configured telemetry to the dedicated Log Analytics workspace.
- Use the `Microsoft-SecurityEvent` stream.

The exact Azure resource names are omitted from this public guide.

## 7. Associate the DCR with the VM

Associate the DCR with the Windows Server lab VM.

Verify the association in Azure.

## 8. Verify the Deployment

Use the following checks:
- Confirm the VM is running.
- Confirm the AMA extension is installed.
- Confirm the DCR association exists.
- Check agent logs for successful DCR retrieval and execution.
- Confirm that the Log Analytics workspace receives Windows Security events.
- Confirm that PowerShell Event ID 4104 records are ingested.

Example KQL verification:

```kusto
SecurityEvent
| where TimeGenerated > ago(1h)
| summarize EventCount = count() by EventID
| order by EventCount desc
```

## 9. Troubleshooting Notes

When telemetry is missing, verify:
- AMA extension health.
- DCR association.
- DCR data sources and destinations.
- Windows event channel configuration.
- Event generation on the source VM.
- Connectivity to Azure Monitor endpoints.
- Agent diagnostic logs.

A successful extension installation alone does not prove successful data ingestion. Always verify the destination workspace.

## 10. Deployment Completion Criteria

The deployment is considered operational when:
- The VM is provisioned.
- AMA is installed and operational.
- The DCR is associated with the VM.
- Configured Windows events are generated and collected.
- Events are visible in the Log Analytics workspace.
- Microsoft Sentinel can query the collected data.

---

**Note:** This guide documents the implemented lab at a reproducible configuration level while omitting exact Azure resource names from the public repository.
