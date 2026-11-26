
# Environment and Prerequisites

## 1. Cloud Environment

This project was implemented using Microsoft Azure.

| Setting | Configuration |
|---|---|
| Cloud provider | Microsoft Azure |
| Azure region | Central India |
| Operating system | Windows Server 2022 Datacenter Azure Edition Core |
| VM name | Windows Server lab VM |
| VM size | Standard B2ats v2 |
| Log Analytics workspace | Dedicated lab workspace |
| Workspace resource group | Dedicated lab resource group |
| VM resource group | Dedicated lab resource group |
| Data Collection Rule | Windows security collection DCR |

## 2. Required Azure Services

The following services are required to reproduce the lab:

- Azure Virtual Machines
- Azure Log Analytics
- Microsoft Sentinel
- Azure Monitor Agent (AMA)
- Data Collection Rules (DCR)
- Azure Monitor

## 3. Virtual Machine Requirements

The lab uses a Windows Server 2022 virtual machine as its telemetry source.

The deployed VM configuration:

- VM size: Standard B2ats v2
- vCPUs: 2
- Memory: 1 GiB
- Region: Central India
- System-assigned managed identity: Enabled
- Public IP: Not assigned
- Inbound internet access: Not exposed

**Note:** The deployed VM is a constrained lab configuration. Its resource size is not a recommendation for production security monitoring workloads.

## 4. Monitoring Configuration

The monitoring pipeline uses:

- Azure Monitor Agent version 1.45.0.0
- Data Collection Rule configured for Windows security telemetry
- Destination: Dedicated Log Analytics workspace
- Windows Security event collection
- PowerShell Operational event collection for Event ID 4104

## 5. Software and Query Requirements

- Windows PowerShell
- Microsoft Sentinel portal access
- Azure portal access
- Kusto Query Language (KQL)
- GitHub account for project documentation

## 6. Cost Considerations

This lab uses Azure pay-as-you-go resources.

Costs may be incurred through:

- Virtual machine compute
- Managed disks
- Log Analytics data ingestion and retention
- Microsoft Sentinel data analysis and related services
- Associated networking resources, if applicable

Check current Azure pricing and subscription entitlements before deployment.

Stop or deallocate the VM when it is not required. Review the workspace and other provisioned resources before leaving the lab running.

## 7. Security and Privacy

Do not publish:

- Azure subscription IDs
- Credentials, tokens or secrets
- Personal email addresses
- Private keys
- Sensitive workspace identifiers
- Unredacted screenshots containing personal or subscription information

Use your own Azure subscription and appropriate permissions when reproducing the lab.
