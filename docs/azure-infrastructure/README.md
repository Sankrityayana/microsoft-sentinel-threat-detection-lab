# Azure Lab Infrastructure

This section records the cloud architecture used by the Microsoft Sentinel lab without publishing environment-specific resource identifiers.

## At a glance

| Component | Recorded configuration |
|---|---|
| Cloud platform | Microsoft Azure |
| Azure region | Central India |
| Monitored compute | One Windows Server 2022 Datacenter Azure Edition (Core) virtual machine |
| VM size | Standard B2ats v2 — 2 vCPUs, 1 GiB memory |
| Public IP | None assigned directly to the VM at the time of review |
| Virtual network/subnet | Dedicated lab virtual network and default subnet |
| Log destination | Azure Log Analytics workspace |
| Data Collection Rule | Windows Security and PowerShell event collection |
| Monitoring agent | Azure Monitor Agent (AMA) |

## Documents

- [Virtual machine and network](vm-and-networking.md)
- [Monitoring and data collection](monitoring-and-data-collection.md)

## Security and publication notes

- Environment-specific VM names, resource group names, workspace names, DCR names, private addresses, account names and resource identifiers are intentionally omitted from this public overview.
- The VM had no public IP address and no inbound NSG allow rules were configured in the reviewed state.
- The VM's system-assigned managed identity was enabled.
- A VM without a public IP should not be described as having no outbound connectivity; outbound access and its security implications must be evaluated separately.
- Configuration details are point-in-time observations, not a guarantee of current or future security posture.

## Verification record

The VM, AMA extension, DCR configuration and workspace destination were reviewed in the Azure portal on 26 November 2026. Fresh telemetry was also queried in the workspace on that date. See [Data Collection and Ingestion](../data-collection-and-ingestion.md) and [Validation and Evidence Matrix](../validation-matrix.md) for the operational validation record.

This is a single-host learning lab, not a production Azure landing zone or enterprise network design.
