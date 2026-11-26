# Virtual Machine and Network Configuration

## Virtual machine

| Property | Recorded configuration |
|---|---|
| Name | Omitted from the public record |
| Resource group | Omitted from the public record |
| Region | Central India |
| Provisioning state at review | Running |
| Operating system | Windows Server 2022 Datacenter Azure Edition (Core) |
| VM size | Standard B2ats v2 |
| vCPU | 2 |
| Memory | 1 GiB |
| Private IPv4 address | Omitted from the public record |
| Public IPv4 address | Not assigned directly to the VM at the time of review |
| Guest agent | Ready at the time of review; exact build omitted |
| System-assigned managed identity | Enabled |

The VM is the single Windows telemetry source used in this lab. Its small memory allocation is suitable only for a lightweight test environment; it is not evidence of capacity for production workloads.

## Network configuration

| Property | Recorded state |
|---|---|
| Virtual network and subnet names | Omitted from the public record |
| Network security group | Inbound traffic denied by default; no custom inbound rules were present in the reviewed state |
| Public IP resource | None associated directly with the VM |
| NAT Gateway | None recorded |
| User-defined route table | None recorded |

### Interpretation

- The VM was not directly assigned a public IP address.
- The reviewed NSG state did not contain custom inbound allow rules.
- These facts do not, by themselves, prove that every possible network path is blocked. Network security also depends on subnet associations, peerings, routing, platform behavior and any other connected resources.
- The Azure portal displayed a warning that the subnet uses a default outbound IP and that this default behavior is being phased out for new subnets after March 2026. This lab should not be described as having a deliberately configured, hardened outbound path.
- No NAT Gateway or custom route table was present in the reviewed configuration.

## Security posture observed

The reviewed configuration provides a limited attack surface for this lab: no VM public IP, no custom inbound NSG allow rules, and a system-assigned managed identity. It is not a complete network security assessment and does not establish that the VM has no internet egress.

## Verification date

Azure VM overview and networking configuration reviewed on 26 November 2026. Values are point-in-time observations and may change if the Azure resources are modified.
