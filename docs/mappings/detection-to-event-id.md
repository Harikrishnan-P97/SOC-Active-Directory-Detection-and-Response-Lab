# Detection → Event ID Mapping

## Purpose

This document maps each custom Wazuh detection to the primary Windows Security, Windows system, or Sysmon telemetry used to generate and validate the alert.

The lab uses Wazuh agents on **DC01 (10.10.10.20)** and **CLIENT01 (10.10.10.30)**. Windows Security telemetry is complemented by **Olaf Hartong's Sysmon-Modular** configuration for endpoint process, network, registry, module, and related activity.

## Windows Security Event Mapping

| ID | Detection | Primary Event ID(s) | Telemetry source |
|---|---|---|---|
| DET-001 | Windows Failed Authentication | **4625** | Windows Security |
| DET-002 | Windows Brute Force Detection | **4625** | Windows Security |
| DET-003 | Successful Interactive Authentication | **4624** | Windows Security |
| DET-004 | Successful Login After Failed Attempts | **4625 + 4624** | Windows Security |
| DET-005 | User Account Locked | **4740** | Windows Security |
| DET-006 | Multiple Authentication Failures Same Source | **4625** | Windows Security |
| DET-007 | New User Account Created | **4720** | Windows Security |
| DET-008 | Password Reset | **4724** | Windows Security |
| DET-009 | User Account Enabled | **4722** | Windows Security |
| DET-010 | Windows User Account Deleted | **4726** | Windows Security |
| DET-011 | User Added to Domain Admins | **4728** | Windows Security |
| DET-012 | User Added to Enterprise Admins | **4756** | Windows Security |
| DET-013 | User Added to Local Administrators | **4732** | Windows Security |
| DET-014 | Administrator Account Enabled | **4722** | Windows Security |
| DET-015 | Privileged Account Logon | **4624** | Windows Security |
| DET-016 | AD Account/Computer Attribute Modification | **5136 / 4662** | Windows Security |
| DET-017 | Kerberos Service Ticket Request / Possible Kerberoasting | **4769** | Windows Security |
| DET-018 | AS-REP Roasting Detection | **4768** | Windows Security |
| DET-019 | Directory Replication Request / Possible DCSync | **4662** | Windows Security |
| DET-020 | Golden Ticket Attack Detection | **4768 / 4624** | Windows Security |
| DET-021 | Silver Ticket Attack Detection | **4769 / 4624** | Windows Security |
| DET-022 | LSASS Credential Dumping | **4688 + Sysmon 10** | Security + Sysmon |
| DET-023 | NTDS Credential Dumping via ntdsutil IFM | **4688 + Sysmon 1** | Security + Sysmon |
| DET-024 | Pass-the-Hash Detection | **4624** | Windows Security |
| DET-025 | SharpHound Execution | **4688 + Sysmon 1/3** | Security + Sysmon |
| DET-026 | AdFind Enumeration Tool Execution | **4688 + Sysmon 1/3** | Security + Sysmon |
| DET-027 | Windows Network Discovery Commands | **4688 + Sysmon 1/3** | Security + Sysmon |
| DET-028 | PsExec Process Execution | **4688 + 7045 + Sysmon 1** | Security + Sysmon |
| DET-029 | SMB Admin Share Access | **5140** | Windows Security |
| DET-030 | WinRM Execution | **4688 + Sysmon 1/3** | Security + Sysmon |
| DET-031 | WMI Execution | **4688 + Sysmon 1/3** | Security + Sysmon |
| DET-032 | Successful RDP Logon | **4624** | Windows Security |
| DET-033 | New Windows Service Installed | **7045** | Windows System |
| DET-034 | New Scheduled Task Creation | **4698** | Windows Security |
| DET-035 | Group Policy Modification | **5136 / 4662** | Windows Security |
| DET-036 | Startup Folder Persistence | **4688 + Sysmon 12/13/14** | Security + Sysmon |
| DET-037 | Security Event Log Cleared | **1102** | Windows Security |
| DET-038 | Windows Audit Policy Modification | **4719** | Windows Security |
| DET-039 | Windows Defender Tampering | **5001 / 5007 / 5013** | Windows Defender |
| DET-040 | Suspicious PowerShell Execution | **4688 + Sysmon 1** | Security + Sysmon |
| DET-041 | Windows Firewall Rule Changed | **4946 / 4947 / 4948** | Windows Security |
| DET-042 | Windows Security Group Deletion | **4730 / 4734 / 4758** | Windows Security |

## Sysmon Telemetry Catalogue

The project uses the Sysmon event types below as endpoint telemetry:

| Sysmon ID | Event | Primary use in the lab |
|---|---|---|
| **1** | Process Creation | Tool execution, PowerShell, PsExec, discovery, credential-access tooling |
| **3** | Network Connection | Network discovery, lateral movement, remote execution |
| **5** | Process Terminated | Process lifecycle / supporting investigation |
| **7** | Image Loaded | DLL/module loading and supporting endpoint investigation |
| **8** | CreateRemoteThread | Injection-related behavior |
| **10** | Process Access | LSASS access / credential dumping / process injection |
| **12** | Registry Object Create/Delete | Persistence and registry activity |
| **13** | Registry Value Set | Run keys, configuration and persistence changes |
| **14** | Registry Key/Value Rename | Registry-based evasion/persistence |
| **15** | FileCreateStreamHash | Alternate Data Streams / downloaded-file activity |

## Telemetry Pipeline

```text
KALI
  │
  │ Attack simulation
  ▼
DC01 / CLIENT01
  │
  ├── Windows Security Events
  ├── Windows System Events
  ├── Defender Events
  └── Sysmon Events
          │
          ▼
     Wazuh Agent
          │
          ▼
     Wazuh Manager
          │
      Decoders
          │
    Custom Rules
  100100–100141
          │
          ▼
        Alert
          │
          ▼
      Indexer
          │
          ▼
     SOC Dashboards
```

## Telemetry Design Principle

Windows Security events provide the authoritative AD/security audit trail, while Sysmon supplies higher-fidelity endpoint context such as process creation, network connections, registry changes, and LSASS process access.

The combination allows detections to correlate **identity + process + network + AD object + endpoint behavior** rather than relying on a single event source.
