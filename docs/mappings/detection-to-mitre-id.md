# Detection → MITRE ATT&CK Mapping

## Purpose

This document maps the **42 custom Wazuh detections** in the SOC Active Directory Detection Lab to the MITRE ATT&CK techniques they are intended to detect.

> **Scope:** The mappings below are based on the project's detection catalogue and stated ATT&CK coverage. A detection may map to more than one technique because the same Windows/Sysmon telemetry can represent multiple attacker behaviors.

## Coverage Summary

| Tactic / Area | Primary techniques represented |
|---|---|
| Initial Access / Persistence | T1078, T1136, T1098, T1547.001, T1543.003, T1053.005 |
| Defense Evasion | T1562.001, T1562.002, T1562.004, T1070.001, T1070.004 |
| Credential Access | T1110, T1558.001–004, T1003.001, T1003.003, T1003.006 |
| Discovery | T1087, T1069.002, T1482, T1016, T1049 |
| Lateral Movement / Execution | T1550.002, T1021.001/.002/.006, T1047, T1569.002, T1059.001, T1484.001 |
| Impact | T1531 |

## Detection Mapping

| ID | Detection | MITRE ATT&CK technique(s) |
|---|---|---|
| DET-001 | Windows Failed Authentication | **T1110** – Brute Force |
| DET-002 | Windows Brute Force Detection | **T1110** – Brute Force |
| DET-003 | Windows Successful Interactive Authentication | **T1078** – Valid Accounts |
| DET-004 | Successful Login After Failed Attempts | **T1110** – Brute Force; **T1078** – Valid Accounts |
| DET-005 | User Account Locked | **T1110** – Brute Force |
| DET-006 | Multiple Authentication Failures Same Source | **T1110** – Brute Force |
| DET-007 | New User Account Created | **T1136** – Create Account |
| DET-008 | Password Reset | **T1098** – Account Manipulation |
| DET-009 | User Account Enabled | **T1098** – Account Manipulation |
| DET-010 | Windows User Account Deleted | **T1531** – Account Access Removal |
| DET-011 | User Added to Domain Admins | **T1098** – Account Manipulation |
| DET-012 | User Added to Enterprise Admins | **T1098** – Account Manipulation |
| DET-013 | User Added to Local Administrators | **T1098** – Account Manipulation |
| DET-014 | Administrator Account Enabled | **T1098** – Account Manipulation |
| DET-015 | Privileged Account Logon | **T1078** – Valid Accounts |
| DET-016 | AD Account/Computer Attribute Modification | **T1098** – Account Manipulation |
| DET-017 | Kerberos Service Ticket Request / Possible Kerberoasting | **T1558.003** – Kerberoasting |
| DET-018 | AS-REP Roasting Detection | **T1558.004** – AS-REP Roasting |
| DET-019 | Directory Replication Request / Possible DCSync | **T1003.006** – DCSync |
| DET-020 | Golden Ticket Attack Detection | **T1558.001** – Golden Ticket |
| DET-021 | Silver Ticket Attack Detection | **T1558.002** – Silver Ticket |
| DET-022 | LSASS Credential Dumping | **T1003.001** – LSASS Memory |
| DET-023 | NTDS Credential Dumping via ntdsutil IFM | **T1003.003** – NTDS |
| DET-024 | Pass-the-Hash Detection | **T1550.002** – Pass the Hash |
| DET-025 | SharpHound Execution | **T1087** – Account Discovery; **T1069.002** – Permission Groups Discovery: Domain Groups; **T1482** – Domain Trust Discovery |
| DET-026 | AdFind Enumeration Tool Execution | **T1087** – Account Discovery; **T1069.002** – Permission Groups Discovery: Domain Groups; **T1482** – Domain Trust Discovery |
| DET-027 | Windows Network Discovery Commands Execution | **T1016** – System Network Configuration Discovery; **T1049** – System Network Connections Discovery |
| DET-028 | PsExec Process Execution Detection | **T1569.002** – Service Execution |
| DET-029 | SMB Admin Share Access | **T1021.002** – SMB/Windows Admin Shares |
| DET-030 | WinRM Execution Detection | **T1021.006** – Windows Remote Management |
| DET-031 | WMI Execution Detection | **T1047** – Windows Management Instrumentation |
| DET-032 | Successful RDP Logon Detection | **T1021.001** – Remote Desktop Protocol |
| DET-033 | New Windows Service Installed | **T1543.003** – Windows Service |
| DET-034 | New Scheduled Task Creation | **T1053.005** – Scheduled Task/Job: Scheduled Task |
| DET-035 | Group Policy Modification | **T1484.001** – Domain Policy Modification: Group Policy Modification |
| DET-036 | Startup Folder Persistence | **T1547.001** – Boot or Logon Autostart Execution: Registry Run Keys / Startup Folder |
| DET-037 | Security Event Log Cleared | **T1070.001** – Clear Windows Event Logs |
| DET-038 | Windows Audit Policy Modification | **T1562.002** – Disable or Modify Windows Event Logging |
| DET-039 | Windows Defender Tampering | **T1562.001** – Impair Defenses: Disable or Modify Tools |
| DET-040 | Suspicious PowerShell Execution | **T1059.001** – PowerShell |
| DET-041 | Windows Firewall Rule Changed | **T1562.004** – Impair Defenses: Disable or Modify System Firewall |
| DET-042 | Windows Security Group Deletion | **T1531** – Account Access Removal |

## Notes on ATT&CK Scope

Some techniques in the project's stated coverage are **behaviorally related to a detection but are not necessarily represented by a unique one-to-one rule**. For example, SharpHound and AdFind can provide telemetry for several discovery objectives, while PsExec can be represented through service execution and SMB/admin-share activity.

The project also lists **T1070.004 – File and Directory Discovery/Deletion-related indicator removal** in its broader ATT&CK coverage. The specific `DET-037` rule, however, detects **Windows Security Event Log clearing**, which is more precisely mapped to **T1070.001 – Clear Windows Event Logs**. Keeping this distinction explicit avoids overstating the rule's actual behavior.

## Coverage Philosophy

The mapping is intended to answer three SOC questions:

1. **What attacker behavior is detected?**
2. **What telemetry produces the detection?**
3. **Which ATT&CK technique does the behavior represent?**

The individual detection documents remain the authoritative source for rule logic, telemetry requirements, investigation guidance, and response actions.
