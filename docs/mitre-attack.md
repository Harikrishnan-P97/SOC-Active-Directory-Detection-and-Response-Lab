# MITRE ATT&CK Alignment & Coverage

## 1. Overview

The SOC Active Directory Detection Lab maps custom detection rules, telemetry log sources, and Incident Response (IR) playbooks against the [MITRE ATT&CK Framework](https://attack.mitre.org/). 

This document outlines how individual detection engineering rules (`DET-001` through `DET-042`) correlate to MITRE tactics and techniques, providing a baseline for threat visibility, coverage density, and visibility gaps across the Active Directory environment.

The mapping encompasses:

* **42 Custom Detections** covering 8 functional security categories.
* **31 Unique MITRE ATT&CK Techniques** mapped across 8 primary tactics.
* **25 Windows & Sysmon Event IDs** integrated into detection logic.
* **7 Incident Response Playbooks** aligned with specific tactic groups.

---

## 2. Detection → MITRE Mapping

The primary detection table provides direct correlation between custom rules, MITRE ATT&CK tactics and techniques, primary event sources, and corresponding response workflows.

| Rule ID | Detection Rule Name | MITRE Tactic | Technique ID | Technique Name | Primary Telemetry / Event IDs | Associated IR Playbook |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| **DET-001** | Windows Failed Authentication | Credential Access | `T1110` | Brute Force | Win Security 4625 | `IR-001` |
| **DET-002** | Windows Brute Force Detection | Credential Access | `T1110.001` | Password Guessing | Win Security 4625 | `IR-001` |
| **DET-003** | Windows Successful Interactive Auth | Defense Evasion / Persistence | `T1078` | Valid Accounts | Win Security 4624 | `IR-001` |
| **DET-004** | Successful Login After Failed Attempts | Persistence / Lateral Movement | `T1078` | Valid Accounts | Win Security 4624, 4625 | `IR-001` |
| **DET-005** | Account Locked Base Rule | Credential Access | `T1110.001` | Password Guessing | Win Security 4740 | `IR-001` |
| **DET-006** | Multiple Auth Failures From Same Source | Credential Access | `T1110.003` | Password Spraying | Win Security 4625 | `IR-001` |
| **DET-007** | New User Account Created | Persistence | `T1136.001` | Local Account / Domain Account | Win Security 4720 | `IR-002` |
| **DET-008** | Password Reset | Persistence / Impact | `T1098` | Account Manipulation | Win Security 4724 | `IR-002` |
| **DET-009** | User Account Enabled | Persistence | `T1098` | Account Manipulation | Win Security 4722 | `IR-002` |
| **DET-010** | Windows User Account Deletion | Impact | `T1531` | Account Access Removal | Win Security 4726 | `IR-002` |
| **DET-011** | User Added To Domain Admins | Privilege Escalation / Persistence | `T1098` | Account Manipulation | Win Security 4728, 4756 | `IR-002` |
| **DET-012** | User Added To Enterprise Admins | Privilege Escalation / Persistence | `T1098` | Account Manipulation | Win Security 4756 | `IR-002` |
| **DET-013** | User Added To Local Admins | Privilege Escalation / Persistence | `T1098` | Account Manipulation | Win Security 4732 | `IR-002` |
| **DET-014** | Administrator Account Enabled | Privilege Escalation / Persistence | `T1098` | Account Manipulation | Win Security 4722 | `IR-002` |
| **DET-015** | Privileged Account Logon | Privilege Escalation / Defense Evasion | `T1078.002` | Domain Accounts | Win Security 4624 | `IR-002` |
| **DET-016** | AD Account/Computer Attribute Mod | Privilege Escalation / Persistence | `T1098` | Account Manipulation | Win Security 5136 | `IR-002` |
| **DET-017** | Kerberoasting Detection | Credential Access | `T1558.003` | Kerberoasting | Win Security 4769 | `IR-003` |
| **DET-018** | AS-REP Roasting Detection | Credential Access | `T1558.004` | AS-REP Roasting | Win Security 4768 | `IR-003` |
| **DET-019** | DCSync Attack Detection | Credential Access | `T1003.006` | DCSync | Win Security 4662 | `IR-003` |
| **DET-020** | Golden Ticket Attack Detection | Credential Access | `T1558.001` | Golden Ticket | Win Security 4768, 4769 | `IR-003` |
| **DET-021** | Silver Ticket Attack Detection | Credential Access | `T1558.002` | Silver Ticket | Win Security 4769 | `IR-003` |
| **DET-022** | LSASS Credential Dumping | Credential Access | `T1003.001` | LSASS Memory | Sysmon Event ID 10 | `IR-003` |
| **DET-023** | NTDS.dit Dumping via ntdsutil IFM | Credential Access | `T1003.003` | NTDS | Sysmon Event ID 1, 4688 | `IR-003` |
| **DET-024** | Pass-the-Hash Detection | Lateral Movement | `T1550.002` | Pass the Hash | Win Security 4624 (Type 3) | `IR-003` |
| **DET-025** | SharpHound/BloodHound Execution | Discovery | `T1087`, `T1069.002` | Account & Group Discovery | Sysmon Event ID 1, 3 | `IR-004` |
| **DET-026** | AdFind Enumeration Tool Execution | Discovery | `T1087`, `T1482` | Domain Trust & Group Discovery | Sysmon Event ID 1 | `IR-004` |
| **DET-027** | Windows Network Discovery Commands | Discovery | `T1016`, `T1049` | Network & Connection Discovery | Sysmon Event ID 1 | `IR-004` |
| **DET-028** | PsExec Process Execution | Execution / Lateral Movement | `T1569.002` | Service Execution | Sysmon Event ID 1, Win 7045 | `IR-005` |
| **DET-029** | SMB Admin Share Access | Lateral Movement | `T1021.002` | SMB/Windows Admin Shares | Win Security 5140 | `IR-005` |
| **DET-030** | WinRM Execution | Lateral Movement | `T1021.006` | Windows Remote Management | Sysmon Event ID 1, 3 | `IR-005` |
| **DET-031** | WMI Execution | Execution / Lateral Movement | `T1047` | WMI Execution | Sysmon Event ID 1 | `IR-005` |
| **DET-032** | Successful RDP Logon Detection | Lateral Movement | `T1021.001` | Remote Desktop Protocol | Win Security 4624 (Logon Type 10) | `IR-005` |
| **DET-033** | New Windows Service Installed | Persistence / Execution | `T1543.003` | Windows Service | Win Security 7045 | `IR-006` |
| **DET-034** | New Scheduled Task Creation | Persistence / Execution | `T1053.005` | Scheduled Task | Win Security 4698 | `IR-006` |
| **DET-035** | GPO Modification | Privilege Escalation / Defense Evasion | `T1484.001` | Group Policy Modification | Win Security 5136 | `IR-006` |
| **DET-036** | Startup Folder Persistence | Persistence | `T1547.001` | Registry Run Keys / Startup Folder | Sysmon Event ID 11, 12, 13 | `IR-006` |
| **DET-037** | Security Event Log Cleared | Defense Evasion | `T1562.002` | Disable Windows Event Logging | Win Security 1102 | `IR-006` |
| **DET-038** | Windows Audit Policy Modification | Defense Evasion | `T1562.002` | Disable Windows Event Logging | Win Security 4719 | `IR-006` |
| **DET-039** | Windows Defender Tampering | Defense Evasion | `T1562.001` | Disable or Modify Tools | Defender 5001, 5007, 5013 | `IR-006` |
| **DET-040** | Suspicious PowerShell Execution | Execution / Defense Evasion | `T1059.001` | PowerShell | Sysmon Event ID 1, 4688 | `IR-006` |
| **DET-041** | Windows Firewall Policy Modification | Defense Evasion | `T1562.004` | Disable or Modify System Firewall | Win Security 4946, 4947, 4948 | `IR-006` |
| **DET-042** | Security-Enabled Group Deletion | Impact | `T1531` | Account Access Removal | Win Security 4730, 4734, 4758 | `IR-007` |

---

## 3. Tactic Coverage

This section categorizes custom rule density across top-level MITRE ATT&CK tactics. High coverage in Credential Access, Persistence, and Defense Evasion aligns directly with Active Directory threat models.

| MITRE ATT&CK Tactic | Mapped Detections Count | Detection IDs | Primary Focus / Objective |
| :--- | :---: | :--- | :--- |
| **Execution** | 4 | DET-028, DET-031, DET-034, DET-040 | Detection of malicious command-line interpreters (PowerShell, WMI, Service Execution). |
| **Persistence** | 8 | DET-003, DET-004, DET-007, DET-008, DET-009, DET-033, DET-034, DET-036 | Identifying long-term access via services, scheduled tasks, account manipulation, and startup paths. |
| **Privilege Escalation** | 7 | DET-011, DET-012, DET-013, DET-014, DET-015, DET-016, DET-035 | Monitoring elevated group modifications (Domain Admins) and Active Directory GPO alterations. |
| **Defense Evasion** | 8 | DET-035, DET-037, DET-038, DET-039, DET-040, DET-041 | Capturing log clearing, Defender disabling, firewall tampering, and audit policy modifications. |
| **Credential Access** | 12 | DET-001, DET-002, DET-005, DET-006, DET-017, DET-018, DET-019, DET-020, DET-021, DET-022, DET-023, DET-024 | Comprehensive coverage against Kerberos tickets, LSASS memory dumping, and DCSync attacks. |
| **Discovery** | 3 | DET-025, DET-026, DET-027 | Identifying internal AD recon tools (BloodHound, AdFind) and native discovery commands. |
| **Lateral Movement** | 6 | DET-024, DET-028, DET-029, DET-030, DET-031, DET-032 | Detection of lateral pivots via PsExec, SMB Admin Shares, WinRM, WMI, and RDP. |
| **Impact** | 2 | DET-010, DET-042 | Detecting destructive actions including deletion of accounts and security-enabled groups. |

---

## 4. Technique Coverage

The table below breaks down technical coverage per specific MITRE ATT&CK technique ID and correlates them directly with the underlying primary telemetry used by the SIEM logic.

| Technique ID | Technique Name | Mapped Detection Rule(s) | Primary Telemetry Source |
| :--- | :--- | :--- | :--- |
| `T1003.001` | OS Credential Dumping: LSASS Memory | DET-022 | Sysmon Event ID 10 |
| `T1003.003` | OS Credential Dumping: NTDS | DET-023 | Sysmon Event ID 1, Win Security 4688 |
| `T1003.006` | OS Credential Dumping: DCSync | DET-019 | Win Security 4662 |
| `T1016` | System Network Configuration Discovery | DET-027 | Sysmon Event ID 1 |
| `T1021.001` | Remote Services: Remote Desktop Protocol | DET-032 | Win Security 4624 (Logon Type 10) |
| `T1021.002` | Remote Services: SMB/Windows Admin Shares | DET-029 | Win Security 5140 |
| `T1021.006` | Remote Services: Windows Remote Management | DET-030 | Sysmon Event ID 1, 3 |
| `T1047` | Windows Management Instrumentation | DET-031 | Sysmon Event ID 1 |
| `T1049` | System Network Connections Discovery | DET-027 | Sysmon Event ID 1 |
| `T1053.005` | Scheduled Task/Job: Scheduled Task | DET-034 | Win Security 4698 |
| `T1059.001` | Command Interpreter: PowerShell | DET-040 | Sysmon Event ID 1 |
| `T1069.002` | Permission Groups Discovery: Domain Groups | DET-025 | Sysmon Event ID 1, 3 |
| `T1078` | Valid Accounts | DET-003, DET-004, DET-015 | Win Security 4624 |
| `T1087` | Account Discovery | DET-025, DET-026 | Sysmon Event ID 1 |
| `T1098` | Account Manipulation | DET-008, DET-009, DET-011, DET-012, DET-013, DET-014, DET-016 | Win Security 4722, 4724, 4728, 4732, 4756, 5136 |
| `T1110` | Brute Force (Password Guessing/Spraying) | DET-001, DET-002, DET-005, DET-006 | Win Security 4625, 4740 |
| `T1136.001` | Create Account: Local Account / Domain Account | DET-007 | Win Security 4720 |
| `T1482` | Domain Trust Discovery | DET-026 | Sysmon Event ID 1 |
| `T1484.001` | Domain Policy Modification: Group Policy | DET-035 | Win Security 5136 |
| `T1531` | Account Access Removal | DET-010, DET-042 | Win Security 4726, 4730, 4734, 4758 |
| `T1543.003` | Create/Modify System Process: Windows Service | DET-033 | Win Security 7045 |
| `T1547.001` | Boot/Logon Autostart: Registry Run / Startup | DET-036 | Sysmon Event ID 11, 12, 13 |
| `T1550.002` | Use Alternate Auth Material: Pass the Hash | DET-024 | Win Security 4624 (Logon Type 3) |
| `T1558.001` | Steal or Forge Tickets: Golden Ticket | DET-020 | Win Security 4768, 4769 |
| `T1558.002` | Steal or Forge Tickets: Silver Ticket | DET-021 | Win Security 4769 |
| `T1558.003` | Steal or Forge Tickets: Kerberoasting | DET-017 | Win Security 4769 |
| `T1558.004` | Steal or Forge Tickets: AS-REP Roasting | DET-018 | Win Security 4768 |
| `T1562.001` | Impair Defenses: Disable or Modify Tools | DET-039 | Windows Defender 5001, 5007, 5013 |
| `T1562.002` | Impair Defenses: Disable Windows Event Logging | DET-037, DET-038 | Win Security 1102, 4719 |
| `T1562.004` | Impair Defenses: Disable/Modify Firewall | DET-041 | Win Security 4946, 4947, 4948 |
| `T1569.002` | System Services: Service Execution | DET-028 | Sysmon Event ID 1, Win Security 7045 |

---

## 5. Coverage Summary

A high-level summary of rule distribution, specific detection IDs, and estimated detection visibility across the Active Directory threat landscape.

| Tactic Name | Rule Count | Detection IDs | Percentage Share | Lab Visibility Status |
| :--- | :---: | :--- | :---: | :--- |
| **Credential Access** | 12 Rules | DET-001, DET-002, DET-005, DET-006, DET-017, DET-018, DET-019, DET-020, DET-021, DET-022, DET-023, DET-024 | 28.6% | **High Coverage (100%)** |
| **Persistence** | 8 Rules | DET-003, DET-004, DET-007, DET-008, DET-009, DET-033, DET-034, DET-036 | 19.0% | **High Coverage (85%)** |
| **Defense Evasion** | 8 Rules | DET-035, DET-037, DET-038, DET-039, DET-040, DET-041 | 19.0% | **High Coverage (85%)** |
| **Privilege Escalation** | 7 Rules | DET-011, DET-012, DET-013, DET-014, DET-015, DET-016, DET-035 | 16.7% | **High Coverage (80%)** |
| **Lateral Movement** | 6 Rules | DET-024, DET-028, DET-029, DET-030, DET-031, DET-032 | 14.3% | **Medium Coverage (70%)** |
| **Execution** | 4 Rules | DET-028, DET-031, DET-034, DET-040 | 9.5% | **Medium Coverage (55%)** |
| **Discovery** | 3 Rules | DET-025, DET-026, DET-027 | 7.1% | **Medium Coverage (45%)** |
| **Impact** | 2 Rules | DET-010, DET-042 | 4.8% | **Low Coverage (30%)** |

---

## 6. Detection Coverage by Tactic

Detailed breakdown of how the rule set aligns across the 8 covered MITRE ATT&CK tactics, including specific detection ID listings:

| MITRE ATT&CK Tactic | Detection IDs | Rule Density | Key Detection Metrics & Objectives |
| :--- | :--- | :---: | :--- |
| **1. Credential Access** | DET-001, DET-002, DET-005, DET-006, DET-017, DET-018, DET-019, DET-020, DET-021, DET-022, DET-023, DET-024 | 12 Rules | Covers Kerberos ticket forgery (Golden/Silver/Roasting), LSASS memory dumping, NTDS extraction, and auth brute-forcing. |
| **2. Persistence** | DET-003, DET-004, DET-007, DET-008, DET-009, DET-033, DET-034, DET-036 | 8 Rules | Tracks unauthorized user creation, account reactivation, startup execution, services, and scheduled tasks. |
| **3. Defense Evasion** | DET-035, DET-037, DET-038, DET-039, DET-040, DET-041 | 8 Rules | Captures security log clearing, Windows Defender manipulation, firewall policy changes, and audit policy tampering. |
| **4. Privilege Escalation** | DET-011, DET-012, DET-013, DET-014, DET-015, DET-016, DET-035 | 7 Rules | Identifies group membership escalation (Domain/Enterprise Admins), privileged logons, and GPO modifications. |
| **5. Lateral Movement** | DET-024, DET-028, DET-029, DET-030, DET-031, DET-032 | 6 Rules | Detects remote execution via PsExec, SMB Admin Share pivots, WinRM, WMI session creation, and RDP. |
| **6. Execution** | DET-028, DET-031, DET-034, DET-040 | 4 Rules | Monitors malicious command execution using PowerShell, WMI, Scheduled Tasks, and custom Windows Services. |
| **7. Discovery** | DET-025, DET-026, DET-027 | 3 Rules | Triggers on internal AD enumeration binaries (`BloodHound`/`SharpHound`, `AdFind`) and network recon commands. |
| **8. Impact** | DET-010, DET-042 | 2 Rules | Flags destructive modifications including deletion of Active Directory accounts and security-enabled groups. |

---

## 7. Detection Coverage by Technique

| MITRE ATT&CK Technique | Detection Coverage |
| :--- | :--- |
| **T1110 – Brute Force** | DET-001, DET-002, DET-004, DET-005, DET-006 |
| **T1078 – Valid Accounts** | DET-003, DET-004, DET-015 |
| **T1136 – Create Account** | DET-007 |
| **T1098 – Account Manipulation** | DET-008, DET-009, DET-011, DET-012, DET-013, DET-014, DET-016 |
| **T1531 – Account Access Removal** | DET-010, DET-042 |
| **T1558.001 – Golden Ticket** | DET-020 |
| **T1558.002 – Silver Ticket** | DET-021 |
| **T1558.003 – Kerberoasting** | DET-017 |
| **T1558.004 – AS-REP Roasting** | DET-018 |
| **T1003.001 – LSASS Memory** | DET-022 |
| **T1003.003 – NTDS** | DET-023 |
| **T1003.006 – DCSync** | DET-019 |
| **T1550.002 – Pass the Hash** | DET-024 |
| **T1087 – Account Discovery** | DET-025, DET-026 |
| **T1069.002 – Permission Groups Discovery: Domain Groups** | DET-025, DET-026 |
| **T1482 – Domain Trust Discovery** | DET-025, DET-026 |
| **T1016 – System Network Configuration Discovery** | DET-027 |
| **T1049 – System Network Connections Discovery** | DET-027 |
| **T1021.001 – Remote Desktop Protocol** | DET-032 |
| **T1021.002 – SMB/Windows Admin Shares** | DET-029 |
| **T1021.006 – Windows Remote Management** | DET-030 |
| **T1047 – Windows Management Instrumentation** | DET-031 |
| **T1569.002 – Service Execution** | DET-028 |
| **T1543.003 – Windows Service** | DET-033 |
| **T1053.005 – Scheduled Task/Job: Scheduled Task** | DET-034 |
| **T1484.001 – Domain Policy Modification: Group Policy Modification** | DET-035 |
| **T1547.001 – Boot or Logon Autostart Execution: Registry Run Keys / Startup Folder** | DET-036 |
| **T1070.001 – Clear Windows Event Logs** | DET-037 |
| **T1562.002 – Disable or Modify Windows Event Logging** | DET-038 |
| **T1562.001 – Impair Defenses: Disable or Modify Tools** | DET-039 |
| **T1059.001 – PowerShell** | DET-040 |
| **T1562.004 – Impair Defenses: Disable or Modify System Firewall** | DET-041 |

---

## 8. ATT&CK Coverage Notes

Some techniques in the project's stated coverage are behaviorally related to a detection but are not necessarily represented by a unique one-to-one rule.

For example, SharpHound and AdFind can provide telemetry for several discovery objectives, while PsExec can be represented through service execution and SMB/admin-share activity.

The project also lists T1070.004 in its broader ATT&CK coverage. The specific DET-037 rule, however, detects Windows Security Event Log clearing, which is mapped to T1070.001 – Clear Windows Event Logs in this detection catalogue. Keeping this distinction explicit avoids overstating the behavior represented by the rule.

---

## 9. Coverage Philosophy

The MITRE mapping is intended to answer three SOC questions:

1. What attacker behavior is detected?
2. What telemetry produces the detection?
3. Which ATT&CK technique does the behavior represent?

The individual detection documents remain the authoritative source for rule logic, telemetry requirements, investigation guidance, validation, and response actions.

This document provides the higher-level ATT&CK view of the detection engineering work and connects the individual Wazuh rules to a common adversary-behavior framework.