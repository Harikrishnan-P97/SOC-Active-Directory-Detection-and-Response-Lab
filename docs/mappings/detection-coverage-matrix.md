# Detection Coverage Matrix

## Project Overview

**SOC Active Directory Detection Lab**

| Component | Coverage |
|---|---|
| Wazuh custom detections | **42** |
| Wazuh rule range | **100100–100141** |
| Windows Security / System / Defender telemetry | Yes |
| Sysmon | Olaf Hartong's Sysmon-Modular + custom settings |
| Monitored endpoints | DC01 + CLIENT01 |
| SOC dashboards | **7** |
| IR playbooks | **7** |
| Primary attack source | KALI |

## Master Detection Coverage

| ID | Detection | Event / Sysmon | MITRE ATT&CK | IR |
|---|---|---|---|---|
| DET-001 | Failed Authentication | 4625 | T1110 | IR-001 |
| DET-002 | Brute Force | 4625 | T1110 | IR-001 |
| DET-003 | Successful Interactive Authentication | 4624 | T1078 | IR-001 / IR-002 |
| DET-004 | Successful Login After Failed Attempts | 4625 + 4624 | T1110, T1078 | IR-001 |
| DET-005 | Account Locked | 4740 | T1110 | IR-001 / IR-002 |
| DET-006 | Multiple Authentication Failures | 4625 | T1110 | IR-001 |
| DET-007 | New User Account Created | 4720 | T1136 | IR-002 |
| DET-008 | Password Reset | 4724 | T1098 | IR-002 / IR-001 |
| DET-009 | User Account Enabled | 4722 | T1098 | IR-002 |
| DET-010 | User Account Deleted | 4726 | T1531 | IR-007 / IR-002 |
| DET-011 | Added to Domain Admins | 4728 | T1098 | IR-002 |
| DET-012 | Added to Enterprise Admins | 4756 | T1098 | IR-002 |
| DET-013 | Added to Local Administrators | 4732 | T1098 | IR-002 |
| DET-014 | Administrator Account Enabled | 4722 | T1098 | IR-002 |
| DET-015 | Privileged Account Logon | 4624 | T1078 | IR-002 / IR-001 |
| DET-016 | AD Attribute Modification | 5136 / 4662 | T1098 | IR-002 / IR-006 |
| DET-017 | Kerberoasting | 4769 | T1558.003 | IR-003 |
| DET-018 | AS-REP Roasting | 4768 | T1558.004 | IR-003 |
| DET-019 | DCSync | 4662 | T1003.006 | IR-003 / IR-002 |
| DET-020 | Golden Ticket | 4768 / 4624 | T1558.001 | IR-003 / IR-002 |
| DET-021 | Silver Ticket | 4769 / 4624 | T1558.002 | IR-003 / IR-005 |
| DET-022 | LSASS Dumping | 4688 + Sysmon 10 | T1003.001 | IR-003 / IR-002 |
| DET-023 | NTDS Dumping | 4688 + Sysmon 1 | T1003.003 | IR-003 / IR-002 |
| DET-024 | Pass the Hash | 4624 | T1550.002 | IR-003 / IR-005 |
| DET-025 | SharpHound | 4688 + Sysmon 1/3 | T1087, T1069.002, T1482 | IR-004 |
| DET-026 | AdFind | 4688 + Sysmon 1/3 | T1087, T1069.002, T1482 | IR-004 |
| DET-027 | Network Discovery | 4688 + Sysmon 1/3 | T1016, T1049 | IR-004 / IR-005 |
| DET-028 | PsExec | 4688 + 7045 + Sysmon 1 | T1569.002 | IR-005 |
| DET-029 | SMB Admin Share | 5140 | T1021.002 | IR-005 |
| DET-030 | WinRM | 4688 + Sysmon 1/3 | T1021.006 | IR-005 |
| DET-031 | WMI | 4688 + Sysmon 1/3 | T1047 | IR-005 |
| DET-032 | RDP Logon | 4624 | T1021.001 | IR-005 |
| DET-033 | Windows Service | 7045 | T1543.003 | IR-006 |
| DET-034 | Scheduled Task | 4698 | T1053.005 | IR-006 |
| DET-035 | Group Policy Modification | 5136 / 4662 | T1484.001 | IR-006 / IR-002 |
| DET-036 | Startup Folder Persistence | 4688 + Sysmon 12/13/14 | T1547.001 | IR-006 |
| DET-037 | Security Event Log Cleared | 1102 | T1070.001 | IR-006 |
| DET-038 | Audit Policy Modification | 4719 | T1562.002 | IR-006 |
| DET-039 | Defender Tampering | 5001 / 5007 / 5013 | T1562.001 | IR-006 |
| DET-040 | Suspicious PowerShell | 4688 + Sysmon 1 | T1059.001 | IR-006 |
| DET-041 | Firewall Rule Changed | 4946 / 4947 / 4948 | T1562.004 | IR-006 |
| DET-042 | Security Group Deletion | 4730 / 4734 / 4758 | T1531 | IR-007 / IR-002 |

## Coverage by Detection Category

| Category | Detections | Count |
|---|---|---:|
| Authentication | DET-001 – DET-006 | **6** |
| Account Management | DET-007 – DET-010 | **4** |
| Privilege Escalation | DET-011 – DET-016 | **6** |
| Credential Access & Kerberos | DET-017 – DET-024 | **8** |
| Discovery & Reconnaissance | DET-025 – DET-027 | **3** |
| Lateral Movement & Remote Execution | DET-028 – DET-032 | **5** |
| Persistence & Defense Evasion | DET-033 – DET-041 | **9** |
| Impact | DET-042 | **1** |
| **Total** | | **42** |

## MITRE Technique Coverage

| MITRE ID | Technique | Detection(s) |
|---|---|---|
| T1078 | Valid Accounts | DET-003, DET-004, DET-015 |
| T1136 | Create Account | DET-007 |
| T1098 | Account Manipulation | DET-008–016 |
| T1547.001 | Registry Run Keys / Startup Folder | DET-036 |
| T1543.003 | Windows Service | DET-033 |
| T1053.005 | Scheduled Task | DET-034 |
| T1562.001 | Impair Defenses: Tools | DET-039 |
| T1562.002 | Disable/Modify Windows Event Logging | DET-038 |
| T1562.004 | Disable/Modify System Firewall | DET-041 |
| T1070.001 | Clear Windows Event Logs | DET-037 |
| T1070.004 | File and Directory Deletion | Supporting coverage / broader lab scope |
| T1110 | Brute Force | DET-001, DET-002, DET-004–006 |
| T1558.003 | Kerberoasting | DET-017 |
| T1558.004 | AS-REP Roasting | DET-018 |
| T1003.001 | LSASS Memory | DET-022 |
| T1003.003 | NTDS | DET-023 |
| T1003.006 | DCSync | DET-019 |
| T1558.001 | Golden Ticket | DET-020 |
| T1558.002 | Silver Ticket | DET-021 |
| T1087 | Account Discovery | DET-025, DET-026 |
| T1069.002 | Domain Groups Discovery | DET-025, DET-026 |
| T1482 | Domain Trust Discovery | DET-025, DET-026 |
| T1016 | System Network Configuration Discovery | DET-027 |
| T1049 | System Network Connections Discovery | DET-027 |
| T1550.002 | Pass the Hash | DET-024 |
| T1021.001 | RDP | DET-032 |
| T1021.002 | SMB/Admin Shares | DET-029 |
| T1021.006 | WinRM | DET-030 |
| T1047 | WMI | DET-031 |
| T1569.002 | Service Execution | DET-028 |
| T1059.001 | PowerShell | DET-040 |
| T1484.001 | Group Policy Modification | DET-035 |
| T1531 | Account Access Removal | DET-010, DET-042 |

## Detection Engineering Chain

```text
ATTACK BEHAVIOR
      │
      ▼
WINDOWS / SYSMON TELEMETRY
      │
      ▼
WAZUH AGENT
      │
      ▼
WAZUH MANAGER
      │
      ▼
CUSTOM RULES
100100 ─────────── 100141
      │
      ▼
WAZUH ALERT
      │
      ├──────────────► MITRE ATT&CK
      │
      ├──────────────► SOC DASHBOARD
      │
      └──────────────► IR PLAYBOOK
                              │
                              ▼
                    INVESTIGATION / RESPONSE
```

## Important Mapping Caveat

MITRE ATT&CK coverage should represent what the lab can **actually observe and detect**, not merely every technique an attack tool could perform.

In particular, `T1070.004` should only be marked as validated coverage when the lab has a detection specifically demonstrating **File and Directory Deletion**. The existing `DET-037` event-log-clearing detection is more accurately represented by `T1070.001 – Clear Windows Event Logs`.

This distinction keeps the coverage matrix defensible during technical review.
