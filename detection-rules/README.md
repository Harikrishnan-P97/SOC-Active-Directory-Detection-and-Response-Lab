# Wazuh Detection Rules

This directory contains the custom **Wazuh XML detection rules** developed for the **SOC Active Directory Detection Lab**.

The rules are designed to detect suspicious authentication activity, Active Directory changes, credential-access techniques, discovery, lateral movement, persistence, defense evasion, and impact activity across the Windows lab environment.

---

## Overview

The project contains **42 custom detection rules**, identified as:

```text
100100 – 100141
```

These rules are deployed to the Wazuh Manager and consume telemetry collected from the Windows endpoints:

```text
DC01      → Wazuh Agent ─┐
                         │
CLIENT01  → Wazuh Agent ─┼→ Wazuh Manager → Custom Rules → Alerts
                         │
Sysmon    → Windows      ┘
```

The detection rules are supported by Windows Security Event Logs and Sysmon telemetry.

---

## Detection Categories

The 42 rules are organized into eight detection-engineering categories.

| Category | Detection IDs | Focus |
|---|---|---|
| Authentication | DET-001 – DET-006 | Authentication failures, successful logons, brute force and account lockouts |
| Account Management | DET-007 – DET-010 | Account creation, password resets, account enablement and deletion |
| Privilege Escalation | DET-011 – DET-016 | Privileged-group changes, administrator activity and AD attribute modification |
| Credential Access & Kerberos | DET-017 – DET-024 | Kerberoasting, AS-REP roasting, DCSync, ticket attacks, LSASS/NTDS dumping and Pass-the-Hash |
| Discovery & Reconnaissance | DET-025 – DET-027 | BloodHound/SharpHound, AdFind and network discovery |
| Lateral Movement & Remote Execution | DET-028 – DET-032 | PsExec, SMB admin shares, WinRM, WMI and RDP |
| Persistence & Defense Evasion | DET-033 – DET-041 | Services, scheduled tasks, GPO, startup persistence, log clearing, audit policy, Defender, PowerShell and firewall changes |
| Impact | DET-042 | Security-enabled group deletion |

---

## Telemetry Sources

The rules primarily analyze Windows endpoint telemetry collected by Wazuh agents.

### Windows Security Event Logs

Key event IDs used by the detection rules include:

| Event ID | Telemetry |
|---:|---|
| 4624 | Successful logon |
| 4625 | Failed logon |
| 4662 | Directory/object access |
| 4688 | Process creation |
| 4698 | Scheduled task creation |
| 4719 | Audit policy modification |
| 4720 | User account creation |
| 4722 | User account enabled |
| 4724 | Password reset |
| 4726 | User account deletion |
| 4728 | Global group membership change |
| 4730 | Global group deletion |
| 4732 | Local group membership change |
| 4734 | Local group deletion |
| 4740 | Account lockout |
| 4756 | Universal group membership change |
| 4758 | Universal group deletion |
| 4768 | Kerberos TGT request |
| 4769 | Kerberos service-ticket request |
| 5136 | Directory service object modification |
| 5140 | Network share access |
| 7045 | Windows service installation |
| 1102 | Security audit log cleared |
| 4946 | Windows Firewall exception change |
| 4947 | Windows Firewall rule change |
| 4948 | Windows Firewall rule deletion |
| 5001 | Defender real-time protection disabled |
| 5007 | Defender configuration changed |
| 5013 | Defender feature disabled |

### Sysmon

The project uses **Olaf Hartong's Sysmon-Modular** with custom settings.

Relevant Sysmon telemetry includes:

| Sysmon ID | Telemetry |
|---:|---|
| 1 | Process creation |
| 3 | Network connection |
| 5 | Process termination |
| 7 | Image/DLL loaded |
| 8 | CreateRemoteThread |
| 10 | Process access |
| 12 | Registry object create/delete |
| 13 | Registry value set |
| 14 | Registry key/value rename |
| 15 | FileCreateStreamHash / alternate data streams |

Sysmon telemetry provides additional endpoint context for process execution, network activity, registry modification, process access and other behaviors that may not be sufficiently visible through Windows Security logs alone.

---

## Rule Naming and Organization

Each detection has a human-readable identifier:

```text
DET-001
DET-002
...
DET-042
```

The corresponding Wazuh rules use the custom rule ID range:

```text
100100 – 100141
```

This provides a clear separation between the project's custom rules and Wazuh's built-in rule set.

Example conceptual mapping:

```text
DET-017
Kerberoasting Detection
        │
        ├── Windows Event ID: 4769
        ├── MITRE ATT&CK: T1558.003
        ├── Wazuh Rule: 100116
        └── IR Playbook: IR-003
```

The exact mappings for all detections are documented separately in the project documentation.

---

## Detection Pipeline

The rules operate as part of the following SOC telemetry and detection pipeline:

```text
┌──────────────┐
│ Windows Host │
│ DC01/CLIENT01│
└──────┬───────┘
       │
       ├── Windows Security Events
       └── Sysmon Events
              │
              ▼
       ┌──────────────┐
       │ Wazuh Agent  │
       └──────┬───────┘
              │
              ▼
       ┌──────────────┐
       │ Wazuh Manager│
       └──────┬───────┘
              │
              ├── Decoding
              ├── Rule matching
              └── Correlation
                     │
                     ▼
              ┌────────────┐
              │   Alert    │
              └─────┬──────┘
                    │
          ┌─────────┴─────────┐
          ▼                   ▼
     Dashboards          SOC Analyst
                              │
                              ▼
                       Investigation
                              │
                              ▼
                        IR Playbook
```

---

## MITRE ATT&CK Integration

The custom detections are mapped to relevant **MITRE ATT&CK Enterprise techniques**.

Coverage includes techniques across:

- Initial Access
- Persistence
- Credential Access
- Discovery
- Lateral Movement
- Execution
- Privilege Escalation
- Defense Evasion
- Impact

Examples include:

| Detection | MITRE ATT&CK |
|---|---|
| DET-002 | T1110 – Brute Force |
| DET-011 | T1098 – Account Manipulation |
| DET-017 | T1558.003 – Kerberoasting |
| DET-018 | T1558.004 – AS-REP Roasting |
| DET-019 | T1003.006 – DCSync |
| DET-022 | T1003.001 – LSASS Memory |
| DET-024 | T1550.002 – Pass the Hash |
| DET-025 | T1087 / AD discovery activity |
| DET-028 | T1569.002 – Service Execution |
| DET-030 | T1021.006 – Windows Remote Management |
| DET-032 | T1021.001 – Remote Desktop Protocol |
| DET-034 | T1053.005 – Scheduled Task/Job |
| DET-035 | T1484.001 – Group Policy Modification |
| DET-037 | T1070.001 – Clear Windows Event Logs |
| DET-039 | T1562.001 – Impair Defenses |
| DET-040 | T1059.001 – PowerShell |
| DET-041 | T1562.004 – Impair System Firewall |
| DET-042 | T1531 – Account Access Removal |

See:

`docs/mappings/detection-to-mitre-id.md`

for the complete detection-to-technique mapping.

---

## Detection-to-Telemetry Mapping

The project maintains a mapping between detection logic and the telemetry required to identify the behavior.

```text
Attack Behavior
      │
      ▼
Windows / Sysmon Event
      │
      ▼
Wazuh Decoder
      │
      ▼
Custom Detection Rule
      │
      ▼
MITRE ATT&CK Technique
      │
      ▼
SOC Alert
```

See:

`docs/mappings/detection-to-event-id.md`

for the complete telemetry mapping.

---

## Detection-to-Response Mapping

Detections are also associated with the project's seven incident-response playbooks.

```text
Detection
    │
    ▼
Alert
    │
    ▼
Investigation
    │
    ▼
IR Playbook
    │
    ├── Credential compromise
    ├── AD privilege compromise
    ├── Kerberos credential theft
    ├── AD reconnaissance
    ├── Lateral movement
    ├── Persistence / defense evasion
    └── Destructive / impact activity
```

See:

`docs/mappings/detection-to-playbook.md`

for the complete mapping.

---

## Validation

The detection rules are validated by generating representative attack and administrative behaviors within the isolated home-lab environment.

Validation focuses on:

1. Generating the target behavior.
2. Confirming the expected Windows/Sysmon telemetry.
3. Confirming Wazuh ingestion.
4. Verifying the custom rule triggers.
5. Reviewing the resulting alert.
6. Confirming relevant MITRE ATT&CK mapping.
7. Testing investigation and response workflow.
8. Tuning the rule where necessary to reduce false positives.

Validation evidence is maintained separately under:

```text
validation/
screenshots/validation/
```

---

## Related Project Documentation

| Documentation | Description |
|---|---|
| `docs/detection-engineering.md` | Detection engineering methodology and rule development |
| `docs/architecture.md` | Lab and SOC monitoring architecture |
| `docs/attack-simulations.md` | Attack simulation methodology |
| `docs/mitre-attack.md` | MITRE ATT&CK coverage |
| `docs/validation.md` | Detection validation methodology and results |
| `docs/incident-response.md` | Incident-response methodology |
| `docs/mappings/detection-to-mitre-id.md` | Detection → MITRE mapping |
| `docs/mappings/detection-to-event-id.md` | Detection → telemetry mapping |
| `docs/mappings/detection-to-playbook.md` | Detection → IR mapping |
| `docs/mappings/detection-coverage-matrix.md` | Master detection coverage matrix |

---

## Repository Contents

```text
detection-rules/
│
├── Wazuh-Rules.xml
└── README.md
```

`Wazuh-Rules.xml` contains the project's custom Wazuh XML rule definitions.

> **Note:** This repository documents an isolated home-lab detection environment. Attack simulations are intended for controlled testing and validation of defensive monitoring capabilities.
