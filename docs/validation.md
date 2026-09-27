# Detection Validation

## Overview

This document records the validation methodology and results for the **42 custom Wazuh detections** developed for the SOC Active Directory Detection & Incident Response Lab.

All `DET-001` through `DET-042` detections were tested using controlled attacker-like activity in the isolated lab environment and recorded as **VALIDATED**.

The validation process verifies the complete detection pipeline:

```text
Controlled Attack Activity
        ↓
Windows / Sysmon Telemetry
        ↓
Wazuh Collection
        ↓
Event Classification / Parent Rule
        ↓
Custom Detection Rule
        ↓
Wazuh Alert
        ↓
Alert Verification
        ↓
Detection Status: VALIDATED
```

---

## Validation Methodology

The detection validation process followed a repeatable workflow:

1. Select the detection being tested.
2. Identify the associated MITRE ATT&CK technique.
3. Generate controlled attacker-like activity.
4. Verify the resulting Windows or Sysmon telemetry.
5. Confirm Wazuh ingestion and event classification.
6. Verify that the expected custom detection rule triggered.
7. Confirm the resulting Wazuh alert.
8. Clean up temporary test artifacts where applicable.
9. Record the detection as validated.

### Validation Principles

- Testing was performed inside the isolated SOC Active Directory Detection Lab.
- Activity was generated from `KALI`, `CLIENT01`, or `DC01` depending on the technique.
- Windows Security logs and Sysmon telemetry were used where applicable.
- Raw telemetry and generated Wazuh alerts were both verified.
- Temporary accounts, memberships, tasks, services, firewall rules, files, policy changes, and other artifacts were cleaned up where applicable.
- Validation was based on observable telemetry and the corresponding Wazuh detection alert rather than simply executing a test command.

---

## Validation Data Sources

The validation process used both raw telemetry and generated alerts.

### Wazuh Archives

```text
wazuh-archives-4.x-*
```

Used to inspect underlying Windows and Sysmon telemetry, including events that did not necessarily generate a custom alert.

### Wazuh Alerts

```text
wazuh-alerts-4.x-*
```

Used to verify that the expected custom detection rule generated an alert.

This two-stage verification helped distinguish between:

```text
Telemetry Generated
        ↓
Telemetry Ingested
        ↓
Detection Logic Matched
        ↓
Alert Generated
```

---

## Detection Validation Results

All 42 custom detections were tested and validated.

| ID | Detection | Validation Source | Primary Signal | MITRE ATT&CK | Status |
|---|---|---|---|---|---|
| DET-001 | Windows Failed Authentication | CLIENT01 | Windows authentication | T1110 | VALIDATED |
| DET-002 | Windows Brute Force Detection | CLIENT01 | Authentication failures | T1110 | VALIDATED |
| DET-003 | Windows Successful Interactive Authentication | CLIENT01 | Event 4624 | T1078 | VALIDATED |
| DET-004 | Successful Login After Failed Attempts | CLIENT01 | Authentication correlation | T1110, T1078 | VALIDATED |
| DET-005 | User Account Locked | CLIENT01 | Account lockout | T1110 | VALIDATED |
| DET-006 | Multiple Authentication Failures Same Source | CLIENT01 | Authentication correlation | T1110 | VALIDATED |
| DET-007 | New User Account Created | DC01 | Event 4720 | T1136 | VALIDATED |
| DET-008 | Password Reset | DC01 | Event 4724 | T1098 | VALIDATED |
| DET-009 | User Account Enabled | DC01 | Event 4722 | T1098 | VALIDATED |
| DET-010 | Windows User Account Deleted | DC01 | Event 4726 | T1531 | VALIDATED |
| DET-011 | User Added to Domain Admins | DC01 | Event 4728 | T1098 | VALIDATED |
| DET-012 | User Added to Enterprise Admins | DC01 | Event 4756 | T1098 | VALIDATED |
| DET-013 | User Added to Local Administrators | DC01 | Event 4732 | T1098 | VALIDATED |
| DET-014 | Administrator Account Enabled | DC01 | Event 4722 | T1098 | VALIDATED |
| DET-015 | Privileged Account Logon | DC01 | Event 4624 | T1078 | VALIDATED |
| DET-016 | AD Account/Computer Attribute Modification | DC01 | Event 5136 | T1098 | VALIDATED |
| DET-017 | Kerberoasting | KALI | Event 4769 | T1558.003 | VALIDATED |
| DET-018 | AS-REP Roasting | KALI | Event 4768 | T1558.004 | VALIDATED |
| DET-019 | DCSync | KALI | Event 4662 | T1003.006 | VALIDATED |
| DET-020 | Golden Ticket | KALI | Kerberos ticket activity | T1558.001 | VALIDATED |
| DET-021 | Silver Ticket | KALI | Kerberos / Event 4624 | T1558.002 | VALIDATED |
| DET-022 | LSASS Credential Dumping | CLIENT01 | Sysmon process access | T1003.001 | VALIDATED |
| DET-023 | NTDS Credential Dumping via IFM | DC01 | Process / command telemetry | T1003.003 | VALIDATED |
| DET-024 | Pass-the-Hash | KALI | NTLM network logon | T1550.002 | VALIDATED |
| DET-025 | SharpHound Execution | CLIENT01 | Process creation | T1087, T1069.002, T1482 | VALIDATED |
| DET-026 | AdFind Enumeration Tool Execution | CLIENT01 | Process creation | T1087, T1069.002, T1482 | VALIDATED |
| DET-027 | Windows Network Discovery Commands | CLIENT01 | Sysmon process creation | T1016, T1049 | VALIDATED |
| DET-028 | PsExec Process Execution | CLIENT01 | Sysmon process creation | T1021.002, T1569.002 | VALIDATED |
| DET-029 | SMB Admin Share Access | CLIENT01 | SMB share access | T1021.002 | VALIDATED |
| DET-030 | WinRM Execution | KALI / CLIENT01 | `wsmprovhost.exe` | T1021.006 | VALIDATED |
| DET-031 | WMI Execution | KALI / CLIENT01 | WMI execution | T1047 | VALIDATED |
| DET-032 | Successful RDP Logon | KALI | Event 4624 / Logon Type 10 | T1021.001 | VALIDATED |
| DET-033 | New Windows Service Installed | Windows host | Service installation | T1543.003 | VALIDATED |
| DET-034 | New Scheduled Task Creation | CLIENT01 | Scheduled task creation | T1053.005 | VALIDATED |
| DET-035 | Group Policy Modification | DC01 | AD/GPO modification | T1484.001 | VALIDATED |
| DET-036 | Startup Folder Persistence | CLIENT01 | Sysmon file creation | T1547.001 | VALIDATED |
| DET-037 | Security Event Log Cleared | CLIENT01 | Security log clear | T1070.001 | VALIDATED |
| DET-038 | Windows Audit Policy Modification | CLIENT01 | Audit policy change | T1562.002 | VALIDATED |
| DET-039 | Windows Defender Tampering | CLIENT01 | Defender events | T1562.001 | VALIDATED |
| DET-040 | Suspicious PowerShell Execution | CLIENT01 | Sysmon PowerShell telemetry | T1059.001 | VALIDATED |
| DET-041 | Windows Firewall Policy Modification | CLIENT01 | Events 4946/4947/4948 | T1562.004 | VALIDATED |
| DET-042 | Windows Security-Enabled Group Deletion | DC01 | Events 4730/4734/4758 | T1531 | VALIDATED |

---

## Coverage Summary

| Detection Category | Detections | Status |
|---|---:|---|
| Authentication | 6 | 6/6 VALIDATED |
| Account Management / Privilege | 10 | 10/10 VALIDATED |
| Credential Access | 8 | 8/8 VALIDATED |
| Discovery / Reconnaissance | 3 | 3/3 VALIDATED |
| Lateral Movement / Remote Execution | 5 | 5/5 VALIDATED |
| Persistence / Defense Evasion | 9 | 9/9 VALIDATED |
| Impact | 1 | 1/1 VALIDATED |
| **Total** | **42** | **42/42 VALIDATED** |

### Validation Status

**42 / 42 detections validated — 100% validation completion.**

Validation status means that the corresponding controlled activity produced observable telemetry and the expected custom Wazuh detection was verified during the testing process.

---

## Example Validated Alerts

The project used multiple detection types to verify the complete telemetry-to-alert pipeline.

### Example: Failed Authentication — DET-001

A controlled failed interactive login from `CLIENT01` generated Windows authentication telemetry. Wazuh classified the event and the custom failed-authentication detection generated the expected alert.

```text
Failed Interactive Login
        ↓
Windows Authentication Event
        ↓
Wazuh Authentication Classification
        ↓
DET-001
        ↓
Wazuh Alert
```

**Status:** VALIDATED

### Example: DCSync — DET-019

A controlled directory replication request generated from `KALI` was used to test the DCSync detection.

```text
DCSync Simulation
        ↓
Windows Event 4662
        ↓
Wazuh Ingestion
        ↓
Directory Replication Detection
        ↓
DET-019
        ↓
Wazuh Alert
```

**MITRE ATT&CK:** T1003.006 — DCSync  
**Status:** VALIDATED

### Example: SharpHound — DET-025

SharpHound execution from `CLIENT01` generated Windows process telemetry used to validate the Active Directory discovery detection.

```text
SharpHound Execution
        ↓
Sysmon Process Creation
        ↓
Wazuh Ingestion
        ↓
Custom Detection Logic
        ↓
DET-025
        ↓
Wazuh Alert
```

**MITRE ATT&CK:** T1087, T1069.002, T1482  
**Status:** VALIDATED

### Example: SMB Administrative Share — DET-029

Administrative SMB share access was used to validate detection of lateral movement through Windows administrative shares.

```text
ADMIN$ / C$ Access
        ↓
Windows SMB Telemetry
        ↓
Wazuh Ingestion
        ↓
DET-029
        ↓
Wazuh Alert
```

**MITRE ATT&CK:** T1021.002 — SMB/Windows Admin Shares  
**Status:** VALIDATED

### Example: Firewall Modification — DET-041

A controlled Windows Firewall rule was created, modified, and removed using a dedicated test artifact.

Relevant Windows telemetry included:

- `4946` — Firewall rule added
- `4947` — Firewall rule modified
- `4948` — Firewall rule deleted

**MITRE ATT&CK:** T1562.004 — Impair Defenses: Disable or Modify System Firewall  
**Status:** VALIDATED

---

## Lessons from Tuning

Validation was not limited to confirming that a rule could generate an alert. Testing also exposed practical detection-engineering considerations.

### 1. Validate the Complete Rule Chain

Custom Wazuh rules may depend on built-in parent rules. Therefore, testing must verify:

```text
Windows / Sysmon Event
        ↓
Decoder
        ↓
Parent Rule
        ↓
Custom Rule
        ↓
Alert
```

A correct custom rule cannot trigger if the underlying event does not match the expected parent rule.

### 2. Validate the Actual Decoded Fields

Detection logic was tested against the fields actually produced by Windows and Sysmon telemetry rather than relying only on assumptions about event structure.

This was particularly important for:

- Windows authentication events
- Active Directory events
- Sysmon process creation
- Sysmon file creation
- Sysmon process access
- Firewall events

### 3. Verify Raw Telemetry Before Troubleshooting the Detection

When a custom alert was not immediately visible, raw telemetry in:

```text
wazuh-archives-4.x-*
```

was inspected before modifying the detection logic.

This helped determine whether the problem was:

- Test activity not generating the expected event
- Windows auditing configuration
- Sysmon telemetry
- Event decoding
- Parent-rule matching
- Custom-rule matching
- Alert generation

### 4. Windows Auditing Must Match the Detection Requirement

Some detections depend on Windows audit categories being enabled.

Scheduled-task validation, for example, required the appropriate Windows auditing configuration before Event ID `4698` could be observed consistently.

This reinforced the principle that **detection logic and telemetry configuration must be validated together**.

### 5. Sysmon Event Chains Matter

Startup persistence validation demonstrated that similar-looking Sysmon Event ID 11 activity can be classified by different built-in rule paths depending on the image and file extension.

The investigation of the underlying `92201` / `92204` rule chain was therefore necessary before validating the custom startup-persistence detection.

### 6. Separate Telemetry Validation from Alert Validation

An event appearing in `wazuh-archives-*` does not automatically mean the custom detection is working.

The validation process therefore treated these as separate checkpoints:

```text
Telemetry Exists
        ≠
Detection Triggered
```

Both had to be verified for a detection to be considered validated.

### 7. Test Cleanup Is Part of Detection Validation

Temporary artifacts were removed after testing where applicable, including:

- User accounts
- Group memberships
- AD groups
- Scheduled tasks
- Services
- Startup-folder files
- Audit-policy changes
- Defender configuration changes
- Firewall rules
- Kerberos ticket caches

This kept the lab in a controlled state while allowing repeated validation.

---

## Detection Validation Status

The final validation status for the project is:

| Metric | Result |
|---|---:|
| Total custom detections | **42** |
| Detections tested | **42** |
| Detections validated | **42** |
| Validation completion | **100%** |
| Validation status | **VALIDATED** |

All `DET-001` through `DET-042` detections were recorded as validated during the detection-engineering testing process.

---

## Validation Workflow

The complete validation workflow is:

```text
                Detection Selected
                       ↓
              ATT&CK Technique
                       ↓
             Controlled Simulation
                       ↓
          Windows / Sysmon Telemetry
                       ↓
                Wazuh Collection
                       ↓
             Event Classification
                       ↓
                Parent Rule
                       ↓
              Custom Detection
                       ↓
                 Wazuh Alert
                       ↓
               Alert Verification
                       ↓
               Detection Validated
                       ↓
                 Cleanup / Reset
                       ↓
                Document Result
```

This workflow connects controlled attacker activity to observable telemetry, custom detection logic, alert generation, and documented validation.

---

## Related Documentation

- [`attack-simulations.md`](attack-simulations.md) — Controlled attack simulations used to validate the detection set.
- [Detection Rules Documentation](detections/) — Individual detection logic, telemetry requirements, validation evidence, investigation guidance, and response playbooks.
- [`mitre-attack.md`](mitre-attack.md) — MITRE ATT&CK mapping and coverage.
- [`incident-response.md`](incident-response.md) — Incident response methodology and detection-to-response workflow.
- [Incident Response Playbooks](../incident-response/) — Detailed response procedures for the seven incident scenarios.
