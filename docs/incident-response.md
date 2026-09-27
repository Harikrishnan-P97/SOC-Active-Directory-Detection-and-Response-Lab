# Incident Response

## Overview

This document defines the incident response methodology for the **SOC Active Directory Detection & Incident Response Lab**.

The lab uses Wazuh custom detections to identify Windows and Active Directory attack behaviors. The individual detection documents provide rule-level technical detail, while the seven incident response playbooks group related detections into broader incident scenarios and provide an operational workflow for investigation, containment, eradication, recovery, validation, and closure.

The overall incident response workflow is:

```text
Attack Simulation
       ↓
Windows / Sysmon Telemetry
       ↓
Wazuh Detection
       ↓
Dashboard Visibility
       ↓
Incident Triage
       ↓
Investigation & Correlation
       ↓
Containment
       ↓
Eradication
       ↓
Recovery
       ↓
Validation & Closure
```

> **Scope:** This methodology is designed for the isolated SOC Active Directory lab environment and its Windows/Active Directory attack simulations.

---

## Incident Response Methodology

The incident response process is organized around seven operational stages.

### 1. Detection

A Wazuh detection identifies potentially suspicious activity from Windows Security, Sysmon, PowerShell, Active Directory, Defender, or related telemetry.

The analyst should establish:

- Detection ID and Wazuh rule ID
- Event ID and telemetry source
- Alert timestamp
- Affected host
- Affected account or identity
- Source IP or source host where available
- Initial attack behavior
- Related alerts in the surrounding time window

A detection is treated as an **indicator requiring investigation**, not automatic proof of compromise.

### 2. Investigation

The analyst investigates the initial alert and correlates related activity to determine whether the event is expected, suspicious, malicious, or indicative of confirmed compromise.

Investigation may include:

- Source investigation
- Account and identity investigation
- Endpoint investigation
- Active Directory investigation
- Correlation with related detections
- Timeline construction
- Scope determination
- Evidence of compromise

Relevant Wazuh dashboards are used to support investigation and correlation.

### 3. Containment

Containment focuses on stopping or limiting the attack while preserving the ability to investigate.

Depending on the incident, actions may include:

- Disabling or locking compromised accounts
- Resetting compromised credentials
- Removing unauthorized privileged memberships
- Isolating CLIENT01
- Stopping malicious processes
- Restricting malicious sources
- Removing attacker access
- Applying appropriate Active Directory containment

Actions affecting **DC01** require particular care because it is the domain controller for the lab environment.

### 4. Eradication

Eradication removes the attacker foothold and reverses unauthorized changes.

Depending on the scenario, this may include:

- Removing malicious files
- Removing persistence mechanisms
- Removing unauthorized accounts
- Removing unauthorized group memberships
- Resetting exposed credentials
- Reverting unauthorized AD or GPO changes
- Restoring security configuration
- Removing attacker-created services or scheduled tasks

### 5. Recovery

Recovery restores affected systems, accounts, and security controls to a known-good state.

Recovery should confirm that:

- Malicious activity has stopped
- Unauthorized changes have been removed
- Compromised credentials have been remediated
- Privileges are correct
- Security controls are enabled
- Windows and Sysmon logging are functioning
- Wazuh is receiving telemetry

### 6. Validation

Validation confirms that remediation was successful and that the detection pipeline continues to operate.

The analyst should verify:

- No continuing evidence of compromise exists
- Related malicious activity has stopped
- Security controls are functioning
- Wazuh is receiving expected telemetry
- Relevant detections continue to trigger when appropriate
- Unauthorized configuration changes have been removed

### 7. Closure

An incident should only be closed after investigation, containment, eradication, recovery, and validation are complete.

Closure should document:

- Incident classification
- Affected hosts and accounts
- Timeline
- Root cause
- Attack scope
- Evidence collected
- Containment actions
- Eradication actions
- Recovery actions
- Validation results
- Lessons learned
- Final findings

---

## Detection → Investigation → Containment → Eradication → Recovery

The lab separates **detection engineering** from **incident handling** while maintaining a direct relationship between the two.

```text
┌─────────────────────────────┐
│ Wazuh Detection             │
│ Specific attacker behavior  │
└──────────────┬──────────────┘
               ↓
┌─────────────────────────────┐
│ Investigation               │
│ Validate • Correlate        │
│ Scope • Build timeline      │
└──────────────┬──────────────┘
               ↓
┌─────────────────────────────┐
│ Containment                 │
│ Stop / limit attacker access│
└──────────────┬──────────────┘
               ↓
┌─────────────────────────────┐
│ Eradication                 │
│ Remove foothold / changes   │
└──────────────┬──────────────┘
               ↓
┌─────────────────────────────┐
│ Recovery                    │
│ Restore and validate        │
└──────────────┬──────────────┘
               ↓
┌─────────────────────────────┐
│ Validation & Closure        │
└─────────────────────────────┘
```

### Incident Assessment

During investigation, activity is assessed using the following progression:

```text
Expected / Benign
       ↓
Suspicious
       ↓
Malicious
       ↓
Confirmed Compromise
```

The surrounding activity, affected identities, affected systems, and available evidence should be considered before classifying an incident.

---

## Incident Scenarios

The 42 custom Wazuh detections are grouped into seven broader incident response scenarios.

| Playbook | Incident Scenario | Detection Coverage |
|---|---|---|
| **IR-001** | Credential Attack & Account Compromise | DET-001 – DET-006 |
| **IR-002** | Active Directory Account & Privilege Compromise | DET-007 – DET-016 |
| **IR-003** | Kerberos & Credential Theft Attack | DET-017 – DET-024 |
| **IR-004** | Active Directory Discovery & Reconnaissance | DET-025 – DET-027 |
| **IR-005** | Lateral Movement & Remote Execution | DET-028 – DET-032 |
| **IR-006** | Persistence & Defense Evasion | DET-033 – DET-041 |
| **IR-007** | Active Directory Destructive / Impact Activity | DET-042 |

### IR-001 — Credential Attack & Account Compromise

Covers authentication attacks and potential account compromise.

**Detections:** DET-001 – DET-006

Primary investigation areas include failed authentication, repeated failures, successful authentication, account lockouts, source-based authentication anomalies, affected identities, and evidence of unauthorized access.

### IR-002 — Active Directory Account & Privilege Compromise

Covers unauthorized account changes, privileged group modifications, administrator account enablement, privileged authentication, and Active Directory attribute manipulation.

**Detections:** DET-007 – DET-016

Primary investigation areas include account creation, password resets, account enablement/deletion, privileged group membership, privileged logons, and sensitive AD object changes.

### IR-003 — Kerberos & Credential Theft Attack

Covers Kerberos abuse and credential theft activity targeting domain identities and authentication material.

**Detections:** DET-017 – DET-024

Primary investigation areas include Kerberoasting, AS-REP roasting, DCSync, Golden Ticket, Silver Ticket, LSASS access, NTDS credential extraction, and Pass-the-Hash activity.

### IR-004 — Active Directory Discovery & Reconnaissance

Covers attacker reconnaissance and enumeration of the Windows and Active Directory environment.

**Detections:** DET-025 – DET-027

Primary investigation areas include SharpHound, AdFind, account and group discovery, domain trust discovery, and Windows network discovery commands.

### IR-005 — Lateral Movement & Remote Execution

Covers remote execution and lateral movement between Windows systems.

**Detections:** DET-028 – DET-032

Primary investigation areas include PsExec, SMB administrative shares, WinRM, WMI, and RDP authentication.

### IR-006 — Persistence & Defense Evasion

Covers persistence mechanisms and activity intended to modify, disable, or evade Windows security controls.

**Detections:** DET-033 – DET-041

Primary investigation areas include services, scheduled tasks, Group Policy modification, Startup Folder persistence, event log clearing, audit policy modification, Defender changes, PowerShell execution, and Windows Firewall changes.

### IR-007 — Active Directory Destructive & Impact Activity

Covers destructive Active Directory activity involving security-enabled group deletion and potential loss of access.

**Detection:** DET-042

Primary investigation areas include the deleted group, initiating identity, source host, timeline, affected access, and evidence of broader domain compromise.

---

## Relationship Between Detections and Playbooks

The **42 custom Wazuh detections** form the technical detection layer. The seven IR playbooks operate at the incident level and group related detections into broader attack scenarios.

Individual detection documentation remains the authoritative source for:

- Detection objective
- Windows/Sysmon telemetry
- Detection logic
- Wazuh rule configuration
- Validation
- Rule-level investigation guidance
- Rule-level response guidance

The incident response playbooks provide the higher-level workflow for handling multiple related alerts, events, hosts, or accounts as one incident.

### Detection-to-Playbook Mapping

| Detection Group | Detections | Incident Response Playbook |
|---|---|---|
| Authentication | DET-001 – DET-006 | IR-001 |
| Account Management / Privilege | DET-007 – DET-016 | IR-002 |
| Credential Access | DET-017 – DET-024 | IR-003 |
| Discovery / Reconnaissance | DET-025 – DET-027 | IR-004 |
| Lateral Movement / Remote Execution | DET-028 – DET-032 | IR-005 |
| Persistence / Defense Evasion | DET-033 – DET-041 | IR-006 |
| Impact | DET-042 | IR-007 |

This grouping prevents analysts from treating every individual alert as an isolated event when multiple detections may represent stages of the same attack.

### Example Correlation

An authentication incident may progress through several detections:

```text
DET-001
Failed Authentication
      │
      ├──────────────→ DET-002
      │                 Repeated failures
      │
      └──────────────→ DET-006
                        Multiple failures from source
                              │
                              ├────────→ DET-005
                              │          Account Lockout
                              │
                              └────────→ DET-003
                                         Successful Authentication
                                               │
                                               ↓
                                         DET-004
                                         Successful Login
                                         After Failed Attempts
                                               │
                                               ↓
                                             IR-001
```

The exact sequence is not guaranteed. Individual detections may trigger independently depending on attacker behavior, Windows configuration, account state, and available telemetry.

---

## Detection-to-Response Workflow

The operational workflow connects a Wazuh alert to the appropriate incident response playbook.

### Step 1 — Identify the Detection

Start with the Wazuh alert and identify:

- Detection ID
- Wazuh rule ID
- Event ID
- Timestamp
- Affected host
- Affected account
- Source IP or host
- Detection category

### Step 2 — Validate the Alert

Review the underlying Windows/Sysmon event and determine whether the activity is expected, suspicious, or potentially malicious.

The analyst should avoid treating a single detection as automatic proof of compromise.

### Step 3 — Select the Incident Scenario

Use the detection-to-playbook mapping to select the relevant IR playbook.

```text
Wazuh Alert
    ↓
Detection ID
    ↓
Incident Scenario
    ↓
IR Playbook
```

### Step 4 — Investigate and Correlate

Use the selected playbook to investigate:

- Source
- Identity
- Affected host
- Destination host where applicable
- Related detections
- Timeline
- Scope
- Evidence of compromise

### Step 5 — Assess the Incident

Determine whether the activity is:

```text
Expected / Benign
        │
        └──→ Document / Monitor / Close

Suspicious
        │
        ↓
Continue Investigation

Malicious / Confirmed Compromise
        │
        ↓
Containment
```

### Step 6 — Contain

Apply the containment actions appropriate to the incident scenario, while preserving investigation capability.

### Step 7 — Eradicate

Remove attacker access, persistence, malicious artifacts, unauthorized accounts, privileges, or configuration changes as appropriate.

### Step 8 — Recover

Restore affected systems, accounts, privileges, and security controls to a known-good state.

### Step 9 — Validate

Confirm that malicious activity has stopped, unauthorized changes have been removed, security controls are functioning, and Wazuh telemetry remains operational.

### Step 10 — Document and Close

Record the timeline, findings, evidence, response actions, validation results, root cause, and final incident classification before closure.

---

## Investigation Resources

The incident response playbooks are designed to work alongside the Wazuh dashboards used throughout the lab.

Relevant dashboards include:

- **SOC Detection Overview**
- **Authentication & Account Monitoring**
- **Active Directory Security**
- **System & Endpoint Activity**
- **Threat Hunting & Lateral Movement**

These dashboards support visibility into authentication activity, Active Directory changes, endpoint activity, detection activity, affected hosts, affected users, and related events.

The underlying investigation should continue to the raw Wazuh event when dashboard aggregation is insufficient to establish the required evidence.

---

## Lab Environment

| Component | Role |
|---|---|
| **DC01** | Windows Server 2022 / Active Directory Domain Controller |
| **CLIENT01** | Windows 11 domain-joined endpoint |
| **WAZUH** | SIEM, log collection, detection, and investigation platform |
| **KALI** | Attack simulation / adversary host |

Primary telemetry sources include:

- Windows Security Event Logs
- Windows System/Application Events
- Sysmon
- PowerShell telemetry
- Active Directory events
- Microsoft Defender telemetry
- Windows Firewall events
- Wazuh custom detection rules

---

## Escalation Principles

The incident should be escalated within the lab response workflow when investigation identifies conditions such as:

- Confirmed unauthorized account access
- Compromise of a privileged account
- Unauthorized Domain Admin or Enterprise Admin membership
- Credential theft or credential material exposure
- DCSync, Golden Ticket, or other domain-level credential compromise indicators
- Evidence of lateral movement to multiple systems
- Persistence established on a domain system
- Security controls intentionally disabled or modified
- Evidence suggesting broader Active Directory compromise
- Destructive activity affecting domain access or functionality

The seven playbooks contain scenario-specific escalation criteria and high-risk conditions.

---

## Incident Closure Criteria

Before closing an incident, confirm that:

- Investigation is complete
- Attack scope is understood
- Root cause is documented
- Evidence has been preserved
- Containment is complete
- Eradication is complete
- Recovery is complete
- Unauthorized changes have been addressed
- Compromised credentials have been remediated where applicable
- Security controls are functioning
- Windows/Sysmon telemetry is functioning
- Wazuh is receiving telemetry
- No continuing evidence of compromise exists
- Final findings and response actions are documented

---

## Related Documentation

### Detection Engineering

The individual detection documents remain the authoritative source for the 42 custom Wazuh rules, including detection logic, telemetry, validation, investigation guidance, and rule-level response guidance.

### Incident Response Playbooks

| Playbook | Scenario | Coverage |
|---|---|---|
| **IR-001** | Credential Attack & Account Compromise | DET-001 – DET-006 |
| **IR-002** | Active Directory Account & Privilege Compromise | DET-007 – DET-016 |
| **IR-003** | Kerberos & Credential Theft Attack | DET-017 – DET-024 |
| **IR-004** | Active Directory Discovery & Reconnaissance | DET-025 – DET-027 |
| **IR-005** | Lateral Movement & Remote Execution | DET-028 – DET-032 |
| **IR-006** | Persistence & Defense Evasion | DET-033 – DET-041 |
| **IR-007** | Active Directory Destructive / Impact Activity | DET-042 |

### MITRE ATT&CK

The project maintains a separate MITRE ATT&CK mapping document connecting the 42 detections to their intended ATT&CK techniques.

---

## Documentation Principle

The project intentionally separates **detection engineering** from **incident response**.

```text
Detection Documentation
        │
        │ Rule-level technical detail
        ↓
Individual Detection
        │
        ↓
Incident Response Playbook
        │
        │ Incident-level correlation
        │ Scope
        │ Containment
        │ Eradication
        │ Recovery
        │ Validation
        ↓
Incident Closure
```

This separation keeps the detection documentation focused on **detecting specific attacker behaviors**, while the incident response documentation focuses on **handling the broader attack scenario**.
