# Incident Response Playbooks

## Overview

This directory contains incident-level response playbooks for the **SOC Active Directory Detection & Incident Response Lab**.

The playbooks provide an operational workflow for investigating and responding to Windows and Active Directory attack scenarios detected by Wazuh. Rather than maintaining a separate incident response document for every detection rule, related detections are grouped into broader attack scenarios.

The playbooks complement the individual detection documentation:

- **Detection Documentation** explains how a specific behavior is detected, investigated, and responded to.
- **Incident Response Playbooks** explain how an analyst handles the broader incident when multiple detections, events, hosts, or accounts may be related.

The overall workflow is:

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

## Playbook Structure

| Playbook | Incident Scenario | Detection Coverage |
|---|---|---|
| **IR-001** | Credential Attack & Account Compromise | DET-001 – DET-006 |
| **IR-002** | Active Directory Account & Privilege Compromise | DET-007 – DET-016 |
| **IR-003** | Kerberos & Credential Theft Attack | DET-017 – DET-024 |
| **IR-004** | Active Directory Discovery & Reconnaissance | DET-025 – DET-027 |
| **IR-005** | Lateral Movement & Remote Execution | DET-028 – DET-032 |
| **IR-006** | Persistence & Defense Evasion | DET-033 – DET-041 |
| **IR-007** | Active Directory Destructive / Impact Activity | DET-042 |

## Incident Response Lifecycle

Each playbook follows a common incident handling lifecycle:

### 1. Initial Triage

Determine whether the Wazuh alert represents expected, suspicious, or potentially malicious activity.

The analyst should establish:

- Detection rule and alert details
- Event timestamp
- Affected host
- Affected account
- Source IP or source host
- First and last observed activity
- Related alerts and events
- Whether the activity was authorized

### 2. Investigation

Investigate the activity beyond the initial alert and determine whether additional events form part of the same attack.

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

### 3. Incident Assessment

Activity is assessed using the following progression:

```text
Expected / Benign
       ↓
Suspicious
       ↓
Malicious
       ↓
Confirmed Compromise
```

A detection alone does not automatically indicate a confirmed compromise. The analyst should consider the surrounding activity, context, affected identities, affected systems, and evidence collected during investigation.

### 4. Containment

Containment focuses on stopping or limiting the attack while preserving the ability to investigate.

Depending on the scenario, containment may include:

- Disabling or locking compromised accounts
- Resetting compromised credentials
- Removing unauthorized privileged memberships
- Isolating CLIENT01
- Stopping malicious processes
- Restricting malicious sources
- Removing attacker access
- Applying appropriate Active Directory containment

Actions affecting **DC01** must be carefully evaluated because it is the domain controller for the lab environment.

### 5. Eradication

Eradication removes the attacker's foothold and reverses unauthorized changes.

Depending on the incident, this may include:

- Removing malicious files
- Removing persistence mechanisms
- Removing unauthorized accounts
- Removing unauthorized group memberships
- Resetting exposed credentials
- Reverting unauthorized AD or GPO changes
- Restoring security configuration
- Removing attacker-created services or scheduled tasks

### 6. Recovery & Validation

Systems and security controls are restored and verified.

Validation should confirm:

- Malicious activity has stopped
- Unauthorized changes have been removed
- Compromised credentials have been remediated
- Privileges are correct
- Security controls are enabled
- Windows and Sysmon logging are functioning
- Wazuh is receiving telemetry
- Related detections continue to function
- No continuing evidence of compromise exists

### 7. Closure

An incident should only be closed after the investigation and remediation activities are complete.

Closure requires:

- Root cause understood
- Attack path identified
- Scope determined
- Evidence documented
- Containment completed
- Eradication completed
- Recovery completed
- Security controls validated
- Wazuh telemetry verified
- No evidence of continued compromise
- Final findings documented

## Detection-to-Incident Relationship

The **42 custom Wazuh detections** are the primary technical detection layer for this lab.

Individual detection documentation remains the authoritative source for rule-specific information, including:

- Detection objective
- Windows/Sysmon telemetry
- Detection logic
- Wazuh rule configuration
- Validation
- Rule-level investigation
- Rule-level response

The incident response playbooks operate at a higher level.

For example:

```text
DET-001 ─┐
DET-002 ─┤
DET-003 ─┤
DET-004 ─┼──→ IR-001
DET-005 ─┤
DET-006 ─┘
```

This allows multiple related alerts to be treated as a single incident rather than investigated independently.

## Lab Environment

The playbooks are designed specifically for the lab environment:

| Component | Role |
|---|---|
| **DC01** | Windows Server 2022 / Active Directory Domain Controller |
| **CLIENT01** | Windows 11 Domain-Joined Endpoint |
| **WAZUH** | SIEM, Log Collection, Detection & Investigation |
| **KALI** | Attack Simulation / Adversary Host |

Primary telemetry sources include:

- Windows Security Event Logs
- Windows System/Application Events
- Sysmon
- PowerShell telemetry
- Active Directory events
- Wazuh custom detection rules

## Investigation Resources

The following Wazuh dashboards support investigation and incident correlation:

- **SOC Detection Overview**
- **Authentication & Account Monitoring**
- **Active Directory Security**
- **Sysmon Endpoint Activity**
- **Detection Validation & Engineering**

Dashboards provide visibility into authentication activity, Active Directory changes, endpoint activity, detection activity, affected hosts, affected users, and related events.

## Playbooks

### IR-001 — Credential Attack & Account Compromise

Covers authentication attacks and account compromise activity.

**Detections:** DET-001 – DET-006

### IR-002 — Active Directory Account & Privilege Compromise

Covers unauthorized account changes, privilege escalation, privileged group modifications, and Active Directory attribute manipulation.

**Detections:** DET-007 – DET-016

### IR-003 — Kerberos & Credential Theft Attack

Covers Kerberos abuse and credential theft techniques targeting domain identities and authentication material.

**Detections:** DET-017 – DET-024

### IR-004 — Active Directory Discovery & Reconnaissance

Covers attacker reconnaissance and enumeration of the Windows/Active Directory environment.

**Detections:** DET-025 – DET-027

### IR-005 — Lateral Movement & Remote Execution

Covers remote execution and lateral movement techniques used to move between Windows systems.

**Detections:** DET-028 – DET-032

### IR-006 — Persistence & Defense Evasion

Covers persistence mechanisms and activity intended to modify, disable, or evade Windows security controls.

**Detections:** DET-033 – DET-041

### IR-007 — Active Directory Destructive / Impact Activity

Covers destructive Active Directory activity that can affect security-enabled groups and domain functionality.

**Detection:** DET-042

## Usage

These playbooks are intended to be used alongside the detection documentation.

Recommended workflow:

1. Identify the Wazuh detection that triggered.
2. Review the corresponding detection documentation.
3. Determine which incident scenario applies.
4. Open the appropriate IR playbook.
5. Perform incident-level triage and correlation.
6. Determine scope and compromise status.
7. Contain the activity.
8. Eradicate the attacker foothold and unauthorized changes.
9. Recover affected systems and accounts.
10. Validate telemetry and security controls.
11. Document findings and close the incident.

## Documentation Principle

The playbooks are intentionally designed to avoid duplicating the 42 individual detection documents.

```text
Detection Documentation
        │
        │  Rule-level technical detail
        ↓
Individual Detection
        │
        ↓
Incident Response Playbook
        │
        │  Incident-level correlation
        │  Scope
        │  Containment
        │  Eradication
        │  Recovery
        │  Validation
        ↓
Incident Closure
```

This separation keeps the detection engineering documentation focused on **detecting specific behaviors**, while the incident response documentation focuses on **handling the broader attack scenario**.
