# Detection → Incident Response Playbook Mapping

## Purpose

This document maps the **42 custom detections** to the seven incident-response playbooks used by the SOC Active Directory Detection Lab.

The playbooks provide the operational bridge between a Wazuh alert and analyst action.

## Playbook Catalogue

| Playbook | Scenario |
|---|---|
| **IR-001** | Credential Attack & Account Compromise |
| **IR-002** | Active Directory Account & Privilege Compromise |
| **IR-003** | Kerberos & Credential Theft Attack |
| **IR-004** | AD Discovery & Reconnaissance |
| **IR-005** | Lateral Movement & Remote Execution |
| **IR-006** | Persistence & Defense Evasion |
| **IR-007** | AD Destructive & Impact Activity |

## Detection → Playbook Matrix

| Detection | Primary playbook | Secondary playbook(s) |
|---|---|---|
| DET-001 | **IR-001** | — |
| DET-002 | **IR-001** | — |
| DET-003 | **IR-001** | IR-002 |
| DET-004 | **IR-001** | — |
| DET-005 | **IR-001** | IR-002 |
| DET-006 | **IR-001** | — |
| DET-007 | **IR-002** | — |
| DET-008 | **IR-002** | IR-001 |
| DET-009 | **IR-002** | — |
| DET-010 | **IR-007** | IR-002 |
| DET-011 | **IR-002** | — |
| DET-012 | **IR-002** | — |
| DET-013 | **IR-002** | — |
| DET-014 | **IR-002** | — |
| DET-015 | **IR-002** | IR-001 |
| DET-016 | **IR-002** | IR-006 |
| DET-017 | **IR-003** | — |
| DET-018 | **IR-003** | — |
| DET-019 | **IR-003** | IR-002 |
| DET-020 | **IR-003** | IR-002 |
| DET-021 | **IR-003** | IR-005 |
| DET-022 | **IR-003** | IR-002 |
| DET-023 | **IR-003** | IR-002 |
| DET-024 | **IR-003** | IR-005 |
| DET-025 | **IR-004** | — |
| DET-026 | **IR-004** | — |
| DET-027 | **IR-004** | IR-005 |
| DET-028 | **IR-005** | — |
| DET-029 | **IR-005** | — |
| DET-030 | **IR-005** | — |
| DET-031 | **IR-005** | — |
| DET-032 | **IR-005** | — |
| DET-033 | **IR-006** | IR-005 |
| DET-034 | **IR-006** | — |
| DET-035 | **IR-006** | IR-002 |
| DET-036 | **IR-006** | — |
| DET-037 | **IR-006** | — |
| DET-038 | **IR-006** | — |
| DET-039 | **IR-006** | — |
| DET-040 | **IR-006** | — |
| DET-041 | **IR-006** | IR-005 |
| DET-042 | **IR-007** | IR-002 |

## Detection-to-Response Model

```text
Telemetry
    │
    ▼
Wazuh Detection
    │
    ▼
Alert Triage
    │
    ├── Credential / authentication
    │          └── IR-001
    │
    ├── AD account / privilege
    │          └── IR-002
    │
    ├── Kerberos / credential theft
    │          └── IR-003
    │
    ├── Discovery / reconnaissance
    │          └── IR-004
    │
    ├── Lateral movement
    │          └── IR-005
    │
    ├── Persistence / defense evasion
    │          └── IR-006
    │
    └── Destructive / impact activity
               └── IR-007
```

## Operational Relationship

The mapping is intentionally many-to-many at the SOC level. A single alert may trigger an initial playbook while investigation reveals a broader incident requiring additional playbooks.

For example:

```text
DET-017 Kerberoasting
        │
        ▼
IR-003 Kerberos & Credential Theft
        │
        ├── compromised account discovered
        │          ↓
        │       IR-002
        │
        └── lateral movement discovered
                   ↓
                IR-005
```

This reflects an incident-response workflow rather than treating detections as isolated events.
