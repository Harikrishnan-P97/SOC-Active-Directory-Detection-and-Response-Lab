# SOC Active Directory Detection & Incident Response Lab

## Architecture

## 1. Architecture Overview

The **SOC Active Directory Detection & Incident Response Lab** is an
isolated Windows Active Directory security monitoring environment
designed to demonstrate end-to-end Security Operations Center (SOC)
workflows.

The lab combines a Windows Active Directory domain, endpoint telemetry,
Wazuh SIEM monitoring, custom detection engineering, security
dashboards, threat simulations, investigation procedures, and documented
incident response playbooks.

The architecture follows the operational flow:

**Attack / Simulation → Telemetry → Collection & Detection → Alerting →
Investigation → Response → Validation & Monitoring**

The environment is intentionally separated from production
infrastructure and is used to safely simulate attacker behavior,
validate detections, and demonstrate incident response capabilities.

------------------------------------------------------------------------

## 2. Lab Components

  ------------------------------------------------------------------------
  Component        Platform                    IP Address Primary Role
  ---------------- ---------------- --------------------- ----------------
  **DC01**         Windows Server           `10.10.10.20` Active Directory
                   2022                                   Domain
                                                          Controller and
                                                          DNS

  **CLIENT01**     Windows 11 Pro           `10.10.10.30` Domain-joined
                                                          Windows endpoint

  **WAZUH**        Ubuntu Server            `10.10.10.10` Wazuh Manager,
                                                          OpenSearch
                                                          Indexer, and
                                                          Wazuh Dashboard

  **KALI**         Kali Linux               `10.10.10.40` Attack
                                                          simulation and
                                                          adversary
                                                          emulation
  ------------------------------------------------------------------------

### 2.1 DC01

DC01 provides the core Windows domain infrastructure for the lab.

Primary services include:

-   Active Directory Domain Services (AD DS)
-   DNS
-   Domain authentication
-   Group Policy
-   User and group management
-   Domain security event generation

**Domain:** `corp.local`

DC01 generates Windows security and Active Directory telemetry used by
Wazuh for detection and investigation.

### 2.2 CLIENT01

CLIENT01 is the primary Windows endpoint used for endpoint security
monitoring and attack simulation.

Telemetry includes:

-   Windows Security Events
-   Sysmon
-   PowerShell activity
-   Windows Defender events
-   Registry activity
-   File Integrity Monitoring
-   Windows Firewall events

The endpoint is joined to the `corp.local` Active Directory domain.

### 2.3 WAZUH

WAZUH is the centralized security monitoring platform for the lab.

The server provides:

-   Wazuh Manager
-   Wazuh Indexer / OpenSearch
-   Wazuh Dashboard
-   Log collection and analysis
-   Event decoding
-   Detection rule processing
-   Alert generation
-   Security visualization and investigation

WAZUH also contains the project's custom detection-engineering rules.

The WAZUH server uses:

-   `10.10.10.10` on the lab network
-   `192.168.58.10` on the additional host-only network

### 2.4 KALI

KALI is the attack and adversary-simulation host.

It is used to generate controlled security activity for detection
validation, including techniques involving:

-   Active Directory enumeration
-   SMB
-   WinRM
-   PsExec
-   Credential attacks
-   Remote administration
-   Discovery activity
-   Other MITRE ATT&CK-aligned simulations

KALI provides the offensive side of the lab while Wazuh provides the
defensive monitoring and detection layer.

------------------------------------------------------------------------

## 3. Network Topology

The primary lab network uses the `10.10.10.0/24` address space.

``` text
                         Isolated SOC Lab Network
                              10.10.10.0/24
                                      |
          ┌───────────────────────────┼───────────────────────────┐
          │                           │                           │
          │                           │                           │
       ┌───────┐                  ┌──────────┐                ┌───────┐
       │ KALI  │                  │  DC01    │                │WAZUH  │
       │.10.10.40│                │.10.10.20 │                │.10.10.10│
       │       │                  │ AD / DNS │                │ SIEM  │
       └───┬───┘                  └────┬─────┘                └───────┘
           │                            │
           │                            │ Domain
           │                            │ Communication
           │                            │
           │                       ┌────┴─────┐
           └───────────────────────│ CLIENT01 │
                                   │.10.10.30 │
                                   │ Windows  │
                                   └──────────┘
```

The architecture separates the offensive simulation host from the
monitored Windows environment while keeping all systems within the
controlled lab network.

### Network Roles

  -----------------------------------------------------------------------
  System                              Network Function
  ----------------------------------- -----------------------------------
  KALI                                Generates controlled attack and
                                      adversary-simulation activity

  DC01                                Provides AD authentication, DNS,
                                      Group Policy, and domain services

  CLIENT01                            Generates endpoint security and
                                      Sysmon telemetry

  WAZUH                               Collects, analyzes, detects,
                                      stores, and visualizes security
                                      events
  -----------------------------------------------------------------------

------------------------------------------------------------------------

## 4. Telemetry and Data Flow

Windows telemetry is collected from the monitored Windows systems and
forwarded to Wazuh for centralized analysis.

### Primary Telemetry Sources

  -----------------------------------------------------------------------
  Telemetry Source                    Purpose
  ----------------------------------- -----------------------------------
  Windows Security Events             Authentication, account, privilege,
                                      and AD security activity

  Sysmon                              Process, network, file, registry,
                                      DNS, and other endpoint activity

  PowerShell                          PowerShell execution and command
                                      activity

  Windows Defender                    Endpoint security and
                                      malware-related events

  Registry                            Registry modification and
                                      persistence-related activity

  File Integrity Monitoring           File and directory change
                                      monitoring

  Windows Firewall                    Firewall policy and configuration
                                      activity
  -----------------------------------------------------------------------

### Telemetry Flow

``` text
Windows / AD Systems
        │
        ├── Windows Security Events
        ├── Sysmon
        ├── PowerShell
        ├── Defender
        ├── Registry
        ├── FIM
        └── Windows Firewall
                │
                ▼
          Wazuh Agent / Collection
                │
                ▼
          Wazuh Manager
                │
        ┌───────┴────────┐
        │                │
     Decoding       Detection Rules
                         │
                         ▼
               Custom Detection Layer
                         │
                         ▼
                   Wazuh Alerts
                         │
                         ▼
              OpenSearch / Indexer
                         │
                         ▼
                 Wazuh Dashboard
```

Raw telemetry is retained in the Wazuh archive indices for threat
hunting and investigation, while generated detections are available
through the Wazuh alert indices.

Common data locations include:

-   `wazuh-archives-4.x-*` --- raw and archived event telemetry
-   `wazuh-alerts-4.x-*` --- generated Wazuh alerts

------------------------------------------------------------------------

## 5. Security Monitoring Architecture

The security monitoring architecture is built around a centralized Wazuh
SIEM layer.

### Monitoring Pipeline

``` text
Collection
    ↓
Decoding
    ↓
Detection
    ↓
Alerting
    ↓
Visualization
    ↓
Investigation
    ↓
Response
```

Wazuh receives telemetry from the Windows environment, decodes the
events, evaluates them against the Wazuh ruleset, and generates alerts
when detection conditions are satisfied.

The lab includes **42 custom detection rules** covering areas such as:

-   Authentication
-   Account Management
-   Credential Access
-   Persistence
-   Defense Evasion
-   Discovery
-   Execution
-   Lateral Movement
-   Impact

The custom detections are mapped to relevant **MITRE ATT&CK** techniques
and are individually documented with validation and investigation
guidance.

------------------------------------------------------------------------

## 6. Detection Engineering Architecture

The detection-engineering layer extends the native Wazuh ruleset with
custom rules designed specifically for the lab's Active Directory threat
model.

``` text
Windows / Sysmon Event
          │
          ▼
     Wazuh Decoder
          │
          ▼
   Built-in Wazuh Rule
          │
          ▼
   Custom Detection Rule
          │
          ├── Detection Logic
          ├── Severity
          ├── MITRE ATT&CK Mapping
          └── Detection Category
          │
          ▼
      Wazuh Alert
```

Custom rules are stored in Wazuh's local rules configuration and are
organized around the project's detection-engineering requirements.

Each documented detection includes:

-   Detection objective
-   MITRE ATT&CK mapping
-   Relevant Windows/Sysmon events
-   Detection logic
-   Wazuh rule XML
-   Simulation procedure
-   Expected alert
-   Validation result
-   Investigation playbook
-   Response playbook
-   False-positive considerations
-   Tuning considerations

The complete detection documentation is maintained separately from this
architecture document.

------------------------------------------------------------------------

## 7. Security Monitoring Dashboards

Wazuh Dashboard provides the primary monitoring and investigation
interface.

The lab dashboards organize security telemetry into operational views
including:

### Authentication & Account Monitoring

Monitors:

-   Successful logons
-   Failed logons
-   Account lockouts
-   Privileged logons
-   Successful vs. failed authentication activity

### Active Directory Security

Monitors:

-   Account creation and deletion
-   Password activity
-   Privileged group changes
-   Account modifications
-   Active Directory security activity

### System & Endpoint Activity

Monitors:

-   Network connections
-   Destination IPs and ports
-   LSASS access
-   Suspicious file activity
-   DNS activity
-   Endpoint process activity

### Threat Hunting & Lateral Movement

Monitors activity associated with:

-   PowerShell
-   Encoded PowerShell
-   Suspicious processes
-   SharpHound
-   AdFind
-   Network discovery
-   Service creation
-   Scheduled tasks
-   Startup persistence
-   Group Policy modification
-   PsExec
-   SMB administrative shares
-   WinRM

These dashboards provide the analyst with both high-level monitoring and
deeper investigation views.

------------------------------------------------------------------------

## 8. Detection → Alert → Investigation → Response

The operational workflow follows a structured SOC incident-handling
process.

``` text
Attack / Suspicious Activity
            ↓
Windows / AD / Sysmon Telemetry
            ↓
        Wazuh SIEM
            ↓
      Custom Detection
            ↓
        Wazuh Alert
            ↓
       Alert Triage
            ↓
        Investigation
            ↓
     Incident Assessment
            │
       ┌────┴────┐
       │         │
   Expected   Suspicious /
    / Benign   Confirmed
       │       Compromise
       │         │
       ▼         ▼
 Close &      Response
 Monitor
```

### 8.1 Detection

Security activity is generated through normal system behavior or
controlled attack simulations.

Wazuh collects the resulting telemetry and evaluates it against the
detection rules.

### 8.2 Alert

When a detection condition is satisfied, Wazuh generates an alert
containing contextual information such as:

-   Detection rule
-   Severity
-   Host
-   User
-   Source information
-   Event details
-   MITRE ATT&CK mapping

### 8.3 Investigation

The analyst validates and investigates the alert using Wazuh Dashboard
and the underlying event telemetry.

The investigation process includes:

1.  Validate the alert
2.  Identify the affected host
3.  Identify the associated user
4.  Identify the source
5.  Determine severity
6.  Correlate related events
7.  Investigate the host and account
8.  Build an event timeline
9.  Determine incident scope
10. Identify evidence of compromise

### 8.4 Incident Assessment

The analyst determines whether the activity is:

-   Expected / Benign
-   Suspicious
-   Malicious
-   Confirmed compromise

Expected or benign activity can be closed and monitored.

Confirmed malicious activity proceeds to the appropriate incident
response playbook.

### 8.5 Response

The lab uses documented incident response playbooks covering the
response lifecycle.

The response process includes:

**Containment → Eradication → Recovery → Validation → Closure &
Monitoring**

Depending on the incident, response actions can include:

-   Isolating affected systems
-   Blocking malicious activity
-   Removing persistence
-   Cleaning compromised systems
-   Restoring required services
-   Validating remediation
-   Increasing monitoring
-   Documenting the incident

The response stage is intentionally documented as an analyst-driven
process rather than presented as fully automated remediation.

------------------------------------------------------------------------

## 9. Incident Response Playbooks

The lab includes **7 documented incident response playbooks**,
referenced by the detection and investigation workflow.

The playbooks provide structured guidance for moving from detection and
investigation into containment, eradication, recovery, and closure.

The architecture therefore separates:

-   **Detection engineering** --- identifies suspicious activity
-   **Security monitoring** --- provides visibility
-   **Investigation** --- determines scope and validity
-   **Incident response** --- provides documented remediation actions

This separation reflects a practical SOC operating model.

------------------------------------------------------------------------

## 10. Detection Tuning and Continuous Improvement

Detection engineering is treated as an iterative process.

``` text
Detection
    ↓
Alert
    ↓
Investigation
    ↓
Response
    ↓
Validation
    ↓
Detection Tuning
    ↓
Improved Coverage
    ↓
Detection
```

Investigation findings can be used to refine:

-   Detection logic
-   Rule conditions
-   Severity levels
-   False-positive handling
-   Event correlation
-   MITRE ATT&CK coverage
-   Monitoring coverage

This feedback loop allows the lab to evolve as new attack simulations
and detection requirements are introduced.

------------------------------------------------------------------------

## 11. Architecture Diagrams

The repository includes visual diagrams that provide a graphical
representation of the architecture and SOC workflow.

### Lab Architecture

![SOC Active Directory Detection Lab Architecture](../diagrams/Architecture-diagram.png)

This diagram illustrates the four primary layers:

1.  Attack / Simulation Layer
2.  Windows / AD Environment
3.  Security Monitoring Layer
4.  Analysis & Response Layer

### Detection → Investigation → Response Workflow

![Detection Investigation Response Workflow](../diagrams/Detection-Investigation-Response-Workflow-Diagram.png)

This diagram illustrates the operational workflow from suspicious
activity through detection, alert triage, investigation, incident
assessment, response, validation, and continuous monitoring.

------------------------------------------------------------------------

## 12. Security Monitoring Coverage

The architecture provides visibility across multiple stages of the
attack lifecycle.

  Security Area        Primary Telemetry / Detection Sources
  -------------------- --------------------------------------------
  Authentication       Windows Security Events
  Account Management   Windows Security Events / AD
  Credential Access    Windows Security Events / Sysmon
  Persistence          Sysmon / Windows Security / Registry / FIM
  Defense Evasion      Sysmon / PowerShell / Windows Security
  Discovery            Sysmon / AD activity
  Execution            Sysmon / PowerShell
  Lateral Movement     Windows Security / Sysmon / SMB / WinRM
  Impact               Windows Security / AD activity
  Network Activity     Sysmon / Windows Firewall

This coverage allows the lab to demonstrate detection and investigation
across both endpoint and Active Directory activity.

------------------------------------------------------------------------

## 13. Architecture Design Principles

The lab architecture follows several practical design principles:

### Centralized Monitoring

Security telemetry is centralized through Wazuh to provide a single
monitoring and investigation platform.

### Layered Detection

Native Wazuh detections are supplemented by custom rules designed around
the lab's threat model.

### Telemetry-Driven Detection

Detections are based on observable Windows and Sysmon events rather than
simulated alert generation.

### MITRE ATT&CK Alignment

Custom detections are mapped to relevant ATT&CK techniques to provide a
consistent threat-modeling framework.

### Controlled Adversary Simulation

KALI is used to safely generate attack activity inside the isolated lab
environment.

### Documented Investigation and Response

Detection logic is paired with investigation and response guidance so
that alerts can be followed through an operational SOC workflow.

### Continuous Improvement

Detection validation, investigation results, and tuning feed back into
the detection-engineering process.

------------------------------------------------------------------------

## 14. Project Scope

This architecture represents a **controlled SOC training and portfolio
environment** rather than a production enterprise deployment.

The primary objectives are to demonstrate:

-   Active Directory security monitoring
-   Windows endpoint telemetry collection
-   SIEM-based detection
-   Detection engineering
-   MITRE ATT&CK mapping
-   Threat hunting
-   Alert investigation
-   Incident response methodology
-   Detection validation and tuning

The environment is designed to demonstrate how an analyst can move from
**attack activity to telemetry, detection, investigation, and documented
response** within a controlled security operations workflow.

------------------------------------------------------------------------

## 15. Related Documentation

The following repository sections provide additional implementation
details:

-   **Detection Rules Documentation** --- detailed documentation for the
    42 custom Wazuh detections
-   **Incident Response Playbooks** --- investigation and response
    procedures
-   **Wazuh Dashboard Documentation** --- dashboard and visualization
    configuration
-   **Detection → Investigation → Response Workflow** --- operational
    incident-handling workflow
-   **Telemetry Data Flow** --- detailed telemetry collection and
    processing flow
