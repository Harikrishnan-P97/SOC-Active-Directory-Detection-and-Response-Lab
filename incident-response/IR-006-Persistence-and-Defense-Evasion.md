# IR-006 — Persistence & Defense Evasion

## 1. Objective

Provide an operational response workflow for suspected persistence mechanisms and defense-evasion activity detected across the Windows and Active Directory environment.

This playbook helps analysts determine whether unauthorized services, scheduled tasks, Group Policy changes, Startup Folder activity, log clearing, audit-policy changes, Windows Defender tampering, suspicious PowerShell execution, or firewall-rule changes are part of an attacker persistence or defense-evasion chain. The workflow emphasizes identifying the initial compromise, determining which security controls or execution mechanisms were altered, removing the attacker foothold, restoring defensive visibility, and validating that the environment remains observable after recovery.

---

## 2. Scope & Related Detections

### 2.1 Scope

This playbook applies to:

- `DC01` — Active Directory Domain Controller
- `CLIENT01` — Domain-joined Windows endpoint
- Windows services and scheduled tasks
- Active Directory Group Policy Objects
- Windows Startup directories
- Windows Security and System event logs
- Windows audit policy
- Windows Defender
- Windows Defender Firewall
- PowerShell execution
- Wazuh and Sysmon telemetry

### 2.2 Related Detection Rules

| Detection | Description | Wazuh Rule | Severity | Primary Event |
|---|---|---:|---:|---|
| DET-033 | New Windows Service Installed | 100132 | 12 | System Event ID 7045 |
| DET-034 | New Scheduled Task Creation | 100133 | 12 | Security Event ID 4698 |
| DET-035 | Group Policy Modification | 100134 | 12 | Security Event ID 5136 |
| DET-036 | Startup Folder Persistence | 100135 | 14 | Sysmon Event ID 11 |
| DET-037 | Security Event Log Cleared | 100136 | 15 | Security Event ID 1102 |
| DET-038 | Windows Audit Policy Modification | 100137 | 13 | Security Event ID 4719 |
| DET-039 | Windows Defender Tampering | 100138 | 13 | Defender Event IDs 5001/5007/5013 |
| DET-040 | Suspicious PowerShell Execution | 100139 | 10 | Sysmon Event ID 1 |
| DET-041 | Windows Firewall Rule Changed | 100140 | 7 | Security Event IDs 4946/4947/4948 |

### 2.3 Detection-to-Incident Relationship

These detections represent persistence, execution, or defense-evasion indicators. They are not automatically proof of compromise.

The incident-level investigation should determine:

```text
Persistence / Defense-Evasion Alert
              ↓
Validate Host + User + Process + Change
              ↓
Expected / Authorized?
       ├── Yes → Document → Monitor / Close
       │
       └── No / Unclear
              ↓
      Identify Initial Access
              ↓
      Correlate Related Changes
              ↓
   Determine Persistence / Evasion Goal
              ↓
     Contain Attacker Activity
              ↓
       Remove Foothold
              ↓
     Restore Security Controls
              ↓
      Validate Telemetry
```

Multiple detections occurring close together are particularly significant. For example, suspicious PowerShell followed by a new service, scheduled task, Startup Folder file, Defender change, or firewall modification may indicate an attacker establishing persistence while attempting to reduce detection capability.

---

## 3. Attack Scenario

### 3.1 Scenario Overview

After gaining access to a Windows endpoint or Active Directory environment, an adversary may establish persistence and modify security controls to survive reboots, execute repeatedly, hide activity, or prevent defenders from observing the attack.

Persistence can be established through Windows services, scheduled tasks, Startup Folder files, or Group Policy changes. Defense evasion can include clearing the Security log, changing audit policy, modifying or disabling Windows Defender, changing firewall rules, and using PowerShell with execution-policy bypass.

These techniques can occur independently or as coordinated stages of a broader compromise.

### 3.2 Typical Attack Flow

```text
Initial Access / Compromised Account
                ↓
        Privilege Acquisition
                ↓
       Attacker Execution
                ↓
     ┌──────────┼──────────┐
     ↓          ↓          ↓
  Service    Scheduled   Startup
  Install      Task       Folder
     ↓          ↓          ↓
     └──────────┼──────────┘
                ↓
        Establish Persistence
                ↓
       Defense Evasion
                ↓
 ┌──────────────┼──────────────┐
 ↓              ↓              ↓
Audit Policy   Defender       Firewall
Change         Tampering      Change
 ↓              ↓              ↓
 └──────────────┼──────────────┘
                ↓
        Log Clearing / Cover Tracks
                ↓
       Continued Attacker Access
```

Group Policy modification can operate at the domain level and may affect multiple systems, making it particularly important to distinguish a local endpoint compromise from a broader Active Directory security incident.

### 3.3 Expected Detection Sequence

A possible sequence is:

```text
Suspicious PowerShell
        ↓
Persistence Mechanism
        ↓
Security-Control Modification
        ↓
Continued Execution
        ↓
Log Clearing / Defense Evasion
        ↓
Additional Attack Activity
```

Another possible sequence is:

```text
Compromised Account
        ↓
Group Policy Modification
        ↓
Policy Applied to Multiple Systems
        ↓
Security-Control Weakening
        ↓
Persistence / Further Attack
```

The actual order may vary and some techniques may not generate a custom alert.

### 3.4 Potential Impact

Potential impact includes:

- Persistent attacker access after reboot or logoff
- Repeated malicious execution
- Reduced security visibility
- Disabled or weakened Windows Defender protection
- Reduced Windows audit coverage
- Modified firewall controls
- Loss of forensic evidence through log clearing
- Domain-wide policy changes
- Increased difficulty detecting subsequent credential theft or lateral movement
- Continued compromise despite removal of the original payload

---

## 4. Initial Triage

### 4.1 Alert Validation

When an alert triggers:

- Identify the DET ID and Wazuh rule ID.
- Review the complete Wazuh alert and raw Windows/Sysmon/Defender event.
- Record the timestamp.
- Identify the affected host.
- Identify the account responsible for the activity where available.
- Identify the process and command line.
- Record the exact configuration change.
- Determine whether the change was authorized.

For DET-037, preserve the fact that log-clearing occurred and immediately search surrounding telemetry because the action may have been intended to conceal earlier activity.

For DET-035, determine whether the modified object is a Group Policy Container and whether the change could affect multiple domain systems.

### 4.2 Identify Affected Assets

Determine:

- Whether the activity occurred on `CLIENT01`.
- Whether `DC01` was modified or was the source of the AD change.
- Whether a domain-level GPO was modified.
- Whether the security-control change affects one endpoint or multiple systems.
- Whether other hosts generated related alerts.

Changes involving `DC01` or domain-wide Group Policy require elevated scrutiny because the potential blast radius is substantially larger than a single endpoint.

### 4.3 Identify Affected Identity

Determine:

- User/account responsible for the change
- Privilege level
- Whether the account is a service account
- Whether the account normally performs administration
- Recent authentication activity
- Recent account or privilege changes

Correlate with **Authentication & Account Monitoring** and **Active Directory Security** where relevant.

### 4.4 Identify Attack Source

For process-based detections, identify:

- Image
- Original file name
- Command line
- Parent process
- User
- Process path
- Process creation time

For configuration-change detections, identify the account that made the change and the administrative context in which it occurred.

### 4.5 Establish Initial Timeline

Record:

| Time | Detection/Event | Host | User | Change/Process | Finding |
|---|---|---|---|---|---|
| `<time>` | `<event>` | `<host>` | `<user>` | `<change/process>` | `<finding>` |

Search before the first persistence or defense-evasion event for:

- Authentication anomalies
- Credential theft
- Discovery
- Privilege escalation
- Lateral movement
- Suspicious PowerShell
- Initial malicious execution

Search afterward for:

- Persistence execution
- Further credential access
- Lateral movement
- Additional security-control changes
- Log clearing
- Repeated attacker activity

### 4.6 Determine Whether Activity Is Expected

Potentially legitimate activity includes:

- Approved software installation
- Scheduled-task deployment
- Enterprise configuration management
- Authorized GPO administration
- Security-tool maintenance
- Defender configuration changes approved by administrators
- Firewall-rule changes for applications
- Administrative PowerShell
- Security testing

Validate the **user, host, process, command line, timing, configuration change, and authorization**.

A legitimate Windows mechanism can still be abused, so classification should be based on context rather than the technique alone.

---

## 5. Investigation Workflow

### 5.1 Establish the Initial Event

Determine precisely what changed or executed.

**DET-033 — Windows Service**

Review Event ID 7045 and identify:

- Service name
- Service file path
- Service account
- Service type
- Start type
- Installing account where available

Determine whether the service corresponds to approved software or an attacker-created executable.

**DET-034 — Scheduled Task**

Review Event ID 4698 and identify:

- Task name
- Author
- Task action
- Executable/script path
- Trigger
- Run-as account

Determine whether the task executes immediately, at logon, at startup, or on another trigger.

**DET-035 — Group Policy Modification**

Review Event ID 5136 and confirm:

- `objectClass` is `groupPolicyContainer`
- Modified object
- Attribute changed
- Account performing the modification
- Previous/current value where available

Determine whether the GPO change affects security settings, scripts, startup/logon behavior, or other execution mechanisms.

**DET-036 — Startup Folder**

Review Sysmon Event ID 11 and identify:

- `win.eventdata.targetFilename`
- Creating process
- Source image
- User
- Startup directory involved

Determine whether the created file will execute at user logon or system startup.

**DET-037 — Security Log Cleared**

Review Event ID 1102 and identify:

- Account that cleared the log
- Timestamp
- Host
- Related activity immediately before the clearing event

Treat the event as a potential indicator-removal action rather than an isolated administrative event.

**DET-038 — Audit Policy Modification**

Review Event ID 4719 and determine:

- Audit subcategory changed
- Previous setting
- New setting
- Account responsible

Identify whether logging for authentication, process creation, privilege use, or other security-relevant activity was weakened.

**DET-039 — Defender Tampering**

Review Defender Operational Event IDs:

- `5001` — Real-Time Protection disabled
- `5007` — Configuration modified
- `5013` — Defender engine status modified/stopped

Determine exactly which protection or configuration was changed.

**DET-040 — Suspicious PowerShell**

Review Sysmon Event ID 1 and identify:

- PowerShell image
- Command line
- Parent process
- User
- Process path

The custom detection specifically identifies PowerShell command lines containing `-ExecutionPolicy Bypass`. Determine what the PowerShell command actually executed.

**DET-041 — Firewall Rule Changed**

Review Event IDs:

- `4946` — Firewall rule added
- `4947` — Firewall rule modified
- `4948` — Firewall rule deleted

Identify:

- `win.eventdata.ruleName`
- `win.eventdata.ruleId`
- Event ID
- Account
- Host

Determine whether the change opened, closed, or otherwise altered a security-relevant network path.

### 5.2 Investigate the Source

Determine whether the system was already compromised before the persistence/evasion event.

Review:

- Authentication
- Process creation
- PowerShell
- Credential access
- Discovery
- Lateral movement
- Existing persistence
- Network connections
- Other custom detections

Use the **Sysmon Endpoint Activity** dashboard for process activity and the **SOC Detection Overview** dashboard for correlated detections.

### 5.3 Investigate the Account / Identity

Determine:

- Whether the account normally performs the observed administration.
- Whether the account recently authenticated from an unusual host.
- Whether the account has privileged group membership.
- Whether the account was recently created, enabled, reset, or modified.
- Whether the same account performed other suspicious changes.

If account compromise is suspected, continue with **IR-001** or **IR-002** as appropriate.

### 5.4 Investigate the Affected Host

For `CLIENT01`, review:

- Process tree
- PowerShell execution
- New services
- Scheduled tasks
- Startup files
- Defender status/configuration
- Firewall rules
- Audit policy
- Event-log state
- Network connections
- Other persistence mechanisms

For `DC01`, investigate:

- GPO modifications
- Audit-policy changes
- Defender/security-control changes
- Suspicious PowerShell
- New services/tasks
- Log clearing
- Other administrative activity

Do not assume that every change on `DC01` is malicious; however, unauthorized changes on the Domain Controller should be treated as high-risk.

### 5.5 Correlate Related Detection Activity

Search for detections occurring before and after the initial event:

- DET-033 — Service installation
- DET-034 — Scheduled task creation
- DET-035 — GPO modification
- DET-036 — Startup Folder persistence
- DET-037 — Log clearing
- DET-038 — Audit policy modification
- DET-039 — Defender tampering
- DET-040 — Suspicious PowerShell
- DET-041 — Firewall change
- IR-001 — Authentication/account compromise
- IR-002 — AD account/privilege compromise
- IR-003 — Credential theft
- IR-004 — Discovery
- IR-005 — Lateral movement

A sequence such as:

```text
Suspicious PowerShell
        ↓
New Scheduled Task / Service
        ↓
Defender Tampering
        ↓
Firewall Modification
        ↓
Log Clearing
```

is substantially more concerning than an isolated administrative change.

### 5.6 Build the Attack Timeline

Document:

1. Initial suspicious authentication or execution
2. First malicious process
3. Privilege escalation, if present
4. Persistence mechanism created
5. Security controls modified
6. Log clearing or other indicator removal
7. Subsequent execution
8. Credential theft/lateral movement
9. Most recent attacker activity

Where Event ID 1102 is present, carefully examine events immediately before the log-clearing action. Earlier evidence may have been removed from the Windows Security log, so use Wazuh archives and other available telemetry where possible.

### 5.7 Determine Attack Scope

Determine whether the incident affects:

- One endpoint
- Multiple endpoints
- One user
- Multiple accounts
- One local configuration
- A domain-wide Group Policy
- `DC01`
- Multiple security controls

For GPO modification, identify which systems may receive the affected policy.

For Defender, audit-policy, or firewall changes, determine whether the control was weakened on one host or across multiple systems.

### 5.8 Determine Evidence of Compromise

Treat the activity as stronger evidence of compromise when:

- The change was unauthorized.
- The initiating account is compromised or anomalous.
- A suspicious process created the persistence mechanism.
- Multiple persistence mechanisms are present.
- Security controls were weakened after malicious execution.
- The Security log was cleared after suspicious activity.
- The same source performs credential theft or lateral movement.
- A GPO change creates execution or security-control changes across multiple systems.

---

## 6. Incident Assessment

### 6.1 Suspicious Activity

Examples:

- A new service appears outside an approved software deployment.
- A new scheduled task executes from a user-writable directory.
- A Startup Folder file is created unexpectedly.
- PowerShell runs with `-ExecutionPolicy Bypass`.
- A firewall rule changes without an approved change record.
- Defender configuration changes unexpectedly.

### 6.2 Confirmed Malicious Activity

Examples:

- An unauthorized persistence mechanism executes attacker-controlled code.
- Defender is disabled immediately before credential theft.
- Audit policy is weakened to reduce telemetry.
- A malicious GPO modifies execution or security settings.
- The Security log is cleared following suspicious activity.
- Multiple defense-evasion techniques occur in sequence.

### 6.3 Confirmed Compromise

Consider compromise confirmed when persistence or defense evasion is linked to:

- Known malicious execution
- Compromised credentials
- Lateral movement
- Credential theft
- Unauthorized privileged access
- Attacker-controlled infrastructure
- Multiple correlated malicious detections

### 6.4 Severity Considerations

Increase severity when:

- Event ID 1102 is confirmed.
- `DC01` is affected.
- A domain-level GPO is modified maliciously.
- Multiple security controls are weakened.
- Persistence survives reboot/logon.
- Privileged credentials are involved.
- Credential theft or lateral movement follows.
- The attacker has established multiple independent persistence mechanisms.

---

## 7. Containment

### 7.1 Immediate Containment

If malicious persistence or defense evasion is active:

- Isolate the compromised endpoint, such as `CLIENT01`, when appropriate.
- Stop attacker-controlled processes.
- Disable or remove active malicious persistence where safe.
- Prevent continued access from the identified source.
- Preserve relevant evidence before cleanup where practical.

Do not immediately isolate `DC01` without considering the impact on Active Directory availability.

### 7.2 Account Containment

If the initiating account is compromised:

- Disable or lock the account when appropriate.
- Reset credentials.
- Remove unauthorized privileged access.
- Terminate active sessions where supported.
- Investigate other systems where the account authenticated.

### 7.3 Endpoint Containment

For a compromised endpoint:

- Isolate it from the network.
- Stop malicious services/tasks/processes where safe.
- Prevent execution of identified payloads.
- Preserve persistence artifacts and relevant event data before removal.

### 7.4 AD Containment

For malicious GPO or privileged AD activity:

- Identify the affected GPO.
- Prevent further unauthorized modification.
- Restrict the compromised administrative account.
- Remove unauthorized privileged access.
- Determine which systems may have received the modified policy.

Avoid broad GPO rollback until the intended configuration and affected scope are understood.

### 7.5 Additional Containment Actions

Depending on the technique:

**Service / Scheduled Task / Startup Folder**
- Disable the malicious execution mechanism.
- Prevent its payload from running again.

**Log Clearing / Audit Policy**
- Restore appropriate logging.
- Preserve remaining Wazuh and endpoint telemetry.

**Defender**
- Re-enable required protection.
- Remove unauthorized exclusions or configuration changes.

**Firewall**
- Revert unauthorized rules.
- Restrict newly exposed ports where appropriate.

**PowerShell**
- Contain the source process.
- Preserve the command line and associated scripts.

---

## 8. Eradication

### 8.1 Remove Attacker Access

- Remove unauthorized accounts or access paths.
- Revoke compromised credentials.
- Remove unauthorized privileged membership.
- Address the initial access vector.

### 8.2 Remove Persistence / Malicious Artifacts

- Remove malicious Windows services.
- Remove unauthorized scheduled tasks.
- Remove Startup Folder payloads.
- Remove malicious scripts and executables.
- Remove unauthorized GPO changes after documenting and preserving evidence.
- Remove other persistence discovered during investigation.

### 8.3 Remediate Compromised Credentials

If persistence or defense evasion resulted from a compromised account:

- Reset the affected credentials.
- Reset privileged credentials when exposed.
- Review service-account exposure.
- Investigate additional systems accessed with the same credentials.
- Continue with IR-003 when credential theft is identified.

### 8.4 Restore Unauthorized Changes

Restore the intended security configuration for:

- Audit policy
- Windows Defender
- Windows Firewall
- Group Policy
- Scheduled tasks
- Windows services
- Startup directories
- Other modified security settings

For Event ID 1102, the cleared log cannot be restored from the Windows Security log itself. Preserve available Wazuh archives and other telemetry as evidence and restore logging for future activity.

---

## 9. Recovery & Validation

### 9.1 System Recovery

- Return contained endpoints to normal operation only after remediation.
- Verify required services and applications.
- Confirm malicious persistence does not execute after reboot or logon.
- Verify normal endpoint operation.

### 9.2 Account / AD Recovery

- Verify affected accounts are secured.
- Confirm privileged memberships are correct.
- Verify GPO configuration is correct.
- Confirm Active Directory functionality remains healthy.
- Verify intended domain policies are being applied.

### 9.3 Security Control Recovery

Verify:

- Windows audit policy is restored.
- Windows Defender protection is enabled and correctly configured.
- Windows Firewall rules match the intended baseline.
- Security event logging is functioning.
- Sysmon is running.
- Wazuh is receiving telemetry.

### 9.4 Telemetry Validation

Confirm Wazuh receives the event sources required for detection:

- Windows System Event ID 7045
- Windows Security Event ID 4698
- Windows Security Event ID 5136
- Sysmon Event ID 11
- Windows Security Event ID 1102
- Windows Security Event ID 4719
- Windows Defender Event IDs 5001/5007/5013
- Sysmon Event ID 1
- Windows Security Event IDs 4946/4947/4948

Verify the affected custom detections remain operational after recovery.

### 9.5 Post-Recovery Monitoring

Monitor for:

- Recreated services
- Recreated scheduled tasks
- New Startup Folder files
- Additional GPO changes
- Repeated audit-policy changes
- Defender tampering
- Firewall changes
- Suspicious PowerShell
- Event-log clearing
- Credential theft
- Lateral movement

Maintain heightened monitoring until recurrence is no longer observed.

---

## 10. Escalation Criteria

### 10.1 Escalate When

Escalate to a senior analyst or incident lead when:

- Unauthorized persistence is confirmed.
- Multiple persistence mechanisms are present.
- Security controls were deliberately weakened.
- Event ID 1102 is confirmed without an approved administrative explanation.
- A compromised account made the changes.
- The source endpoint cannot be confidently contained.
- The attack path cannot be established.

### 10.2 High-Risk Conditions

Prioritize escalation when:

- `DC01` is affected.
- A domain-level GPO is maliciously modified.
- Audit logging is disabled or weakened.
- Defender protection is disabled or materially weakened.
- Multiple security controls are modified together.
- Log clearing occurs after credential theft, privilege escalation, or lateral movement.
- Persistence is established using multiple mechanisms.
- Privileged credentials are involved.

### 10.3 Domain-Level Compromise Indicators

Treat the incident as potentially domain-wide when:

- A malicious GPO affects multiple systems.
- `DC01` is compromised.
- Domain administrative credentials are involved.
- Persistence is deployed across multiple endpoints.
- Security controls are weakened across multiple systems.
- Defense evasion is followed by credential theft or lateral movement.
- The attacker maintains access despite remediation of the original endpoint.

---

## 11. Closure Criteria

### 11.1 Investigation Complete

- Initial detection validated.
- Source account and host identified.
- Persistence/evasion technique identified.
- Initial access path investigated.
- Related detections correlated.
- Attack timeline documented.
- Scope determined.

### 11.2 Containment Complete

- Active attacker access stopped.
- Compromised endpoints contained.
- Compromised accounts secured.
- Unauthorized privileged access removed.
- Further persistence or defense evasion prevented.

### 11.3 Eradication Complete

- Malicious services/tasks/startup artifacts removed.
- Unauthorized GPO changes remediated.
- Malicious scripts and executables removed.
- Security-control modifications reverted.
- Compromised credentials remediated.
- Initial access vector addressed.

### 11.4 Recovery Complete

- Systems returned to normal operation.
- Active Directory and GPO functionality verified.
- Defender protection restored.
- Firewall configuration restored.
- Audit policy restored.
- Required services and scheduled tasks verified.

### 11.5 Validation Complete

- Windows logging functioning.
- Sysmon telemetry functioning.
- Wazuh receiving telemetry.
- Relevant custom detections operational.
- No recurring persistence or defense-evasion activity observed.

### 11.6 Final Documentation

Document:

- Initial detection
- Persistence/evasion mechanism
- Source account and host
- Exact configuration changes
- Related processes and commands
- Initial access indicators
- Attack timeline
- Affected systems/accounts
- Security controls affected
- Containment actions
- Eradication actions
- Credential remediation
- Recovery and validation results
- Remaining risks or monitoring requirements

---

## 12. MITRE ATT&CK Mapping

| Technique | Name | Relevance |
|---|---|---|
| T1543.003 | Create or Modify System Process: Windows Service | DET-033 identifies newly installed Windows services that may provide persistent or privileged execution. |
| T1053.005 | Scheduled Task/Job: Scheduled Task | DET-034 identifies newly created scheduled tasks that may provide recurring or trigger-based execution. |
| T1484.001 | Domain or Tenant Policy Modification: Group Policy Modification | DET-035 identifies modifications to Group Policy Containers that may alter domain security or execution behavior. |
| T1547.001 | Boot or Logon Autostart Execution: Registry Run Keys / Startup Folder | DET-036 identifies files created in Windows Startup directories that may execute at logon/startup. |
| T1070.004 | Indicator Removal: File Deletion / Clear Windows Event Logs | DET-037 identifies Windows Security log clearing used to remove evidence. |
| T1562.002 | Impair Defenses: Disable Windows Event Logging | DET-038 identifies changes to Windows audit policy that can reduce security telemetry. |
| T1562.001 | Impair Defenses: Disable or Modify Tools | DET-039 identifies Windows Defender protection/configuration changes. |
| T1059.001 | Command and Scripting Interpreter: PowerShell | DET-040 identifies PowerShell execution using `-ExecutionPolicy Bypass`. |
| T1562.004 | Impair Defenses: Disable or Modify System Firewall | DET-041 identifies Windows Firewall rule additions, modifications, and deletions. |

---

## Analyst Decision Flow

```text
Wazuh Persistence / Evasion Alert
              ↓
Validate Host + User + Process + Change
              ↓
Expected / Authorized?
       ├── Yes → Document → Monitor / Close
       │
       └── No / Unclear
              ↓
       Investigate Initial Access
              ↓
   Persistence / Evasion Confirmed?
       ├── No → Continue Investigation
       │
       └── Yes
              ↓
     Multiple Mechanisms / Controls?
       ├── No → Targeted Containment
       │
       └── Yes
              ↓
       Assess Attack Chain
              ↓
 Credential Theft / Lateral Movement?
       ├── No → Eradicate + Recover
       │
       └── Yes → Correlate IR-003 / IR-005
              ↓
      Domain-Level Impact?
       ├── No → Recover + Validate
       │
       └── Yes → Escalate Incident
              ↓
       Validate Logging + Security Controls
              ↓
        Heightened Monitoring
              ↓
             Close
```

---

## Related Playbooks

- **[IR-001 — Credential Attack & Account Compromise](../incident-response/IR-001-Credential-Attack-and-Account-Compromise.md)** — Authentication anomalies or compromised accounts associated with persistence activity.

- **[IR-002 — AD Account & Privilege Compromise](../incident-response/IR-002-Active-Directory-Account-and-Privilege-Compromise.md)** — Unauthorized account, privilege, group, or AD object changes associated with the incident.

- **[IR-003 — Kerberos & Credential Theft Attack](../incident-response/IR-003-Kerberos-and-Credential-Theft-Attack.md)** — Credential theft discovered before or during persistence/defense-evasion activity.

- **[IR-004 — Active Directory Discovery & Reconnaissance](../incident-response/IR-004-AD-Discovery-and-Reconnaissance.md)** — Reconnaissance performed before establishing persistence.

- **[IR-005 — Lateral Movement & Remote Execution](../incident-response/IR-005-Lateral-Movement-and-Remote-Execution.md)** — Remote access or execution associated with the persistence/evasion incident.

DET-033 through DET-041 are intentionally handled as one incident-response scenario because persistence and defense evasion frequently operate together: an attacker establishes a foothold, weakens visibility, and maintains access rather than treating each technique as an isolated incident.

- [DET-033 — New Windows Service Installed](../docs/detections/07-persistence-and-defense-evasion/DET-033-New-Windows-Service-Installed.md)
- [DET-034 — New Scheduled Task Creation](../docs/detections/07-persistence-and-defense-evasion/DET-034-New-Scheduled-Task-Creation.md)
- [DET-035 — Group Policy Modification](../docs/detections/07-persistence-and-defense-evasion/DET-035-Group-Policy-Modification.md)
- [DET-036 — Startup Folder Persistence](../docs/detections/07-persistence-and-defense-evasion/DET-036-Startup-Folder-Persistence.md)
- [DET-037 — Security Event Log Cleared](../docs/detections/07-persistence-and-defense-evasion/DET-037-Security-Event-Log-Cleared.md)
- [DET-038 — Windows Audit Policy Modification](../docs/detections/07-persistence-and-defense-evasion/DET-038-Windows-Audit-Policy-Modification.md)
- [DET-039 — Windows Defender Tampering](../docs/detections/07-persistence-and-defense-evasion/DET-039-Windows-Defender-Tampering.md)
- [DET-040 — Suspicious PowerShell Execution](../docs/detections/07-persistence-and-defense-evasion/DET-040-Suspicious-PowerShell-Execution.md)
- [DET-041 — Windows Firewall Rule Changed](../docs/detections/07-persistence-and-defense-evasion/DET-041-Windows-Firewall-Rule-Changed.md)
