# IR-005 — Lateral Movement & Remote Execution

## 1. Objective

Provide an operational response workflow for suspected lateral movement and remote execution across Windows and Active Directory systems detected by Wazuh.

This playbook helps analysts determine whether PsExec, SMB administrative-share access, WinRM, WMI, or RDP activity represents authorized administration or attacker-controlled remote access. The workflow focuses on identifying the source and destination, validating the account and execution context, correlating the remote-access activity with credential abuse and endpoint execution, and containing movement before additional systems are compromised.

---

## 2. Scope & Related Detections

### 2.1 Scope

This playbook applies to:

- `DC01` — Active Directory Domain Controller
- `CLIENT01` — Domain-joined Windows endpoint
- Domain and privileged user accounts
- Windows remote administration services
- SMB administrative shares
- WinRM / PowerShell remoting
- WMI remote execution
- Remote Desktop Protocol
- PsExec-based remote execution
- Wazuh and Sysmon telemetry associated with lateral movement

### 2.2 Related Detection Rules

| Detection | Description | Wazuh Rule | Severity | Primary Event |
|---|---|---:|---:|---|
| DET-028 | PsExec Process Execution | 100127 | 12 | Sysmon Event ID 1 |
| DET-029 | SMB Admin Share Access | 100128 | 12 | Windows Security Event ID 5140 |
| DET-030 | WinRM Execution | 100129 | 12 | Sysmon Event ID 1 |
| DET-031 | WMI Execution | 100130 | 12 | Sysmon Event ID 1 / Security Event ID 4688 |
| DET-032 | Successful RDP Logon | 100131 | 7 | Windows Security Event ID 4624 |

### 2.3 Detection-to-Incident Relationship

These detections represent individual indicators of remote access or remote execution. A legitimate administrator may generate the same underlying Windows events.

The incident-level investigation should establish:

```text
Remote Access / Execution Alert
            ↓
Identify Source + Destination + User
            ↓
Validate Administrative Authorization
            ↓
Investigate Remote Execution Context
            ↓
Correlate Authentication + Process Activity
            ↓
Determine Whether Movement Is Malicious
            ↓
Identify Additional Compromised Hosts
            ↓
Contain Source + Destination
            ↓
Eradicate Attacker Access
```

Multiple remote-access detections involving the same account, source, destination, or short timeframe provide stronger evidence of coordinated lateral movement.

---

## 3. Attack Scenario

### 3.1 Scenario Overview

After obtaining valid credentials or compromising an endpoint, an adversary may move laterally through the Windows environment using legitimate remote administration mechanisms.

PsExec can execute processes remotely through SMB and Windows services. SMB administrative shares can be used to access `ADMIN$` or `C$` and stage files. WinRM can provide remote command execution through `wsmprovhost.exe`. WMI can execute commands remotely through `WmiPrvSE.exe`. RDP can provide an interactive remote desktop session using Logon Type 10.

These techniques can be used individually or as parts of a larger attack chain.

### 3.2 Typical Attack Flow

```text
Initial Access / Credential Compromise
                ↓
       Identify Target Systems
                ↓
      ┌─────────┼──────────┐
      ↓         ↓          ↓
     SMB      WinRM       RDP
      ↓         ↓          ↓
   PsExec      WMI     Interactive
      ↓         ↓       Session
      └─────────┼──────────┘
                ↓
       Remote Process Execution
                ↓
      Credential / Privilege Abuse
                ↓
      Persistence or Data Access
                ↓
       Additional Lateral Movement
```

A common PsExec chain may look like:

```text
Compromised Source
      ↓
SMB / ADMIN$ or C$
      ↓
PSEXESVC
      ↓
Remote Process
      ↓
SYSTEM-level Execution
```

This is a representative attack path, not a guaranteed sequence.

### 3.3 Expected Detection Sequence

Possible detection sequences include:

**PsExec / SMB movement**

```text
DET-029 — ADMIN$ / C$ access
        ↓
DET-028 — PsExec execution
        ↓
Remote service / process execution
        ↓
Follow-on process activity
```

**WinRM movement**

```text
Remote Authentication
        ↓
DET-030 — wsmprovhost.exe
        ↓
Child Process Execution
        ↓
Command / Script Activity
```

**WMI movement**

```text
Remote Authentication
        ↓
WmiPrvSE.exe
        ↓
DET-031 — Suspicious Child Process
        ↓
Command / Script / Payload Execution
```

**RDP movement**

```text
DET-032 — Successful Logon Type 10
        ↓
Interactive Session
        ↓
Administrative / Command Execution
        ↓
Potential Credential Access or Further Movement
```

These sequences are investigative patterns and should not be treated as mandatory event order.

### 3.4 Potential Impact

Lateral movement can result in:

- Unauthorized access to additional Windows hosts
- Privilege escalation
- Execution under `SYSTEM`
- Deployment of malware or ransomware
- Credential theft from additional systems
- Access to sensitive files and services
- Compromise of administrative workstations
- Domain Controller compromise
- Expansion from a single compromised endpoint to domain-wide compromise

---

## 4. Initial Triage

### 4.1 Alert Validation

When a lateral-movement alert triggers:

- Identify the DET ID and Wazuh rule ID.
- Review the complete Wazuh alert and raw Windows/Sysmon event.
- Record the timestamp.
- Identify the source host.
- Identify the destination host where available.
- Identify the account involved.
- Identify the source IP address.
- Review command line, process image, parent process, and logon context.
- Determine whether the activity is authorized.

For DET-028 through DET-031, process execution context is particularly important. For DET-032, validate the source IP, target account, and RDP session context.

### 4.2 Identify Affected Assets

Establish:

- Source system
- Destination system
- Any additional systems accessed afterward
- Whether `CLIENT01` is the source or target
- Whether `DC01` is involved
- Whether a privileged administrative workstation is involved

A lateral-movement event involving `DC01` should receive elevated scrutiny because compromise of the Domain Controller can expose the wider Active Directory environment.

### 4.3 Identify Affected Identity

Record:

- Account name
- Domain
- Privilege level
- Whether the account is a service account
- Whether the account normally administers the destination
- Recent authentication history
- Recent password or privilege changes

Correlate with **Authentication & Account Monitoring** and **Active Directory Security** when relevant.

### 4.4 Identify Attack Source

Determine:

- Source IP
- Source hostname
- Destination hostname
- Executing user
- Process image
- Original file name
- Parent process
- Command line
- Authentication mechanism

For PsExec, inspect the remote target and command-line parameters.

For WinRM, identify `wsmprovhost.exe` and investigate its child processes.

For WMI, identify `WmiPrvSE.exe` and the suspicious child process.

For RDP, identify the source IP and target account associated with Logon Type 10.

### 4.5 Establish Initial Timeline

Record:

| Time | Detection/Event | Source | Destination | User | Finding |
|---|---|---|---|---|---|
| `<time>` | `<event>` | `<source>` | `<destination>` | `<user>` | `<finding>` |

Search before and after the triggering event for:

- Failed and successful authentication
- Credential theft
- Discovery
- Privilege escalation
- Process creation
- File creation
- Persistence
- Additional remote access
- Security-control tampering

### 4.6 Determine Whether Activity Is Expected

Potentially legitimate activity includes:

- IT support
- Remote administration
- Patch management
- Software deployment
- Approved PowerShell remoting
- Authorized WMI management
- Administrative RDP sessions
- Security assessment activity

Validate the **user, source, destination, process, command line, timing, and authorization**.

A legitimate administrative tool does not automatically make the activity benign.

---

## 5. Investigation Workflow

### 5.1 Establish the Initial Event

Determine exactly what remote-access mechanism was used.

**DET-028 — PsExec**

Review:

- `win.eventdata.image`
- `win.eventdata.user`
- `win.eventdata.commandLine`
- `win.eventdata.parentImage`
- Target system specified in the command line
- Whether `-s` was used
- Whether `-u` / `-p` was supplied
- Whether `-c` was used

Use of `-s` is particularly significant because it requests execution under `NT AUTHORITY\SYSTEM`.

**DET-029 — SMB Administrative Share**

Review:

- `win.eventdata.shareName`
- `win.eventdata.subjectUserName`
- `win.eventdata.subjectDomainName`
- `win.eventdata.ipAddress`
- `win.eventdata.ipPort`
- Destination host

Determine whether `ADMIN$` or `C$` access was part of a larger remote-execution sequence.

**DET-030 — WinRM**

Confirm:

- `wsmprovhost.exe`
- Source system
- User context
- Parent/child processes
- Command or script executed remotely

**DET-031 — WMI**

Confirm:

- `WmiPrvSE.exe`
- Suspicious child process
- User context
- Source client where available
- Command or payload executed

**DET-032 — RDP**

Confirm:

- Event ID 4624
- Logon Type 10
- Target account
- Source IP
- Target host
- Interactive processes launched after the session

### 5.2 Investigate the Source

Determine whether the source host was already compromised.

Review:

- Recent authentication
- Process creation
- PowerShell activity
- Credential-access detections
- Discovery activity
- Persistence
- Network connections
- Other lateral-movement detections

Use the **Sysmon Endpoint Activity** dashboard for process activity and the **SOC Detection Overview** dashboard for correlated detections.

If the source host is `CLIENT01`, determine whether it represents the initial compromised endpoint or simply a pivot point.

### 5.3 Investigate the Account / Identity

Determine:

- Whether the account is authorized to access the destination.
- Whether it normally uses the observed remote service.
- Whether authentication originated from the expected workstation.
- Whether the account recently generated authentication anomalies.
- Whether the account has privileged group membership.

If the account appears compromised, continue with **IR-001 — Credential Attack & Account Compromise** and **IR-003 — Kerberos & Credential Theft Attack** as applicable.

### 5.4 Investigate the Destination Host

Review the destination for:

- Process creation
- Child processes
- Service creation
- File creation
- PowerShell
- Credential access
- Persistence
- Additional authentication
- Additional lateral movement

For PsExec, investigate `PSEXESVC` and processes launched by the remote service.

For WinRM, investigate processes associated with `wsmprovhost.exe`.

For WMI, investigate processes spawned by `WmiPrvSE.exe`.

For RDP, investigate interactive processes created after the Type 10 logon.

If `DC01` is the destination, prioritize evidence preservation and Active Directory availability.

### 5.5 Correlate Related Detection Activity

Search for related detections around the same timeframe:

- DET-028 — PsExec
- DET-029 — SMB administrative share
- DET-030 — WinRM
- DET-031 — WMI
- DET-032 — RDP
- IR-001 authentication detections
- IR-002 account and privilege changes
- IR-003 credential theft
- IR-004 discovery
- IR-006 persistence and defense evasion

A stronger lateral-movement chain may look like:

```text
Credential Compromise
        ↓
Authentication from CLIENT01
        ↓
Discovery
        ↓
SMB / WinRM / WMI / RDP
        ↓
Remote Process Execution
        ↓
Privilege / Credential Access
        ↓
Second Host
```

### 5.6 Build the Attack Timeline

Document:

1. Initial suspicious authentication
2. Source-host compromise indicators
3. Discovery activity
4. First remote connection
5. Remote execution
6. Destination-host execution
7. Credential or privilege activity
8. Subsequent remote connections
9. Persistence or defense evasion
10. Most recent attacker activity

Maintain the timeline in chronological order.

### 5.7 Determine Attack Scope

Determine whether lateral movement affected:

- One source and one destination
- Multiple Windows endpoints
- Multiple user accounts
- Administrative workstations
- `DC01`
- Multiple domain systems

Identify the **first compromised system** and the **furthest confirmed destination**.

Where possible, construct:

```text
Source → Destination → Destination → Destination
```

This provides a practical representation of the attack path.

### 5.8 Determine Evidence of Compromise

Remote administration should be treated as stronger evidence of compromise when:

- The account is not authorized for the destination.
- The source endpoint shows compromise indicators.
- Remote execution is followed by suspicious child processes.
- PsExec is executed with suspicious parameters.
- SMB administrative-share access is followed by file staging or execution.
- WinRM or WMI launches suspicious commands.
- RDP is followed by credential theft, discovery, or additional movement.
- Multiple remote-access mechanisms are used in sequence.
- The same credentials are used across multiple unexpected systems.

---

## 6. Incident Assessment

### 6.1 Suspicious Activity

Examples:

- A standard user unexpectedly accesses `ADMIN$`.
- A user initiates RDP to a system they do not normally administer.
- `wsmprovhost.exe` launches an unusual process.
- `WmiPrvSE.exe` launches a command shell.
- PsExec executes from an unusual endpoint.
- Remote access occurs at an unusual time or from an unexpected source.

### 6.2 Confirmed Malicious Activity

Examples:

- Unauthorized PsExec execution.
- Unauthorized SMB administrative-share access associated with payload staging.
- Suspicious WinRM execution.
- WMI remote execution followed by malicious child processes.
- Unauthorized RDP followed by attacker-controlled activity.
- Remote execution linked to a compromised account.

### 6.3 Confirmed Compromise

Consider compromise confirmed when evidence demonstrates:

- Attacker-controlled commands executed on the destination.
- Malicious payloads were transferred or executed.
- Compromised credentials were used for lateral movement.
- The destination host subsequently generated additional attack detections.
- Multiple systems were accessed as part of a coherent attack chain.

### 6.4 Severity Considerations

Increase severity when:

- `DC01` is involved.
- Privileged credentials are used.
- Multiple hosts are affected.
- Multiple remote-access mechanisms are used.
- Credential theft occurs on the destination.
- Persistence is established.
- The destination is an administrative or security-sensitive system.
- Lateral movement progresses across several systems.

---

## 7. Containment

### 7.1 Immediate Containment

If active malicious lateral movement is confirmed:

- Isolate the compromised source endpoint.
- Isolate compromised destination endpoints when appropriate.
- Stop attacker-controlled remote processes where safe.
- Terminate unauthorized remote sessions.
- Preserve relevant evidence before cleanup where practical.
- Prevent further access from identified attacker sources.

Avoid indiscriminately disabling remote-management services across the environment if doing so would disrupt legitimate operations. Containment should be targeted whenever possible.

### 7.2 Account Containment

For compromised accounts:

- Disable or lock the account when appropriate.
- Reset credentials.
- Terminate active sessions where supported.
- Remove unauthorized privileged access.
- Review other systems accessed by the same account.

If privileged credentials were used for lateral movement, assess whether those credentials should be considered compromised.

### 7.3 Endpoint Containment

For compromised Windows endpoints:

- Isolate the endpoint from the network.
- Stop malicious processes.
- Preserve process and file evidence.
- Restrict identified attacker infrastructure where appropriate.
- Investigate both source and destination systems.

When the destination is `DC01`, containment decisions must account for Active Directory availability and should avoid unnecessary disruption.

### 7.4 AD Containment

If lateral movement involves privileged AD credentials:

- Secure the affected account.
- Remove unauthorized privileged group membership.
- Review privileged authentication across the domain.
- Identify other systems accessed with the same credentials.
- Treat the credentials as potentially exposed until remediation is complete.

### 7.5 Additional Containment Actions

Depending on the technique:

**PsExec / SMB**
- Restrict unnecessary SMB connectivity.
- Remove unauthorized remote services or payloads.
- Review `ADMIN$` / `C$` activity.

**WinRM**
- Restrict remote WinRM access to authorized administrative systems where practical.
- Terminate unauthorized sessions.

**WMI**
- Restrict remote WMI/DCOM access where appropriate.
- Review suspicious WMI child processes.

**RDP**
- Terminate unauthorized RDP sessions.
- Restrict RDP exposure to approved administrative paths.

---

## 8. Eradication

### 8.1 Remove Attacker Access

- Remove unauthorized accounts and access paths.
- Revoke compromised credentials.
- Remove unauthorized privileged membership.
- Address the initial access vector.
- Remove unauthorized remote-access configuration where identified.

### 8.2 Remove Persistence / Malicious Artifacts

- Remove malicious executables and scripts.
- Remove payloads transferred through `ADMIN$` or `C$`.
- Remove unauthorized services such as attacker-created PsExec services.
- Remove persistence established after remote execution.
- Remove malicious WMI or scheduled execution mechanisms where discovered.

### 8.3 Remediate Compromised Credentials

If credentials were used for lateral movement:

- Reset the affected user credentials.
- Reset privileged credentials when exposed.
- Reset service-account credentials when exposed.
- Investigate whether the same credentials were used on additional hosts.
- Continue with IR-003 when credential-theft evidence is identified.

### 8.4 Restore Unauthorized Changes

Review and revert unauthorized:

- Service creation
- Account changes
- Group membership changes
- Scheduled tasks
- WMI persistence
- RDP configuration
- Firewall changes
- Other attacker-created access mechanisms

---

## 9. Recovery & Validation

### 9.1 System Recovery

- Return isolated endpoints to normal operation only after remediation.
- Verify required Windows services and applications.
- Confirm no attacker-controlled processes remain.
- Verify remote administration functions normally where required.

### 9.2 Account / AD Recovery

- Verify affected accounts are secured.
- Confirm privileged memberships are correct.
- Confirm unauthorized accounts and access paths are removed.
- Verify Active Directory authentication and replication remain healthy.

### 9.3 Security Control Recovery

Verify:

- Windows security logging is functioning.
- Sysmon is running.
- Wazuh is receiving endpoint telemetry.
- RDP, WinRM, WMI, and SMB controls remain in the intended security state.
- No attacker-modified security controls remain.

### 9.4 Telemetry Validation

Confirm Wazuh receives the telemetry required for:

- Sysmon Event ID 1 process creation
- Windows Security Event ID 4624
- Windows Security Event ID 5140
- Remote execution process activity
- Related authentication and endpoint events

Verify the relevant custom detections remain operational.

### 9.5 Post-Recovery Monitoring

Monitor for:

- New PsExec execution
- New administrative-share access
- New WinRM sessions
- New WMI remote execution
- Unexpected RDP logons
- Repeated authentication from unusual sources
- Additional compromised endpoints
- Credential theft
- Privilege escalation
- Persistence

Maintain heightened monitoring until the lateral-movement path is understood and recurrence is no longer observed.

---

## 10. Escalation Criteria

### 10.1 Escalate When

Escalate to a senior analyst or incident lead when:

- Unauthorized lateral movement is confirmed.
- A compromised account is used across multiple hosts.
- Multiple destination systems are affected.
- Remote execution is confirmed.
- Privileged credentials are involved.
- The source endpoint cannot be confidently contained.
- The complete attack path cannot be established.

### 10.2 High-Risk Conditions

Prioritize escalation when:

- `DC01` is accessed through unauthorized remote execution.
- Domain Admin or equivalent privileged credentials are used.
- PsExec executes with `SYSTEM` privileges.
- Remote execution is followed by credential dumping.
- Multiple hosts are compromised.
- Persistence is established on destination systems.
- Lateral movement occurs through several remote-access mechanisms.

### 10.3 Domain-Level Compromise Indicators

Treat the incident as potentially domain-wide when:

- `DC01` is compromised.
- Privileged credentials are reused across multiple systems.
- Multiple administrative hosts are compromised.
- Credential theft follows remote execution.
- Lateral movement continues after initial containment.
- Multiple hosts show coordinated attacker activity.
- The attacker demonstrates sustained access across the domain.

---

## 11. Closure Criteria

### 11.1 Investigation Complete

- Initial remote-access event validated.
- Source and destination systems identified.
- User/account identified.
- Remote-access mechanism identified.
- Attack path reconstructed.
- Related detections correlated.
- Scope determined.

### 11.2 Containment Complete

- Active remote access stopped.
- Compromised source and destination systems contained.
- Compromised accounts secured.
- Unauthorized privileged access removed.
- Further lateral movement prevented.

### 11.3 Eradication Complete

- Malicious processes and payloads removed.
- Unauthorized services/persistence removed.
- Unauthorized configuration changes reverted.
- Compromised credentials remediated.
- Initial access vector addressed.

### 11.4 Recovery Complete

- Systems returned to normal operation.
- Required remote-management functionality verified.
- Accounts restored to the correct security state.
- Active Directory functionality verified.

### 11.5 Validation Complete

- Windows logging functioning.
- Sysmon telemetry functioning.
- Wazuh receiving telemetry.
- Relevant lateral-movement detections operational.
- No continuing unauthorized remote-access activity observed.

### 11.6 Final Documentation

Document:

- Initial detection
- Source and destination systems
- Account used
- Remote-access technique
- Commands/processes involved
- Authentication context
- Attack path
- Affected hosts/accounts
- Credential exposure
- Containment actions
- Eradication actions
- Recovery and validation results
- Remaining risks or monitoring requirements

---

## 12. MITRE ATT&CK Mapping

| Technique | Name | Relevance |
|---|---|---|
| T1021.001 | Remote Services: Remote Desktop Protocol | DET-032 identifies successful RDP logons using Windows Logon Type 10. |
| T1021.002 | Remote Services: SMB/Windows Admin Shares | DET-028 and DET-029 identify PsExec/SMB administrative-share activity used for remote execution and lateral movement. |
| T1021.006 | Remote Services: Windows Remote Management | DET-030 identifies remote WinRM execution through `wsmprovhost.exe`. |
| T1047 | Windows Management Instrumentation | DET-031 identifies suspicious processes spawned through WMI remote execution. |
| T1569.002 | System Services: Service Execution | DET-028 identifies PsExec execution, which can use a remote Windows service to execute processes. |

---

## Analyst Decision Flow

```text
Wazuh Lateral-Movement Alert
             ↓
Identify Source + Destination + User
             ↓
Validate Remote-Access Mechanism
             ↓
Expected / Authorized?
    ├── Yes → Document → Monitor / Close
    │
    └── No / Unclear
             ↓
     Investigate Source Host
             ↓
     Investigate Destination Host
             ↓
   Compromised Credentials?
      ├── No → Continue Context Analysis
      │
      └── Yes → Credential Remediation
             ↓
    Remote Execution Confirmed?
      ├── No → Suspicious Remote Access
      │
      └── Yes
             ↓
      Correlate Follow-on Activity
             ↓
  Additional Hosts / Privilege Abuse?
      ├── No → Contain + Eradicate
      │
      └── Yes
             ↓
      Reconstruct Attack Path
             ↓
      Assess Domain-Level Impact
             ↓
      Escalate as Required
             ↓
    Recover + Validate Telemetry
             ↓
      Heightened Monitoring
             ↓
            Close
```

---

## Related Playbooks

- **[IR-001 — Credential Attack & Account Compromise](../incident-response/IR-001-Credential-Attack-and-Account-Compromise.md)** — Authentication anomalies or compromised accounts used during lateral movement.

- **[IR-002 — AD Account & Privilege Compromise](../incident-response/IR-002-Active-Directory-Account-and-Privilege-Compromise.md)** — Unauthorized account, group, or privilege changes discovered during the incident.

- **[IR-003 — Kerberos & Credential Theft Attack](../incident-response/IR-003-Kerberos-and-Credential-Theft-Attack.md)** — Credential theft or exposed authentication material associated with remote movement.

- **[IR-004 — Active Directory Discovery & Reconnaissance](../incident-response/IR-004-AD-Discovery-and-Reconnaissance.md)** — Reconnaissance performed before or during lateral movement.

- **[IR-006 — Persistence & Defense Evasion](../incident-response/IR-006-Persistence-and-Defense-Evasion.md)** — Persistence or security-control tampering established after remote execution.
