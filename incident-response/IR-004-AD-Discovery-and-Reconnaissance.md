# IR-004 — Active Directory Discovery & Reconnaissance

## 1. Objective

Provide an operational response workflow for suspected Active Directory, account, trust, host, and network reconnaissance detected by Wazuh.

This playbook helps analysts determine whether discovery activity is authorized administration or evidence of post-compromise reconnaissance. The workflow focuses on correlating multiple discovery detections, identifying the compromised source, determining what information the adversary may have collected, and preventing reconnaissance from progressing into privilege escalation or lateral movement.

---

## 2. Scope & Related Detections

### 2.1 Scope

This playbook applies to:

- `DC01` — Active Directory Domain Controller
- `CLIENT01` — Domain-joined Windows endpoint
- Domain users, groups, computers, trusts, and related AD objects
- Windows native network and host discovery commands
- Active Directory enumeration utilities
- SharpHound / BloodHound collection activity
- AdFind execution
- Wazuh and Sysmon telemetry associated with discovery activity

### 2.2 Related Detection Rules

| Detection | Description | Wazuh Rule | Severity | Primary Event |
|---|---|---:|---:|---|
| DET-025 | SharpHound / BloodHound Collector Execution | 100124 | 10 | Sysmon 1 |
| DET-026 | AdFind Active Directory Enumeration Tool Execution | 100125 | 12 | Sysmon 1 |
| DET-027 | Windows Network Discovery Commands Execution | 100126 | 8 | Sysmon 1 |

### 2.3 Detection-to-Incident Relationship

These detections identify reconnaissance behaviors rather than automatically proving compromise.

The incident investigation should establish whether discovery is:

```text
Discovery Alert
      ↓
Validate User + Host + Process
      ↓
Expected / Authorized?
      ├── Yes → Document → Close / Monitor
      │
      └── No / Unclear
             ↓
      Correlate Discovery Activity
             ↓
      Identify Information Being Collected
             ↓
      Investigate Initial Access / Compromise
             ↓
      Assess Follow-on Activity
             ↓
      Contain Source + Prevent Further Access
```

Multiple discovery techniques executed from the same host or account within a short period provide stronger evidence of automated or hands-on-keyboard reconnaissance.

---

## 3. Attack Scenario

### 3.1 Scenario Overview

After gaining access to a Windows endpoint or domain account, an adversary may perform reconnaissance to understand the Active Directory environment before escalating privileges or moving laterally.

The adversary may use SharpHound/BloodHound to map users, groups, sessions, computers, trusts, ACLs, and attack paths. AdFind may be used to query directory objects, groups, trusts, subnets, and other AD information. Native Windows commands can reveal the local network configuration, routing, connections, domain information, and available hosts without requiring additional tooling.

### 3.2 Typical Attack Flow

```text
Initial Access / Compromised Account
              ↓
       Local Host Discovery
              ↓
   Network / Domain Discovery
              ↓
 ┌────────────┼────────────┐
 ↓            ↓            ↓
SharpHound   AdFind     Native Commands
 ↓            ↓            ↓
AD Users     AD Objects   Network/Host Data
Groups       Trusts       Routes/Connections
Sessions     Groups       Domain Information
ACLs         Computers
 ↓            ↓
 └────────────┼────────────┘
              ↓
     Identify Attack Paths
              ↓
    Privilege Escalation
              ↓
      Lateral Movement
```

This is a representative attack path, not a guaranteed detection sequence.

### 3.3 Expected Detection Sequence

A possible reconnaissance sequence is:

```text
DET-027
  ↓
Native network / host discovery
  ↓
DET-026 or DET-025
  ↓
Detailed Active Directory enumeration
  ↓
Identify privileged groups / computers / trusts
  ↓
Privilege Escalation or Lateral Movement
```

An adversary may use only one technique, may execute the techniques in a different order, or may use tools that are not covered by these detections.

### 3.4 Potential Impact

Reconnaissance can expose:

- Domain users and groups
- Privileged group membership
- Domain computers
- Domain trusts
- Network topology
- Active sessions
- Administrative relationships
- ACL-based privilege escalation paths
- Service and infrastructure information
- Potential lateral-movement targets

Discovery itself may not modify systems, but it can materially reduce the effort required for privilege escalation, credential theft, lateral movement, or ransomware deployment.

---

## 4. Initial Triage

### 4.1 Alert Validation

When a discovery alert triggers:

- Identify the DET ID and Wazuh rule ID.
- Review the complete Wazuh alert and raw Sysmon event.
- Record the timestamp.
- Identify the affected agent.
- Identify the executing user.
- Identify the process image and original file name where available.
- Review the command line.
- Identify the parent process.
- Record the process hash when available.
- Determine whether the activity is authorized.

For DET-025 and DET-026, pay particular attention to execution of the enumeration tools from unusual directories or through suspicious parent processes.

### 4.2 Identify Affected Assets

Determine:

- Which endpoint executed the discovery activity.
- Whether the source is `CLIENT01`.
- Whether `DC01` is the target of enumeration.
- Whether other systems appear in related telemetry.
- Whether the source host is an approved administrative or security assessment workstation.

A normal administrative workstation performing documented discovery may be benign. The same behavior from an ordinary user endpoint following suspicious process execution is substantially more concerning.

### 4.3 Identify Affected Identity

Record:

- Executing account
- Domain
- Account privilege level
- Whether the account is a service account
- Whether the account normally performs AD administration
- Recent authentication activity
- Recent account or privilege changes

Correlate with the **Authentication & Account Monitoring** and **Active Directory Security** dashboards when relevant.

### 4.4 Identify Attack Source

Establish:

- Source host
- Source IP where available
- Executing process
- Parent process
- Command line
- Binary path
- Process hash
- Process execution context

For DET-027, determine whether the discovery commands were launched by an interactive shell, PowerShell, script host, WMI process, management software, or an unknown process.

### 4.5 Establish Initial Timeline

Record:

| Time | Detection/Event | Host | User | Source | Finding |
|---|---|---|---|---|---|
| `<time>` | `<event>` | `<host>` | `<user>` | `<source>` | `<finding>` |

Search before and after the triggering event for:

- Initial access indicators
- PowerShell or command-shell activity
- Additional discovery
- Credential access
- Account/privilege changes
- Lateral movement
- Persistence
- Defense evasion

### 4.6 Determine Whether Activity Is Expected

Potentially legitimate activity includes:

- Domain administration
- Network troubleshooting
- Authorized security assessment
- Blue Team / Red Team testing
- Approved directory reporting
- Enterprise management scripts

Validate the **user, host, process, command line, timing, and authorization** rather than classifying the activity based only on the executable name.

---

## 5. Investigation Workflow

### 5.1 Establish the Initial Event

Determine exactly what executed.

For DET-025:

- Confirm `win.eventdata.originalFileName` indicates `SharpHound.exe`.
- Review the image path.
- Review the command line and collection options.
- Identify the executing user and parent process.

For DET-026:

- Confirm `win.eventdata.originalFileName` indicates `AdFind.exe`.
- Review enumeration parameters such as trust, user, computer, group, subnet, or global catalog queries.
- Identify output files where applicable.

For DET-027:

- Identify the exact native discovery command.
- Determine whether commands were executed individually or in rapid succession.

### 5.2 Investigate the Source

Determine whether the source endpoint was already compromised.

Review Sysmon process creation around the detection for:

- Suspicious PowerShell
- Command shells
- Script hosts
- WMI execution
- Unknown binaries
- Executables from temporary or user-writable directories
- Suspicious parent-child process relationships
- Recently created files

The **Sysmon Endpoint Activity** dashboard should be used to review process execution and related endpoint activity.

### 5.3 Investigate the Account / Identity

Determine:

- Whether the executing account is privileged.
- Whether the account normally performs AD enumeration.
- Whether the account has recently authenticated from another system.
- Whether the account has recent failed authentication or successful-login anomalies.
- Whether the account has recently been created, enabled, reset, or added to privileged groups.

If suspicious identity activity is found, continue with **IR-001 — Credential Attack & Account Compromise** or **IR-002 — AD Account & Privilege Compromise** as appropriate.

### 5.4 Investigate the Affected Host

Review:

- Process execution tree
- Parent process
- Command lines
- File creation
- Network connections
- PowerShell activity
- Recently downloaded or dropped binaries
- Other custom Wazuh detections

For `CLIENT01`, determine whether the endpoint represents the likely initial access point or an already-compromised system performing reconnaissance.

For `DC01`, determine whether the system is merely the target of directory queries or whether unauthorized processes were actually executed on the domain controller.

### 5.5 Correlate Related Detection Activity

Search for related activity around the same timeframe:

- DET-025 — SharpHound
- DET-026 — AdFind
- DET-027 — Native discovery commands
- IR-001 authentication detections
- IR-002 account and privilege changes
- IR-003 credential theft
- IR-005 lateral movement
- IR-006 persistence or defense evasion

A sequence such as:

```text
Suspicious Process
      ↓
DET-027 Network Discovery
      ↓
DET-026 AdFind
      ↓
DET-025 SharpHound
      ↓
Privileged Account / Group Discovery
      ↓
Lateral Movement
```

is a stronger indication of post-compromise reconnaissance than any single discovery event.

### 5.6 Build the Attack Timeline

Document:

1. Earliest suspicious process or authentication
2. First discovery command
3. Active Directory enumeration
4. Network/host enumeration
5. Credential-access activity, if present
6. Privilege changes, if present
7. Lateral movement, if present
8. Most recent attacker activity

Preserve the original Wazuh event details for significant findings.

### 5.7 Determine Attack Scope

Determine whether reconnaissance is limited to:

- One endpoint
- One account
- One subnet
- One portion of Active Directory
- Multiple domain endpoints
- Multiple accounts
- Privileged infrastructure
- The wider domain environment

Where SharpHound or AdFind output is found, determine what categories of information were collected and whether the output was staged for later use or exfiltration.

### 5.8 Determine Evidence of Compromise

Discovery should be treated as stronger evidence of compromise when:

- Enumeration is executed by an unauthorized account.
- The source endpoint has unrelated suspicious activity.
- Discovery tools are executed from unusual locations.
- Discovery is launched by suspicious PowerShell, WMI, C2, or script processes.
- Multiple discovery techniques are executed rapidly.
- Discovery is followed by credential access, privilege escalation, or lateral movement.
- Output is staged in unusual directories.
- The same source subsequently authenticates to other systems.

---

## 6. Incident Assessment

### 6.1 Suspicious Activity

Examples:

- A standard user unexpectedly executes `whoami`, `nltest`, `netstat`, or `ipconfig`.
- An unknown process launches multiple discovery commands.
- AdFind executes from a temporary directory.
- SharpHound executes outside an approved security assessment.
- Discovery activity occurs immediately after suspicious authentication.

### 6.2 Confirmed Malicious Activity

Examples:

- Unauthorized SharpHound collection.
- Unauthorized AdFind enumeration.
- Automated discovery command bursts associated with a suspicious process.
- Discovery followed by privilege escalation or lateral movement.
- Enumeration performed by a compromised account.

### 6.3 Confirmed Compromise

Discovery activity should be treated as evidence of a broader compromise when it is correlated with:

- Confirmed malicious code execution
- Credential theft
- Unauthorized privilege changes
- Lateral movement
- Persistence
- Command-and-control activity
- Compromised credentials used from the enumerating host

### 6.4 Severity Considerations

Increase severity when:

- Multiple discovery techniques are correlated.
- A privileged account performs unauthorized discovery.
- `DC01` is being actively targeted.
- Enumeration is followed by credential theft.
- Enumeration is followed by lateral movement.
- Attack-path mapping is followed by privilege escalation.
- The source endpoint is confirmed compromised.
- The activity appears automated or coordinated.

---

## 7. Containment

### 7.1 Immediate Containment

If reconnaissance is confirmed malicious and active:

- Isolate the compromised endpoint, such as `CLIENT01`, when appropriate.
- Stop the unauthorized discovery process.
- Terminate suspicious parent processes when safe.
- Preserve relevant evidence before cleanup where practical.
- Prevent continued access from the identified source.

Do not disrupt `DC01` merely because it is the target of directory enumeration. Prioritize containment of the compromised source while maintaining Active Directory availability.

### 7.2 Account Containment

If the executing account is compromised:

- Disable or lock the account when appropriate.
- Reset its credentials.
- Review active sessions and recent authentication.
- Remove unauthorized privileged access.
- Investigate other systems where the account authenticated.

### 7.3 Endpoint Containment

For a compromised endpoint:

- Isolate it from the network.
- Stop attacker-controlled enumeration tools.
- Preserve process and file evidence.
- Restrict access to identified attacker infrastructure where applicable.
- Investigate the initial access vector.

### 7.4 AD Containment

If reconnaissance is combined with privilege or credential compromise:

- Secure affected privileged accounts.
- Remove unauthorized group membership.
- Review suspicious administrative access.
- Identify other endpoints that may have been targeted using the collected information.

### 7.5 Additional Containment Actions

Where discovery output is confirmed to have been staged:

- Preserve relevant files as evidence.
- Prevent unauthorized access to the staging location.
- Determine whether collected data was transferred elsewhere.
- Increase monitoring for the systems and accounts identified as likely targets.

---

## 8. Eradication

### 8.1 Remove Attacker Access

- Remove unauthorized accounts or access paths discovered during the investigation.
- Revoke compromised credentials.
- Remove unauthorized privileged memberships.
- Address the initial access vector.

### 8.2 Remove Persistence / Malicious Artifacts

- Remove SharpHound, AdFind, or other unauthorized enumeration tools.
- Remove malicious scripts and executables.
- Remove staged `.zip`, `.json`, `.txt`, or `.csv` collection output after evidence preservation.
- Remove persistence discovered during the endpoint investigation.

### 8.3 Remediate Compromised Credentials

If the discovery activity originated from a compromised account:

- Reset the account password.
- Reset privileged credentials if they were exposed.
- Review service-account exposure where applicable.
- Continue with IR-003 if credential-theft activity is discovered.

### 8.4 Restore Unauthorized Changes

Review and remediate unauthorized:

- Account changes
- Group membership changes
- AD object modifications
- Security-control changes
- Persistence mechanisms
- Other attacker-created access paths

Discovery itself may not modify AD, so remediation should be based on evidence rather than assumed changes.

---

## 9. Recovery & Validation

### 9.1 System Recovery

- Return contained endpoints to normal network operation only after remediation.
- Verify required applications and services operate normally.
- Confirm no unauthorized discovery processes remain active.

### 9.2 Account / AD Recovery

- Verify affected accounts are secured.
- Confirm privileged memberships are correct.
- Verify unauthorized accounts and access paths are removed.
- Confirm Active Directory functionality remains healthy.

### 9.3 Security Control Recovery

Verify:

- Windows security logging is functioning.
- Sysmon is running.
- Wazuh is receiving endpoint telemetry.
- Relevant detection rules remain enabled.
- Security controls have not been disabled or modified.

### 9.4 Telemetry Validation

Confirm Wazuh continues receiving:

- Sysmon Event ID 1 process creation
- Windows authentication events
- Active Directory security events
- Related endpoint telemetry

Verify that the relevant discovery detections remain capable of identifying their intended behaviors.

### 9.5 Post-Recovery Monitoring

Monitor for:

- Repeated SharpHound execution
- Repeated AdFind execution
- Discovery command bursts
- New suspicious process trees
- Credential access
- Privilege escalation
- Lateral movement
- Authentication from newly identified systems

Continue heightened monitoring until recurring malicious activity is no longer observed.

---

## 10. Escalation Criteria

### 10.1 Escalate When

Escalate to a senior analyst or incident lead when:

- Unauthorized reconnaissance is confirmed.
- The source endpoint is compromised.
- Multiple discovery techniques are correlated.
- Discovery is associated with suspicious authentication.
- Credential theft or privilege escalation is identified.
- Lateral movement follows reconnaissance.
- The scope of collected information cannot be determined.

### 10.2 High-Risk Conditions

Prioritize escalation when:

- A privileged account performs unauthorized enumeration.
- SharpHound maps privileged AD relationships.
- AdFind is used extensively against the domain.
- Discovery is followed by credential theft.
- Discovery is followed by remote execution.
- Multiple endpoints perform related reconnaissance.
- `DC01` is involved in a broader attack chain.

### 10.3 Domain-Level Compromise Indicators

Treat the incident as potentially domain-wide when:

- Multiple compromised endpoints perform coordinated discovery.
- Privileged credentials are exposed after reconnaissance.
- Discovery is followed by DCSync, NTDS.dit extraction, or forged-ticket activity.
- Multiple systems are accessed using compromised credentials.
- The attacker demonstrates knowledge of AD privilege paths and subsequently escalates privileges.

---

## 11. Closure Criteria

### 11.1 Investigation Complete

- Discovery activity validated.
- Authorization status determined.
- Source host and account identified.
- Discovery methods identified.
- Collected information and potential scope assessed.
- Related detections correlated.
- Attack timeline documented.

### 11.2 Containment Complete

- Active reconnaissance stopped.
- Compromised endpoint contained.
- Compromised accounts secured.
- Unauthorized privileged access removed.

### 11.3 Eradication Complete

- Unauthorized discovery tools removed.
- Malicious files/scripts removed.
- Staged discovery output handled appropriately.
- Initial access vector addressed.
- Persistence removed where identified.

### 11.4 Recovery Complete

- Systems returned to normal operation.
- Accounts restored to correct security state.
- Active Directory functionality verified.
- Security controls restored.

### 11.5 Validation Complete

- Windows logging functioning.
- Sysmon telemetry functioning.
- Wazuh receiving telemetry.
- Relevant discovery detections operational.
- No recurring unauthorized reconnaissance observed.

### 11.6 Final Documentation

Document:

- Initial detection
- Source host and account
- Discovery tools/commands used
- Command lines
- Parent processes
- Information potentially collected
- Related detections
- Attack timeline
- Scope and affected assets
- Containment actions
- Eradication actions
- Recovery and validation results
- Remaining risks or monitoring requirements

---

## 12. MITRE ATT&CK Mapping

| Technique | Name | Relevance |
|---|---|---|
| T1087 | Account Discovery | DET-025 and DET-026 can expose domain account information during Active Directory enumeration. |
| T1069.002 | Permission Groups Discovery: Domain Groups | SharpHound and AdFind can identify domain groups and privileged group relationships. |
| T1482 | Domain Trust Discovery | SharpHound and AdFind can enumerate domain trust relationships. |
| T1016 | System Network Configuration Discovery | DET-027 identifies native Windows commands used to inspect network configuration and routing information. |
| T1049 | System Network Connections Discovery | DET-027 identifies native commands used to enumerate active network connections. |

---

## Analyst Decision Flow

```text
Wazuh Discovery Alert
          ↓
Validate User + Host + Process + Command Line
          ↓
Expected / Authorized?
    ├── Yes → Document → Close / Monitor
    │
    └── No / Unclear
             ↓
       Correlate Discovery
             ↓
  Multiple Discovery Techniques?
      ├── No → Investigate Context
      │
      └── Yes
             ↓
    Investigate Source Endpoint
             ↓
  Initial Access / Compromise Evidence?
      ├── No → Suspicious Reconnaissance
      │
      └── Yes
             ↓
   Credential / Privilege Abuse?
      ├── No → Contain + Eradicate
      │
      └── Yes
             ↓
   Lateral Movement / Domain Impact?
      ├── No → Contain + Remediate
      │
      └── Yes
             ↓
      Escalate Incident
             ↓
    Recover + Validate Telemetry
             ↓
      Heightened Monitoring
             ↓
            Close
```

---

## Related Playbooks

- **IR-001 — Credential Attack & Account Compromise** — Authentication anomalies or compromised accounts identified during reconnaissance.
- **IR-002 — AD Account & Privilege Compromise** — Unauthorized account, group, privilege, or AD object changes discovered during investigation.
- **IR-003 — Kerberos & Credential Theft Attack** — Credential theft identified as part of the reconnaissance chain.
- **IR-005 — Lateral Movement & Remote Execution** — Remote execution or movement following discovery.
- **IR-006 — Persistence & Defense Evasion** — Persistence or security-control tampering discovered on the source endpoint.
