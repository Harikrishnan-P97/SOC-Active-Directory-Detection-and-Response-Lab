# IR-007 — Active Directory Destructive & Impact Activity

## 1. Objective

This playbook defines the incident response workflow for unauthorized or potentially malicious deletion of security-enabled Windows or Active Directory groups.

The objective is to determine whether the group deletion was authorized, identify the account and host responsible, assess the operational and security impact, identify any related attacker activity, and restore affected access controls. The playbook covers DET-042 and focuses on incident-level investigation, containment, eradication, recovery, and validation.

---

## 2. Scope & Related Detections

### 2.1 Scope

This playbook applies to security-enabled group deletion activity detected through Windows Security Event Logs.

The primary incident concern is unauthorized removal of groups that control access to systems, services, administrative functions, or other protected resources.

The investigation should consider:

- Deleted security group
- Group type and scope
- Account that performed the deletion
- Host from which the activity originated
- Time of deletion
- Group membership and access previously associated with the group
- Related account, privilege, discovery, lateral movement, persistence, or defense-evasion activity
- Potential impact on domain or endpoint operations

### 2.2 Related Detection Rules

| Detection ID | Detection | Wazuh Rule ID | Relevant Events | MITRE ATT&CK |
|---|---|---:|---|---|
| DET-042 | Windows Security-Enabled Group Deletion | 100141 | 4730, 4734, 4758 | T1531 |

**Relevant Windows Security Events:**

- **4730** — A security-enabled local group was deleted
- **4734** — A security-enabled global group was deleted
- **4758** — A security-enabled universal group was deleted

### 2.3 Detection-to-Incident Relationship

DET-042 is an indicator of potentially destructive Active Directory or Windows account-management activity.

The detection should not automatically be treated as confirmed compromise. The analyst must establish whether the deletion was authorized and determine whether the event forms part of a broader attack.

```text
DET-042
   │
   ├── Deleted Group
   ├── Performing Account
   ├── Source Host
   └── Related Activity
          ↓
Incident Assessment
          ↓
Containment / Recovery
```

---

## 3. Attack Scenario

### 3.1 Scenario Overview

An attacker who has obtained sufficient privileges may delete a security-enabled group to disrupt access controls, remove administrative or operational access, or interfere with security and recovery functions.

The attacker may first compromise an account, escalate privileges, or move laterally before performing the destructive group modification.

A group deletion can therefore represent either an isolated administrative change or the final stage of a broader post-compromise activity chain.

### 3.2 Typical Attack Flow

```text
Initial Access / Account Compromise
             ↓
Privilege Acquisition
             ↓
Access to Windows / Active Directory
             ↓
Security Group Deletion
             ↓
Access / Authorization Impact
             ↓
Detection by Wazuh
             ↓
Incident Investigation
             ↓
Containment → Eradication → Recovery
```

### 3.3 Expected Detection Sequence

A possible detection sequence is:

```text
Account / Privilege Activity
          ↓
Administrative Access
          ↓
DET-042 — Security Group Deletion
          ↓
Related Authentication / Endpoint / AD Activity
```

This sequence is **not guaranteed**. DET-042 may occur as an isolated event or alongside other detections.

### 3.4 Potential Impact

Potential impact includes:

- Loss of access to systems or resources
- Removal of administrative authorization
- Disruption of operational access
- Loss of access to security or recovery functions
- Interruption of services dependent on group-based authorization
- Increased difficulty recovering affected systems
- Evidence of broader Active Directory compromise

Deletion of a highly privileged or operationally important group should be treated as higher risk than deletion of an obsolete or unused group.

---

## 4. Initial Triage

### 4.1 Alert Validation

Confirm the Wazuh alert and review the underlying Windows Security event.

Record:

- Detection ID: `DET-042`
- Wazuh Rule ID: `100141`
- Event ID: `4730`, `4734`, or `4758`
- Event timestamp
- Deleted group name
- Performing account
- Affected host
- Alert description

Relevant Wazuh fields include:

- `win.system.eventID`
- `win.eventdata.targetUserName`
- `win.eventdata.subjectUserName`

### 4.2 Identify Affected Assets

Determine which system generated the event.

Establish:

- Hostname / Wazuh agent
- Whether the host is **DC01** or **CLIENT01**
- Whether the deletion affected Active Directory or a local Windows security group
- Whether additional systems depend on the deleted group

For Active Directory group deletion, determine whether the affected object was domain-wide in scope.

### 4.3 Identify Affected Identity

Identify the account recorded in:

`win.eventdata.subjectUserName`

Determine:

- Account type
- Privilege level
- Whether the account is expected to perform directory administration
- Recent authentication activity
- Recent privilege or group membership changes
- Whether the account may itself be compromised

### 4.4 Identify Attack Source

Determine the system from which the administrative activity originated.

Correlate the event with available endpoint telemetry, including Sysmon Process Creation events where available.

Look for:

- `powershell.exe`
- `cmd.exe`
- Active Directory administration tools
- MMC / Active Directory Users and Computers activity
- Other unexpected administrative processes

### 4.5 Establish Initial Timeline

Record the first known deletion event and search for related activity before and after it.

| Time | Detection/Event | Host | User | Source | Finding |
|---|---|---|---|---|---|
| `<time>` | DET-042 / Event 4730, 4734, or 4758 | `<host>` | `<user>` | `<source>` | Group deleted |
| `<time>` | Related event | `<host>` | `<user>` | `<source>` | `<finding>` |

### 4.6 Determine Whether Activity Is Expected

Determine whether the deletion was part of:

- Authorized administrative maintenance
- IAM or directory cleanup
- Decommissioning of a legacy group
- Approved security or configuration change

If an approved change exists and no suspicious related activity is identified, classify the event as **Expected / Benign** and document the reason.

If authorization cannot be established, continue the investigation.

---

## 5. Investigation Workflow

### 5.1 Establish the Initial Event

Confirm that the event represents an actual security-enabled group deletion.

Determine:

- Group name
- Group type
- Event ID
- Performing account
- Host
- Timestamp

Determine whether the group was local, global, or universal based on the event type.

### 5.2 Investigate the Source

Investigate the host and process context associated with the deletion.

Where telemetry is available, correlate the event with Sysmon Process Creation activity around the event timestamp.

Look for:

- PowerShell
- Command Prompt
- Active Directory administration utilities
- Unexpected scripting activity
- Recently executed tools
- Processes associated with known attack activity

An administrative process alone does not establish malicious intent. Assess it together with account, timing, authorization, and surrounding activity.

### 5.3 Investigate the Account / Identity

Investigate the account responsible for the deletion.

Review:

- Recent successful and failed logons
- Account lockouts
- Privilege changes
- Group membership changes
- Password changes or resets
- Other administrative activity
- Activity outside the account's normal expected behavior

Determine whether the account was compromised or legitimately performing the change.

### 5.4 Investigate the Affected Host

Determine whether the host shows evidence of broader compromise.

For **CLIENT01**, review endpoint activity for:

- Suspicious process execution
- PowerShell activity
- Network connections
- Credential access
- Lateral movement
- Persistence
- Defense-evasion activity

For **DC01**, use additional caution because it is the domain controller. Review relevant Active Directory, authentication, privilege, and administrative activity without unnecessarily disrupting domain services.

### 5.5 Correlate Related Detection Activity

Search for related detections around the deletion timestamp.

Particularly important correlations include:

- Authentication failures or suspicious successful logons
- Privileged account activity
- Unauthorized group membership changes
- AD attribute modifications
- Kerberos attacks
- Credential theft
- Lateral movement
- Persistence
- Security-control tampering

The presence of multiple related detections can indicate that the group deletion is part of a broader compromise rather than an isolated administrative event.

### 5.6 Build the Attack Timeline

Construct a chronological view of relevant events.

Include:

- Initial suspicious authentication
- Account or privilege changes
- Discovery activity
- Remote execution or lateral movement
- Group deletion
- Post-deletion activity
- Containment actions
- Recovery actions

The timeline should distinguish confirmed events from analyst assumptions.

### 5.7 Determine Attack Scope

Determine:

- Which group was deleted
- Which systems and resources relied on the group
- Which accounts were affected
- Whether other groups were modified
- Whether additional Active Directory objects were changed
- Whether the same account performed other suspicious actions
- Whether more than one host was involved

If the deleted group controlled administrative access, backup access, remote access, or other critical permissions, increase the assessed severity.

### 5.8 Determine Evidence of Compromise

Evidence supporting confirmed compromise may include:

- Unauthorized deletion with no valid change authorization
- Compromised or suspicious performing account
- Suspicious source host
- Malicious process or command execution
- Related credential-access activity
- Privilege escalation
- Lateral movement
- Persistence
- Multiple unauthorized AD modifications
- Continued attacker activity after the deletion

If the deletion is authorized and no additional malicious indicators exist, classify it as benign or expected.

---

## 6. Incident Assessment

### 6.1 Suspicious Activity

Classify the incident as **Suspicious** when:

- The deletion cannot be immediately explained
- The performing account is unusual for the activity
- The source host is unexpected
- The deleted group is operationally important
- Change authorization is unclear
- Related suspicious activity exists but compromise is not yet established

Continue investigation and preserve relevant evidence.

### 6.2 Confirmed Malicious Activity

Classify the activity as **Malicious** when there is sufficient evidence that the group deletion was intentional and unauthorized.

Examples include:

- Deliberate deletion without administrative authorization
- Suspicious account and host context
- Correlated attacker behavior
- Destructive activity occurring during a broader attack

### 6.3 Confirmed Compromise

Classify the incident as **Confirmed Compromise** when evidence indicates that an attacker or compromised identity performed the deletion.

Strong indicators include:

- Confirmed compromised account
- Unauthorized privileged access
- Credential theft followed by administrative activity
- Lateral movement followed by group deletion
- Multiple malicious actions by the same identity or host
- Additional unauthorized Active Directory changes

### 6.4 Severity Considerations

Increase severity based on:

- Criticality of the deleted group
- Administrative or security privileges controlled by the group
- Number of affected users or systems
- Whether DC01 was involved
- Whether a privileged account was used
- Evidence of credential compromise
- Evidence of lateral movement
- Evidence of persistence
- Multiple unauthorized AD changes
- Potential domain-wide impact

---

## 7. Containment

### 7.1 Immediate Containment

If malicious activity is confirmed or strongly suspected:

- Stop ongoing attacker activity where safely possible.
- Preserve relevant evidence before making destructive changes when practical.
- Identify whether the performing account remains active.
- Identify whether the source host is still under attacker control.

### 7.2 Account Containment

For a compromised performing account:

- Disable or lock the account when appropriate.
- Reset the account password.
- Revoke active sessions or tokens where applicable.
- Review and remove unauthorized privileged memberships.
- Investigate other activity performed by the account.

If the account is a highly privileged administrative identity, treat the incident as higher risk and investigate for broader credential compromise.

### 7.3 Endpoint Containment

If the deletion originated from **CLIENT01** and compromise is suspected:

- Isolate CLIENT01 from the network where appropriate.
- Stop confirmed malicious processes.
- Preserve relevant endpoint evidence.
- Prevent further administrative access from the compromised endpoint.

Do not isolate or disrupt **DC01** without considering the operational impact on Active Directory and dependent lab systems.

### 7.4 AD Containment

Where required:

- Remove unauthorized administrative access.
- Remove compromised accounts from privileged groups.
- Restrict suspicious administrative access.
- Identify and contain additional unauthorized AD changes.

Prioritize containment actions that prevent further destructive modifications while preserving domain functionality.

### 7.5 Additional Containment Actions

If investigation identifies broader compromise:

- Contain additional affected endpoints.
- Reset credentials for accounts confirmed or suspected to be exposed.
- Restrict compromised administrative paths.
- Increase monitoring of DC01 and CLIENT01.
- Review recent privileged Active Directory activity.

---

## 8. Eradication

### 8.1 Remove Attacker Access

Remove the attacker's ability to continue modifying the environment.

Actions may include:

- Disable compromised accounts
- Remove unauthorized privileged memberships
- Remove unauthorized accounts
- Terminate malicious sessions
- Remove unauthorized administrative access

### 8.2 Remove Persistence / Malicious Artifacts

If the investigation identifies persistence or attacker tooling:

- Remove malicious scheduled tasks
- Remove unauthorized services
- Remove malicious startup artifacts
- Remove malicious scripts or binaries
- Remove other identified persistence mechanisms

The exact remediation should follow the relevant detection-level response procedures.

### 8.3 Remediate Compromised Credentials

If the performing account or other credentials were exposed:

- Reset affected passwords
- Reset privileged credentials where required
- Review other accounts accessed using the compromised identity
- Investigate whether credential theft occurred before the group deletion

Credential remediation should account for the possibility that the attacker retained knowledge of previously valid credentials.

### 8.4 Restore Unauthorized Changes

Restore the deleted security group using the appropriate recovery mechanism.

Where the group is recoverable through Active Directory Recycle Bin or an available backup, restore it according to the lab's recovery procedure.

Example:

```powershell
Restore-ADObject -Filter 'Name -eq "<TARGET_GROUP>"'
```

After restoration:

- Verify the group exists.
- Verify the group's intended scope and properties.
- Restore required membership.
- Confirm dependent permissions are functioning.
- Check for additional unauthorized changes.

---

## 9. Recovery & Validation

### 9.1 System Recovery

Confirm that affected systems and services continue to operate normally after the group is restored.

Validate:

- User access
- Administrative access
- Resource access
- Services dependent on group membership
- Remote access where applicable

### 9.2 Account / AD Recovery

Verify:

- Deleted group has been restored
- Expected group membership is present
- Unauthorized membership changes are removed
- Administrative groups contain only authorized accounts
- Affected accounts have appropriate credentials and privileges

### 9.3 Security Control Recovery

Confirm that relevant security controls remain operational.

Review:

- Windows security auditing
- Sysmon
- Windows Defender
- Windows Firewall
- Wazuh agent connectivity
- Active Directory auditing

### 9.4 Telemetry Validation

Confirm that Wazuh continues receiving telemetry from affected systems.

Verify:

- Windows Security events are being collected
- Sysmon events are being collected where configured
- Wazuh alerts are generated correctly
- DET-042 remains operational
- Related detections continue to provide visibility

### 9.5 Post-Recovery Monitoring

Continue monitoring for:

- Repeated group deletion attempts
- Privileged account activity
- Authentication anomalies
- Additional AD modifications
- Suspicious endpoint activity
- Persistence attempts
- Lateral movement
- Security-control tampering

A restored group alone does not establish that the environment is clean.

---

## 10. Escalation Criteria

### 10.1 Escalate When

Escalate the incident when:

- Group deletion is confirmed unauthorized
- A privileged account performed the deletion
- The source host is compromised
- Multiple related detections are present
- Multiple AD objects were modified
- Credentials may have been compromised
- Persistence or lateral movement is identified
- Recovery of the deleted group cannot be completed reliably

### 10.2 High-Risk Conditions

Treat the incident as high risk when:

- A highly privileged or security-critical group was deleted
- Domain administrative access was affected
- DC01 shows evidence of compromise
- A privileged account is confirmed compromised
- Multiple accounts or hosts are affected
- Credential theft preceded the deletion
- Destructive activity continues after initial containment

### 10.3 Domain-Level Compromise Indicators

Escalate for possible domain-level compromise when investigation identifies:

- Unauthorized privileged account access
- Domain Admin or Enterprise Admin compromise
- DCSync activity
- Golden Ticket activity
- NTDS.dit credential theft
- Multiple privileged Active Directory modifications
- Broad lateral movement across the domain
- Multiple destructive changes
- Continued attacker access to DC01

---

## 11. Closure Criteria

### 11.1 Investigation Complete

- Deleted group identified
- Performing account identified
- Source host identified
- Authorization status determined
- Related activity investigated
- Attack timeline established
- Incident scope determined

### 11.2 Containment Complete

- Attacker access removed or controlled
- Compromised accounts contained
- Affected endpoints contained where necessary
- Unauthorized privileged access removed

### 11.3 Eradication Complete

- Malicious tooling and persistence removed
- Unauthorized accounts or memberships removed
- Compromised credentials remediated
- Unauthorized Active Directory changes addressed

### 11.4 Recovery Complete

- Deleted group restored where required
- Group membership validated
- Affected access restored
- Systems and services verified

### 11.5 Validation Complete

- Windows logging operational
- Sysmon telemetry operational where configured
- Wazuh telemetry confirmed
- DET-042 validated
- No continuing related alerts or evidence of compromise observed

### 11.6 Final Documentation

Document:

- Incident summary
- Deleted group
- Performing account
- Source host
- Timeline
- Root cause
- Scope
- Evidence collected
- Containment actions
- Eradication actions
- Recovery actions
- Validation results
- Lessons learned
- Final incident classification

The incident should not be closed solely because the deleted group was restored. Closure requires reasonable confidence that the underlying cause and attacker access have been addressed.

---

## 12. MITRE ATT&CK Mapping

| Technique | Name | Relevance |
|---|---|---|
| **T1531** | Account Access Removal | Security-enabled group deletion can remove access to systems, resources, or administrative functions and may be used as an impact technique. |

