# IR-002 — Active Directory Account & Privilege Compromise

## 1. Objective

This playbook provides an incident-level workflow for investigating and responding to unauthorized Active Directory account and privilege changes within the Windows Active Directory lab.

It covers incidents involving account creation, password resets, account enablement, account deletion, privileged group membership changes, privileged account authentication, and Active Directory object attribute modification.

The objective is to determine whether the observed activity is authorized, suspicious, malicious, or evidence of account or privilege compromise; establish the affected identity, source, target objects, and scope; and guide containment, eradication, recovery, and validation.

---

## 2. Scope & Related Detections

### 2.1 Scope

This playbook applies to Active Directory account and privilege activity involving:

- **DC01** — Windows Server 2022 / Active Directory Domain Controller
- **CLIENT01** — Windows 11 domain-joined endpoint
- Domain user accounts
- Privileged and administrative accounts
- Security-enabled Active Directory groups
- User and computer objects
- Active Directory object attributes
- Wazuh alerts generated from Windows security and directory-service telemetry

Primary Windows events covered by this incident scenario are:

- `4720` — A user account was created
- `4724` — An attempt was made to reset an account's password
- `4722` — A user account was enabled
- `4726` — A user account was deleted
- `4728` — A member was added to a security-enabled global group
- `4756` — A member was added to a security-enabled universal group
- `4732` — A member was added to a security-enabled local group
- `4624` — An account was successfully logged on
- `5136` — A directory service object was modified

### 2.2 Related Detection Rules

| Detection | Name | Wazuh Rule | Severity | Windows Event |
|---|---|---:|---:|---:|
| DET-007 | New User Account Created | 100106 | 8 | 4720 |
| DET-008 | Password Reset | 100107 | 9 | 4724 |
| DET-009 | User Account Enabled | 100108 | 7 | 4722 |
| DET-010 | Windows User Account Deletion | 100109 | 10 | 4726 |
| DET-011 | User Added to Domain Admins | 100110 | 12 | 4728 |
| DET-012 | User Added to Enterprise Admins | 100111 | 13 | 4756 |
| DET-013 | User Added to Local Administrators | 100112 | 11 | 4732 |
| DET-014 | Administrator Account Enabled | 100113 | 10 | 4722 |
| DET-015 | Privileged Account Logon | 100114 | 10 | 4624 |
| DET-016 | AD Account/Computer Attribute Modification | 100115 | 10 | 5136 |

### 2.3 Detection-to-Incident Relationship

The individual detections provide signals that should be correlated during the investigation.

A possible account and privilege compromise chain is:

```text
Unauthorized Account Activity
          │
          ├──────────────→ DET-007
          │                 New Account Created
          │
          ├──────────────→ DET-008
          │                 Password Reset
          │
          ├──────────────→ DET-009
          │                 Account Enabled
          │
          ├──────────────→ DET-014
          │                 Administrator Account Enabled
          │
          └──────────────→ DET-016
                            AD Attribute Modification
                                  │
                                  ↓
                       Privilege / Access Modification
                                  │
                    ┌─────────────┼─────────────┐
                    ↓             ↓             ↓
                DET-011       DET-012       DET-013
             Domain Admins  Enterprise     Local Admins
                              Admins
                    │             │             │
                    └─────────────┼─────────────┘
                                  ↓
                              DET-015
                         Privileged Logon
```

Account deletion is handled separately within the same incident scenario:

```text
Unauthorized AD Activity
          ↓
      DET-010
   Account Deleted
```

The sequence above represents a possible attack progression. It is not guaranteed that every detection will trigger during the same incident.

---

## 3. Attack Scenario

### 3.1 Scenario Overview

An attacker who has obtained sufficient access to Active Directory may manipulate accounts or privileges to establish unauthorized access, escalate privileges, maintain access, or interfere with legitimate identities.

The activity may begin with creation or modification of an account, a password reset, or enablement of an existing account. The attacker may then add an account to a privileged group, enable the built-in Administrator account, modify sensitive directory attributes, or use a privileged account to authenticate to a system.

Account deletion can also occur as part of malicious activity, either to remove legitimate access or to interfere with administrative operations.

The analyst must determine whether the observed activity represents:

- Legitimate identity administration
- Automated account provisioning
- Authorized password or account maintenance
- Routine administrative group management
- Unauthorized account manipulation
- Privilege escalation
- Persistence through Active Directory
- Compromised privileged credentials
- Broader domain compromise

### 3.2 Typical Attack Flow

```text
Initial Access / Existing Privilege
              │
              ↓
       Active Directory
       Account Manipulation
              │
       ┌──────┼───────┐
       ↓      ↓       ↓
   Create   Enable   Reset
   Account  Account  Password
       │      │       │
       └──────┼───────┘
              ↓
      Modify Privileges
              │
      ┌───────┼────────┐
      ↓       ↓        ↓
 Domain    Enterprise  Local
 Admins     Admins    Admins
      │       │        │
      └───────┼────────┘
              ↓
      Privileged Logon
              │
              ↓
       Further Activity
```

An alternative path may involve the built-in Administrator account or direct Active Directory attribute manipulation:

```text
Existing Administrator / AD Object
              ↓
       Account or Attribute
          Modification
              ↓
       Unauthorized Access
              ↓
       Privileged Logon
```

### 3.3 Expected Detection Sequence

A potential privilege-compromise incident may generate activity in the following order:

1. **DET-007** may identify creation of an unauthorized user account.
2. **DET-008** may identify a password reset affecting an account.
3. **DET-009** may identify an account being enabled.
4. **DET-011**, **DET-012**, or **DET-013** may identify unauthorized privileged-group membership changes.
5. **DET-014** may identify enablement of the built-in Administrator account.
6. **DET-016** may identify modification of a sensitive Active Directory object attribute.
7. **DET-015** may identify a subsequent successful privileged authentication.
8. **DET-010** may identify deletion of an account during or after the activity.

This sequence is illustrative. Actual event order depends on the attack technique, account state, permissions, and attacker behavior.

### 3.4 Potential Impact

A confirmed account or privilege compromise can result in:

- Unauthorized domain account access
- Privilege escalation
- Domain Administrator or Enterprise Administrator compromise
- Unauthorized local administrator access
- Persistence through account manipulation
- Unauthorized Active Directory configuration changes
- Privileged lateral movement
- Loss of legitimate user access
- Deletion of accounts or identities
- Broader domain compromise

The risk is highest when unauthorized changes affect privileged accounts, security-enabled administrative groups, Domain Controllers, or sensitive Active Directory objects.

---

## 4. Initial Triage

### 4.1 Alert Validation

When an AD account or privilege alert is received:

1. Identify the triggering detection and Wazuh rule ID.
2. Review the raw Windows event.
3. Record the event timestamp.
4. Identify the Domain Controller or host that generated the event.
5. Identify the subject account responsible for the change where available.
6. Identify the target account, group, object, or attribute.
7. Determine the type of change.
8. Search for related account and privilege alerts around the same timestamp.

The initial alert should be treated as an indicator requiring context rather than automatic proof of compromise.

### 4.2 Identify Affected Assets

Determine:

- Which Domain Controller generated the event
- Whether the target is a user, computer, group, or directory object
- Whether the target is privileged
- Whether the activity affects **DC01**
- Whether **CLIENT01** is the suspected source of the administrative activity
- Whether multiple objects or systems are involved

Changes affecting Domain Admins, Enterprise Admins, Administrator accounts, Domain Controllers, or other high-value objects require elevated scrutiny.

### 4.3 Identify Affected Identity

Establish:

- Subject account that performed the change
- Target account
- Target group
- Target object
- Whether the subject account is privileged
- Whether the target account is privileged
- Whether the account is newly created
- Whether the account was recently enabled or had its password reset
- Whether the account subsequently authenticated successfully

### 4.4 Identify Attack Source

Determine the system from which the administrative activity originated where available.

Review:

- Source workstation
- Source IP
- Domain Controller processing the event
- Process execution telemetry on the suspected source
- Whether the source is an expected administrative workstation

An authorized administrator account performing an unexpected change from an unusual endpoint should be treated as suspicious until validated.

### 4.5 Establish Initial Timeline

Record the earliest related event and activity surrounding the alert.

At minimum, capture:

| Time | Detection/Event | Host | Subject | Target | Finding |
|---|---|---|---|---|---|
| `timestamp` | Event / DET ID | Host | Account | Account/Group/Object | Initial finding |

Determine:

- First observed account or privilege change
- Password reset or account enablement
- Privileged group membership change
- Sensitive AD attribute modification
- Privileged authentication
- Account deletion, if applicable
- Subsequent endpoint or AD activity

### 4.6 Determine Whether Activity Is Expected

Consider:

- Was there an authorized account-management request?
- Was a user legitimately created or enabled?
- Was the password reset expected?
- Was the group membership change approved?
- Was the Administrator account intentionally enabled?
- Was the AD attribute change part of legitimate administration?
- Was the activity performed by an approved administrative account?
- Did the change occur during an expected maintenance window?

Decision:

```text
Expected / Authorized
        │
        └──→ Document / Monitor / Close

Suspicious
        │
        ↓
Continue Investigation

Malicious / Compromise
        │
        ↓
Containment & Eradication
```

---

## 5. Investigation Workflow

### 5.1 Establish the Initial Event

Start with the Wazuh alert and identify:

- Detection ID
- Wazuh rule ID
- Windows event ID
- Timestamp
- Subject account
- Target account/object/group
- Domain Controller
- Relevant source information
- Modified attribute, where applicable

For Event `4720`, determine who created the account and which account was created.

For Event `4724`, determine who initiated the password reset and which account was affected.

For Event `4722`, determine which account was enabled.

For Event `4726`, determine which account was deleted and who performed the action.

For Events `4728`, `4756`, and `4732`, identify the member added and the target security-enabled group.

For Event `4624`, determine how and from where the privileged account authenticated.

For Event `5136`, identify the target object and modified LDAP attribute.

### 5.2 Investigate the Initiating Identity

Determine whether the subject account was authorized to perform the observed action.

Review:

- Account type
- Privilege level
- Normal administrative responsibilities
- Recent authentication activity
- Recent password or account changes
- Other changes performed by the same account
- Whether the account itself may be compromised

A privileged account performing multiple unexpected changes should be investigated as a potential compromised identity.

### 5.3 Investigate the Target Account / Group / Object

For account-related activity:

- Determine whether the account is legitimate.
- Determine when it was created.
- Determine whether it was enabled.
- Determine whether its password was reset.
- Determine whether it received new privileges.
- Determine whether it subsequently authenticated.

For group-related activity:

- Identify the member added.
- Identify the target group.
- Determine whether the group provides administrative privileges.
- Determine whether additional members were modified.

For attribute-related activity:

- Identify the target object.
- Identify the modified LDAP attribute.
- Determine whether the attribute is security-sensitive.
- Compare the change with the expected configuration.

### 5.4 Investigate Privilege Changes

Prioritize:

- Domain Admin membership
- Enterprise Admin membership
- Local Administrators membership
- Administrator account enablement
- Sensitive AD attribute modification

For **DET-011**, **DET-012**, and **DET-013**, verify whether the membership change was authorized and whether the affected account subsequently authenticated.

For **DET-014**, determine why the built-in Administrator account was enabled and whether the action was expected.

### 5.5 Investigate Privileged Authentication

When **DET-015** fires, correlate the privileged logon with preceding account-management activity.

Review:

- Target privileged account
- Logon Type
- Source IP
- Workstation name
- Target computer
- Timestamp
- Authentication package
- Related failed logons
- Recent password resets
- Recent account enablement
- Recent privilege changes

A suspicious chain may look like:

```text
Account / Privilege Change
          ↓
Privileged Account
          ↓
Successful Authentication
          ↓
Post-Logon Administrative Activity
```

Review post-logon Sysmon and Windows process activity for:

- `powershell.exe`
- `cmd.exe`
- `wmic.exe`
- `psexec.exe`
- Credential-access tools
- Discovery tools
- Service creation
- Scheduled task creation
- Firewall or security-control modification

### 5.6 Investigate Active Directory Attribute Changes

For **DET-016**, examine:

- `win.eventdata.objectDN`
- `win.eventdata.attributeLDAPDisplayName`
- `win.eventdata.attributeValue`
- `win.eventdata.subjectUserName`
- `win.eventdata.subjectDomain`
- `win.eventdata.subjectUserSid`

Give additional scrutiny to security-sensitive attributes such as:

- `servicePrincipalName`
- `userAccountControl`
- `msDS-AllowedToDelegateTo`
- `msDS-AllowedToActOnBehalfOfOtherIdentity`
- `nTSecurityDescriptor`

Correlate the modification with authentication, Kerberos, discovery, or endpoint execution activity.

If the change is associated with Kerberos abuse or credential theft, expand the investigation to **IR-003 — Kerberos & Credential Theft Attack**.

### 5.7 Correlate Related Detection Activity

Search for related detections involving the same:

- Subject account
- Target account
- Group
- Object
- Host
- Source IP
- Time period

Priority correlations include:

| Detection | Correlation Question |
|---|---|
| DET-007 | Was an account created before the privilege activity? |
| DET-008 | Was the target account's password reset? |
| DET-009 | Was the account enabled before use? |
| DET-010 | Was an account deleted as part of the activity? |
| DET-011 | Was an account added to Domain Admins? |
| DET-012 | Was an account added to Enterprise Admins? |
| DET-013 | Was an account added to Local Administrators? |
| DET-014 | Was the built-in Administrator account enabled? |
| DET-015 | Did the affected privileged account successfully authenticate? |
| DET-016 | Were sensitive AD attributes modified? |

Also search for authentication, lateral movement, persistence, credential-access, and defense-evasion detections that may indicate follow-on activity.

### 5.8 Build the Attack Timeline

Construct a single timeline combining account, privilege, authentication, and endpoint events.

Example:

| Time | Event / Detection | Host | Subject | Target | Finding |
|---|---|---|---|---|---|
| T1 | DET-007 / 4720 | DC01 | Admin account | New user | Account created |
| T2 | DET-008 / 4724 | DC01 | Admin account | New user | Password reset |
| T3 | DET-009 / 4722 | DC01 | Admin account | New user | Account enabled |
| T4 | DET-011 / 4728 | DC01 | Admin account | New user | Domain Admin membership |
| T5 | DET-015 / 4624 | DC01/CLIENT01 | New user | Target host | Privileged logon |
| T6 | Sysmon / Windows | Target | New user | Target host | Post-logon activity |

The example is an investigation format. The actual sequence must be established from observed telemetry.

### 5.9 Determine Attack Scope

Determine whether the activity is limited to:

**Single account**

```text
One subject → One target account
```

**Privilege compromise**

```text
One account → Administrative group
```

**Multiple accounts**

```text
One subject → Multiple accounts/groups
```

**Domain-level activity**

```text
Subject → Multiple privileged objects / systems
```

Scope should include:

- Number of affected accounts
- Number of privileged accounts
- Number of affected groups
- Number of affected AD objects
- Number of affected systems
- Source systems involved
- Duration of activity
- Successful privileged authentications
- Evidence of persistence or lateral movement

### 5.10 Determine Evidence of Compromise

Evidence supporting confirmed compromise may include:

- Unauthorized privileged group membership
- Unauthorized Administrator account enablement
- Unauthorized account creation followed by privilege assignment
- Privileged authentication inconsistent with expected activity
- Sensitive AD attribute modification without authorization
- Multiple related account changes from the same suspicious source
- Post-authentication malicious activity
- Evidence that the initiating administrative account was compromised
- Lateral movement or persistence following privilege changes

A single legitimate account-management event does not establish compromise.

---

## 6. Incident Assessment

### 6.1 Suspicious Activity

Classify the activity as suspicious when the change is unusual or cannot immediately be explained, but there is insufficient evidence to confirm malicious activity.

Examples:

- Unexpected account enablement
- Password reset outside normal workflow
- Unusual group membership change
- Privileged logon from an unexpected workstation
- Unscheduled AD attribute modification

Actions:

- Continue investigation
- Validate administrative authorization
- Correlate related events
- Monitor the affected accounts and systems

### 6.2 Confirmed Malicious Activity

Classify the activity as malicious when the evidence indicates deliberate unauthorized manipulation.

Examples:

- Unauthorized account added to an administrative group
- Administrator account enabled without an approved reason
- Unauthorized privileged access from a suspicious source
- Multiple account changes performed outside established administrative procedures
- Sensitive AD attributes modified to facilitate unauthorized access

### 6.3 Confirmed Compromise

Classify the incident as confirmed compromise when there is sufficient evidence that an attacker obtained or used unauthorized account privileges.

Strong indicators include:

- Unauthorized account with administrative privileges
- Unauthorized Domain Admin or Enterprise Admin membership
- Suspicious privileged authentication after privilege modification
- Compromised administrative account performing unauthorized changes
- Malicious post-logon activity
- Persistence established through account or AD manipulation
- Evidence of broader domain compromise

### 6.4 Severity Considerations

Severity should increase based on:

- Privilege level
- Target object sensitivity
- Domain-wide impact
- Number of affected accounts
- Number of affected systems
- Successful privileged authentication
- Persistence
- Credential compromise
- Follow-on lateral movement
- Security-control tampering

**Enterprise Admin** or **Domain Admin** compromise should be treated as a high-risk condition requiring immediate escalation.

---

## 7. Containment

### 7.1 Immediate Containment

Containment should prevent further unauthorized account or privilege use while preserving investigation capability.

Depending on the findings:

- Stop unauthorized administrative activity.
- Disable or lock compromised accounts.
- Remove unauthorized privileged group membership.
- Isolate **CLIENT01** if it is identified as the compromised source.
- Preserve relevant Windows and Wazuh telemetry.
- Avoid unnecessary disruption to **DC01**.

### 7.2 Account Containment

For a compromised or unauthorized account:

- Disable the account where appropriate.
- Reset its password.
- Review all current group memberships.
- Remove unauthorized privileges.
- Review recent authentication activity.
- Identify other accounts potentially affected by the same source.

For newly created malicious accounts:

- Disable the account.
- Preserve relevant evidence.
- Remove the account after investigation requirements are satisfied.

### 7.3 Privileged Access Containment

For unauthorized privilege changes:

- Remove the affected account from unauthorized administrative groups.
- Disable compromised privileged accounts where appropriate.
- Reset credentials for compromised privileged accounts.
- Review privileged group membership across the domain.
- Review recent privileged authentications.

Prioritize Domain Admin and Enterprise Admin changes because of their potential domain-wide impact.

### 7.4 Endpoint Containment

If the source endpoint is suspected to be compromised:

- Isolate **CLIENT01** from the network where appropriate.
- Preserve evidence before destructive remediation when practical.
- Investigate endpoint process and network activity.
- Review Sysmon telemetry for credential access, discovery, or lateral movement.

### 7.5 AD Containment

For suspected domain-level compromise:

- Restrict compromised administrative identities.
- Remove unauthorized group memberships.
- Disable unauthorized accounts.
- Review privileged accounts and groups for additional unauthorized changes.
- Audit sensitive AD objects and attributes.
- Assess whether the incident has expanded into credential theft, Kerberos abuse, lateral movement, or persistence.

Actions affecting **DC01** must be carefully evaluated because it is the domain controller for the lab.

---

## 8. Eradication

### 8.1 Remove Attacker Access

- Remove unauthorized accounts.
- Remove unauthorized group memberships.
- Disable compromised identities.
- Remove unauthorized administrative access.
- Revert unauthorized Active Directory changes.

### 8.2 Remove Persistence / Malicious Artifacts

If account or privilege manipulation was part of a larger endpoint compromise:

- Remove malicious tools and files.
- Remove identified persistence mechanisms.
- Remove malicious scheduled tasks or services.
- Investigate suspicious PowerShell or command execution.

If persistence is confirmed, continue the investigation under **IR-006 — Persistence & Defense Evasion** as appropriate.

### 8.3 Remediate Compromised Credentials

For compromised accounts:

- Reset affected passwords.
- Identify other credentials that may have been exposed.
- Review privileged account exposure.
- Reset additional credentials when evidence indicates potential compromise.
- Verify that unauthorized users can no longer authenticate.

For privileged or domain-level compromise, credential remediation should cover all accounts reasonably believed to be exposed rather than only the initially detected account.

### 8.4 Restore Unauthorized Changes

Depending on the incident:

- Remove unauthorized group membership.
- Restore disabled or deleted legitimate accounts where appropriate.
- Revert unauthorized account-state changes.
- Revert unauthorized AD attributes.
- Restore expected privileged-group membership.
- Remove unauthorized delegation or security-descriptor changes when identified.

All remediation actions should be validated against the expected AD configuration.

---

## 9. Recovery & Validation

### 9.1 System Recovery

For a compromised endpoint:

- Restore the endpoint to a trusted state.
- Reconnect it to the environment only after remediation is complete.
- Verify that malicious activity has stopped.

For **DC01**:

- Preserve domain availability.
- Verify Active Directory services remain functional.
- Confirm authentication services continue operating normally.
- Validate that security logging remains enabled.

### 9.2 Account / AD Recovery

Verify:

- Legitimate accounts exist and are enabled as expected.
- Unauthorized accounts have been removed.
- Passwords have been reset where required.
- Privileged group memberships are correct.
- Administrator account state is correct.
- Unauthorized AD attribute modifications have been reverted.
- Legitimate administrative functions continue to operate.

### 9.3 Security Control Recovery

Verify that:

- Windows Security Event Logging is operational.
- Active Directory auditing is functioning.
- Sysmon is operating on monitored endpoints.
- Wazuh agents are connected.
- Wazuh manager processing is functioning.
- Relevant security controls remain enabled.

### 9.4 Telemetry Validation

Confirm that Wazuh continues receiving Active Directory telemetry.

Validation should include visibility of:

- Event `4720`
- Event `4724`
- Event `4722`
- Event `4726`
- Event `4728`
- Event `4756`
- Event `4732`
- Event `4624`
- Event `5136`

Confirm that the related custom detections remain operational.

Relevant dashboards include:

- **Active Directory Security**
- **Authentication & Account Monitoring**
- **SOC Detection Overview**
- **Sysmon Endpoint Activity**

The **Active Directory Security** dashboard should be used to review:

- User account creation
- User account deletion
- Password reset activity
- Group membership changes
- Privileged group changes
- AD attribute modifications
- AD attack detections
- Recent AD security events

### 9.5 Post-Recovery Monitoring

Continue monitoring for:

- New unauthorized accounts
- Unexpected password resets
- Unexpected account enablement
- Administrator account enablement
- Privileged group membership changes
- Privileged logons from unexpected sources
- Sensitive AD attribute modifications
- Additional lateral movement
- Persistence
- Credential theft

No continuing related activity should be observed before the incident is considered fully resolved.

---

## 10. Escalation Criteria

### 10.1 Escalate When

Escalate the incident when:

- Unauthorized account manipulation is confirmed.
- Unauthorized privilege escalation is confirmed.
- A privileged account is suspected to be compromised.
- Multiple accounts or systems are affected.
- Unauthorized AD attribute modification is identified.
- Suspicious privileged authentication follows an account or privilege change.
- The activity continues after initial containment.

### 10.2 High-Risk Conditions

Treat the incident as high risk when:

- An account is added to Domain Admins.
- An account is added to Enterprise Admins.
- A privileged account is compromised.
- The built-in Administrator account is unexpectedly enabled.
- Sensitive AD delegation or security attributes are modified.
- Unauthorized administrative access is established.
- Credential theft is suspected.
- Persistence or lateral movement follows the privilege change.

### 10.3 Domain-Level Compromise Indicators

Escalate immediately when the investigation identifies:

- Domain Admin compromise
- Enterprise Admin compromise
- Multiple privileged accounts compromised
- Unauthorized changes across multiple privileged groups
- Sensitive AD attribute manipulation across multiple objects
- Credential theft
- DCSync activity
- Golden Ticket activity
- NTDS.dit credential theft
- Widespread lateral movement
- Domain-wide persistence

These conditions require correlation with **IR-003 — Kerberos & Credential Theft Attack**, **IR-005 — Lateral Movement & Remote Execution**, **IR-006 — Persistence & Defense Evasion**, or other applicable playbooks.

---

## 11. Closure Criteria

### 11.1 Investigation Complete

Confirm that:

- The initiating identity has been identified or reasonably assessed.
- Affected accounts, groups, and objects have been identified.
- The attack timeline has been established.
- The source system has been identified or assessed.
- The scope of account and privilege changes is understood.
- Related detections have been investigated.

### 11.2 Containment Complete

Confirm that:

- Unauthorized account activity has stopped.
- Compromised accounts have been contained.
- Unauthorized privileges have been removed.
- Affected endpoints have been isolated or remediated where required.
- Domain-level risk has been assessed.

### 11.3 Eradication Complete

Confirm that:

- Unauthorized accounts have been removed.
- Unauthorized group memberships have been removed.
- Compromised credentials have been remediated.
- Malicious artifacts and persistence have been removed.
- Unauthorized AD changes have been reverted.
- Attacker access has been removed.

### 11.4 Recovery Complete

Confirm that:

- Legitimate accounts function normally.
- Active Directory services function normally.
- Privileged group memberships are correct.
- Administrator account state is correct.
- Affected endpoints are operational.
- Security controls are restored.

### 11.5 Validation Complete

Confirm that:

- Windows security telemetry is functioning.
- Active Directory auditing is functioning.
- Sysmon telemetry is functioning where applicable.
- Wazuh is receiving telemetry.
- Related custom detections remain operational.
- No continuing evidence of unauthorized account or privilege activity exists.

### 11.6 Final Documentation

Document:

- Initial alert and detection
- Initiating identity
- Affected accounts
- Affected groups
- Affected AD objects
- Source systems
- Attack timeline
- Scope
- Evidence of compromise
- Privilege changes
- Containment actions
- Eradication actions
- Recovery actions
- Validation results
- Related incidents or playbooks
- Final incident disposition

The incident should not be closed solely because the unauthorized change has been reversed. The analyst must establish that attacker access has been removed and that no continuing compromise is evident.

---

## 12. MITRE ATT&CK Mapping

The following techniques represent the primary attack behaviors covered by this incident scenario.

| Technique | Name | Relevance |
|---|---|---|
| **T1136** | Create Account | Covers unauthorized creation of Active Directory accounts detected by DET-007. |
| **T1098** | Account Manipulation | Covers password resets, account enablement, privileged group membership changes, Administrator account enablement, and Active Directory attribute manipulation detected by DET-008, DET-009, DET-011, DET-012, DET-013, DET-014, and DET-016. |
| **T1078** | Valid Accounts | Covers successful authentication using privileged accounts, particularly when credentials are unauthorized or compromised, as detected by DET-015. |
| **T1531** | Account Access Removal | Covers malicious account deletion activity detected by DET-010 where account removal is used to disrupt or remove access. |

The individual detection documents remain the authoritative source for rule-level MITRE mappings. This playbook maps the broader incident scenario rather than duplicating every detection-level mapping.

---

## Related Detection Documentation

The following detection documents provide the technical details for the detections covered by this playbook:

- `DET-007-New-User-Account-Created.md`
- `DET-008-Password-Reset.md`
- `DET-009-User-Account-Enabled.md`
- `DET-010_Windows_User_Account_Deleted.md`
- `DET-011_User_Added_to_Domain_Admins.md`
- `DET-012_User_Added_to_Enterprise_Admins.md`
- `DET-013_User_Added_to_Local_Administrators.md`
- `DET-014_Administrator_Account_Enabled.md`
- `DET-015_Privileged_Account_Logon.md`
- `DET-016_AD_Account_Computer_Attribute_Modification.md`
