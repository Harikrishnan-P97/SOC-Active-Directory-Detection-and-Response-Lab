# Detection 016 — AD Account/Computer Attribute Modification

## Objective

Detect changes to Directory Service object attributes within Active Directory, providing critical visibility into account manipulation, privilege escalation vectors, and stealthy persistence mechanisms.

Adversaries with sufficient permissions inside Active Directory often modify specific object attributes to maintain low-profile access, bypass security controls, or prepare for complex attacks. Key target attributes include `servicePrincipalName` (SPN targeted for Kerberoasting or targeted AS-REP roasting), `userAccountControl` (enabling accounts or disabling pre-authentication), `msDS-AllowedToDelegateTo` / `msDS-AllowedToActOnBehalfOfOtherIdentity` (Constrained and Resource-Based Constrained Delegation abuse), and security descriptor changes.

DET-016 monitors Directory Service audit telemetry to capture attribute modifications, highlighting the modified object, the target LDAP attribute name, and the subject identity responsible for the change.

## MITRE ATT&CK

**Related Technique:** T1098 — Account Manipulation

Adversaries may modify account attributes to maintain persistent access, escalate privileges, or evade security defenses without creating new user accounts. Modifying computer or user object parameters directly within Active Directory enables advanced delegation attacks (e.g., RBCD) and stealthy backdoors.

DET-016 alerts on Directory Service modifications, allowing analysts to correlate target LDAP attributes against known attack primitives and unauthorized administrative actions.

## Windows Events

**Event ID:** `5136` — A directory service object was modified.

Relevant fields include:

- Target Object DN (`win.eventdata.objectDN`)
- Attribute LDAP Display Name (`win.eventdata.attributeLDAPDisplayName`)
- Attribute Value (`win.eventdata.attributeValue`)
- Subject Username (`win.eventdata.subjectUserName`)
- Subject Domain (`win.eventdata.subjectDomain`)
- Subject User SID (`win.eventdata.subjectUserSid`)
- Computer / Domain Controller Name
- Timestamp

The **subject username** identifies who performed the directory modification, while **objectDN** and **attributeLDAPDisplayName** reveal the target asset and specific setting changed.

## Detection Logic

```text
Windows Event 5136
        ↓
Wazuh base rule 60229
        ↓
Custom rule 100115
        ↓
DET-016 alert
```

The rule triggers on directory object modification events processed under Wazuh base rule `60229`.

The detection structure:

```text
Base Rule Match: 60229 (Directory Service Object Modification)
Target Event: Windows Event 5136
```

No additional field filtering is enforced in rule `100115`, allowing it to capture all Directory Service object attribute changes under parent rule `60229` and present detailed context within the dynamic description.

## Wazuh Rule

```xml
<rule id="100115" level="10">
    <if_sid>60229</if_sid>

    <description>
        DET-016 - Active Directory object attribute modified: $(win.eventdata.objectDN) - Attribute: $(win.eventdata.attributeLDAPDisplayName) - Modified by: $(win.eventdata.subjectUserName)
    </description>

    <mitre>
        <id>T1098</id>
    </mitre>

    <group>
        custom_detection_engineering,
        windows,
        account_management,
        privilege_escalation,
        ad_attribute_modification
    </group>
</rule>
```

### Rule Details

| Field | Value |
|---|---|
| Detection ID | DET-016 |
| Wazuh Rule ID | 100115 |
| Severity | 10 |
| Parent Rule | 60229 |
| Detection Type | AD Account/Computer Attribute Modification |
| Windows Event | 5136 |
| MITRE Technique | T1098 |
| Category | Account Management / Privilege Escalation |

---

## Simulation

A controlled directory object modification was executed on a Domain Controller within the lab environment by altering an LDAP attribute (such as adding a `servicePrincipalName` or modifying `userAccountControl`) using PowerShell ActiveDirectory module or `Set-ADObject`.

```text
Domain Controller / Administrative Workstation
        ↓
Executes Set-ADUser / Set-ADComputer attribute modification
        ↓
Windows DC generates Event 5136
        ↓
Wazuh base rule 60229 matches
        ↓
Custom rule 100115 matches
        ↓
DET-016 alert generated
```

## Expected Alert

The expected Wazuh alert contains:

- **Detection:** `DET-016`
- **Rule ID:** `100115`
- **Severity:** `10`
- **Windows Event:** `5136`
- Target Object Distinguished Name (`objectDN`)
- Modified Attribute Name (`attributeLDAPDisplayName`)
- Subject Username (`subjectUserName`)
- Domain Controller name
- Timestamp

The alert description explicitly reports:

```text
DET-016 - Active Directory object attribute modified: <objectDN> - Attribute: <attributeLDAPDisplayName> - Modified by: <subjectUserName>
```

## Validation Result

**Status: VALIDATED**

The rule successfully identified Windows Event 5136 directory modification events via base rule `60229` and generated custom alert 100115, populating key fields including target object DN, modified attribute name, and performing subject.

The rule provides high-fidelity insight into sensitive Active Directory configuration changes across domain controllers.

## Investigation Playbook

When DET-016 fires, analysts must evaluate the risk level of the modified LDAP attribute and confirm authorized administrative intent.

### 1. Identify the modified attribute and target object

Review:

- **Target Object:** (`win.eventdata.objectDN`) — Is it a Domain Controller, Tier-0 admin account, computer object, or standard user?
- **Attribute Name:** (`win.eventdata.attributeLDAPDisplayName`)
  - `servicePrincipalName`: SPN assignment (Kerberoasting prep or SPN hijacking).
  - `msDS-AllowedToDelegateTo` / `msDS-AllowedToActOnBehalfOfOtherIdentity`: Kerberos Delegation configuration (RBCD attack vector).
  - `userAccountControl`: Account property flags (e.g., `DONT_REQ_PREAUTH` for AS-REP Roasting).
  - `unixUserPassword` / `unicodePwd`: Direct password/hash modifications.
  - `nTSecurityDescriptor`: ACL modifications granting implicit privileges.
- **Subject Account:** (`win.eventdata.subjectUserName`) — Who made the change?

### 2. Verify change management authorization

Check:

- Active IT infrastructure change tickets or Active Directory maintenance requests
- Identity and Access Management (IAM) ticket workflows
- Scheduled automated identity provisioning or synchronization jobs (e.g., Azure AD Connect)

Unscheduled attribute modifications on high-value objects (Domain Admins, DCs, service accounts) should immediately be treated as high risk.

### 3. Review preceding and post-event telemetry

Inspect activity around the event timestamp:

- Did the subject account perform mass attribute enumeration (e.g., via BloodHound or LDAP query floods)?
- Were process executions on the subject's host involving `PowerView`, `ADModule`, or `dsmod` logged (Sysmon Event 1 / Windows 4688)?
- Are there subsequent Kerberos ticket requests (Event 4768 / 4769) for newly registered SPNs?

### 4. Determine classification

Classify the event:

- **Authorized Administrative Change:** Routine IT update supported by a valid change management ticket.
- **Automated Directory Sync:** Normal operations performed by an authorized service account (e.g., AAD Connect).
- **Unauthorized Manipulation / Adversarial Activity:** Unapproved attribute changes indicative of Kerberoasting setup, RBCD abuse, or persistence insertion.

## Response Playbook

### If the activity is benign

- Validate the ticket reference with the initiating IT administrator.
- Document ticket numbers in SOC incident notes.
- Close the alert as authorized directory administration.

### If the activity is unauthorized or policy-violating

- Revert the target LDAP attribute back to its compliant baseline state using Active Directory administrative tools or restore from backup.
- Notify Active Directory engineering leads of unauthorized manual changes.

### If compromise is suspected

- Immediately isolate the host system used by the initiating subject account.
- Revoke active administrative tokens and force a password reset for the subject account.
- Revert the modified AD attribute immediately to prevent privilege abuse (e.g., remove unauthorized SPNs or RBCD delegation rights).
- Audit domain-wide security descriptors and delegation properties for additional stealthy backdoors.
- Initiate standard Incident Response procedures.

## False Positives

Common benign causes include:

- Automated identity management platforms (Azure AD Connect, MIM) syncing user objects.
- Automated server joining routines configuring computer object attributes.
- Exchange Server or PKI auto-enrollment scripts updating object parameters.

## Tuning Considerations

DET-016 operates at **medium-high severity (Level 10)**.

The current rule structure:

```text
Windows Event 5136
        ↓
Wazuh base rule 60229
        ↓
DET-016 / Rule 100115
```

Tuning strategies include:

- Creating specific child rules targeting critical security-sensitive attributes (`msDS-AllowedToActOnBehalfOfOtherIdentity`, `servicePrincipalName`, `userAccountControl`) with elevated severity (Level 12-14).
- Filtering out known service account SIDs performing legitimate automated synchronization (e.g., Azure AD Sync accounts).
- Adding alert grouping for high-value OUs (e.g., Domain Controllers, Admin Accounts OU).

Directory attribute monitoring ensures adversaries cannot quietly manipulate Kerberos properties or Active Directory delegation for persistent privilege escalation.
