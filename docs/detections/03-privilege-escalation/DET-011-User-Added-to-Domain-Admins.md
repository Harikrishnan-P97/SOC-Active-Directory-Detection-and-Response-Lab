# Detection 011 — User Added to Domain Admins

## Objective

Detect when a user account is added to the Domain Admins security group and provide visibility into high-privilege group manipulation within Active Directory.

Adding an account to Domain Admins grants full administrative control over the Active Directory domain. While this may occur during legitimate administrative provisioning or escalation procedures, unauthorized or unexpected additions represent a critical security event that can indicate persistence, privilege escalation, or full domain compromise.

DET-011 provides the core telemetry required to investigate who added the member, which account was granted domain administrative rights, the authorization context, and any subsequent high-privilege actions.

## MITRE ATT&CK

**Related Technique:** T1098 — Account Manipulation

Attackers may manipulate group memberships to escalate privileges or maintain persistent control over an environment. Adding an account to high-value security groups such as Domain Admins is a primary vector for securing domain-wide administrative access.

DET-011 detects the group-addition event itself. The analyst should investigate the performing subject account, the target member, the administrative justification, and subsequent authentication or operational activity across the domain.

## Windows Events

**Event ID:** `4728` — A member was added to a security-enabled global group.

Relevant fields may include:

- Target group name (`Domain Admins`)
- Target group domain
- Target group SID
- Member name (account added)
- Member SID
- Subject username
- Subject domain
- Subject user SID
- Timestamp
- Source system information where available

The **subject account** identifies the account that performed the group modification, while the **member name** identifies the account that received Domain Admins privileges.

## Detection Logic

```text
Windows Event 4728
        ↓
Wazuh base rule 60103
        ↓
Custom rule 100110
        ↓
DET-011 alert
```

The rule detects Windows global group member additions identified by Wazuh base rule `60103`.

The rule explicitly requires:

```text
win.system.eventID = 4728
win.eventdata.targetUserName = Domain Admins
```

No frequency or time-based correlation is applied by DET-011 itself.

## Wazuh Rule

```xml
<rule id="100110" level="12">

    <if_sid>60103</if_sid>

    <field name="win.system.eventID">4728</field>

    <field name="win.eventdata.targetUserName">Domain Admins</field>

    <description>
        DET-011 Member Added to Domain Admins: $(win.eventdata.memberName)
    </description>

    <group>
        custom_windows,
        privilege_escalation,
        domain_admins,
        attack.t1098,
    </group>

    <mitre>
        <id>T1098</id>
    </mitre>

</rule>
```

### Rule Details

| Field | Value |
|---|---|
| Detection ID | DET-011 |
| Wazuh Rule ID | 100110 |
| Severity | 12 |
| Parent Rule | 60103 |
| Detection Type | Member Added to Domain Admins |
| Windows Event | 4728 |
| MITRE Technique | T1098 |
| Category | Privilege Escalation / Account Manipulation |

---

## Simulation

A controlled privilege-assignment action was performed in the Windows Active Directory lab environment by adding a test account to the Domain Admins group.

```text
Administrator / Privileged Account
        ↓
Adds user to Domain Admins group
        ↓
Windows generates Event 4728
        ↓
Wazuh base rule 60103 matches
        ↓
Custom rule 100110 matches
        ↓
DET-011 alert generated
```

## Expected Alert

The expected Wazuh alert should contain:

- **Detection:** `DET-011`
- **Rule ID:** `100110`
- **Severity:** `12`
- **Windows Event:** `4728`
- Target group name (`Domain Admins`)
- Member name
- Member SID
- Subject username
- Subject domain
- Timestamp

The alert description should identify the account added to the group:

```text
DET-011 Member Added to Domain Admins: <memberName>
```

## Validation Result

**Status: VALIDATED**

The rule successfully detected Windows global group modification telemetry targeting Domain Admins through Wazuh base rule `60103` and generated the expected high-severity custom detection.

The detection provides immediate visibility into critical privilege escalation that can be audited for legitimate administration, privilege abuse, or domain compromise.

## Investigation Playbook

When a DET-011 alert is generated, the analyst should treat the event as critical, immediately verify authorization, and investigate the subject and added member accounts.

### 1. Identify the added member account

Review:

- Member name / Target account
- Member SID
- Account type (standard user, service account, temporary account)
- Account creation date (check for recently created accounts via **DET-007**)
- Account status (check if recently enabled via **DET-009** or password reset via **DET-008**)

Adding a newly created, dormant, or standard user account to Domain Admins presents extreme risk.

### 2. Identify who performed the addition

Review:

- Subject username
- Subject domain
- Subject user SID
- Source workstation / Domain Controller
- Timestamp

Determine whether the performing subject account is an authorized Domain Controller or a Tier-0 administrative identity.

### 3. Verify administrative authorization

Check:

- Emergency access / Privileged Access Management (PAM) requests
- Change-management tickets
- Identity & Access Management (IAM) privilege elevation requests
- Onboarding / Role-change documentation

If no active ticket or change request matches this action, treat the event as an active incident.

### 4. Audit prior history of the member account

Search for recent event telemetry for the added account prior to group addition:

- Account creation (Event 4720 / **DET-007**)
- Password resets (Event 4724 / **DET-008**)
- Failed or suspicious authentication attempts
- Commands executed on compromised hosts

Determine whether the account was staged specifically for privilege escalation.

### 5. Review activity performed immediately after group addition

Search for post-escalation activity initiated by the added account across the domain:

- Interactive logons to Domain Controllers
- DCSync / Active Directory database replication activity (e.g., secretsdump)
- Group Policy Object (GPO) modifications
- Creation of additional privileged accounts or scheduled tasks
- PowerShell / WMI remote execution on key infrastructure

### 6. Review subject account activity surrounding the event

Audit all actions taken by the subject account before and after modifying Domain Admins:

- Other group modifications (e.g., Enterprise Admins, Schema Admins)
- User provisioning or account manipulation
- Logon locations and session context

### 7. Assess domain integrity

Determine whether this event indicates:

- **Legitimate Administration:** Authorized Tier-0 role assignment.
- **Privilege Misconfiguration:** Over-privileging a user instead of delegating specific rights.
- **Persistence / Attack Sequence:** An adversary leveraging stolen credentials to establish domain dominance.

## Response Playbook

### If the activity is benign

- Confirm valid PAM ticket or change ticket approval.
- Ensure the privilege assignment strictly follows the principle of least privilege.
- Document the approval and change details in the alert notes.
- Close the alert as an authorized administrative action.

### If the activity is suspicious

- Contact the administrative team lead to verify if an emergency change was enacted.
- Temporarily revert the group modification by removing the account from Domain Admins.
- Initiate a hunting query across domain controllers for any remote sessions using the added account.
- Escalate immediately to the Incident Response lead.

### If compromise is suspected

- Immediately remove the member from Domain Admins and disable the account.
- Revoke all active Kerberos tickets (TGT) across the domain if domain compromise is confirmed (consider `krbtgt` password reset protocol).
- Disable or isolate the subject account that performed the unauthorized addition.
- Conduct a full forensic review of the Domain Controller and source workstation.
- Audit Active Directory for any secondary persistence mechanisms (GPO shifts, extra accounts, delegation changes).
- Document the incident timeline and execute the Domain Remediation Playbook.

## False Positives

Common legitimate causes include:

- Authorized Tier-0 identity provisioning.
- Emergency break-glass account assignments during major outages.
- Identity Lifecycle Management (ILM) automated role updates.
- Controlled active directory deployment or migration tasks.

Due to the extreme risk associated with Domain Admins privileges, **a DET-011 alert should always be investigated, even when originating from known administrative accounts**.

## Tuning Considerations

DET-011 is configured as a **critical severity (Level 12) privilege escalation detection**.

The current detection focuses strictly on additions to Domain Admins:

```text
Windows Event 4728 + Domain Admins
        ↓
Wazuh rule 60103
        ↓
DET-011 / Rule 100110
```

Potential tuning options include:

- Expanding rules to cover other Tier-0 groups (e.g., `Enterprise Admins`, `Schema Admins`, `Administrators`, `Account Operators`).
- Raising severity to 14/15 if the added account was created within the last 24–48 hours.
- Raising severity if the subject account performing the addition is not a recognized break-glass or PAM account.
- Correlating group additions with immediate interactive logons to Domain Controllers.
- Correlating group additions with subsequent GPO changes or DCSync telemetry.
- Suppressing alerts from dedicated, audited PAM automation tooling (only after strict verification).

An addition to Domain Admins represents one of the highest-risk identity events in a Windows environment. DET-011 provides foundational, high-confidence detection for domain privilege escalation tactics.
