# Detection 007 — New User Account Created

## Objective

Detect the creation of new Windows user accounts and provide visibility into account-management activity that could introduce unauthorized access or persistence within the Active Directory environment.

This detection focuses on newly created user accounts and provides an important security signal for investigating whether the account creation was authorized, administrative, or potentially malicious.

## MITRE ATT&CK

**Related Technique:** T1136 — Create Account

Attackers may create new accounts to establish or maintain access to an environment. Unauthorized account creation can therefore be an indicator of persistence or privilege escalation.

DET-007 detects the account-creation event itself. The analyst should investigate the account creator, target account, group memberships, and subsequent activity to determine whether the creation was legitimate.

## Windows Events

**Event ID:** `4720` — A user account was created.

Relevant fields may include:

- Target username
- Target domain
- Subject username
- Subject domain
- Subject user SID
- Target user SID
- Account name
- Display name
- User principal name
- Primary group ID
- User account control
- Timestamp

The **subject account** identifies the account that performed the account-creation action, while the **target account** identifies the newly created user.

## Detection Logic

```text
Windows Event 4720
        ↓
Wazuh base rule 60109
        ↓
Custom rule 100106
        ↓
DET-007 alert
```

The rule detects Windows user-account creation events identified by Wazuh base rule `60109`.

The rule also explicitly requires:

```text
win.system.eventID = 4720
```

No frequency or time-based correlation is applied by DET-007 itself.

## Wazuh Rule

```xml
<rule id="100106"
      level="8">

    <if_sid>60109</if_sid>

    <field name="win.system.eventID">4720</field>

    <description>
        DET-007 New User Account Created: $(win.eventdata.targetUserName)
    </description>

    <group>
        custom_windows,
        account_management,
        user_creation,
        attack.t1136,
    </group>

    <mitre>
        <id>T1136</id>
    </mitre>

</rule>
```

### Rule Details

| Field | Value |
|---|---|
| Detection ID | DET-007 |
| Wazuh Rule ID | 100106 |
| Severity | 8 |
| Parent Rule | 60109 |
| Detection Type | New User Account Created |
| Windows Event | 4720 |
| MITRE Technique | T1136 |
| Category | Account Management / User Creation |

---

## Simulation

A controlled user-account creation event was performed in the Windows Active Directory lab environment.

```text
Administrator / Test Account
        ↓
Creates a new Windows user
        ↓
Windows generates Event 4720
        ↓
Wazuh base rule 60109 matches
        ↓
Custom rule 100106 matches
        ↓
DET-007 alert generated
```

## Expected Alert

The expected Wazuh alert should contain:

- **Detection:** `DET-007`
- **Rule ID:** `100106`
- **Severity:** `8`
- **Windows Event:** `4720`
- Target username
- Target domain
- Subject username
- Subject domain
- Account-creation details
- Timestamp

The alert description should identify the newly created account:

```text
DET-007 New User Account Created: <username>
```

## Validation Result

**Status: VALIDATED**

The rule successfully detected Windows user-account creation telemetry through Wazuh base rule `60109` and generated the expected custom Wazuh detection.

The detection provides visibility into new account creation that can be investigated for unauthorized access, persistence, or legitimate administrative activity.

## Investigation Playbook

When a DET-007 alert is generated, the analyst should determine whether the new account was intentionally created and whether it received any privileges or access beyond what was expected.

### 1. Identify the newly created account

Review:

- Target username
- Target domain
- Display name
- User principal name
- Account type
- Account location / OU where available
- User account control settings

Determine whether the account follows the organization's expected naming and provisioning conventions.

### 2. Identify who created the account

Review:

- Subject username
- Subject domain
- Subject user SID
- Source system where available
- Timestamp

Determine whether the creating account is authorized to provision users.

An unexpected administrative account creating a new user should receive additional scrutiny.

### 3. Determine whether the account creation was authorized

Check:

- Change request or ticket
- HR/user onboarding records where applicable
- Administrative procedures
- Expected account naming conventions
- Account creation timing

If the account cannot be associated with legitimate administrative activity, escalate the investigation.

### 4. Review account privileges and group membership

Determine whether the newly created account was subsequently added to:

- Domain Admins
- Enterprise Admins
- Administrators
- IT administration groups
- Other privileged groups
- Sensitive application or resource groups

Correlate with relevant group-membership detections where applicable.

A newly created account followed by privileged-group membership is a significantly higher-risk sequence.

### 5. Review subsequent account activity

Search for:

- Successful authentication
- Failed authentication
- Remote Desktop activity
- SMB access
- PowerShell execution
- Process creation
- Privilege escalation
- Account modifications
- Lateral movement
- Persistence activity

Pay particular attention to activity occurring shortly after account creation.

### 6. Check for additional account changes

Review whether the newly created account was subsequently:

- Enabled or disabled
- Given a password reset
- Added to groups
- Granted additional privileges
- Modified with unusual account-control settings

Correlate with other account-management detections where applicable.

### 7. Determine whether the account represents persistence

Assess whether:

- The creator account was compromised.
- The new account has unusual privileges.
- The account was created outside normal administrative processes.
- The account immediately performed authentication.
- The account was added to privileged groups.
- The account remains active without a legitimate owner.

These indicators can support a potential **Create Account** persistence scenario.

## Response Playbook

### If the activity is benign

- Confirm the account creation was authorized.
- Verify the account owner and intended purpose.
- Confirm group memberships and privileges are appropriate.
- Document the finding if required.
- Close the alert when no suspicious activity is identified.

### If the activity is suspicious

- Investigate the account that created the new user.
- Review the new account's group memberships and permissions.
- Check for authentication activity using the new account.
- Determine whether additional account modifications occurred.
- Escalate if unauthorized account creation is confirmed.

### If compromise is suspected

- Disable the newly created account where appropriate.
- Remove unauthorized group memberships and privileges.
- Reset or revoke credentials associated with the account.
- Investigate the account that created the user.
- Review other accounts created by the same administrator or source.
- Search for post-creation authentication and lateral-movement activity.
- Investigate the originating system for signs of compromise.
- Document the incident and response actions.

## False Positives

Common legitimate causes include:

- Normal employee onboarding.
- Administrative account provisioning.
- Service-account creation.
- Application deployment.
- Test-account creation.
- Helpdesk activity.
- Domain administration.
- Automated identity-management systems.
- Scheduled account-provisioning workflows.

A DET-007 alert **should not automatically be considered malicious**.

The primary investigative question is whether the account creation was authorized and whether the newly created account received unexpected access or privileges.

## Tuning Considerations

DET-007 is configured as a **medium-high severity account-management detection**.

The current detection is intentionally focused on the account-creation event:

```text
Windows Event 4720
        ↓
Wazuh rule 60109
        ↓
DET-007 / Rule 100106
```

Potential tuning options include:

- Increasing severity when privileged accounts create new users unexpectedly.
- Increasing severity when accounts are created outside approved OUs.
- Correlating account creation with subsequent privileged-group membership.
- Correlating account creation with successful authentication.
- Correlating account creation with password resets or account enablement.
- Suppressing known automated identity-management systems where appropriate.
- Creating separate severity levels for standard, service, and privileged account creation.
- Monitoring for multiple accounts created by the same subject account within a short period.
- Correlating newly created accounts with subsequent lateral-movement or persistence activity.

A newly created account becomes a stronger indicator of malicious activity when it is followed by **privilege assignment, authentication, persistence, or other suspicious behavior**.

DET-007 therefore provides the foundational account-creation telemetry required for higher-confidence account-management investigations.
