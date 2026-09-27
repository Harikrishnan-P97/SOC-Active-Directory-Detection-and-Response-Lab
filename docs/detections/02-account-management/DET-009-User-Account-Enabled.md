# Detection 009 — User Account Enabled

## Objective

Detect Windows user-account enablement events and provide visibility into account-management activity that could restore or introduce access to an account.

An account being enabled can be a legitimate administrative action, but unexpectedly enabling a disabled or dormant account may indicate unauthorized account manipulation or an attempt to restore access for persistence.

DET-009 provides the underlying telemetry required to investigate who enabled the account, which account was affected, and what activity followed the account enablement.

## MITRE ATT&CK

**Related Technique:** T1098 — Account Manipulation

Attackers may manipulate existing accounts to maintain or expand access to an environment. Enabling a previously disabled account can be part of an account-manipulation or persistence sequence, particularly when the account is privileged or subsequently used for suspicious activity.

DET-009 detects the account-enable event itself. The analyst should investigate the initiating account, target account, reason for enablement, and subsequent authentication or privilege activity.

## Windows Events

**Event ID:** `4722` — A user account was enabled.

Relevant fields may include:

- Target username
- Target domain
- Subject username
- Subject domain
- Subject user SID
- Target user SID
- Account name
- User account control
- Timestamp
- Source system information where available

The **subject account** identifies the account that performed the account-enable action, while the **target account** identifies the user account that was enabled.

## Detection Logic

```text
Windows Event 4722
        ↓
Wazuh base rule 60109
        ↓
Custom rule 100108
        ↓
DET-009 alert
```

The rule detects Windows account-enable events identified by Wazuh base rule `60109`.

The rule also explicitly requires:

```text
win.system.eventID = 4722
```

No frequency or time-based correlation is applied by DET-009 itself.

## Wazuh Rule

```xml
<rule id="100108" level="7">

    <if_sid>60109</if_sid>

    <field name="win.system.eventID">4722</field>

    <description>
        DET-009 User Account Enabled: $(win.eventdata.targetUserName)
    </description>

    <group>
        custom_windows,
        account_management,
        account_enabled,
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
| Detection ID | DET-009 |
| Wazuh Rule ID | 100108 |
| Severity | 7 |
| Parent Rule | 60109 |
| Detection Type | User Account Enabled |
| Windows Event | 4722 |
| MITRE Technique | T1098 |
| Category | Account Management / Account Enablement |

---

## Simulation

A controlled account-management action was performed in the Windows Active Directory lab environment by enabling a previously disabled test account.

```text
Administrator / Test Account
        ↓
Enables a disabled Windows user
        ↓
Windows generates Event 4722
        ↓
Wazuh base rule 60109 matches
        ↓
Custom rule 100108 matches
        ↓
DET-009 alert generated
```

## Expected Alert

The expected Wazuh alert should contain:

- **Detection:** `DET-009`
- **Rule ID:** `100108`
- **Severity:** `7`
- **Windows Event:** `4722`
- Target username
- Target domain
- Subject username
- Subject domain
- Account-enable information
- Timestamp

The alert description should identify the enabled account:

```text
DET-009 User Account Enabled: <username>
```

## Validation Result

**Status: VALIDATED**

The rule successfully detected Windows user-account enablement telemetry through Wazuh base rule `60109` and generated the expected custom Wazuh detection.

The detection provides visibility into account-enablement activity that can be investigated for legitimate administration, unauthorized access restoration, or account manipulation.

## Investigation Playbook

When a DET-009 alert is generated, the analyst should determine why the account was enabled, who performed the action, and whether the account subsequently exhibited suspicious activity.

### 1. Identify the affected account

Review:

- Target username
- Target domain
- Account type
- Whether the account was previously disabled
- Whether the account is privileged
- Whether the account is a service account
- Whether the account is dormant or normally inactive

An unexpectedly enabled dormant or privileged account should receive additional scrutiny.

### 2. Identify who enabled the account

Review:

- Subject username
- Subject domain
- Subject user SID
- Source system where available
- Timestamp

Determine whether the initiating account is authorized to enable user accounts.

An unexpected administrative account performing the action should be investigated further.

### 3. Determine whether the enablement was authorized

Check:

- Change-management ticket
- Helpdesk request
- User onboarding or return-to-work process
- Administrative procedures
- Account lifecycle records
- Expected account-provisioning workflow

Determine whether the action has a legitimate business or administrative reason.

### 4. Review the account's privileges

Determine whether the affected account has access to:

- Domain Admins
- Enterprise Admins
- Administrators
- IT administration groups
- Sensitive servers
- Critical applications
- Other privileged resources

An unexpected enablement of a privileged or dormant account represents a higher-risk event.

### 5. Review authentication activity after enablement

Search for successful and failed authentication events involving the affected account after the account was enabled.

Review:

- Source IP address
- Source hostname
- Logon type
- Authentication package
- Timestamp
- Destination system

Unexpected authentication shortly after account enablement may indicate that the account was enabled to facilitate unauthorized access.

Correlate with **DET-003 — Windows Successful Interactive Authentication** and **DET-004 — Successful Login After Failed Attempts** where applicable.

### 6. Review related account changes

Check whether the account was also:

- Added to privileged groups
- Given a password reset
- Modified
- Granted additional access
- Used to create another account
- Subjected to additional account-management actions

Correlate with **DET-007 — New User Account Created**, **DET-008 — Password Reset**, and other account-management detections where applicable.

### 7. Check for post-enablement activity

Review for:

- PowerShell execution
- RDP activity
- SMB access
- Remote administration
- Privilege escalation
- Lateral movement
- Persistence
- Credential-access activity

Pay particular attention to activity occurring shortly after the account was enabled.

## Response Playbook

### If the activity is benign

- Confirm the account enablement was authorized.
- Verify the account owner and intended purpose.
- Confirm group memberships and privileges are appropriate.
- Document the finding if required.
- Continue monitoring the account for unusual activity.
- Close the alert when no suspicious activity is identified.

### If the activity is suspicious

- Investigate the account that enabled the user.
- Review the target account's privileges and group memberships.
- Check authentication activity after enablement.
- Review related account-management events.
- Determine whether the enablement was part of an unauthorized access sequence.
- Escalate if malicious activity is confirmed.

### If compromise is suspected

- Disable the affected account where appropriate.
- Review and remove unauthorized privileges or group memberships.
- Reset or revoke credentials associated with the account.
- Investigate the account that performed the enablement.
- Review authentication activity involving the affected account.
- Investigate the originating system for signs of compromise.
- Search for other accounts enabled by the same initiating account.
- Document the incident and response actions.

## False Positives

Common legitimate causes include:

- Employee return from leave.
- Account reactivation.
- Helpdesk account recovery.
- Administrative account maintenance.
- User onboarding or provisioning.
- Service-account maintenance.
- Application deployment.
- Scheduled identity-management workflows.
- Security or compliance procedures.
- Administrative troubleshooting.

A DET-009 alert **should not automatically be considered malicious**.

The analyst should determine whether the account enablement was authorized and whether the account subsequently showed suspicious activity.

## Tuning Considerations

DET-009 is configured as a **medium-high severity account-management detection**.

The current detection is intentionally focused on the account-enable event:

```text
Windows Event 4722
        ↓
Wazuh rule 60109
        ↓
DET-009 / Rule 100108
```

Potential tuning options include:

- Increasing severity when privileged or dormant accounts are enabled.
- Increasing severity when accounts are enabled outside approved administrative workflows.
- Correlating account enablement with subsequent successful authentication.
- Correlating account enablement with password resets.
- Correlating account enablement with privileged-group membership changes.
- Monitoring accounts that remain disabled for extended periods before being enabled.
- Suppressing known automated identity-management systems where appropriate.
- Creating separate severity levels for standard, service, and privileged accounts.
- Correlating multiple account-enablement events performed by the same subject account.
- Increasing severity when enablement is followed by lateral movement or other suspicious activity.

An account enablement becomes a stronger indicator of malicious account manipulation when a dormant or privileged account is unexpectedly enabled and is subsequently used for authentication, privilege escalation, or lateral movement.

DET-009 therefore provides the foundational account-enable telemetry required for higher-confidence account-management investigations.
