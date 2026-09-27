# Detection 008 — Password Reset

## Objective

Detect Windows password-reset events and provide visibility into account-management activity that could indicate unauthorized credential changes, account takeover, or persistence.

Password resets can be legitimate administrative actions, but an unexpected reset of a privileged or sensitive account may indicate malicious activity. DET-008 provides the underlying telemetry required to investigate who initiated the reset, which account was affected, and what activity followed the credential change.

## MITRE ATT&CK

**Related Technique:** T1098 — Account Manipulation

Attackers may manipulate user accounts to maintain or expand access to an environment. An unauthorized password reset can be part of an account-manipulation sequence, particularly when performed against privileged or high-value accounts.

DET-008 detects the password-reset event itself. The analyst should investigate the initiating account, target account, authorization context, and subsequent authentication activity before determining whether the event is malicious.

## Windows Events

**Event ID:** `4724` — An attempt was made to reset an account's password.

Relevant fields may include:

- Target username
- Target domain
- Subject username
- Subject domain
- Subject user SID
- Target user SID
- Account name
- Timestamp
- Source system information where available

The **subject account** identifies the account that initiated the password-reset action, while the **target account** identifies the account whose password was reset.

## Detection Logic

```text
Windows Event 4724
        ↓
Wazuh base rule 60103
        ↓
Custom rule 100107
        ↓
DET-008 alert
```

The rule detects Windows password-reset events identified by Wazuh base rule `60103`.

The rule also explicitly requires:

```text
win.system.eventID = 4724
```

No frequency or time-based correlation is applied by DET-008 itself.

## Wazuh Rule

```xml
<rule id="100107"
      level="9">

    <if_sid>60103</if_sid>

    <field name="win.system.eventID">4724</field>

    <description>
        DET-008 Password Reset for $(win.eventdata.targetUserName)
    </description>

    <group>
        custom_windows,
        account_management,
        password_reset,
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
| Detection ID | DET-008 |
| Wazuh Rule ID | 100107 |
| Severity | 9 |
| Parent Rule | 60103 |
| Detection Type | Password Reset |
| Windows Event | 4724 |
| MITRE Technique | T1098 |
| Category | Account Management / Password Reset |

---

## Simulation

A controlled password-reset event was performed in the Windows Active Directory lab environment against a test account.

```text
Administrator / Test Account
        ↓
Resets password for a Windows user
        ↓
Windows generates Event 4724
        ↓
Wazuh base rule 60103 matches
        ↓
Custom rule 100107 matches
        ↓
DET-008 alert generated
```

## Expected Alert

The expected Wazuh alert should contain:

- **Detection:** `DET-008`
- **Rule ID:** `100107`
- **Severity:** `9`
- **Windows Event:** `4724`
- Target username
- Target domain
- Subject username
- Subject domain
- Password-reset information
- Timestamp

The alert description should identify the affected account:

```text
DET-008 Password Reset for <username>
```

## Validation Result

**Status: VALIDATED**

The rule successfully detected Windows password-reset telemetry through Wazuh base rule `60103` and generated the expected custom Wazuh detection.

The detection provides visibility into password-reset activity that can be investigated for legitimate administration, account takeover, or unauthorized account manipulation.

## Investigation Playbook

When a DET-008 alert is generated, the analyst should determine whether the password reset was authorized and whether the affected account subsequently showed suspicious activity.

### 1. Identify the affected account

Review:

- Target username
- Target domain
- Account type
- Whether the account is privileged
- Whether the account is a service account
- Whether the account is a high-value or sensitive account

Password resets involving privileged accounts should receive additional scrutiny.

### 2. Identify who initiated the reset

Review:

- Subject username
- Subject domain
- Subject user SID
- Source system where available
- Timestamp

Determine whether the initiating account is authorized to reset passwords.

An unexpected administrative account performing password resets should be investigated further.

### 3. Determine whether the reset was authorized

Check:

- Helpdesk or change-management ticket
- Password-reset request
- Administrative procedures
- Account-owner confirmation where applicable
- Expected administrative workflow
- Timing of the activity

Determine whether the password reset can be associated with legitimate account-management activity.

### 4. Review the target account's privileges

Determine whether the affected account has access to:

- Domain Admins
- Enterprise Admins
- Administrators
- IT administration groups
- Sensitive servers
- Critical applications
- Other privileged resources

An unauthorized password reset involving a privileged account represents a higher-risk event.

### 5. Review authentication activity after the reset

Search for successful and failed authentication events involving the affected account after the password reset.

Review:

- Source IP address
- Source hostname
- Logon type
- Authentication package
- Timestamp
- Destination system

Unexpected authentication shortly after a password reset may indicate that the reset was performed to facilitate unauthorized access.

Correlate with **DET-003 — Windows Successful Interactive Authentication** and **DET-004 — Successful Login After Failed Attempts** where applicable.

### 6. Review related account changes

Check whether the affected account was also:

- Added to privileged groups
- Enabled or disabled
- Modified
- Granted additional access
- Used to create another account
- Subjected to additional password resets

Correlate with **DET-007 — New User Account Created** and other account-management detections where applicable.

### 7. Check for post-authentication activity

Review for:

- PowerShell execution
- RDP activity
- SMB access
- Remote administration
- Privilege escalation
- Lateral movement
- Persistence
- Credential-access activity

Pay particular attention to activity occurring shortly after the password reset.

## Response Playbook

### If the activity is benign

- Confirm the password reset was authorized.
- Verify the affected account and intended administrative action.
- Document the finding if required.
- Continue monitoring the account for unusual activity.
- Close the alert when no suspicious activity is identified.

### If the activity is suspicious

- Investigate the initiating account.
- Confirm the target account's privileges.
- Review authentication activity after the reset.
- Check for additional account modifications.
- Determine whether the reset was part of an unauthorized account-management sequence.
- Escalate if malicious activity is confirmed.

### If compromise is suspected

- Secure the affected account according to incident-response procedures.
- Reset the account credentials using a trusted administrative process.
- Review and revoke unauthorized access where appropriate.
- Investigate the account that initiated the password reset.
- Review authentication activity involving the affected account.
- Investigate the originating system for signs of compromise.
- Search for other accounts modified by the same initiating account.
- Document the incident and response actions.

## False Positives

Common legitimate causes include:

- Helpdesk password resets.
- Administrative password resets.
- User account recovery.
- Forgotten-password procedures.
- Employee onboarding or account provisioning.
- Service-account maintenance.
- Password rotation.
- Security or compliance procedures.
- Automated identity-management systems.
- Administrative troubleshooting.

A DET-008 alert **should not automatically be considered malicious**.

The analyst should determine whether the password reset was authorized and whether the affected account subsequently exhibited suspicious activity.

## Tuning Considerations

DET-008 is configured as a **high-severity account-management detection**.

The current detection is intentionally focused on the password-reset event:

```text
Windows Event 4724
        ↓
Wazuh rule 60103
        ↓
DET-008 / Rule 100107
```

Potential tuning options include:

- Increasing severity when privileged accounts are reset.
- Correlating password resets with subsequent successful authentication.
- Correlating password resets with failed-authentication activity.
- Correlating password resets with privileged-group membership changes.
- Monitoring password resets performed by unusual administrative accounts.
- Suppressing known automated identity-management systems where appropriate.
- Creating separate severity levels for standard, service, and privileged accounts.
- Correlating multiple password resets performed by the same subject account.
- Increasing severity when password resets are followed by lateral movement or other suspicious activity.

A password reset becomes a stronger indicator of malicious account manipulation when it is performed by an unexpected account, targets a privileged user, or is followed by suspicious authentication or privilege changes.

DET-008 therefore provides the foundational password-reset telemetry required for higher-confidence account-management investigations.
