# Detection 005 — User Account Locked

## Objective

Detect Windows user-account lockout events and provide visibility into accounts that have been automatically locked following repeated unsuccessful authentication attempts.

This detection provides an important authentication-security signal and can be correlated with failed authentication, brute-force activity, password spraying, and other suspicious account activity.

## MITRE ATT&CK

**Related Technique:** T1110 — Brute Force

Account lockouts can occur as a result of brute-force or password-spraying activity. However, a lockout alone does not confirm malicious activity because legitimate users, applications, and services can also generate repeated failed authentication attempts.

DET-005 therefore provides account-lockout telemetry that should be investigated together with the authentication events that preceded the lockout.

## Windows Events

**Event ID:** `4740` — A user account was locked out.

Relevant fields may include:

- Target username
- Target domain
- Caller computer name
- Account name
- Timestamp
- Authentication context

The caller computer name can be particularly useful when determining which system may have generated the failed authentication attempts that resulted in the lockout.

## Detection Logic

```text
Windows Event 4740
        ↓
Wazuh base rule 60115
        ↓
Custom rule 100104
        ↓
DET-005 alert
```

The rule detects Windows account-lockout events identified by Wazuh base rule `60115`.

No additional frequency or correlation threshold is applied by DET-005 itself.

## Wazuh Rule

```xml
<rule id="100104"
      level="5">

    <if_sid>60115</if_sid>

    <description>
        DET-005 - Account Locked: $(win.eventdata.targetUserName)
    </description>

    <group>
        custom_windows,
        authentication,
        account_lockout,
    </group>

</rule>
```

### Rule Details

| Field | Value |
|---|---|
| Detection ID | DET-005 |
| Wazuh Rule ID | 100104 |
| Severity | 5 |
| Parent Rule | 60115 |
| Detection Type | Account Lockout |
| Windows Event | 4740 |
| Category | Authentication / Account Lockout |

---

## Simulation

A controlled authentication scenario was used in the Windows lab environment to generate repeated unsuccessful authentication attempts until the test account reached the configured account-lockout threshold.

```text
Windows account
        ↓
Repeated unsuccessful authentication attempts
        ↓
Windows locks the account
        ↓
Windows generates Event 4740
        ↓
Wazuh base rule 60115 matches
        ↓
Custom rule 100104 matches
        ↓
DET-005 alert generated
```

## Expected Alert

The expected Wazuh alert should contain:

- **Detection:** `DET-005`
- **Rule ID:** `100104`
- **Severity:** `5`
- **Windows Event:** `4740`
- Target username
- Target domain
- Caller computer name
- Timestamp
- Account-lockout information

The alert description should identify the affected account:

```text
DET-005 - Account Locked: <username>
```

## Validation Result

**Status: VALIDATED**

The rule successfully detected Windows account-lockout telemetry through Wazuh base rule `60115` and generated the expected custom Wazuh detection.

The detection provides visibility into account-lockout events that can be correlated with preceding failed-authentication activity.

## Investigation Playbook

When a DET-005 alert is generated, the analyst should determine why the account was locked and whether the lockout resulted from legitimate activity or an authentication attack.

### 1. Identify the affected account

Review:

- Target username
- Target domain
- Account type
- Whether the account is privileged
- Whether the account is a service account
- Whether the account is a high-value or sensitive account

Privileged and service accounts should receive additional scrutiny.

### 2. Identify the source system

Review:

- Caller computer name
- Source IP address where available
- Workstation information
- Authentication source
- Whether the source system is expected for the affected account

The caller computer can help identify the system responsible for generating the authentication failures.

### 3. Review preceding failed authentication

Search for Event ID `4625` events involving the locked account immediately before the lockout.

Review:

- Number of failures
- Source IP addresses
- Workstation names
- Failure reasons
- Logon types
- Authentication packages
- Time between attempts

Correlate with **DET-001 — Windows Failed Authentication** and **DET-002 — Windows Brute Force Detection** where applicable.

### 4. Determine whether multiple accounts were targeted

Review authentication failures from the identified source for other usernames.

Multiple accounts being targeted by the same source may indicate password-spraying activity rather than an isolated account lockout.

### 5. Check for successful authentication

Determine whether the affected account successfully authenticated before or after the lockout.

A sequence involving repeated failures followed by successful authentication should be correlated with **DET-004 — Successful Login After Failed Attempts**.

### 6. Review related activity

Search for other suspicious activity involving the affected account or source system, including:

- Privilege escalation
- Account modifications
- RDP activity
- SMB access
- PowerShell execution
- Remote administration
- Lateral movement
- Credential-access activity

### 7. Determine the likely cause

Establish whether the lockout was caused by:

- A user repeatedly entering an incorrect password.
- A service using stale credentials.
- A scheduled task using an outdated password.
- A mapped drive or stored credential.
- An application repeatedly authenticating with old credentials.
- Administrative activity.
- Potential brute-force or password-spraying activity.

## Response Playbook

### If the activity is benign

- Confirm the reason for the lockout.
- Identify and correct stale credentials where applicable.
- Unlock the account according to organizational procedures.
- Document the finding if required.
- Continue monitoring for additional lockouts.
- Close the alert when no suspicious activity is identified.

### If the activity is suspicious

- Investigate the affected account and caller system.
- Review preceding authentication failures.
- Check whether additional accounts were targeted.
- Review source systems and authentication patterns.
- Check for successful authentication attempts.
- Investigate related lateral-movement or privilege-escalation activity.
- Escalate if malicious activity is confirmed.

### If compromise is suspected

- Restrict or disable the affected account where appropriate.
- Reset the account credentials.
- Investigate the originating system.
- Contain the source if required.
- Search for additional affected accounts.
- Review successful authentications involving the account.
- Investigate post-authentication activity for signs of lateral movement or persistence.
- Document the incident and response actions.

## False Positives

Common legitimate causes include:

- User repeatedly entering an incorrect password.
- Forgotten or recently changed password.
- Password manager using outdated credentials.
- Mapped drives using old credentials.
- Scheduled tasks configured with an expired password.
- Windows services configured with stale credentials.
- Applications repeatedly attempting authentication with old credentials.
- Cached credentials remaining on a workstation.
- Administrative troubleshooting.

An account-lockout event **should not automatically be considered malicious**.

The analyst should determine what caused the lockout and whether the authentication pattern is consistent with normal activity.

## Tuning Considerations

DET-005 is configured as a **medium-severity account-lockout detection**.

The current rule intentionally detects the lockout event directly:

```text
Windows Event 4740
        ↓
Wazuh rule 60115
        ↓
DET-005 / Rule 100104
```

Potential tuning options include:

- Increasing severity for privileged-account lockouts.
- Correlating lockouts with repeated Event ID `4625` failures.
- Correlating lockouts with DET-002 brute-force alerts.
- Correlating multiple locked accounts from the same source to identify password spraying.
- Suppressing known service-account lockouts where the cause is understood and documented.
- Correlating the caller computer with other suspicious activity.
- Increasing severity when a lockout is preceded by authentication activity from an unusual source.
- Correlating account lockouts with successful authentication attempts.

DET-005 is intentionally kept as a direct account-lockout detection. Higher-confidence behavioral analysis can be achieved by correlating the lockout with the authentication failures and source activity that caused it.
