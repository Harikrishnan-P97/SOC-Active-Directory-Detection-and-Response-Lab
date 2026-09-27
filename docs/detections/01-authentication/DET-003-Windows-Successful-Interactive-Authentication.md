# Detection 003 — Windows Successful Interactive Authentication

## Objective

Detect successful Windows interactive authentication events that indicate a user successfully established an interactive session on a Windows system.

This detection provides visibility into successful authentication activity and serves as an important correlation point for identifying potentially unauthorized access, especially when associated with previous failed authentication attempts.

## MITRE ATT&CK

**Related Technique:** T1078 — Valid Accounts

Successful authentication using valid credentials can represent legitimate user activity or, when the credentials have been compromised, unauthorized access using valid accounts.

DET-003 therefore provides authentication telemetry that can be correlated with failed logins, brute-force activity, account lockouts, privilege escalation, and other suspicious behavior.

## Windows Events

**Event ID:** `4624` — An account was successfully logged on.

The rule focuses on the following Windows logon types:

| Logon Type | Description |
|---|---|
| `2` | Interactive |
| `7` | Unlock |
| `10` | RemoteInteractive / Remote Desktop |
| `11` | CachedInteractive |

Relevant fields may include:

- Target username
- Target domain
- Source IP address
- Workstation name
- Logon type
- Authentication package
- Logon ID
- Timestamp

## Detection Logic

```text
Windows Event 4624
        ↓
Wazuh base rule 67022
        ↓
Logon type = 2, 7, 10, or 11
        ↓
Custom rule 100102
        ↓
DET-003 alert
```

The rule detects successful authentication events that match the configured interactive logon types.

## Wazuh Rule

```xml
<rule id="100102" level="5">

    <if_sid>67022</if_sid>
    <field name="win.eventdata.logonType">2|7|10|11</field>

    <description>
        DET-003 Successful Interactive Login by $(win.eventdata.targetUserName)
    </description>

    <group>
        custom_windows,
        authentication,
        successful_login,
        attack.t1078,
    </group>

    <mitre>
        <id>T1078</id>
    </mitre>

</rule>
```

### Rule Details

| Field | Value |
|---|---|
| Detection ID | DET-003 |
| Wazuh Rule ID | 100102 |
| Severity | 5 |
| Parent Rule | 67022 |
| Detection Type | Successful Interactive Authentication |
| Windows Event | 4624 |
| Logon Types | 2, 7, 10, 11 |
| MITRE Technique | T1078 |
| Category | Authentication / Successful Login |

---

## Simulation

A controlled successful authentication was performed in the Windows lab environment using valid credentials.

```text
Windows authentication
        ↓
Valid credentials
        ↓
Windows generates Event 4624
        ↓
Wazuh base rule 67022 matches
        ↓
Logon type matches 2, 7, 10, or 11
        ↓
Custom rule 100102 matches
        ↓
DET-003 alert generated
```

## Expected Alert

The expected Wazuh alert should contain:

- **Detection:** `DET-003`
- **Rule ID:** `100102`
- **Severity:** `5`
- **Windows Event:** `4624`
- Target username
- Target domain
- Logon type
- Source information
- Authentication details
- Timestamp

The alert description should identify the authenticated username:

```text
DET-003 Successful Interactive Login by <username>
```

## Validation Result

**Status: VALIDATED**

The rule successfully detected Windows successful authentication events matching the configured interactive logon types and generated the expected custom Wazuh detection.

The detection was validated using successful authentication activity in the Windows lab environment.

## Investigation Playbook

When a DET-003 alert is generated, the analyst should determine whether the successful authentication represents expected user activity or potentially unauthorized access using valid credentials.

### 1. Identify the authenticated account

Review:

- Target username
- Target domain
- Account type
- Whether the account is privileged
- Whether the account is a service account
- Whether the account is expected to authenticate to the affected system

### 2. Identify the authentication source

Review:

- Source IP address
- Source hostname
- Workstation name
- Whether the source is expected for the account
- Geographic or network context where available

Unexpected source systems should receive additional scrutiny.

### 3. Review the logon type

Determine which logon type generated the alert:

- `2` — Interactive
- `7` — Unlock
- `10` — RemoteInteractive / RDP
- `11` — CachedInteractive

A logon type of `10`, for example, may indicate Remote Desktop activity and should be investigated according to the user's normal access pattern.

### 4. Review authentication details

Examine:

- Authentication package
- Logon ID
- Timestamp
- Workstation information
- Source address
- Target system

Use these fields to establish how and where the authentication occurred.

### 5. Check for preceding failed authentication

Review recent Event ID `4625` activity involving:

- The same username
- The same source IP
- The same workstation
- The same target system

A successful authentication following repeated failures may indicate a successful brute-force attempt or compromised credentials.

Correlate with **DET-004 — Successful Login After Failed Attempts** where applicable.

### 6. Check for related suspicious activity

Review activity before and after the successful authentication, including:

- Privilege escalation
- Account modifications
- PowerShell execution
- Process creation
- RDP activity
- SMB access
- Remote administration
- Lateral movement
- Credential-access activity

### 7. Validate the user's expected behavior

Determine whether:

- The user normally accesses the system.
- The login occurred during expected hours.
- The source system is recognized.
- The account is authorized for the target system.
- The authentication matches normal administrative or operational activity.

## Response Playbook

### If the activity is benign

- Confirm the authentication was expected.
- Document the finding if required.
- Close the alert when no suspicious activity is identified.
- Continue monitoring for unusual authentication patterns.

### If the activity is suspicious

- Investigate the affected account and source system.
- Review preceding and subsequent authentication activity.
- Check for failed authentication attempts.
- Review privilege changes and post-authentication activity.
- Determine whether the account may have been used without authorization.
- Escalate if malicious activity is confirmed.

### If compromise is suspected

- Restrict or disable the affected account where appropriate.
- Reset the account credentials.
- Investigate the source system.
- Revoke active sessions or credentials where appropriate.
- Search for additional authentications using the same account.
- Investigate post-authentication activity for signs of lateral movement or persistence.
- Document the incident and response actions.

## False Positives

Common legitimate causes include:

- Normal user logins.
- Administrative logins.
- Remote Desktop sessions.
- Workstation unlocks.
- Cached domain authentication.
- Authorized helpdesk activity.
- Scheduled or operational activity that produces supported interactive authentication events.

Because successful authentication is common in a Windows environment, a DET-003 alert **should not automatically be considered malicious**.

The context of the account, source, logon type, timing, and surrounding activity is critical.

## Tuning Considerations

DET-003 is intentionally configured as a **medium-severity authentication visibility detection**.

The rule currently focuses on selected interactive authentication types:

```text
Event 4624
    ↓
Logon Type 2 / 7 / 10 / 11
    ↓
DET-003
```

Potential tuning options include:

- Restricting detection to specific high-value systems.
- Increasing severity for privileged-account authentication.
- Increasing severity for authentication from unusual source systems.
- Correlating successful authentication with recent failed authentication attempts.
- Correlating successful authentication with account lockouts.
- Creating additional detections for unusual Remote Desktop authentication.
- Establishing expected administrative access patterns and tuning known legitimate activity.

DET-003 is primarily intended to provide **high-value successful-authentication telemetry** that can be correlated with other detections. By itself, a successful login is not evidence of compromise; suspiciousness depends on the account, source, timing, authentication method, and surrounding activity.
