# Detection 004 — Successful Login After Failed Attempts

## Objective

Detect a successful Windows authentication that occurs after multiple failed authentication attempts against the same user account within a short time window.

This detection provides a higher-confidence authentication signal by correlating repeated failed authentication activity with a subsequent successful login.

DET-004 builds on **DET-001 — Windows Failed Authentication** and **DET-003 — Windows Successful Interactive Authentication**.

## MITRE ATT&CK

**Related Techniques:**

- T1110 — Brute Force
- T1078 — Valid Accounts

A successful authentication following repeated failures may indicate that an attacker successfully guessed or obtained valid credentials. However, legitimate users can also generate the same pattern through repeated password-entry mistakes, so contextual investigation is required.

## Windows Events

**Event IDs:**

- `4625` — An account failed to log on.
- `4624` — An account was successfully logged on.

The detection correlates:

- Multiple failed authentication events from DET-001.
- A subsequent successful authentication from DET-003.
- The same `win.eventdata.targetUserName` across the correlated events.

Relevant fields may include:

- Target username
- Target domain
- Source IP address
- Workstation name
- Logon type
- Authentication package
- Failure reason
- Logon ID
- Timestamp

## Detection Logic

```text
Windows Event 4625
        ↓
DET-001 / Rule 100100
        ↓
3 failed attempts
within 120 seconds
        ↓
Same target username
        ↓
Windows Event 4624
        ↓
DET-003 / Rule 100102
        ↓
Successful login for same target username
        ↓
Custom rule 100103
        ↓
DET-004 alert
```

The rule triggers when a successful authentication matching **DET-003** occurs for a username that has also generated **3 DET-001 failed-authentication events within 120 seconds**.

The correlation is performed using:

```text
win.eventdata.targetUserName
```

## Wazuh Rule

```xml
<rule id="100103"
      level="8">

    <if_sid>100102</if_sid>

    <if_matched_sid frequency="3" timeframe="120">100100</if_matched_sid>

    <same_field>win.eventdata.targetUserName</same_field>

    <description>
        DET-004 Successful login after brute force against $(win.eventdata.targetUserName)
    </description>

    <group>
        custom_windows,
        authentication,
        successful_login_after_failures,
        attack.t1110,
        attack.t1078,
    </group>

    <mitre>
        <id>T1110</id>
        <id>T1078</id>
    </mitre>

</rule>
```

### Rule Details

| Field | Value |
|---|---|
| Detection ID | DET-004 |
| Wazuh Rule ID | 100103 |
| Severity | 8 |
| Parent Rule | 100102 |
| Correlated Rule | 100100 |
| Failed Attempts | 3 |
| Timeframe | 120 seconds |
| Correlation Field | `win.eventdata.targetUserName` |
| Detection Type | Successful Login After Failed Attempts |
| Windows Events | 4625 + 4624 |
| MITRE Techniques | T1110, T1078 |
| Category | Authentication / Brute Force / Valid Accounts |

---

## Simulation

A controlled authentication sequence was performed in the Windows lab environment by generating multiple incorrect authentication attempts followed by a successful authentication using the correct credentials.

```text
CLIENT01
    ↓
Multiple incorrect authentication attempts
    ↓
Windows generates Event 4625
    ↓
DET-001 / Rule 100100 matches
    ↓
3 failures for the same username
within 120 seconds
    ↓
Successful authentication
    ↓
Windows generates Event 4624
    ↓
DET-003 / Rule 100102 matches
    ↓
Same target username is correlated
    ↓
Custom rule 100103 matches
    ↓
DET-004 alert generated
```

## Expected Alert

The expected Wazuh alert should contain:

- **Detection:** `DET-004`
- **Rule ID:** `100103`
- **Severity:** `8`
- **Failed Windows Event:** `4625`
- **Successful Windows Event:** `4624`
- Target username
- Target domain
- Source information
- Authentication details
- Correlation with previous failed attempts

The alert description should identify the affected account:

```text
DET-004 Successful login after brute force against <username>
```

## Validation Result

**Status: VALIDATED**

The rule successfully correlated a successful Windows authentication with multiple preceding failed authentication events for the same target username within the configured time window.

The detection provides a higher-confidence authentication signal than either an individual failed login or a standalone successful login.

## Investigation Playbook

When a DET-004 alert is generated, the analyst should treat the event as a potentially significant authentication sequence and determine whether the successful login was legitimate.

### 1. Identify the affected account

Review:

- Target username
- Target domain
- Account type
- Whether the account is privileged
- Whether the account is a service account
- Whether the account is expected to access the affected system

Privileged or sensitive accounts should receive additional scrutiny.

### 2. Identify the source of the authentication activity

Review:

- Source IP address
- Source hostname
- Workstation name
- Target system
- Whether the source is expected for the account

Determine whether the failed and successful authentication events originated from the same or different sources.

A successful authentication from a different source after repeated failures may provide additional investigative context.

### 3. Reconstruct the authentication sequence

Review the timeline of:

- Failed Event ID `4625` events
- Successful Event ID `4624` event
- Time between attempts
- Number of failed attempts
- Source addresses
- Logon types
- Authentication packages

Determine whether the sequence resembles automated brute-force behavior or normal user activity.

### 4. Review the successful logon

Examine:

- Logon type
- Source IP
- Workstation name
- Authentication package
- Logon ID
- Timestamp

Determine whether the successful authentication was expected for the account and system.

### 5. Determine whether the credentials may have been compromised

Look for indicators including:

- Repeated failures followed by a successful login.
- Authentication from an unusual source.
- Authentication outside expected hours.
- Access to a system the user does not normally access.
- Privileged account usage.
- Multiple accounts targeted from the same source.

### 6. Check for account lockout

Determine whether the failed authentication activity caused or preceded an account lockout.

Correlate with **DET-005 — Account Lockout** where applicable.

### 7. Check for post-authentication activity

Review activity immediately after the successful login, including:

- PowerShell execution
- Process creation
- Privilege escalation
- Account modifications
- RDP activity
- SMB access
- Remote administration
- Credential-access activity
- Lateral movement
- Persistence mechanisms

A successful authentication followed by suspicious activity substantially increases the likelihood of compromise.

## Response Playbook

### If the activity is benign

- Confirm the successful login was legitimate.
- Determine whether repeated failures were caused by user error or stale credentials.
- Document the finding if required.
- Close the alert when no suspicious activity is identified.
- Continue monitoring for unusual authentication behavior.

### If the activity is suspicious

- Investigate the affected account and source.
- Review the complete authentication timeline.
- Check whether other accounts were targeted.
- Review post-authentication activity.
- Determine whether the successful login resulted in access to sensitive resources.
- Escalate the alert if malicious activity is confirmed.

### If compromise is suspected

- Restrict or disable the affected account where appropriate.
- Reset the account credentials.
- Revoke active sessions or credentials where appropriate.
- Investigate and contain the originating host if required.
- Search for other successful authentications using the same account.
- Search for additional accounts targeted by the source.
- Investigate post-authentication activity for lateral movement, privilege escalation, or persistence.
- Document the incident and response actions.

## False Positives

Common legitimate causes include:

- User repeatedly entering an incorrect password before entering the correct password.
- Forgotten or mistyped credentials.
- Recently changed password.
- Password manager using an outdated password before submitting the updated password.
- Applications or services retrying authentication with stale credentials.
- Administrative troubleshooting.
- Remote users reconnecting after failed authentication attempts.

A DET-004 alert is a **higher-confidence authentication signal, but it should not automatically be considered a confirmed compromise**.

The analyst should evaluate the source, account, timing, logon type, and post-authentication activity.

## Tuning Considerations

DET-004 is designed as a **correlation detection** that increases the significance of authentication activity when repeated failures are followed by a successful login.

Current correlation:

```text
3 failed authentications
        +
Same target username
        +
Within 120 seconds
        +
Successful authentication
        ↓
DET-004
```

Potential tuning options include:

- Adjusting the failed-attempt threshold.
- Adjusting the correlation timeframe.
- Correlating source IP addresses in addition to the target username.
- Increasing severity for privileged accounts.
- Increasing severity for successful logins from unusual sources.
- Correlating with account lockouts.
- Correlating with post-authentication PowerShell or process activity.
- Correlating with lateral-movement detections.
- Suppressing known benign authentication patterns generated by specific applications or service accounts.

The detection intentionally combines **T1110 — Brute Force** and **T1078 — Valid Accounts** because the observed sequence can represent an attempted credential attack followed by successful use of valid credentials.

DET-004 therefore provides a stronger behavioral signal than isolated failed or successful authentication events.
