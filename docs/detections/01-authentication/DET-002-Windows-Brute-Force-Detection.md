# Detection 002 — Windows Brute Force Detection

## Objective

Detect repeated Windows authentication failures against the same user account within a short time window, providing a higher-confidence indicator of potential brute-force activity.

This detection builds on **DET-001 — Windows Failed Authentication**, using repeated authentication failures to identify suspicious authentication behavior.

## MITRE ATT&CK

**Related Technique:** T1110 — Brute Force

DET-002 detects repeated failed authentication attempts against the same account. While repeated failures may indicate brute-force activity, the alert should be investigated in context because legitimate users and applications can also generate multiple authentication failures.

## Windows Events

**Event ID:** `4625` — An account failed to log on.

Relevant fields include:

- Target username
- Target domain
- Source IP address
- Logon type
- Authentication package
- Failure reason
- Workstation name
- Timestamp

The detection specifically correlates the **target username** across multiple failed-authentication events.

## Detection Logic

```text
Windows Event 4625
        ↓
Wazuh base rule 60122
        ↓
DET-001 / Rule 100100
        ↓
3 matching failures
within 120 seconds
        ↓
Same target username
        ↓
Custom rule 100101
        ↓
DET-002 alert
```

The rule triggers when **3 events matching DET-001** occur for the **same `win.eventdata.targetUserName`** within a **120-second timeframe**.

## Wazuh Rule

```xml
<rule id="100101"
      level="10"
      frequency="3"
      timeframe="120">

    <if_matched_sid>100100</if_matched_sid>

    <same_field>win.eventdata.targetUserName</same_field>

    <description>
        DET-002 Possible Brute Force against user $(win.eventdata.targetUserName)
    </description>

    <group>
        custom_windows,
        authentication,
        brute_force,
        attack.t1110,
    </group>
    <mitre>
        <id>T1110</id>
    </mitre>

</rule>
```

### Rule Details

| Field | Value |
|---|---|
| Detection ID | DET-002 |
| Wazuh Rule ID | 100101 |
| Severity | 10 |
| Parent Rule | 100100 |
| Frequency | 3 events |
| Timeframe | 120 seconds |
| Correlation Field | `win.eventdata.targetUserName` |
| Detection Type | Brute Force |
| Windows Event | 4625 |
| MITRE Technique | T1110 |
| Category | Authentication / Brute Force |

---

## Simulation

A controlled authentication test was performed in the Windows lab environment using an incorrect password multiple times against the same user account.

```text
CLIENT01
    ↓
Repeated incorrect authentication attempts
    ↓
Windows generates multiple Event 4625 events
    ↓
Wazuh base rule 60122 matches
    ↓
DET-001 / Rule 100100 matches
    ↓
3 failures for the same target username
within 120 seconds
    ↓
Custom rule 100101 matches
    ↓
DET-002 alert generated
```

## Expected Alert

The expected Wazuh alert should contain:

- **Detection:** `DET-002`
- **Rule ID:** `100101`
- **Severity:** `10`
- **Windows Event:** `4625`
- Target username
- Target domain
- Source information
- Authentication details
- Correlation indicating repeated failures

The alert description should identify the affected username:

```text
DET-002 Possible Brute Force against user <username>
```

## Validation Result

**Status: VALIDATED**

The rule successfully correlated repeated Windows failed-authentication events for the same target username and generated the expected custom Wazuh detection.

The detection was validated using a controlled authentication test in the Windows lab environment.

## Investigation Playbook

When a DET-002 alert is generated, the analyst should determine whether the repeated authentication failures represent legitimate activity, a misconfigured application, or a potential brute-force attack.

### 1. Identify the affected account

Review:

- Target username
- Target domain
- Account type
- Whether the account is privileged
- Whether the account is a service account
- Whether the account is expected to receive authentication attempts from the observed source

### 2. Identify the source

Review:

- Source IP address
- Source hostname
- Workstation name
- Whether the source is expected for the affected account
- Whether multiple accounts are being targeted from the same source

A single source targeting multiple accounts may indicate password-spraying behavior rather than traditional brute force.

### 3. Review authentication details

Examine:

- Logon type
- Authentication package
- Failure reason
- Timestamp
- Target domain
- Workstation information

Determine whether the authentication pattern is consistent with normal user activity.

### 4. Establish the attack timeline

Review authentication events immediately before and after the DET-002 alert.

Determine:

- Number of failed attempts
- Time between attempts
- Whether failures continued
- Whether the source changed
- Whether additional accounts were targeted

### 5. Check for successful authentication

Determine whether the affected account successfully authenticated following the failed attempts.

A successful authentication after repeated failures may increase the likelihood of account compromise and should be correlated with **DET-004 — Successful Login After Failed Attempts**.

### 6. Check for account lockout

Determine whether the repeated failures resulted in an account lockout.

Correlate with **DET-005 — Account Lockout** if applicable.

### 7. Check for related activity

Search for additional suspicious activity involving the affected account or source, including:

- Privilege escalation
- Account modifications
- RDP activity
- SMB access
- PowerShell execution
- Remote process execution
- Lateral-movement activity
- Other authentication failures

## Response Playbook

### If the activity is benign

- Determine the legitimate cause of the repeated failures.
- Document the finding if required.
- Identify and correct stale or misconfigured credentials where applicable.
- Continue monitoring for additional authentication activity.
- Close the alert when no malicious behavior is identified.

### If the activity is suspicious

- Investigate the affected account and originating source.
- Review authentication activity across the environment.
- Check whether additional accounts were targeted.
- Determine whether a successful authentication occurred.
- Review related lateral-movement or privilege-escalation activity.
- Escalate the alert if malicious activity is confirmed.

### If compromise is suspected

- Restrict or disable the affected account where appropriate.
- Reset the account credentials.
- Investigate and contain the originating host if required.
- Review other accounts targeted by the same source.
- Search for successful authentications following the failed attempts.
- Investigate post-authentication activity.
- Document the incident and response actions.

## False Positives

Common legitimate causes include:

- User repeatedly entering an incorrect password.
- Forgotten or mistyped credentials.
- Recently changed password.
- Applications using outdated credentials.
- Scheduled tasks using an expired password.
- Services configured with stale credentials.
- Mapped drives using old credentials.
- Password managers submitting outdated credentials.
- Administrative troubleshooting.
- Authentication retries generated by legitimate applications.

A DET-002 alert is therefore a **stronger indicator than a single failed authentication, but it should not automatically be considered malicious**.

## Tuning Considerations

DET-002 is configured as a **higher-severity behavioral detection** than DET-001 because it requires multiple authentication failures within a defined time window.

Current correlation:

```text
3 failed authentications
        +
Same target username
        +
Within 120 seconds
        ↓
DET-002
```

Potential tuning options include:

- Adjusting the `frequency` threshold based on observed authentication behavior.
- Adjusting the `timeframe` to reduce noise or improve detection speed.
- Correlating failures by source IP in addition to target username.
- Correlating multiple target usernames from the same source to identify password spraying.
- Increasing severity when repeated failures are followed by a successful login.
- Suppressing known benign service-account or application-generated authentication failures where appropriate.
- Correlating authentication activity with account lockouts and other suspicious events.

The current rule intentionally uses the **target username** as its correlation field. This makes it effective for detecting repeated authentication attempts against the same account while providing a foundation for more advanced authentication detections.
