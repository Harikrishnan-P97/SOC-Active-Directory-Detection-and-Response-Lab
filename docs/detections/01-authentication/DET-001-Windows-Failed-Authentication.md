# Detection 001 — Windows Failed Authentication

## Objective

Detect failed Windows authentication attempts and provide the base telemetry for identifying suspicious authentication activity.

This detection serves as the foundation for higher-level authentication detections such as **DET-002 — Windows Brute Force Detection** and **DET-004 — Successful Login After Failed Attempts**.

## MITRE ATT&CK

**Related Technique:** T1110 — Brute Force

A single failed login is not necessarily malicious. DET-001 provides the underlying authentication-failure telemetry used by higher-level correlation detections.

## Windows Events

**Event ID:** `4625` — An account failed to log on.

Relevant fields may include:

- Target username
- Target domain
- Source IP address
- Logon type
- Authentication package
- Failure reason
- Workstation name

## Detection Logic

```text
Windows Event 4625
        ↓
Wazuh base rule 60122
        ↓
Custom rule 100100
        ↓
DET-001 alert
```

The rule detects individual authentication failures without applying a frequency threshold.

## Wazuh Rule

```xml
<rule id="100100" level="3">

    <if_sid>60122</if_sid>

    <description>
        DET-001 Base - Windows Failed Authentication
    </description>

    <group>
        custom_windows,
        authentication,
    </group>

</rule>
```

### Rule Details

| Field | Value |
|---|---|
| Detection ID | DET-001 |
| Wazuh Rule ID | 100100 |
| Severity | 3 |
| Parent Rule | 60122 |
| Detection Type | Authentication Failure |
| Windows Event | 4625 |
| Category | Authentication |

---

## Simulation

A controlled authentication attempt was performed using an incorrect password in the Windows lab environment.

```text
CLIENT01
    ↓
Incorrect password
    ↓
Windows generates Event 4625
    ↓
Wazuh base rule 60122 matches
    ↓
Custom rule 100100 matches
    ↓
DET-001 alert generated
```

## Expected Alert

The expected Wazuh alert should contain:

- **Detection:** `DET-001`
- **Rule ID:** `100100`
- **Severity:** `3`
- **Windows Event:** `4625`
- Target username
- Source information
- Authentication details

## Validation Result

**Status: VALIDATED**

The rule successfully detected Windows failed-authentication telemetry and generated the expected custom Wazuh detection.

The detection also provides the authentication-failure events used by subsequent correlation rules.

## Investigation Playbook

When a DET-001 alert is generated, the analyst should determine whether the failed authentication is expected or potentially suspicious.

### 1. Identify the affected account

Review:

- Target username
- Target domain
- Account type
- Whether the account is privileged or a service account

### 2. Identify the source

Review:

- Source IP address
- Source hostname
- Workstation name
- Whether the source is expected for the user

### 3. Review authentication details

Check:

- Logon type
- Authentication package
- Failure reason
- Timestamp

### 4. Look for repeated failures

Search for additional Event ID `4625` events involving:

- The same username
- The same source IP
- Other usernames from the same source
- The same time period

Repeated failures may indicate brute-force or password-spraying activity.

### 5. Check for successful authentication

Determine whether the affected account successfully authenticated after the failed attempts.

If repeated failures are followed by a successful login, correlate the activity with **DET-004 — Successful Login After Failed Attempts**.

### 6. Check related activity

Look for other suspicious activity from the same account or source, including:

- Privilege escalation
- Account changes
- RDP activity
- SMB access
- PowerShell execution
- Other lateral-movement activity

## Response Playbook

### If the activity is benign

- Document the finding if required.
- Continue monitoring for repeated failures.
- Close the alert when no suspicious activity is identified.

### If the activity is suspicious

- Investigate the affected account and source.
- Review additional authentication activity.
- Check for related lateral-movement or privilege-escalation activity.
- Escalate if malicious activity is confirmed.

### If compromise is suspected

- Disable or restrict the affected account where appropriate.
- Reset the account credentials.
- Investigate the originating host.
- Contain the source if required.
- Search for additional affected accounts.
- Document the incident and response actions.

## False Positives

Common legitimate causes include:

- Incorrect password entered by a user.
- Forgotten password.
- Recently changed password.
- Outdated credentials stored by an application.
- Password manager using an outdated password.
- Mapped drives using old credentials.
- Legitimate services using outdated credentials.
- Administrative troubleshooting.

A single DET-001 alert should therefore **not automatically be considered malicious**.

## Tuning Considerations

DET-001 is intentionally configured as a **low-severity base detection**.

It captures individual authentication failures while higher-level detections perform behavioral correlation.

```text
DET-001
Failed Authentication
        ↓
        ├── DET-002
        │   Multiple failures against same account
        │
        └── DET-004
            Successful login after repeated failures
```

Potential tuning options include:

- Excluding known benign service-account activity where appropriate.
- Correlating failures by source IP and username.
- Increasing severity when repeated failures occur.
- Increasing severity when a successful login follows repeated failures.
- Correlating authentication failures with other suspicious activity from the same source.

The low severity is intentional: the rule preserves authentication-failure visibility while higher-level detections provide stronger indicators of malicious behavior.
