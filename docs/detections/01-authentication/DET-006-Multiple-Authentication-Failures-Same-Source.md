# Detection 006 — Multiple Authentication Failures From Same Source

## Objective

Detect multiple Windows authentication failures originating from the same source IP address within a short time window.

This detection provides a source-based indicator of potential brute-force or password-spraying activity by identifying repeated authentication failures associated with a common source.

DET-006 builds on **DET-001 — Windows Failed Authentication** and uses the source IP address as the primary correlation field.

## MITRE ATT&CK

**Related Technique:** T1110 — Brute Force

Password spraying is a variation of brute-force activity in which an attacker attempts credentials against multiple accounts. DET-006 is labeled a **Password Spray Approximation** because it correlates failed authentication events by source IP address but does not explicitly require multiple unique usernames.

The alert therefore requires investigation to determine whether the activity represents password spraying, repeated brute force against one account, or legitimate authentication failures.

## Windows Events

**Event ID:** `4625` — An account failed to log on.

Relevant fields may include:

- Target username
- Target domain
- Source IP address
- Workstation name
- Logon type
- Authentication package
- Failure reason
- Timestamp

The detection specifically correlates failed-authentication events using:

```text
win.eventdata.ipAddress
```

## Detection Logic

```text
Windows Event 4625
        ↓
Wazuh base rule 60122
        ↓
DET-001 / Rule 100100
        ↓
6 matching failures
from the same source IP
within 180 seconds
        ↓
Custom rule 100105
        ↓
DET-006 alert
```

The rule triggers when **6 events matching DET-001** are observed from the **same `win.eventdata.ipAddress`** within a **180-second timeframe**.

Because the rule does not require different usernames, the resulting alert represents a **source-based authentication anomaly** rather than definitive password-spraying detection.

## Wazuh Rule

```xml
<rule id="100105"
      level="12"
      frequency="6"
      timeframe="180">

    <if_matched_sid>100100</if_matched_sid>

    <same_field>win.eventdata.ipAddress</same_field>

    <description>
        DET-006 Multiple Authentication Failures From $(win.eventdata.ipAddress) (Password Spray Approximation)
    </description>

    <group>
        custom_windows,
        authentication,
        password_spraying,
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
| Detection ID | DET-006 |
| Wazuh Rule ID | 100105 |
| Severity | 12 |
| Parent Rule | 100100 |
| Frequency | 6 events |
| Timeframe | 180 seconds |
| Correlation Field | `win.eventdata.ipAddress` |
| Detection Type | Multiple Authentication Failures / Password Spray Approximation |
| Windows Event | 4625 |
| MITRE Technique | T1110 |
| Category | Authentication / Password Spraying |

---

## Simulation

A controlled authentication test was performed in the Windows lab environment by generating multiple failed authentication attempts from the same source.

```text
Authentication Source
        ↓
Repeated incorrect authentication attempts
        ↓
Windows generates multiple Event 4625 events
        ↓
Wazuh base rule 60122 matches
        ↓
DET-001 / Rule 100100 matches
        ↓
6 failures from the same source IP
within 180 seconds
        ↓
Custom rule 100105 matches
        ↓
DET-006 alert generated
```

## Expected Alert

The expected Wazuh alert should contain:

- **Detection:** `DET-006`
- **Rule ID:** `100105`
- **Severity:** `12`
- **Windows Event:** `4625`
- Source IP address
- Target username
- Target domain
- Authentication details
- Timestamp
- Correlation indicating multiple failures from the same source

The alert description should identify the source IP:

```text
DET-006 Multiple Authentication Failures From <source-ip> (Password Spray Approximation)
```

## Validation Result

**Status: VALIDATED**

The rule successfully correlated multiple Windows failed-authentication events originating from the same source IP address and generated the expected custom Wazuh detection.

The detection provides a source-based authentication signal that can be used to investigate potential password-spraying or other brute-force activity.

## Investigation Playbook

When a DET-006 alert is generated, the analyst should determine whether the source is generating suspicious authentication activity against one or multiple accounts.

### 1. Identify the source

Review:

- Source IP address
- Source hostname
- Workstation name
- Network segment
- Whether the source is a known administrative or user workstation
- Whether the source is expected to authenticate to the affected systems

An unexpected source should receive additional scrutiny.

### 2. Identify the targeted accounts

Review the target usernames associated with the failed authentication events.

Determine:

- Number of unique usernames targeted
- Whether the same username was repeatedly targeted
- Whether privileged accounts were targeted
- Whether service accounts were targeted
- Whether multiple accounts were targeted from the same source

Multiple usernames from the same source strengthen the password-spraying hypothesis.

### 3. Review authentication details

Examine:

- Logon type
- Authentication package
- Failure reason
- Target domain
- Workstation information
- Timestamps

Determine whether the authentication pattern is consistent with normal activity.

### 4. Establish the attack timeline

Review authentication failures before and after the DET-006 alert.

Determine:

- Number of failures
- Number of unique accounts
- Time between attempts
- Whether activity continued
- Whether the source changed
- Whether additional systems were targeted

### 5. Check for successful authentication

Search for successful Event ID `4624` activity involving accounts targeted by the source.

A successful authentication following repeated failures may indicate that valid credentials were eventually obtained or successfully guessed.

Correlate with **DET-003 — Windows Successful Interactive Authentication** and **DET-004 — Successful Login After Failed Attempts** where applicable.

### 6. Check for account lockouts

Determine whether any targeted accounts became locked.

Correlate with **DET-005 — User Account Locked**.

Multiple account lockouts originating from the same source can significantly increase the likelihood of malicious authentication activity.

### 7. Check for related activity

Review the source and affected accounts for:

- Privilege escalation
- Account modifications
- PowerShell execution
- RDP activity
- SMB access
- Remote administration
- Lateral movement
- Credential-access activity
- Other suspicious authentication activity

## Response Playbook

### If the activity is benign

- Identify the legitimate source of the authentication failures.
- Determine whether a user, application, service, or administrative process caused the activity.
- Correct stale or misconfigured credentials where applicable.
- Document the finding if required.
- Continue monitoring the source.
- Close the alert when no malicious activity is identified.

### If the activity is suspicious

- Investigate the originating source system.
- Identify all accounts targeted by the source.
- Review authentication activity across the environment.
- Check for successful authentications.
- Check for account lockouts.
- Investigate related lateral-movement or privilege-escalation activity.
- Escalate if malicious activity is confirmed.

### If compromise is suspected

- Isolate or contain the originating system where appropriate.
- Restrict the source from accessing authentication services if required.
- Reset credentials for confirmed or potentially compromised accounts.
- Review all accounts targeted by the source.
- Investigate successful authentications following the failed attempts.
- Search for post-authentication activity.
- Document the incident and response actions.

## False Positives

Common legitimate causes include:

- Misconfigured applications repeatedly attempting authentication.
- Services using stale credentials.
- Scheduled tasks using outdated passwords.
- Administrative scripts using incorrect credentials.
- Multiple users authenticating through a shared system.
- Domain-joined systems repeatedly retrying authentication.
- Network services using expired credentials.
- Legitimate administrative troubleshooting.
- Authentication failures generated by automated enterprise applications.

A DET-006 alert **does not by itself confirm password spraying or malicious activity**.

Because the rule is based on a shared source IP, the analyst should determine whether the source is legitimately responsible for authentication attempts involving the affected accounts.

## Tuning Considerations

DET-006 is configured as a **high-severity source-based authentication detection**.

The current correlation is:

```text
6 failed authentications
        +
Same source IP
        +
Within 180 seconds
        ↓
DET-006
```

The detection is intentionally described as a **Password Spray Approximation** because it does not currently require multiple unique usernames.

Potential tuning options include:

- Requiring multiple unique target usernames from the same source.
- Adjusting the `frequency` threshold based on the environment's authentication baseline.
- Adjusting the `timeframe` to reduce noise or improve detection speed.
- Correlating source IP with target username diversity.
- Increasing severity when privileged accounts are targeted.
- Increasing severity when successful authentication follows the failures.
- Correlating with account-lockout events.
- Excluding known authentication infrastructure where appropriate.
- Creating separate thresholds for internal workstations, servers, and external sources.
- Correlating authentication activity with other indicators from the same source.

A stronger password-spraying detection would typically combine **source IP**, **multiple unique target usernames**, **authentication-failure volume**, and **time-based behavior**.

DET-006 provides the source-based foundation for that analysis while maintaining visibility into repeated authentication failures originating from a common source.
