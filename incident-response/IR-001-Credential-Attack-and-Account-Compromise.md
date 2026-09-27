# IR-001 — Credential Attack & Account Compromise

## 1. Objective

This playbook provides an incident-level workflow for investigating and responding to authentication attacks and potential account compromise within the Windows Active Directory lab.

It covers incidents involving repeated failed authentication, brute-force behavior, successful authentication, successful login following failed attempts, account lockouts, and multiple authentication failures originating from the same source.

The objective is to determine whether the authentication activity is benign, suspicious, malicious, or indicative of a compromised account; establish the affected identity, source, and scope; and guide containment, eradication, recovery, and validation.

---

## 2. Scope & Related Detections

### 2.1 Scope

This playbook applies to authentication-related activity involving:

- **DC01** — Windows Server 2022 / Active Directory Domain Controller
- **CLIENT01** — Windows 11 domain-joined endpoint
- Domain user accounts
- Privileged or service accounts where applicable
- Authentication sources generating Windows security events
- Wazuh alerts generated from Windows authentication telemetry

Primary Windows events covered by this incident scenario are:

- `4625` — An account failed to log on
- `4624` — An account was successfully logged on
- `4740` — A user account was locked out

### 2.2 Related Detection Rules

| Detection | Name | Wazuh Rule | Severity | Primary Event / Correlation |
|---|---|---:|---:|---|
| DET-001 | Windows Failed Authentication | 100100 | 3 | Event 4625 |
| DET-002 | Windows Brute Force Detection | 100101 | 10 | 3 failures / 120s / same username |
| DET-003 | Windows Successful Interactive Authentication | 100102 | 5 | Event 4624 / logon types 2, 7, 10, 11 |
| DET-004 | Successful Login After Failed Attempts | 100103 | 8 | 4625 + 4624 / same username |
| DET-005 | User Account Locked | 100104 | 5 | Event 4740 |
| DET-006 | Multiple Authentication Failures From Same Source | 100105 | 12 | 6 failures / 180s / same source IP |

### 2.3 Detection-to-Incident Relationship

The individual detections provide signals that should be correlated during the incident investigation.

```text
DET-001
Failed Authentication
      │
      ├──────────────→ DET-002
      │                 Repeated failures
      │                 against same account
      │
      └──────────────→ DET-006
                        Multiple failures
                        from same source
                              │
                              ├────────→ DET-005
                              │          Account Lockout
                              │
                              └────────→ DET-003
                                         Successful Authentication
                                               │
                                               ↓
                                         DET-004
                                         Successful Login
                                         After Failed Attempts
```

The sequence above represents a possible attack progression. It is not guaranteed that every detection will trigger during the same incident.

---

## 3. Attack Scenario

### 3.1 Scenario Overview

An attacker attempts to obtain access to a Windows or Active Directory account by repeatedly submitting authentication attempts.

The activity may initially appear as individual failed logons. Repeated failures against the same account can produce brute-force indicators, while repeated failures from a common source may indicate broader authentication abuse or a password-spraying pattern.

If valid credentials are eventually obtained or correctly guessed, a successful authentication may follow the failed attempts. An account lockout may also occur when authentication failures exceed the configured Windows account-lockout policy.

The analyst must determine whether the observed activity represents:

- User error
- Stale or misconfigured credentials
- Application or service authentication problems
- Administrative activity
- Brute-force activity
- Password-spraying activity
- Compromised credentials
- Unauthorized account access

### 3.2 Typical Attack Flow

```text
Attacker / Suspicious Source
          │
          ↓
Authentication Attempts
          │
          ↓
Windows Event 4625
          │
          ↓
Wazuh Authentication Detection
          │
          ├───────────────┐
          ↓               ↓
Repeated failures    Multiple failures
same account         same source
          │               │
          ↓               ↓
      DET-002          DET-006
          │               │
          └───────┬───────┘
                  ↓
       Possible account lockout
                  │
                  ↓
               DET-005
                  │
                  ↓
      Possible successful login
                  │
                  ↓
               DET-003
                  │
                  ↓
 Successful login after failures
                  │
                  ↓
               DET-004
```

### 3.3 Expected Detection Sequence

A potential authentication attack may generate activity in the following order:

1. Individual failed authentication events trigger **DET-001**.
2. Repeated failures against the same username may trigger **DET-002**.
3. Multiple failures from the same source IP may trigger **DET-006**.
4. Sufficient failures may result in **DET-005** account-lockout activity.
5. If valid credentials are successfully used, **DET-003** may identify the successful authentication.
6. A successful authentication following repeated failures may trigger **DET-004**.

Not every incident will produce all six detections. The actual sequence depends on the attack behavior, Windows authentication configuration, account state, and available telemetry.

### 3.4 Potential Impact

A confirmed credential attack can result in:

- Unauthorized account access
- Compromise of user credentials
- Compromise of privileged accounts
- Unauthorized access to domain resources
- Account lockouts and availability impact
- Follow-on privilege escalation
- Lateral movement
- Credential theft
- Further Active Directory compromise

The impact is significantly higher when a privileged or administrative account is successfully compromised.

---

## 4. Initial Triage

### 4.1 Alert Validation

When an authentication-related Wazuh alert is received:

1. Identify the triggering detection and Wazuh rule ID.
2. Review the raw Windows event associated with the alert.
3. Record the event timestamp.
4. Identify the affected agent and host.
5. Identify the target username and domain.
6. Identify source IP and workstation information where available.
7. Determine whether the alert is an individual failure, repeated failure, successful authentication, lockout, or source-based authentication anomaly.
8. Search for related authentication alerts around the same timestamp.

The initial alert should be treated as an indicator rather than automatic proof of compromise.

### 4.2 Identify Affected Assets

Determine:

- Which system generated the authentication event
- Whether the event originated from **DC01** or **CLIENT01**
- Whether the source system is known
- Whether multiple systems are involved
- Whether the activity is directed toward domain authentication infrastructure

Pay particular attention to activity involving **DC01**, because it provides domain authentication and Active Directory services.

### 4.3 Identify Affected Identity

Determine:

- Target username
- Target domain
- Whether the account is a normal user account
- Whether the account is privileged
- Whether the account is a service account
- Whether multiple accounts were targeted
- Whether the account became locked
- Whether the account subsequently authenticated successfully

### 4.4 Identify Attack Source

Review available source information:

- Source IP address
- Source hostname
- Workstation name
- Caller computer name for account-lockout events
- Whether the source is an expected workstation or administrative system

An authentication source should be evaluated in context. A known workstation generating authentication failures may be legitimate, compromised, or misconfigured.

### 4.5 Establish Initial Timeline

Record the earliest relevant authentication event and identify activity before and after the triggering alert.

At minimum, capture:

| Time | Detection/Event | Host | User | Source | Finding |
|---|---|---|---|---|---|
| `timestamp` | Event / DET ID | Host | Username | IP / Host | Initial finding |

Determine:

- First observed authentication failure
- Number of failures
- Time between failures
- Successful authentication, if any
- Account lockout, if any
- Last observed related activity

### 4.6 Determine Whether Activity Is Expected

Consider:

- Did the user recently change their password?
- Could an application or service be using stale credentials?
- Is the source system expected for the account?
- Was there legitimate administrative activity?
- Is the account known to be used from this source?
- Is the authentication pattern consistent with normal behavior?

Decision:

```text
Expected / Benign
      │
      └──→ Document / Monitor / Close

Suspicious
      │
      ↓
Continue Investigation

Malicious / Compromise
      │
      ↓
Containment & Eradication
```

---

## 5. Investigation Workflow

### 5.1 Establish the Initial Event

Start with the triggering Wazuh alert and identify:

- Detection ID
- Wazuh rule ID
- Windows event ID
- Timestamp
- Target username
- Target domain
- Source IP
- Workstation/source host
- Logon type where applicable
- Authentication package
- Failure reason where applicable

For Event `4625`, use the failed-authentication event as the starting point.

For Event `4624`, review the successful authentication details and determine whether the login is expected.

For Event `4740`, identify the locked account and the caller computer information where available.

### 5.2 Investigate the Source

Determine whether the source is:

- A legitimate user workstation
- An administrative system
- A server
- A service/application host
- An unexpected endpoint
- A potentially compromised system
- An unknown or suspicious source

For source-based activity, review whether the same source generated authentication failures against multiple usernames.

This is particularly important for **DET-006**, which correlates six failed authentication events from the same `win.eventdata.ipAddress` within 180 seconds.

### 5.3 Investigate the Account / Identity

For the affected account:

- Determine account type and purpose.
- Determine whether it is privileged.
- Check whether it was locked.
- Check for successful authentication after failures.
- Review whether other sources attempted authentication for the same account.
- Determine whether the account was targeted by multiple authentication attempts.

For **DET-002**, verify the repeated failures against the same `win.eventdata.targetUserName`.

For **DET-004**, verify that the successful authentication followed the correlated failed attempts for the same target username.

### 5.4 Investigate the Affected Host

Review the system associated with the authentication activity.

For **CLIENT01**, determine whether:

- The user was legitimately using the workstation.
- The source process or application may have caused the failures.
- Other suspicious endpoint activity occurred around the same time.
- The system may be the source of the authentication attack.

For **DC01**, determine whether the activity represents normal domain authentication or suspicious authentication behavior affecting domain accounts.

If the source is a suspected compromised endpoint, correlate authentication activity with endpoint telemetry and the **Sysmon Endpoint Activity** dashboard.

### 5.5 Correlate Related Detection Activity

Search for related detections involving the same account, source, host, or time period.

Priority correlations include:

| Detection | Correlation Question |
|---|---|
| DET-001 | Were there individual failed authentication events? |
| DET-002 | Were multiple failures directed at the same account? |
| DET-003 | Was the account successfully authenticated? |
| DET-004 | Did successful authentication follow repeated failures? |
| DET-005 | Did the account become locked? |
| DET-006 | Were multiple failures generated from the same source? |

Also review for signs of follow-on activity such as:

- Privilege escalation
- Account modification
- RDP activity
- SMB access
- PowerShell execution
- Remote execution
- Credential-access activity
- Other lateral-movement detections

If follow-on activity is identified, the incident should be expanded beyond IR-001 and correlated with the appropriate incident response playbook.

### 5.6 Build the Attack Timeline

Construct a single timeline combining authentication events and related activity.

Example:

| Time | Event / Detection | Host | User | Source | Finding |
|---|---|---|---|---|---|
| T1 | DET-001 / 4625 | DC01 | user | source | Failed authentication |
| T2 | DET-001 / 4625 | DC01 | user | source | Failed authentication |
| T3 | DET-002 | DC01 | user | source | Repeated failures |
| T4 | DET-005 / 4740 | DC01 | user | caller | Account locked |
| T5 | DET-003 / 4624 | DC01 | user | source | Successful authentication |
| T6 | DET-004 | DC01 | user | source | Success following failures |

The table is an investigation format; the actual sequence must be derived from observed telemetry.

### 5.7 Determine Attack Scope

Determine whether the activity is limited to:

**Single account**

```text
One source → One account
```

**Multiple accounts**

```text
One source → Multiple accounts
```

**Multiple sources**

```text
Multiple sources → One or more accounts
```

**Multiple systems**

```text
Source → Multiple Windows systems / authentication targets
```

The scope should include:

- Number of affected accounts
- Number of privileged accounts
- Number of affected hosts
- Number of source systems
- Duration of activity
- Number of successful authentications
- Number of lockouts
- Evidence of post-authentication activity

### 5.8 Determine Evidence of Compromise

Evidence supporting a confirmed compromise may include:

- Successful authentication following suspicious repeated failures
- Successful authentication from an unexpected source
- Authentication involving a privileged account without a legitimate explanation
- Multiple accounts targeted from a suspicious source
- Follow-on activity after successful authentication
- Credential-access or lateral-movement activity
- Persistence or privilege changes following authentication
- Evidence that the source endpoint is compromised

A failed-authentication pattern or account lockout alone does not establish that credentials were compromised.

---

## 6. Incident Assessment

### 6.1 Suspicious Activity

Classify the activity as suspicious when authentication behavior cannot be readily explained but there is insufficient evidence to confirm malicious activity.

Examples:

- Repeated failures from an unusual source
- Multiple authentication failures outside normal user behavior
- Unexpected account lockout
- Successful authentication following repeated failures without clear business context

Actions:

- Continue investigation
- Expand the timeline
- Review related accounts and sources
- Monitor for recurrence

### 6.2 Confirmed Malicious Activity

Classify the activity as malicious when the authentication pattern and surrounding evidence indicate deliberate unauthorized activity.

Examples:

- Repeated authentication attempts from an unauthorized source
- Clear brute-force behavior
- Multiple accounts targeted from a suspicious source
- Authentication activity inconsistent with the account's expected use
- Malicious follow-on activity associated with the source

### 6.3 Confirmed Compromise

Classify the incident as confirmed compromise when there is sufficient evidence that an unauthorized party obtained or used valid credentials.

Strong indicators include:

- Suspicious successful authentication
- Successful login following a malicious authentication attack
- Unauthorized access using a privileged account
- Post-authentication malicious activity
- Evidence of credential theft or credential exposure
- Lateral movement following successful authentication

### 6.4 Severity Considerations

Severity should increase based on:

- Privilege level of the affected account
- Number of accounts targeted
- Number of systems affected
- Successful authentication
- Evidence of credential compromise
- Lateral movement
- Persistence
- Credential theft
- Domain-level impact

A successful compromise of a privileged account should be treated as significantly higher risk than repeated failed authentication against a standard user account.

---

## 7. Containment

### 7.1 Immediate Containment

The containment objective is to prevent continued unauthorized access while preserving evidence.

Depending on the investigation findings:

- Stop active malicious authentication attempts where possible.
- Restrict the suspicious source if appropriate.
- Isolate **CLIENT01** if it is identified as a compromised source.
- Avoid unnecessary disruption to **DC01**.
- Preserve relevant authentication and endpoint telemetry.

### 7.2 Account Containment

For a suspected or confirmed compromised account:

- Disable or lock the account where appropriate.
- Reset the account password.
- Revoke or invalidate known compromised credentials through the available Windows/AD controls.
- Review whether the account has privileged access.
- Remove unauthorized access if identified.
- Review other accounts that may have been targeted.

Password resets should be performed carefully for service accounts because changing service-account credentials can disrupt dependent applications or services.

### 7.3 Endpoint Containment

If the source is a suspected compromised endpoint:

- Isolate **CLIENT01** from the network where appropriate.
- Preserve evidence before destructive remediation when practical.
- Investigate the endpoint for malicious processes, scripts, credentials, and persistence.
- Continue monitoring Wazuh telemetry for related activity.

### 7.4 AD Containment

If the incident involves a privileged or domain account:

- Restrict the affected account.
- Remove unauthorized access where identified.
- Review privileged group membership.
- Identify other potentially compromised accounts.
- Assess whether the incident has progressed into privilege escalation or domain compromise.

Do not take disruptive actions against **DC01** unless the impact and necessity are understood.

### 7.5 Additional Containment Actions

Escalate containment when:

- Multiple accounts are affected.
- Multiple systems are involved.
- A privileged account is compromised.
- Lateral movement is identified.
- Credential theft is suspected.
- The attack source cannot be contained through account controls alone.

---

## 8. Eradication

### 8.1 Remove Attacker Access

- Remove unauthorized access identified during investigation.
- Disable unauthorized accounts if created.
- Remove unauthorized authentication mechanisms where applicable.
- Confirm that compromised accounts have been remediated.

### 8.2 Remove Persistence / Malicious Artifacts

If the authentication incident originated from a compromised endpoint:

- Remove malicious tools and files.
- Remove identified persistence mechanisms.
- Remove malicious scheduled tasks or services where applicable.
- Investigate and remediate suspicious PowerShell or other execution activity.

If additional persistence is identified, continue the incident under **IR-006 — Persistence & Defense Evasion** as appropriate.

### 8.3 Remediate Compromised Credentials

For confirmed credential compromise:

- Reset affected credentials.
- Identify other credentials that may have been exposed.
- Review privileged and service-account exposure.
- Reset additional credentials when evidence indicates they may also be compromised.
- Verify that unauthorized users can no longer authenticate.

Credential remediation should consider the entire attack path rather than only the account that generated the initial alert.

### 8.4 Restore Unauthorized Changes

If the attacker performed follow-on changes after authentication:

- Revert unauthorized account changes.
- Remove unauthorized privileges.
- Restore affected security configuration.
- Remove attacker-created access.
- Continue investigation under the appropriate IR playbook for privilege escalation, persistence, or lateral movement.

---

## 9. Recovery & Validation

### 9.1 System Recovery

For a compromised endpoint:

- Restore the endpoint to a trusted state.
- Reconnect it to the environment only after containment and remediation are complete.
- Verify that malicious activity is no longer occurring.

For **DC01**, prioritize preserving domain availability while validating that authentication and Active Directory services remain functional.

### 9.2 Account / AD Recovery

Verify:

- Affected accounts are in the correct state.
- Passwords have been reset where required.
- Unauthorized access has been removed.
- Privileged memberships are correct.
- Locked accounts are handled appropriately.
- Legitimate users and services can authenticate normally.

### 9.3 Security Control Recovery

Verify that relevant security controls remain operational, including:

- Windows authentication logging
- Windows Security Event Logging
- Sysmon on monitored endpoints
- Wazuh agent connectivity
- Wazuh manager processing
- Appropriate Windows security controls

### 9.4 Telemetry Validation

Confirm that Wazuh continues to receive authentication telemetry.

Validation should include:

- New Event `4625` events are visible when generated.
- New Event `4624` events are visible when generated.
- Event `4740` is visible when an account is locked.
- Relevant custom detections remain operational.
- Authentication dashboards continue displaying current telemetry.

The **Authentication & Account Monitoring** dashboard should be used to review:

- Successful Logons
- Failed Logons
- Account Lockouts
- Privileged Logons
- Authentication activity over time
- Failed logons by user/source/host

The **SOC Detection Overview** dashboard can be used to confirm broader detection activity.

### 9.5 Post-Recovery Monitoring

Continue monitoring for:

- Repeated authentication failures
- New successful logons from unexpected sources
- Additional account lockouts
- Authentication activity involving the remediated account
- Authentication activity from the original source
- Privilege escalation
- Lateral movement
- Credential-access activity

No related activity should be observed before the incident is considered fully resolved.

---

## 10. Escalation Criteria

### 10.1 Escalate When

Escalate the incident when:

- Malicious authentication activity is confirmed.
- Credentials are suspected to be compromised.
- A successful unauthorized login is identified.
- Multiple accounts are targeted.
- Multiple systems are affected.
- The attack continues after initial containment.
- Follow-on malicious activity is identified.

### 10.2 High-Risk Conditions

Treat the incident as high risk when:

- A privileged account is compromised.
- Administrative credentials are exposed.
- Successful authentication is followed by lateral movement.
- Credential theft is identified.
- Multiple domain accounts are compromised.
- Persistence is established.
- Security controls are tampered with.

### 10.3 Domain-Level Compromise Indicators

Escalate immediately when authentication activity is associated with evidence of broader Active Directory compromise, including:

- Domain Admin or Enterprise Admin compromise
- DCSync activity
- Golden Ticket activity
- NTDS.dit credential theft
- Multiple privileged accounts compromised
- Domain-wide lateral movement
- Widespread credential exposure

These conditions require investigation beyond the initial authentication incident and should be correlated with **IR-002 — AD Account & Privilege Compromise**, **IR-003 — Kerberos & Credential Theft Attack**, or other applicable playbooks.

---

## 11. Closure Criteria

### 11.1 Investigation Complete

Confirm that:

- The authentication activity has been understood.
- The source has been identified or reasonably assessed.
- Affected accounts have been identified.
- The incident timeline has been established.
- The scope has been determined.

### 11.2 Containment Complete

Confirm that:

- Malicious authentication activity has stopped.
- Compromised accounts have been contained.
- Compromised endpoints have been isolated or remediated where required.
- Unauthorized access has been restricted.

### 11.3 Eradication Complete

Confirm that:

- Attacker access has been removed.
- Malicious artifacts have been removed.
- Persistence has been addressed.
- Compromised credentials have been remediated.
- Unauthorized changes have been reversed.

### 11.4 Recovery Complete

Confirm that:

- Affected accounts function normally.
- Affected systems function normally.
- Active Directory services remain operational.
- Security controls are restored.

### 11.5 Validation Complete

Confirm that:

- Windows authentication telemetry is functioning.
- Sysmon telemetry is functioning where applicable.
- Wazuh is receiving telemetry.
- Relevant detections remain operational.
- No continuing evidence of compromise is present.
- Post-recovery monitoring has not identified recurrence.

### 11.6 Final Documentation

Document:

- Initial alert and detection
- Affected accounts
- Affected hosts
- Source of the activity
- Attack timeline
- Scope
- Findings
- Evidence of compromise
- Containment actions
- Eradication actions
- Recovery actions
- Validation results
- Lessons learned
- Final incident disposition

The incident should not be closed solely because authentication alerts have stopped.

---

## 12. MITRE ATT&CK Mapping

The following techniques represent the primary attack behaviors covered by this incident scenario.

| Technique | Name | Relevance |
|---|---|---|
| **T1110** | Brute Force | Covers repeated authentication attempts, brute-force behavior, and source-based authentication anomalies detected by DET-001, DET-002, DET-005, and DET-006. |
| **T1078** | Valid Accounts | Covers successful authentication using valid credentials, particularly when the authentication is unauthorized or follows suspicious failed attempts as detected by DET-003 and DET-004. |

The individual detection documents provide the authoritative rule-level MITRE mappings. This playbook maps the broader incident scenario rather than duplicating every detection-level mapping.

---

## Related Detection Documentation

The following detection documents provide the technical details for the detections covered by this playbook:

- [DET-001 — Windows Failed Authentication](01-authentication/DET-001-Windows-Failed-Authentication.md)
- [DET-002 — Windows Brute Force Detection](01-authentication/DET-002-Windows-Brute-Force-Detection.md)
- [DET-003 — Windows Successful Interactive Authentication](01-authentication/DET-003-Windows-Successful-Interactive-Authentication.md)
- [DET-004 — Successful Login After Failed Attempts](01-authentication/DET-004-Successful-Login-After-Failed-Attempts.md)
- [DET-005 — User Account Locked](01-authentication/DET-005-User-Account-Locked.md)
- [DET-006 — Multiple Authentication Failures — Same Source](01-authentication/DET-006-Multiple-Authentication-Failures-Same-Source.md)
