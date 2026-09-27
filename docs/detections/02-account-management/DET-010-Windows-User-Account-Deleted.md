# Detection 010 — Windows User Account Deleted

## Objective

Detect the deletion of Windows user accounts and provide visibility into account-management activity that could indicate anti-forensics, operational disruption, unauthorized administrative action, or malicious account cleanup.

Account deletion can be a routine administrative lifecycle process, but an unexpected or unauthorized deletion of a user account—especially a privileged, service, or administrative account—may indicate an attacker attempting to cover their tracks, disrupt logging/access, or remove evidence of compromised accounts.

DET-010 provides the underlying telemetry required to investigate who deleted the account, which account was deleted, the authorization context of the deletion, and the surrounding activity.

## MITRE ATT&CK

**Related Technique:** T1531 — Account Access Removal

Attackers may interrupt availability of system and network resources by inhibiting access to accounts. Deleting accounts can disrupt legitimate administrative workflows, revoke access for security personnel, or destroy evidence of prior account manipulation and persistence.

DET-010 detects the account-deletion event itself. The analyst should investigate the initiating subject account, target account, administrative context, and post-deletion activity to determine whether the event is malicious.

## Windows Events

**Event ID:** `4726` — A user account was deleted.

Relevant fields may include:

- Target username
- Target domain
- Target user SID
- Subject username
- Subject domain
- Subject user SID
- Account name
- User account control
- Timestamp
- Source system information where available

The **subject account** identifies the account that performed the account-deletion action, while the **target account** identifies the user account that was deleted.

## Detection Logic

```text
Windows Event 4726
        ↓
Wazuh base rule 60111
        ↓
Custom rule 100109
        ↓
DET-010 alert
```

The rule detects Windows user account deletion events identified by Wazuh base rule `60111`.

The rule also explicitly requires:

```text
win.system.eventID = 4726
```

No frequency or time-based correlation is applied by DET-010 itself.

## Wazuh Rule

```xml
<rule id="100109" level="10">
    <if_sid>60111</if_sid>

    <field name="win.system.eventID">^4726$</field>

    <description>
        DET-010 - Windows user account deleted: $(win.eventdata.targetUserName) by $(win.eventdata.subjectUserName)
    </description>

    <group>
        windows,
        impact,
        account_management,
        custom_detection_engineering,
        custom_detection
    </group>

    <mitre>
        <id>T1531</id>
    </mitre>
</rule>
```

### Rule Details

| Field | Value |
|---|---|
| Detection ID | DET-010 |
| Wazuh Rule ID | 100109 |
| Severity | 10 |
| Parent Rule | 60111 |
| Detection Type | Windows User Account Deleted |
| Windows Event | 4726 |
| MITRE Technique | T1531 |
| Category | Account Management / Impact / Access Removal |

---

## Simulation

A controlled user-account deletion event was performed in the Windows Active Directory lab environment against a test account.

```text
Administrator / Test Account
        ↓
Deletes a Windows user account
        ↓
Windows generates Event 4726
        ↓
Wazuh base rule 60111 matches
        ↓
Custom rule 100109 matches
        ↓
DET-010 alert generated
```

## Expected Alert

The expected Wazuh alert should contain:

- **Detection:** `DET-010`
- **Rule ID:** `100109`
- **Severity:** `10`
- **Windows Event:** `4726`
- Target username
- Target domain
- Subject username
- Subject domain
- Account-deletion details
- Timestamp

The alert description should identify both the deleted account and the performing user:

```text
DET-010 - Windows user account deleted: <targetUserName> by <subjectUserName>
```

## Validation Result

**Status: VALIDATED**

The rule successfully detected Windows user-account deletion telemetry through Wazuh base rule `60111` and generated the expected custom Wazuh detection.

The detection provides critical visibility into account removal activity that can be investigated for legitimate administrative deprovisioning, anti-forensics, or unauthorized access destruction.

## Investigation Playbook

When a DET-010 alert is generated, the analyst should determine whether the user account deletion was an authorized deprovisioning event and whether any suspicious activity preceded or followed the deletion.

### 1. Identify the deleted account

Review:

- Target username
- Target domain
- Target user SID
- Account type (standard, administrative, service account)
- Whether the account was previously active, dormant, or recently enabled
- Whether the account held sensitive access or privileged group memberships

Deleting a privileged or service account represents a significantly higher-risk event.

### 2. Identify who deleted the account

Review:

- Subject username
- Subject domain
- Subject user SID
- Source system where available
- Timestamp

Determine whether the initiating subject account is authorized to delete user accounts.

An unexpected administrative account or compromised user deleting accounts should be investigated immediately.

### 3. Determine whether the deletion was authorized

Check:

- Identity and Access Management (IAM) deprovisioning tickets
- Offboarding change-management logs
- Administrative request procedures
- Scheduled employee offboarding timelines
- Expected administrative workflows

If the account deletion cannot be linked to a valid change request or offboarding ticket, escalate the alert.

### 4. Review the target account's history prior to deletion

Search recent telemetry involving the deleted target account prior to its deletion for:

- Recent account creation or enablement events (e.g., **DET-007**, **DET-009**)
- Password resets (e.g., **DET-008**)
- Group membership changes (e.g., addition to Domain Admins)
- Recent authentications and interactive sessions
- Commands or scripts executed under the account context

Assess whether the account was created, used for unauthorized activity, and then deleted as part of an anti-forensics cleanup routine.

### 5. Review the subject account's recent activity

Search for activity performed by the initiating subject account before and after the deletion:

- Other account-management events (creations, resets, disablements)
- Privilege escalation or lateral movement attempts
- Unusual remote administration (PowerShell, RDP, WMI)
- Mass account modification or deletion activity

### 6. Check for operational impact

Assess whether the deleted account:

- Serves critical services or automated scheduled tasks
- Belongs to key active personnel
- Disrupted active business operations or administrative processes upon deletion

### 7. Determine whether the deletion represents anti-forensics or disruption

Evaluate if the deletion fits an attack sequence:

- **Anti-Forensics:** Adversary created a temporary user account, achieved objective, and deleted the account to clear traces.
- **Operational Disruption / Denial of Service:** Adversary deleted key administrative or operational accounts to lock out defenders or disrupt services.

## Response Playbook

### If the activity is benign

- Confirm the account deletion was tied to an authorized offboarding ticket or administrative workflow.
- Verify the subject account was operating within its scope of duty.
- Document the ticket ID and administrative context in the alert notes.
- Close the alert as a benign administrative action.

### If the activity is suspicious

- Contact the administrative account owner who performed the deletion to confirm intent.
- Review recent activity logs for both the subject account and target account.
- Preserve event logs related to the target account's historical activity before log rollover.
- Escalate to senior incident handlers if unauthorized account manipulation is suspected.

### If compromise is suspected

- Immediately disable or isolate the subject account that performed the unauthorized deletion.
- Audit Active Directory for any other accounts created, modified, or deleted by the subject account.
- Determine if the deleted account needs to be restored from backup/tombstone to resume critical operations or facilitate forensic analysis.
- Initiate host isolation and incident response procedures on systems accessed by the subject or target accounts.
- Document all findings, timeline of events, and response actions.

## False Positives

Common legitimate causes include:

- Routine employee offboarding and HR deprovisioning.
- Scheduled identity lifecycle management (ILM) workflows.
- IT helpdesk cleanup of expired or temporary contractor accounts.
- Automated Active Directory cleanup scripts.
- Deletion of test or staging accounts following lab testing.
- Administrative remediation of duplicate or incorrectly created accounts.

A DET-010 alert **should not automatically be considered malicious**.

The primary analyst objective is to confirm authorization via change-management records and verify that the deletion was not an anti-forensics tactic following unauthorized activity.

## Tuning Considerations

DET-010 is configured as a **high-severity (Level 10) account-management detection**.

The current detection is intentionally focused on the user account deletion event:

```text
Windows Event 4726
        ↓
Wazuh rule 60111
        ↓
DET-010 / Rule 100109
```

Potential tuning options include:

- Increasing severity when high-value, service, or Domain Admin accounts are deleted.
- Correlating account deletion with short account lifespans (e.g., account created and deleted within 24 hours).
- Correlating account deletion with prior failed authentications or suspicious command execution.
- Suppressing alerts generated by trusted, dedicated IAM service accounts with valid ticket correlation.
- Creating separate alert paths or higher severity for account deletions occurring outside standard business hours.
- Correlating multiple account deletions initiated by the same subject account within a short timeframe (potential mass-deletion attack).

An account deletion becomes a strong indicator of malicious anti-forensics or impact when executed by an unexpected account, outside change windows, or immediately following suspicious authentication and lateral movement.

DET-010 therefore provides the core telemetry required to detect access removal and anti-forensics tactics across the environment.
