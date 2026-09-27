# Detection 014 — Administrator Account Enabled

## Objective

Detect when the default built-in `Administrator` account is enabled on a Windows system or Active Directory domain, providing visibility into high-risk privilege activation and persistence attempts.

The built-in `Administrator` account (RID 500) possesses unrestricted administrative permissions on a local host or domain controller. Standard security baselines require this account to remain disabled and renamed to mitigate password spraying, brute-force attacks, and pass-the-hash techniques. Enabling the default Administrator account—especially without proper change control—frequently indicates malicious persistence, backdooring, or unauthorized privilege elevation.

DET-014 captures account modification telemetry, identifying the subject performing the enable action, the target host or domain, and the authorization context.

## MITRE ATT&CK

**Related Technique:** T1098 — Account Manipulation

Adversaries may modify account structures or enable disabled accounts to maintain persistent access or execute privileged operations. Enabling the default local or domain Administrator account provides a reliable, high-privilege foothold that often bypasses traditional access controls if unmonitored.

DET-014 monitors explicit account status changes. Analysts must evaluate the subject account executing the change, the target system context, and post-enable activity.

## Windows Events

**Event ID:** `4722` — A user account was enabled.

Relevant fields include:

- Target account name (`Administrator`)
- Target SID / Domain
- Subject username (account performing the action)
- Subject domain
- Subject user SID
- Computer name / Domain Controller
- Timestamp

The **subject account** identifies who performed the administrative action, while the **target account name** explicitly targets the built-in `Administrator` identity.

## Detection Logic

```text
Windows Event 4722
        ↓
Wazuh base rule 60109
        ↓
Custom rule 100113
        ↓
DET-014 alert
```

The rule triggers on account-enabled events processed under Wazuh base rule `60109`.

The rule explicitly requires:

```text
win.system.eventID = 4722
win.eventdata.targetUserName = Administrator
```

No frequency thresholding is applied by DET-014; any single instance fires a high-severity alert.

## Wazuh Rule

```xml
<rule id="100113" level="10">

    <if_sid>60109</if_sid>

    <field name="win.system.eventID">4722</field>

    <field name="win.eventdata.targetUserName">Administrator</field>

    <description>
        DET-014 Administrator Account Enabled
    </description>

    <group>
        custom_windows,
        privilege_escalation,
        administrator_enabled,
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
| Detection ID | DET-014 |
| Wazuh Rule ID | 100113 |
| Severity | 10 |
| Parent Rule | 60109 |
| Detection Type | Administrator Account Enabled |
| Windows Event | 4722 |
| MITRE Technique | T1098 |
| Category | Privilege Escalation / Account Manipulation |

---

## Simulation

A controlled account-enablement event was executed in the Windows lab environment by activating the disabled built-in `Administrator` account using the `net user` utility or Active Directory Administrative Center.

```text
Host / Domain Controller
        ↓
Executes net user Administrator /active:yes
        ↓
Windows generates Event 4722
        ↓
Wazuh base rule 60109 matches
        ↓
Custom rule 100113 matches
        ↓
DET-014 alert generated
```

## Expected Alert

The expected Wazuh alert contains:

- **Detection:** `DET-014`
- **Rule ID:** `100113`
- **Severity:** `10`
- **Windows Event:** `4722`
- Target account name (`Administrator`)
- Subject username
- Subject domain
- Computer / Domain Controller name
- Timestamp

The alert description explicitly reports:

```text
DET-014 Administrator Account Enabled
```

## Validation Result

**Status: VALIDATED**

The rule successfully identified Windows Event 4722 account-enablement telemetry specifically matching the target user `Administrator` via base rule `60109` and generated custom alert 100113.

The rule provides immediate detection of high-privilege account activations across host endpoints and Active Directory domain controllers.

## Investigation Playbook

When DET-014 fires, analysts must verify whether the enablement of the RID 500 Administrator account aligns with pre-approved maintenance or emergency break-glass procedures.

### 1. Identify the initiating subject account

Review:

- Subject username
- Subject domain
- Subject user SID
- System / DC where the event was logged
- Logon session context of the subject

Determine if the account enabling Administrator is a privileged administrator, an automated software script, or an unauthorized account.

### 2. Differentiate between local and domain scope

Check:

- Computer name vs. Domain context
- RID matching (verify if target SID ends in `-500`)

Enabling the local Administrator account on an endpoint poses host compromise risks; enabling the domain Administrator account on a Domain Controller poses forest-wide risks.

### 3. Verify administrative authorization

Check:

- Change management and emergency break-glass tickets
- IT Service Desk tickets for localized machine recovery
- Hardened baseline exceptions

If no documented ticket exists for enabling the Administrator account, treat the action as suspect.

### 4. Review preceding account actions

Inspect logs prior to the enablement event:

- Password reset events (Event 4724 / **DET-008**)
- Account unlocks or configuration changes
- Command-line execution logs (Sysmon Event 1 / Windows 4688) for `net user Administrator /active:yes` or PowerShell commands (`Enable-LocalUser`)

### 5. Audit post-enablement activities

Monitor the enabled `Administrator` account for immediate activity:

- Interactive or remote network logons (Event 4624 Type 2, 3, or 10)
- Command executions, tool staging, or security software tampering
- Additional user provisioning or group additions (e.g., **DET-011**, **DET-012**, **DET-013**)
- Password changes immediately following activation

### 6. Determine classification

Classify the event:

- **Authorized Break-Glass:** Emergency maintenance following approved Privileged Access Management (PAM) workflow.
- **Policy Non-Compliance:** Local IT enabling the account for routine maintenance contrary to security baseline policy.
- **Adversarial Persistence:** Malicious actor enabling the account as a backdoor or for privilege elevation.

## Response Playbook

### If the activity is benign

- Confirm ticket authorization with systems engineering or the helpdesk.
- Ensure the Administrator account is scheduled for immediate re-disabling upon task completion.
- Document ticket references in the incident case notes.
- Close the alert as an authorized administrative event.

### If the activity violates organizational policy

- Re-disable the Administrator account (`net user Administrator /active:no` or `Disable-LocalUser -Name "Administrator"`).
- Reset the Administrator account password to a long, random value (or rotate via LAPS).
- Enforce Group Policy Objects (GPO) to ensure the built-in Administrator account remains disabled by default.

### If compromise is suspected

- Immediately disable the target Administrator account.
- Isolate the host system from the network.
- Force password resets and terminate active sessions for the initiating subject account.
- Audit security event logs across all Domain Controllers for lateral movement or secondary backdoor creation.
- Execute host forensic routines to scan for webshells, RATs, or dumped SAM hashes.
- Follow organizational Incident Response protocols.

## False Positives

Common causes include:

- Emergency recovery operations performed by IT infrastructure teams.
- Legacy software deployment scripts configuring local account states.
- Automated system provisioning routines that fail to re-disable the account post-build.

## Tuning Considerations

DET-014 operates at **high severity (Level 10)**.

The current rule structure:

```text
Windows Event 4722 + Administrator user
        ↓
Wazuh rule 60109
        ↓
DET-014 / Rule 100113
```

Tuning strategies include:

- Raising severity to Level 13 or 14 if the enablement occurs on a Domain Controller.
- Raising severity if the enablement is combined with an immediate password reset (Event 4724).
- Creating child rules to explicitly match renamed Administrator accounts (monitoring by SID `-500` instead of account name alone).
- Suppressing alerts generated by approved Privileged Access Management (PAM) break-glass automation tools.

Tracking the status of the built-in Administrator account prevents adversaries from silently reactivating dormant, highly privileged accounts.
