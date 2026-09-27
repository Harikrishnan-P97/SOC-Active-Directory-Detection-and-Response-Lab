# Detection 013 — User Added to Local Administrators

## Objective

Detect when a member account or SID is added to the local Administrators security group on a host and provide visibility into endpoint-level privilege escalation and persistence.

The local `Administrators` group controls full administrative rights on the specific endpoint or server. Unauthorized additions to this group allow adversaries to bypass User Account Control (UAC), execute arbitrary code with elevated privileges, access local Security Account Manager (SAM) hashes, install persistence mechanisms, and move laterally across neighboring systems.

DET-013 captures endpoint privilege modification telemetry, identifying who performed the addition, which account was granted local administrative access, and the context around the privilege assignment.

## MITRE ATT&CK

**Related Technique:** T1098 — Account Manipulation

Adversaries may modify local group security memberships to escalate privileges or establish persistent administrative access on target endpoints. Granting local admin rights ensures continued control even if domain privileges are revoked or limited.

DET-013 monitors local security group modifications. Analysts should investigate the subject account performing the addition, the target endpoint, authorization state, and post-escalation execution.

## Windows Events

**Event ID:** `4732` — A member was added to a security-enabled local group.

Relevant fields include:

- Target group name (`Administrators`)
- Target group SID (`S-1-5-32-544`)
- Member SID (account/SID added)
- Member name (if resolved)
- Subject username
- Subject domain
- Subject user SID
- Computer name
- Timestamp

The **subject account** indicates the user executing the change, while the **member SID** identifies the account receiving local administrator privileges.

## Detection Logic

```text
Windows Event 4732
        ↓
Wazuh base rule 60103
        ↓
Custom rule 100112
        ↓
DET-013 alert
```

The rule triggers on local security group additions identified by Wazuh base rule `60103`.

The rule explicitly requires:

```text
win.system.eventID = 4732
win.eventdata.targetUserName = Administrators
```

No time window or thresholding is applied by DET-013 itself.

## Wazuh Rule

```xml
<rule id="100112" level="11">

    <if_sid>60103</if_sid>

    <field name="win.system.eventID">4732</field>

    <field name="win.eventdata.targetUserName">Administrators</field>

    <description>
        DET-013 SID $(win.eventdata.memberSid) added to Local Administrators
    </description>

    <group>
        custom_windows,
        privilege_escalation,
        local_admins,
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
| Detection ID | DET-013 |
| Wazuh Rule ID | 100112 |
| Severity | 11 |
| Parent Rule | 60103 |
| Detection Type | User Added to Local Administrators |
| Windows Event | 4732 |
| MITRE Technique | T1098 |
| Category | Privilege Escalation / Local Account Modification |

---

## Simulation

A controlled privilege-elevation event was executed in the Windows lab environment by adding a local user account to the host's `Administrators` security group using the `net localgroup` command.

```text
Host / Local Administrator
        ↓
Executes net localgroup Administrators <username> /add
        ↓
Windows generates Event 4732
        ↓
Wazuh base rule 60103 matches
        ↓
Custom rule 100112 matches
        ↓
DET-013 alert generated
```

## Expected Alert

The expected Wazuh alert contains:

- **Detection:** `DET-013`
- **Rule ID:** `100112`
- **Severity:** `11`
- **Windows Event:** `4732`
- Target group name (`Administrators`)
- Member SID
- Subject username
- Subject domain
- Computer / Host name
- Timestamp

The alert description explicitly displays the member SID added:

```text
DET-013 SID <memberSid> added to Local Administrators
```

## Validation Result

**Status: VALIDATED**

The rule successfully identified Windows Event 4732 local group telemetry targeting the `Administrators` group via base rule `60103` and generated custom alert 100112.

The rule provides immediate oversight of local privilege assignment across endpoints and servers.

## Investigation Playbook

When DET-013 fires, analysts should evaluate the necessity of local admin rights on the host, audit the initiating account, and inspect immediate endpoint activity.

### 1. Resolve and analyze the added member SID

Review:

- Member SID (resolve to local or domain account name via AD / SAM lookup)
- Account creation history (check if newly provisioned local user via **DET-007**)
- Account type (standard user, domain user, service account, or temporary vendor identity)

Adding non-standard or temporary accounts to local administrators without PAM oversight is a major compliance and security risk.

### 2. Identify the performing subject account

Review:

- Subject username
- Subject domain
- Subject user SID
- Target computer name / IP
- Logon type of subject session (e.g., interactive, network, RDP)

Determine if the operation was executed by an IT administrator, deployment script, software installer, or non-privileged user.

### 3. Verify administrative change management

Check:

- Service desk ticket numbers for local privilege grant
- Endpoint Management / MDM push schedules (e.g., Intune, SCCM deployments)
- Helpdesk / Local IT authorization logs

If no ticket or scheduled deployment exists, treat as unauthorized privilege escalation.

### 4. Inspect execution telemetry surrounding the event

Audit endpoint logs (Process Creation Event 4688 / Sysmon Event 1) near the timestamp:

- Command-line executions (`net localgroup administrators <user> /add`, `Add-LocalGroupMember`)
- Parent process launching the addition (e.g., `cmd.exe`, `powershell.exe`, remote management tools)
- Unexpected administrative tools or scripts executed before/after the group change

### 5. Audit post-escalation host activity

Check for high-risk actions following local privilege elevation:

- LSASS credential dumping or access attempts
- Modification of local security settings, firewall rules, or security agents
- Scheduled task creation or service installation for persistence
- Lateral movement attempts to adjacent systems using the new local admin credentials

### 6. Determine classification

Identify whether the alert is:

- **Authorized IT Action:** Routine helpdesk support, software installation, or approved privilege elevation.
- **Misconfiguration / Shadow IT:** Local IT adding permanent local admins outside policy.
- **Adversarial Escalation:** Malicious actor leveraging local commands to persist or elevate on a compromised endpoint.

## Response Playbook

### If the activity is benign

- Confirm ticket authorization and scope with helpdesk/desktop engineering.
- Verify if the local admin assignment is intended to be temporary or permanent.
- Document ticket references and sign-offs in the case note.
- Close the alert as authorized operational activity.

### If the activity is unauthorized or policy-violating

- Remove the added member from the local `Administrators` group (`net localgroup Administrators <user> /delete`).
- Notify endpoint management to enforce group membership via Group Policy (GPO) or MDM compliance policy.
- Remind local support staff of official Privilege Access Management (PAM) policies.

### If compromise is suspected

- Remove the account from `Administrators` and disable the target user account.
- Isolate the host from the network via EDR / SOC management tools.
- Force password resets and revoke active sessions for the performing subject account.
- Initiate endpoint forensic analysis to check for persistence, credential dumps, or lateral movement.
- Document forensic findings and follow the Incident Response Plan.

## False Positives

Common benign causes include:

- IT Support manual escalation for troubleshooting local workstation issues.
- Software installers or endpoint management agents configuring required local permissions.
- Developer workstation provisioning scripts configuring local sandbox permissions.

## Tuning Considerations

DET-013 operates at **high-severity (Level 11)**.

The current rule structure:

```text
Windows Event 4732 + Administrators group
        ↓
Wazuh rule 60103
        ↓
DET-013 / Rule 100112
```

Tuning strategies include:

- Increasing severity to Level 13 if the target endpoint is a critical server, Domain Controller, or Tier-0 asset.
- Correlating with new local account creation (Event 4720) within a short time frame (e.g., local user created AND immediately added to local Admins).
- Suppressing or lowering severity for authorized automation tools (e.g., LAPS, Intune remediation scripts) when operating under designated system accounts.

Monitoring local group membership ensures local endpoint compromises do not silently convert into persistent administrative footholds.
