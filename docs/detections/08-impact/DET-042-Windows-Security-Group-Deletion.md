# Detection 042 — Windows Security Enabled Group Deletion

## Objective

Detect when a security-enabled group (local, global, or universal) is deleted from Active Directory or a local Windows system.

Security groups control authorization boundaries across Windows networks. Threat actors attempting denial-of-service, impact operations, or active defense disruption may delete critical security groups to strip user access permissions, break domain authentication flows, or disrupt organizational operations. DET-042 monitors Windows Security Event IDs 4730, 4734, and 4758 to ensure visibility into security group destruction.

## MITRE ATT&CK

**Related Techniques:**
- **T1531** — Account Access Removal

Adversaries may delete security groups to disrupt access to systems, services, or resource shares, effectively severing administrative control or operational availability across the target domain.

## Windows / Sysmon Events

**Base Rule:** `60139` — Generic Windows Account Management Event.

Relevant fields and trigger conditions include:

- Event ID (`win.system.eventID`): `4730`, `4734`, or `4758`
  - **Event ID 4730:** A security-enabled local group was deleted.
  - **Event ID 4734:** A security-enabled global group was deleted.
  - **Event ID 4758:** A security-enabled universal group was deleted.
- Target Group Name (`win.eventdata.targetUserName`): Name of the deleted security group.
- Performing Account (`win.eventdata.subjectUserName`): Account context that initiated the deletion.

## Detection Logic

```text
Windows Security Log
        ↓
Event ID matches Regex: ^(4730|4734|4758)$ (Parent Rule 60139)
        ↓
Custom rule 100141 matches
        ↓
DET-042 alert generated (Level 10 - Medium/High Severity)
```

The rule triggers when Windows Security log events match parent rule `60139` AND `win.system.eventID` explicitly matches Event IDs `4730`, `4734`, or `4758`.

## Wazuh Rule

```xml
<rule id="100141" level="10">

    <if_sid>60139</if_sid>

    <field name="win.system.eventID" type="pcre2">^(4730|4734|4758)$</field>

    <description>
        DET-042 - Windows security-enabled group deleted: $(win.eventdata.targetUserName) by $(win.eventdata.subjectUserName) (Event $(win.system.eventID))
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
| Detection ID | DET-042 |
| Wazuh Rule ID | 100141 |
| Severity | 10 (Medium / High Severity) |
| Parent Rule ID | 60139 (Windows Account Management Event) |
| Detection Type | Windows Security Event Audit |
| Event Source | Windows Security Log |
| Targeted Event IDs | 4730, 4734, 4758 |
| MITRE Techniques | T1531 |
| Category | Impact / Account Access Removal |

---

## Simulation

A security group deletion simulation was conducted in the lab environment using Active Directory module commands and legacy Windows net utilities.

```text
Attacker / Compromised Administrator
        ↓
Executes command to remove a target security group:
  > Remove-ADGroup -Identity "Domain Admins Backup" -Confirm:$false
    OR
  > net localgroup "Lab_Operators" /delete
        ↓
Windows Security Log records Event ID 4730, 4734, or 4758
        ↓
Wazuh parent rule 60139 matches
        ↓
Custom rule 100141 matches
        ↓
DET-042 alert generated (Level 10)
```

## Expected Alert

The expected Wazuh alert contains:

- **Detection:** `DET-042`
- **Rule ID:** `100141`
- **Severity:** `10`
- Description: `DET-042 - Windows security-enabled group deleted: <TARGET_GROUP> by <SUBJECT_USER> (Event <EVENT_ID>)`
- Target Group (`win.eventdata.targetUserName`)
- Subject User (`win.eventdata.subjectUserName`)
- Event ID (`win.system.eventID`)
- Timestamp

Example Alert Description Output:

```text
DET-042 - Windows security-enabled group deleted: Tier1_Admins by LAB-DC01\sec_admin (Event 4734)
```

## Validation Result

**Status: VALIDATED**

Custom rule 100141 successfully generated Level 10 alerts whenever local, global, or universal security groups were deleted across Active Directory Domain Controllers and local standalone hosts.

## Investigation Playbook

When DET-042 triggers, SOC analysts must immediately assess whether the group deletion was an authorized administrative cleanup or an operational impact attack.

### 1. Identify Target Group & Performing Account

- **Target Group (`win.eventdata.targetUserName`):** Determine the critical nature of the deleted group (e.g., Domain Admins, Backup Operators, Remote Desktop Users, custom enterprise RBAC groups).
- **Subject User (`win.eventdata.subjectUserName`):** Identify who authorized or performed the deletion.

### 2. Verify Change Management Approval

- Cross-reference Active Directory ticketing logs to determine if a formal change request existed for removing the security group.

### 3. Correlate Process & Host Context

- Correlate the event with Sysmon Event ID 1 (Process Creation) to identify the process or management shell (`powershell.exe`, `dsmod.exe`, `mmc.exe`, `dsa.msc`) used to perform the deletion.

### 4. Determine Classification

Classify the event:

- **False Positive / Benign:** Authorized administrative decommissioning of legacy or redundant security groups.
- **True Positive:** Unauthorized group deletion performed by a malicious actor or insider to cause service disruption or destroy access control structures.

## Response Playbook

### If activity is confirmed malicious

- **Restore Deleted Group:** Restore the security group from the Active Directory Recycle Bin or backup state:
  ```powershell
  Restore-ADObject -Filter 'Name -eq "<TARGET_GROUP>"'
  ```
- **Revoke Subject Account Credentials:** Reset passwords and revoke active tokens/sessions for the account specified in `win.eventdata.subjectUserName`.
- **Isolate Host:** Network isolate the workstation or host from which the command-line administration tools were launched.
- **Audit Group Membership:** Conduct a full review of domain groups to ensure no other security boundaries were modified or severed during the incident.

## False Positives

Common benign sources include:

- Routine Identity and Access Management (IAM) lifecycle operations, such as removing temporary project groups or legacy access structures.
- Scripted directory cleanup utilities managed by sysadmins.

## Tuning Considerations

DET-042 operates at **Level 10 (Medium/High Severity)**.

Tuning options:

- **Elevate High-Privilege Groups:** Create higher-level rules (Level 13+) specifically targeting deletions of critical default Active Directory groups (e.g., Domain Admins, Enterprise Admins, Schema Admins).
- **Service Account Suppressions:** If enterprise IAM automation software handles group lifecycles, suppress alerts specifically originating from trusted IAM service accounts after verifying strict RBAC guardrails.

Active tracking of security group deletion protects organizational access structures from destructive post-exploitation actions.
