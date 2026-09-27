# Detection 012 — User Added to Enterprise Admins

## Objective

Detect when a member account is added to the Enterprise Admins universal security group and provide visibility into critical Tier-0 privilege escalation within Active Directory forests.

Enterprise Admins exist in the forest root domain and possess complete administrative authority across all domains in the Active Directory forest. Unauthorized or unexpected additions to Enterprise Admins represent an extreme security event, often indicating total forest compromise, malicious persistence, or high-level privilege escalation.

DET-012 provides the core telemetry required to investigate who performed the addition, which account was elevated to Enterprise Admin status, the authorization context, and any subsequent forest-wide administrative activity.

## MITRE ATT&CK

**Related Technique:** T1098 — Account Manipulation

Attackers may manipulate group memberships to escalate privileges or maintain persistent control across an environment. Adding an account to universal administrative groups like Enterprise Admins allows adversaries to bypass domain boundaries and control the entire Active Directory forest structure.

DET-012 detects the universal group-addition event itself. The analyst should investigate the initiating subject account, the added member account, administrative authorization, and post-escalation activity across all forest domains.

## Windows Events

**Event ID:** `4756` — A member was added to a security-enabled universal group.

Relevant fields may include:

- Target group name (`Enterprise Admins`)
- Target group domain
- Target group SID
- Member name (account added)
- Member SID
- Subject username
- Subject domain
- Subject user SID
- Timestamp
- Source system information where available

The **subject account** identifies the account that performed the group modification, while the **member name** identifies the account that was added to Enterprise Admins.

## Detection Logic

```text
Windows Event 4756
        ↓
Wazuh base rule 60103
        ↓
Custom rule 100111
        ↓
DET-012 alert
```

The rule detects Windows universal group member additions identified by Wazuh base rule `60103`.

The rule explicitly requires:

```text
win.system.eventID = 4756
win.eventdata.targetUserName = Enterprise Admins
```

No frequency or time-based correlation is applied by DET-012 itself.

## Wazuh Rule

```xml
<rule id="100111" level="13">

    <if_sid>60103</if_sid>

    <field name="win.system.eventID">4756</field>

    <field name="win.eventdata.targetUserName">Enterprise Admins</field>

    <description>
        DET-012 Member Added to Enterprise Admins: $(win.eventdata.memberName)
    </description>

    <group>
        custom_windows,
        privilege_escalation,
        enterprise_admins,
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
| Detection ID | DET-012 |
| Wazuh Rule ID | 100111 |
| Severity | 13 |
| Parent Rule | 60103 |
| Detection Type | Member Added to Enterprise Admins |
| Windows Event | 4756 |
| MITRE Technique | T1098 |
| Category | Privilege Escalation / Account Manipulation |

---

## Simulation

A controlled privilege-elevation event was executed in the Windows Active Directory lab environment by adding a test user account to the Enterprise Admins universal group on the forest root domain controller.

```text
Forest Root Administrator / Privileged Account
        ↓
Adds member to Enterprise Admins universal group
        ↓
Windows generates Event 4756
        ↓
Wazuh base rule 60103 matches
        ↓
Custom rule 100111 matches
        ↓
DET-012 alert generated
```

## Expected Alert

The expected Wazuh alert should contain:

- **Detection:** `DET-012`
- **Rule ID:** `100111`
- **Severity:** `13`
- **Windows Event:** `4756`
- Target group name (`Enterprise Admins`)
- Member name
- Member SID
- Subject username
- Subject domain
- Timestamp

The alert description should explicitly state the member added to Enterprise Admins:

```text
DET-012 Member Added to Enterprise Admins: <memberName>
```

## Validation Result

**Status: VALIDATED**

The rule successfully detected Windows universal group modification telemetry targeting Enterprise Admins through Wazuh base rule `60103` and generated the expected critical custom detection.

The detection provides instantaneous visibility into the highest tier of Active Directory privilege assignment, allowing immediate auditing of forest-level privilege changes.

## Investigation Playbook

When a DET-012 alert is generated, the analyst must treat the alert as a critical priority, immediately verify authorization with forest administrators, and isolate the accounts involved if unauthorized.

### 1. Identify the added member account

Review:

- Member name / Target account
- Member SID
- Account creation date (check for newly provisioned accounts via **DET-007**)
- Account status (check if recently enabled via **DET-009** or password reset via **DET-008**)
- Home domain of the target account within the forest

Adding a standard, non-root domain, or recently modified account to Enterprise Admins carries catastrophic risk for the forest.

### 2. Identify who initiated the addition

Review:

- Subject username
- Subject domain (must be the forest root domain)
- Subject user SID
- Source workstation / Domain Controller IP
- Timestamp

Determine whether the performing account is an authorized Enterprise Admin or a dedicated break-glass account.

### 3. Verify administrative authorization

Check:

- Emergency change-management tickets
- Forest root Privileged Access Management (PAM) break-glass logs
- Formal architectural approval documents for forest modifications

If no active, approved ticket corresponds to this change, treat the event as an ongoing forest compromise.

### 4. Review the historical context of the added member

Audit past telemetry involving the added member account prior to group addition:

- Account creation details (Event 4720 / **DET-007**)
- Password reset actions (Event 4724 / **DET-008**)
- Additions to lower-tier groups (e.g., Domain Admins via **DET-011**)
- Source systems used for prior authentications

Determine whether the member account was staged via prior account manipulation.

### 5. Review activity performed after group elevation

Search for immediate post-escalation events initiated by the elevated member across all forest domains:

- Interactive logons to Forest Root Domain Controllers
- Schema modifications or GPO deployments at the forest root
- Cross-domain trust modifications or SID History injection
- DCSync / Directory replication requests across multiple domains
- Mass credential access or secrets dump execution

### 6. Review subject account activity surrounding the event

Audit all actions performed by the initiating subject account:

- Modifications to other universal or global groups (e.g., Schema Admins, Domain Admins)
- System access from unusual IP addresses or outside maintenance windows
- Active Directory object permission changes (ACL modifications)

### 7. Assess forest integrity

Determine whether this event represents:

- **Legitimate Forest Administration:** Authorized forest-level maintenance or break-glass access.
- **Architectural Misconfiguration:** Incorrect privilege delegation across child domains.
- **Adversarial Forest Compromise:** Persistent backdooring or privilege escalation by an adversary.

## Response Playbook

### If the activity is benign

- Validate strict alignment with authorized PAM/emergency ticket documentation.
- Ensure the account is scheduled for de-escalation if part of temporary maintenance.
- Document ticket references and administrative sign-offs in the alert notes.
- Close the alert as an authorized administrative event.

### If the activity is suspicious

- Contact the Enterprise Security Architect / SOC Lead immediately.
- Immediately remove the member from Enterprise Admins while verification takes place.
- Execute hunting queries across all forest Domain Controllers for interactive sessions established by both subject and member accounts.
- Escalate to the Incident Response Command Center.

### If compromise is suspected

- Remove the member from Enterprise Admins and immediately disable the account.
- Disable or isolate the performing subject account.
- Revoke Kerberos Ticket Granting Tickets (TGT) across the entire forest root and child domains.
- Initiate forest-wide incident response protocols and host isolation on affected endpoints/DCs.
- Inspect Schema, Trust relationships, and GPOs for secondary persistence mechanisms.
- Document all actions and initiate the Active Directory Forest Recovery Plan.

## False Positives

Common legitimate causes include:

- Forest-wide Active Directory architecture deployments or upgrades.
- Emergency break-glass procedures invoked during major disasters.
- Automated Identity Lifecycle Management (ILM) for top-tier enterprise accounts.

Because Enterprise Admins grants root control over the entire AD infrastructure, **DET-012 alerts must never be dismissed automatically, even when performed by default admin accounts**.

## Tuning Considerations

DET-012 is configured as a **critical-severity (Level 13) privilege escalation detection**.

The current rule explicitly targets universal group modifications involving Enterprise Admins:

```text
Windows Event 4756 + Enterprise Admins
        ↓
Wazuh rule 60103
        ↓
DET-012 / Rule 100111
```

Potential tuning options include:

- Expanding similar rules for other critical forest groups (e.g., `Schema Admins`, `Forest Admins`).
- Raising severity to Level 15 if the added account belongs to a child domain rather than the forest root domain.
- Raising severity to Level 15 if the added account was created within the preceding 7 days.
- Correlating group addition with DCSync activity or Schema modification within a 1-hour window.
- Suppressing alerts from dedicated, hardware-token-enforced PAM systems with pre-approved ticket integration.

Adding an account to Enterprise Admins gives full administrative access across every domain in the forest. DET-012 provides high-confidence telemetry to detect critical forest-level privilege escalation.
