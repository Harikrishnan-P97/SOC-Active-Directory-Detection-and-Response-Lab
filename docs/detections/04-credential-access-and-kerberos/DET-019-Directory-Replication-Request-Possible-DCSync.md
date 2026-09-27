# Detection 019 — Directory Replication Request (Possible DCSync)

## Objective

Detect directory replication requests initiated against Active Directory domain controllers to identify potential DCSync attacks.

DCSync is a critical credential harvesting technique where an attacker impersonates a Domain Controller (DC) using Directory Replication Services (DRS) Remote Protocol RPC calls (such as `DSGetNCChanges`). By requesting replication services, an attacker with high-privilege permissions (e.g., Domain Admins, Enterprise Admins, or accounts granted explicit `Replicating Directory Changes` extended rights) can extract domain password hashes—including the `krbtgt` account hash—without executing code directly on a Domain Controller.

DET-019 monitors Directory Service Access events for specific access mask patterns (`0x100` / Control Access) matching Directory Replication operations, triggering a critical alert when replication is requested by accounts or endpoints.

## MITRE ATT&CK

**Related Sub-technique:** T1003.006 — OS Credential Dumping: DCSync

Adversaries may simulate the behavior of a Domain Controller to request Active Directory data, including domain password hashes, using the Directory Replication Service (DRS) Remote Protocol. This allows adversaries to harvest credential material domain-wide without triggering traditional host-based memory dumping detections on DCs.

DET-019 alerts on Directory Service access operations that request Control Access permissions necessary to initiate replication.

## Windows Events

**Event ID:** `4662` — An operation was performed on an object.

Relevant fields include:

- Object Server (`win.eventdata.objectServer`)
- Object Type (`win.eventdata.objectType`)
- Object Name (`win.eventdata.objectName`)
- Access Mask (`win.eventdata.accessMask`): `0x100` (Control Access / Extended Right)
- Properties / Extended Rights GUIDs (`win.eventdata.properties`):
  - `1131f6aa-9c0e-11d1-f79f-00c04fc2dcd2` (`DS-Replication-Get-Changes`)
  - `1131f6ad-9c0e-11d1-f79f-00c04fc2dcd2` (`DS-Replication-Get-Changes-All`)
  - `89e86c8a-011d-11d1-e9ef-0000f87579da` (`DS-Replication-Get-Changes-In-Filtered-Set`)
- Subject Security ID (`win.eventdata.subjectUserSid`)
- Subject Account Name (`win.eventdata.subjectUserName`)
- Subject Domain Name (`win.eventdata.subjectDomainName`)
- Domain Controller Name
- Timestamp

The **subjectUserName** identifies the identity requesting directory object operations, while **accessMask = 0x100** indicates Extended Rights execution.

## Detection Logic

```text
Windows Event 4662
        ↓
Wazuh base rule 60103
        ↓
Custom rule 100118 (accessMask == 0x100)
        ↓
DET-019 alert (Level 15)
```

The rule triggers on object access events processed under Wazuh base rule `60103`.

The rule explicitly matches:

```text
win.system.eventID = 4662
win.eventdata.accessMask = 0x100
```

By filtering for Event 4662 with Access Mask `0x100`, custom rule 100118 captures attempts to execute Extended Rights against Directory Service objects at maximum severity (Level 15).

## Wazuh Rule

```xml
<rule id="100118" level="15">

    <if_sid>60103</if_sid>

    <field name="win.system.eventID">4662</field>

    <field name="win.eventdata.accessMask">0x100</field>

    <description>
        DET-019 Directory Replication Request (Possible DCSync)
    </description>

    <group>
        custom_windows,
        credential_access,
        active_directory,
        dcsync,
        attack.t1003.006,
    </group>

    <mitre>
        <id>T1003.006</id>
    </mitre>

</rule>
```

### Rule Details

| Field | Value |
|---|---|
| Detection ID | DET-019 |
| Wazuh Rule ID | 100118 |
| Severity | 15 (Critical) |
| Parent Rule | 60103 |
| Detection Type | Possible DCSync Attack |
| Windows Event | 4662 |
| Access Mask | `0x100` |
| MITRE Technique | T1003.006 |
| Category | Credential Access / Active Directory |

---

## Simulation

A controlled DCSync simulation was performed in the test environment using Mimikatz (`lsadump::dcsync`) or Impacket (`secretsdump.py`).

```text
Attacker Host / Workstation
        ↓
Executes mimikatz "lsadump::dcsync /domain:lab.local /user:krbtgt"
        ↓
Sends RPC DRSGetNCChanges request to Domain Controller
        ↓
Domain Controller logs Windows Event 4662 with accessMask 0x100
        ↓
Wazuh base rule 60103 matches
        ↓
Custom rule 100118 matches
        ↓
DET-019 alert generated (Level 15 Critical)
```

## Expected Alert

The expected Wazuh alert contains:

- **Detection:** `DET-019`
- **Rule ID:** `100118`
- **Severity:** `15`
- **Windows Event:** `4662`
- Access Mask (`0x100`)
- Subject Account Name (`subjectUserName`)
- Subject Domain Name (`subjectDomainName`)
- Properties / GUIDs (`properties`)
- Domain Controller name
- Timestamp

The alert description explicitly reports:

```text
DET-019 Directory Replication Request (Possible DCSync)
```

## Validation Result

**Status: VALIDATED**

The rule successfully identified Windows Event 4662 with `accessMask = 0x100` via base rule `60103` and generated critical custom alert 100118 at severity level 15.

The detection effectively flags potential DCSync activity across domain controllers for analyst triage.

## Investigation Playbook

When DET-019 fires at Level 15, SOC analysts must immediately prioritize the alert to verify whether the replication request originated from a legitimate Domain Controller or an unauthorized machine/user.

### 1. Analyze performing identity and machine computer account

Review:

- **Subject Account Name:** (`win.eventdata.subjectUserName`) — Is the initiating account a recognized computer account belonging to an active Domain Controller (ends with `$`)?
- Standard Active Directory replication only occurs between legitimate Domain Controllers (e.g., `DC01$`, `DC02$`).
- Requests originating from user accounts or non-DC machine accounts (e.g., `WORKSTATION01$`, `AdminUser`) are **high-probability DCSync attacks**.

### 2. Inspect GUID properties in the event

Check `win.eventdata.properties` for DRS Replication Extended Rights GUIDs:

- `1131f6aa-9c0e-11d1-f79f-00c04fc2dcd2` (`DS-Replication-Get-Changes`)
- `1131f6ad-9c0e-11d1-f79f-00c04fc2dcd2` (`DS-Replication-Get-Changes-All`)
- `89e86c8a-011d-11d1-e9ef-0000f87579da` (`DS-Replication-Get-Changes-In-Filtered-Set`)

Presence of these GUIDs combined with a non-DC subject identity confirms DCSync replication behavior.

### 3. Review network RPC / SMB connection logs

Inspect network telemetry surrounding the event time:

- Identify the source IP address establishing RPC calls over port `135` (RPC Endpoint Mapper) and dynamic RPC ports to the Domain Controller.
- Verify if the source IP matches a known DC IP address.

### 4. Review host-level execution telemetry (If source host is monitored)

If the request originated from an internal workstation/server:

- Search process creation logs (Sysmon 1 / Event 4688) for `mimikatz.exe`, `python.exe` (`secretsdump.py`), `rcat.exe`, or custom C# tools executing in memory.

### 5. Determine classification

Classify the event:

- **Legitimate DC-to-DC Replication:** Scheduled domain synchronization between authorized Domain Controllers.
- **Authorized Azure AD Connect / Backup Sync:** Approved Directory Sync service accounts (e.g., AAD Connect account) performing replication tasks.
- **Malicious DCSync Attack:** Unauthorized user or system requesting replication changes to dump NTLM hashes or `krbtgt` credentials.

## Response Playbook

### If the activity is benign / legitimate replication

- Verify that the subject account belongs to an authorized DC or approved Azure AD Connect sync service account.
- Tune detection rules to exclude known DC machine accounts if necessary.
- Document ticket reference and close alert.

### If DCSync Attack / Adversarial activity is confirmed

- **Immediately Isolate Source Endpoint:** Sever network access for the source IP originating the DCSync request.
- **Disable Compromised Account:** Disable the user or machine account (`subjectUserName`) used to request replication.
- **Reset KRBTGT Password Twice:** If there is any possibility the `krbtgt` account hash was requested, initiate a double reset of the domain `krbtgt` password following Microsoft best practices to invalidate all active Kerberos TGTs (Golden Tickets).
- **Reset Domain Administrator Passwords:** Force password resets for all Tier-0 administrative accounts.
- **Audit Directory Replication ACLs:** Review Active Directory Root ACLs for unauthorized accounts granted `Replicating Directory Changes` rights:
  ```powershell
  Get-Acl "AD:\DC=domain,DC=local" | Select-Object -ExpandProperty Access
  ```
- **Initiate Emergency Incident Response:** Declare a high-severity incident, audit domain trust relationships, and inspect for persistent backdoors.

## False Positives

Common benign causes include:

- Inter-DC Directory Replication operations between legitimate Domain Controllers.
- Azure AD Connect (Entra Connect) synchronization services configured with replication rights.
- Third-party Active Directory backup software executing domain snapshots.

## Tuning Considerations

DET-018 operates at **critical severity (Level 15)**.

To reduce noise while preserving high-fidelity alerts:

- **Filter Legitimate DC Machine Accounts:** Append match conditions to exclude known Domain Controller computer accounts (e.g., matching SID patterns or known DC group memberships).
- **Filter Azure AD Connect Accounts:** If Azure AD Connect is active, explicitly filter its designated service account SID while monitoring for unauthorized permission changes to that account.
- **Require Specific Replication GUIDs:** Create a child rule requiring both `accessMask = 0x100` AND one of the replication GUIDs (`1131f6aa-...` or `1131f6ad-...`) in `win.eventdata.properties` to ensure maximum detection precision.

DCSync monitoring is an essential defensive control that prevents covert domain-wide credential harvesting.
