# Detection 035 — Group Policy Modification

## Objective

Detect changes made to Active Directory Group Policy Objects (GPOs) within a Windows Domain environment.

Active Directory Group Policy Objects are used by system administrators to manage system configurations, security settings, user rights, and software deployments centrally across domain-joined systems. Threat actors who gain administrative or domain-level access frequently modify existing GPOs or deploy malicious GPOs to maintain domain-wide persistence, disable security software (such as Windows Defender or EDR agents), deploy malware (such as ransomware or backdoors) across all domain endpoints, or escalate privileges. DET-035 tracks modifications to GPO container objects in Active Directory to capture unauthorized or suspicious Active Directory policy changes.

## MITRE ATT&CK

**Related Techniques:**
- **T1484.001** — Domain Policy Modification: Group Policy Modification

Adversaries abuse Group Policy Objects to push malicious changes—such as executing scheduled tasks, modifying registry keys, creating local administrator accounts, or altering security settings—to multiple hosts simultaneously across an Active Directory domain.

## Windows / Sysmon Events

**Base Rule:** `60229` — Windows Directory Service Access / Audit Directory Service Changes (Event ID 5136: A directory service object was modified).

Relevant fields include:

- Object Class (`win.eventdata.objectClass`): `groupPolicyContainer` (filters specifically for modifications targeting Active Directory GPOs)
- Object DN (`win.eventdata.objectDN`): Distinguished Name of the GPO container being modified (e.g., `CN={31B2F340-016D-11D2-945F-00C04FB984F9},CN=Policies,CN=System,DC=domain,DC=local`)
- Subject User Name (`win.eventdata.subjectUserName`): Account that performed the GPO modification
- Subject Domain Name (`win.eventdata.subjectDomainName`): Domain associated with the performing account
- Attribute Name (`win.eventdata.attributeLDAPDisplayName`): Specific LDAP attribute modified within the GPO container (e.g., `gPCFileSysPath`, `versionNumber`)
- Attribute Value (`win.eventdata.attributeValue`): Value written to or removed from the Active Directory attribute

## Detection Logic

```text
Windows Security Event ID 5136 (Rule 60229)
        ↓
Field win.eventdata.objectClass == "groupPolicyContainer"
        ↓
Custom rule 100134 matches
        ↓
DET-035 alert generated (Level 12 - High)
```

The rule triggers when Windows Directory Service Access Event ID 5136 (Object Modified) matches parent rule `60229` AND the `objectClass` explicitly matches `groupPolicyContainer`.

Every modification to a GPO container object in Active Directory generates an alert containing the modifying user and the affected GPO's Distinguished Name.

## Wazuh Rule

```xml
<rule id="100134" level="12">
    <if_sid>60229</if_sid>

    <field name="win.eventdata.objectClass">groupPolicyContainer</field>

    <description>
        DET-035 GPO Modified - $(win.eventdata.subjectUserName) modified $(win.eventdata.objectDN)
    </description>

    <group>
        custom_detection_engineering,
        custom_windows,
        persistence,
        gpo_modification,
        attack.t1484.001
    </group>

    <mitre>
        <id>T1484.001</id>
    </mitre>
</rule>
```

### Rule Details

| Field | Value |
|---|---|
| Detection ID | DET-035 |
| Wazuh Rule ID | 100134 |
| Severity | 12 (High) |
| Parent Rule ID | 60229 (Windows Event ID 5136 - Directory Service Object Modified) |
| Detection Type | Group Policy Object Modification |
| Event Source | Domain Controller Security Log (Event ID 5136) |
| Target Object | Active Directory `groupPolicyContainer` Objects |
| MITRE Techniques | T1484.001 |
| Category | Persistence / Defense Evasion / Domain Policy Modification |

---

## Simulation

A GPO modification simulation was performed in the laboratory environment on a Windows Domain Controller using the Group Policy Management Console (`gpmc.msc`) and PowerShell (`Set-GPRegistryValue`).

```text
Attacker / Compromised Domain Admin Account
        ↓
Modifies existing GPO via GPMC or PowerShell:
  > Set-GPRegistryValue -Name "Default Domain Policy" -Key "HKLM\Software\Policies\Microsoft\Windows Defender" -ValueName "DisableAntiSpyware" -Type DWord -Value 1
        ↓
Domain Controller processes LDAP modification targeting groupPolicyContainer in Active Directory
        ↓
Windows Security Log records Event ID 5136 with objectClass "groupPolicyContainer"
        ↓
Wazuh parent rule 60229 matches
        ↓
Custom rule 100134 matches
        ↓
DET-035 high-severity alert generated (Level 12) showing user and GPO objectDN
```

## Expected Alert

The expected Wazuh alert contains:

- **Detection:** `DET-035`
- **Rule ID:** `100134`
- **Severity:** `12`
- Description: `DET-035 GPO Modified - <USER> modified <OBJECT_DN>`
- Subject User (`win.eventdata.subjectUserName`)
- Object DN (`win.eventdata.objectDN`)
- Object Class (`groupPolicyContainer`)
- Timestamp

Example Alert Description Output:

```text
DET-035 GPO Modified - admin_sec modified CN={31B2F340-016D-11D2-945F-00C04FB984F9},CN=Policies,CN=System,DC=lab,DC=local
```

## Validation Result

**Status: VALIDATED**

Custom rule 100134 successfully generated Level 12 high-severity alerts whenever a Group Policy Object container was modified via `gpmc.msc`, PowerShell ActiveDirectory/GroupPolicy modules, or direct LDAP manipulation tools.

## Investigation Playbook

When DET-035 triggers, SOC analysts must verify whether the GPO modification was part of an approved Change Management request or indicates rogue administrative activity.

### 1. Identify the Modified GPO & Performing User

- **User Context:** Identify `win.eventdata.subjectUserName`. Was this modification executed by an authorized SysAdmin, a service account, or an unfamiliar/compromised user?
- **GPO Identification:** Map the GUID in `win.eventdata.objectDN` (e.g., `{31B2F340-...}`) to the friendly GPO display name using PowerShell:
  ```powershell
  Get-GPO -Guid "31B2F340-016D-11D2-945F-00C04FB984F9"
  ```

### 2. Inspect Changes in SYSVOL / Group Policy Report

- **SYSVOL File Verification:** Navigate to `\\<Domain>\SYSVOL\<Domain>\Policies\{GUID}\` to inspect modified `gpt.ini` files, scheduled task XML definitions, or registry files (`registry.pol`).
- **GPO Audit Log Check:** Use Group Policy Management (`gpmc.msc`) or PowerShell (`Get-GPOReport`) to generate an HTML report of the GPO configuration and review recently modified policy settings.

### 3. Verify Change Management Authorization

- Check internal IT ticketing systems (ServiceNow, Jira) for approved change tickets authorizing GPO updates at the recorded timestamp.

### 4. Determine Classification

Classify the event:

- **False Positive / Benign:** Authorized domain policy update by system administrators under a valid IT change ticket.
- **True Positive:** Unauthorized or unannounced GPO modification intended to weaken endpoint security, deploy unauthorized software, schedule persistent commands, or grant elevated rights.

## Response Playbook

### If activity is confirmed malicious

- **Revert / Restore GPO:** Immediately restore the affected GPO from a known-good backup or backup set using `Restore-GPO` or GPMC.
- **Revoke Admin Account Access:** Disable or reset credentials for the account identified in `win.eventdata.subjectUserName`.
- **Force GPO Update Across Domain:** Force endpoints to re-apply healthy policy configurations to purge malicious settings:
  ```cmd
  gpupdate /force
  ```
- **Inspect Endpoints for Artifacts:** Query SIEM logs for endpoints that recently fetched the malicious GPO version to remediate any deployed payloads or registry modifications.
- **Audit Domain Admin Accounts:** Conduct an emergency audit of Active Directory privileged groups (Domain Admins, Enterprise Admins, Schema Admins) for rogue account additions.

## False Positives

Common benign sources include:

- Scheduled or routine Active Directory domain administrative maintenance.
- Automated security compliance tools or GPO backup/sync operations modifying GPO version numbers or attributes.

## Tuning Considerations

DET-035 operates at **High Severity (Level 12)** due to the massive blast radius of unauthorized Active Directory GPO modifications across an enterprise domain.

Tuning options:

- **Correlate with SYSVOL Audit Logs:** Combine Active Directory object modification logs (Event 5136) with File Integrity Monitoring (FIM) on `SYSVOL` policy directories to get full visibility into exact policy setting changes.
- **Filter Whitelisted Admin Accounts (Optional):** If dedicated automated identity/policy deployment tools run routinely, introduce strict exclusion conditions matching those specific service account SID/User pairs.
- **Monitor GPO Link/Unlink Events:** Pair DET-035 with events monitoring GPO links (`Event ID 5137` / `5141`) to detect attackers linking malicious GPOs to Organizational Units (OUs).

Monitoring GPO modifications is essential to defending Active Directory infrastructure against domain-wide persistence and policy tampering.
