# Detection 038 — Windows Audit Policy Modification

## Objective

Detect unauthorized modifications to Windows Audit Policies on domain endpoints or servers.

Windows Audit Policies define what security-relevant events—such as logon attempts, object access, privilege usage, process tracking, and policy changes—are logged by the operating system. Threat actors who obtain administrative privileges frequently alter or disable audit subcategories (e.g., turning off auditing for Process Creation or Account Logon) to blind security monitoring systems, evade SIEM detection, and obscure post-exploitation activities. DET-038 monitors Windows Event ID 4719 to capture changes made to subcategory audit policies.

## MITRE ATT&CK

**Related Techniques:**
- **T1562.002** — Impair Defenses: Disable Windows Event Logging

Adversaries modify Windows Audit Policy configurations using tools like `auditpol.exe` or Group Policy to disable event generation for specific subcategories, suppressing critical security telemetry.

## Windows / Sysmon Events

**Base Rule:** `60112` — Windows Audit Policy Changed (Event ID 4719: System audit policy was changed).

Relevant fields include:

- Subject User Name (`win.eventdata.subjectUserName`): Account that modified the audit policy
- Subject Domain Name (`win.eventdata.subjectDomainName`): Domain/Workgroup of the performing account
- Category (`win.eventdata.category`): Top-level audit policy category modified (e.g., Detailed Tracking, Logon/Logoff, Account Management)
- Subcategory (`win.eventdata.subcategory`): Specific subcategory modified (e.g., Process Creation, User Account Management)
- Audit Policy Changes (`win.eventdata.auditPolicyChanges`): Nature of change (e.g., `Success removed`, `Failure removed`, `No Auditing`)

## Detection Logic

```text
Windows Security Log
        ↓
Event ID 4719 (Parent Rule 60112)
        ↓
Custom rule 100137 matches
        ↓
DET-038 alert generated (Level 13 - High Severity)
```

The rule triggers when Windows Security Event ID 4719 (System audit policy was changed) matches parent parent rule `60112`.

Any modification to audit policies—especially removal of success or failure auditing—generates an alert containing the modifying user, affected category/subcategory, and the policy change description.

## Wazuh Rule

```xml
<rule id="100137" level="13">
    <if_sid>60112</if_sid>

    <description>
        DET-038 - $(win.eventdata.subjectUserName) modified Windows Audit Policy: $(win.eventdata.category) / $(win.eventdata.subcategory) ($(win.eventdata.auditPolicyChanges))
    </description>

    <mitre>
        <id>T1562.002</id>
    </mitre>

    <group>
        windows,
        defense_evasion,
        attack,
        custom_detection,
    </group>
</rule>
```

### Rule Details

| Field | Value |
|---|---|
| Detection ID | DET-038 |
| Wazuh Rule ID | 100137 |
| Severity | 13 (High Severity) |
| Parent Rule ID | 60112 (Windows Event ID 4719 - System Audit Policy Changed) |
| Detection Type | Windows Security Policy Audit |
| Event Source | Windows Security Log (Event ID 4719) |
| MITRE Techniques | T1562.002 |
| Category | Defense Evasion / Impair Defenses |

---

## Simulation

An audit policy modification simulation was executed in the laboratory environment using `auditpol.exe` and Group Policy (`secpol.msc`).

```text
Attacker / Compromised Admin User
        ↓
Executes command to disable auditing for process tracking or logon events:
  > auditpol /set /subcategory:"Process Creation" /success:disable /failure:disable
    OR
  > auditpol /clear
        ↓
Windows Security Log records Event ID 4719 detailing the modified subcategory and removed audit flags
        ↓
Wazuh parent rule 60112 matches
        ↓
Custom rule 100137 matches
        ↓
DET-038 high-severity alert generated (Level 13)
```

## Expected Alert

The expected Wazuh alert contains:

- **Detection:** `DET-038`
- **Rule ID:** `100137`
- **Severity:** `13`
- Description: `DET-038 - <USER> modified Windows Audit Policy: <CATEGORY> / <SUBCATEGORY> (<CHANGES>)`
- Subject User (`win.eventdata.subjectUserName`)
- Category (`win.eventdata.category`)
- Subcategory (`win.eventdata.subcategory`)
- Audit Policy Changes (`win.eventdata.auditPolicyChanges`)
- Timestamp

Example Alert Description Output:

```text
DET-038 - admin_sec modified Windows Audit Policy: Detailed Tracking / Process Creation (Success removed)
```

## Validation Result

**Status: VALIDATED**

Custom rule 100137 successfully generated Level 13 alerts whenever audit policy settings were altered or disabled via `auditpol.exe`, PowerShell, or Group Policy propagation.

## Investigation Playbook

When DET-038 triggers, SOC analysts must evaluate whether audit settings were reduced to evade detection or updated as part of valid baseline configuration changes.

### 1. Evaluate Audit Policy Changes

- **Direction of Change:** Was auditing enabled/added (`Success added`, `Failure added`) or disabled/removed (`Success removed`, `Failure removed`, `No Auditing`)? Disabling logging is indicative of malicious intent.
- **Affected Subcategory:** High-risk subcategories include `Process Creation`, `Credential Validation`, `User Account Management`, `Directory Service Access`, and `Logon`.

### 2. Identify the Performing Account & Execution Context

- **User Context:** Inspect `win.eventdata.subjectUserName`. Was the change initiated by a domain administrator, a local admin, or a service account?
- **Process Lineage:** Correlate with Sysmon Event ID 1 (Process Creation) around the timestamp to check for `auditpol.exe` execution, command-line arguments, and parent processes.

### 3. Cross-Reference Change Tickets

- Verify if system administrators were pushing new audit configurations via Group Policy Objects (GPO) or security baseline scripts during scheduled maintenance.

### 4. Determine Classification

Classify the event:

- **False Positive / Benign:** Authorized deployment of enterprise audit configuration baselines via GPO, SCCM, or security hardening scripts.
- **True Positive:** Unauthorized suppression of audit policies designed to blind endpoint monitoring and security monitoring.

## Response Playbook

### If activity is confirmed malicious

- **Re-enable Audit Policies:** Re-apply the organization's required audit baseline immediately:
  ```cmd
  auditpol /set /category:"Detailed Tracking" /Success:enable /Failure:enable
  gpupdate /force
  ```
- **Isolate Endpoint:** Network isolate the system to stop active post-exploitation work.
- **Revoke Admin Credentials:** Reset passwords and terminate active sessions for the account identified in `win.eventdata.subjectUserName`.
- **Audit Recent Host Activity:** Inspect SIEM logs prior to policy suppression to identify actions taken right before audit disabling.
- **Inspect GPO & Security Templates:** Ensure domain-level Group Policy Objects for auditing have not been tampered with.

## False Positives

Common benign sources include:

- Domain Controllers or endpoints applying updated GPO Audit Policies.
- Automated system hardening scripts or compliance enforcement tools.

## Tuning Considerations

DET-038 operates at **High Severity (Level 13)** due to the risk of logging blindspots created by audit policy manipulation.

Tuning options:

- **Filter Enabling Events (Optional):** If security teams frequently roll out expanded auditing, create a child rule with lower severity for changes where policy settings are *enabled* rather than *removed*.
- **Alert Escalation for Disabling Events:** Maintain Level 13+ alerts specifically when `auditPolicyChanges` contains `removed` or `No Auditing`.
- **Correlate with GPO Updates:** Pair with DET-035 (Group Policy Modification) to capture domain-wide audit policy tampering at the source.

Continuous monitoring of audit policy modifications ensures defender visibility remains uncompromised across enterprise systems.
