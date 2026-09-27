# Detection 039 — Windows Defender Tampering

## Objective

Detect when Windows Defender Real-Time Protection features, features components, or configuration settings are disabled, modified, or tampered with on an endpoint.

Threat actors routinely attempt to disable or bypass host-based antivirus and EDR solutions prior to dropping payloads, executing credential dumps, or performing lateral movement. Windows Defender logs operational changes to its dedicated Operational event log (`Microsoft-Windows-Windows Defender/Operational`). DET-039 monitors specific Defender Event IDs indicating that core protection features—such as Real-Time Protection, Antivirus Engine features, or policy configurations—have been altered or turned off.

## MITRE ATT&CK

**Related Techniques:**
- **T1562.001** — Impair Defenses: Disable or Modify Tools

Adversaries disable or tamper with security software like Windows Defender using PowerShell (`Set-MpPreference`), Group Policy, Registry modifications (`DisableAntiSpyware`, `DisableRealtimeMonitoring`), or command-line utilities to avoid detection.

## Windows / Sysmon Events

**Base Rule:** `62100` — Windows Defender Operational Log Event.

Relevant fields and trigger conditions include:

- Event ID (`win.system.eventID`): `5001`, `5007`, or `5013`
  - **Event ID 5001:** Real-Time Protection feature disabled.
  - **Event ID 5007:** Configuration modified (e.g., exclusions added, protection features altered).
  - **Event ID 5013:** Defender engine status modified or stopped.
- User / Account Name (`win.eventdata.user` / `win.eventdata.subjectUserName`): Identity that modified Defender settings.
- Parameter / Setting Name (`win.eventdata.oldValue` / `win.eventdata.newValue`): Details of altered registry key, GPO, or PowerShell preference setting.

## Detection Logic

```text
Windows Defender Operational Log (Microsoft-Windows-Windows Defender/Operational)
        ↓
Event ID matches Regex: ^(5001|5007|5013)$ (Parent Rule 62100)
        ↓
Custom rule 100138 matches
        ↓
DET-039 alert generated (Level 13 - High Severity)
```

The rule triggers when Windows Defender Operational log events match parent rule `62100` AND `win.system.eventID` explicitly matches Event IDs `5001`, `5007`, or `5013`.

Any tampering attempt—whether disabling real-time monitoring, altering operational parameters, or disabling protection features—generates a Level 13 alert.

## Wazuh Rule

```xml
<rule id="100138" level="13">
    <if_sid>62100</if_sid>

    <field name="win.system.eventID" type="pcre2">^(5001|5007|5013)$</field>

    <description>
        DET-039 - Windows Defender protection tampering detected
    </description>

    <group>
        windows,
        defense_evasion,
        attack,
        custom_detection_engineering,
        custom_detection
    </group>

    <mitre>
        <id>T1562.001</id>
    </mitre>
</rule>
```

### Rule Details

| Field | Value |
|---|---|
| Detection ID | DET-039 |
| Wazuh Rule ID | 100138 |
| Severity | 13 (High Severity) |
| Parent Rule ID | 62100 (Windows Defender Log Event) |
| Detection Type | Windows Security & AV Operational Audit |
| Event Source | `Microsoft-Windows-Windows Defender/Operational` |
| Targeted Event IDs | 5001, 5007, 5013 |
| MITRE Techniques | T1562.001 |
| Category | Defense Evasion / Impair Defenses |

---

## Simulation

A Windows Defender tampering simulation was conducted in the lab using PowerShell (`Set-MpPreference`).

```text
Attacker / Compromised Privileged Account
        ↓
Executes command to disable Real-Time Protection or add exclusions:
  > Set-MpPreference -DisableRealtimeMonitoring $true
    OR
  > Set-MpPreference -ExclusionPath "C:\Windows\Temp"
        ↓
Windows Defender logs Event ID 5001 or 5007 in Defender Operational Log
        ↓
Wazuh parent rule 62100 matches
        ↓
Custom rule 100138 matches
        ↓
DET-039 high-severity alert generated (Level 13)
```

## Expected Alert

The expected Wazuh alert contains:

- **Detection:** `DET-039`
- **Rule ID:** `100138`
- **Severity:** `13`
- Description: `DET-039 - Windows Defender protection tampering detected`
- Event ID (`win.system.eventID`)
- User / Account (`win.eventdata.user`)
- Modified Setting Details (`win.eventdata.newValue` / `win.eventdata.oldValue`)
- Timestamp

Example Alert Description Output:

```text
DET-039 - Windows Defender protection tampering detected
```

## Validation Result

**Status: VALIDATED**

Custom rule 100138 successfully generated Level 13 alerts immediately upon execution of `Set-MpPreference -DisableRealtimeMonitoring $true` or when adding paths to Defender exclusion lists.

## Investigation Playbook

When DET-037 / DET-039 triggers, SOC analysts must verify whether Defender protection was intentionally turned off by an adversary preparing to drop payloads.

### 1. Analyze Event Details & Specific Event ID

- **Event ID 5001:** Real-Time Monitoring was disabled completely. Treat as critical.
- **Event ID 5007:** Configuration changed. Check details to see if an exclusion path/extension was added (e.g., excluding `C:\Users\Public` or `.exe` files).
- **Event ID 5013:** Protection engine features failed or stopped.

### 2. Identify Modifying Process & Execution Context

- **User & Process Lineage:** Identify the user who modified the settings. Correlate with Sysmon Event ID 1 (Process Creation) to inspect command-line arguments (e.g., `powershell.exe Set-MpPreference`, `reg.exe add HKLM\...\Defender`).

### 3. Verify IT / Security Approval

- Check if the modification was performed by authorized IT support during software troubleshooting or automated deployment.

### 4. Determine Classification

Classify the event:

- **False Positive / Benign:** Authorized security policy changes or legitimate administrative troubleshooting.
- **True Positive:** Malicious disabling of Defender components or addition of exclusion paths to facilitate undetected malware execution.

## Response Playbook

### If activity is confirmed malicious

- **Re-enable Windows Defender Immediately:** Force re-enable Real-Time Protection and flush malicious exclusions via PowerShell:
  ```powershell
  Set-MpPreference -DisableRealtimeMonitoring $false
  Remove-MpPreference -ExclusionPath "C:\Windows\Temp"
  ```
- **Isolate Endpoint:** Network isolate the machine to contain potential payload delivery.
- **Run Full Defender Scan:** Trigger an immediate offline / full system scan:
  ```powershell
  Start-MpScan -ScanType FullScan
  ```
- **Revoke Admin Account Access:** Reset passwords and revoke active sessions for the account that modified Defender parameters.
- **Enable Tamper Protection:** Ensure Windows Defender **Tamper Protection** is globally enforced via Microsoft Defender Portal or GPO to prevent local administrators from disabling protection settings.

## False Positives

Common benign sources include:

- System administrators temporarily adding exclusions for software build directories or specialized enterprise applications.
- Security baseline management tools deploying updated policy templates.

## Tuning Considerations

DET-039 operates at **High Severity (Level 13)** due to the severe threat posed by disabling host antivirus defenses.

Tuning options:

- **Enforce Tamper Protection:** Enabling Windows Defender Tamper Protection natively blocks local administrative overrides, reducing the incidence of Event ID 5001/5007.
- **Monitor Exclusion Additions specifically:** Build focused rules specifically tracking Event ID 5007 for path/process exclusions, as threat actors routinely add `C:\` or `%TEMP%` exclusions.

Maintaining strict monitoring on antivirus integrity stops defense evasion before adversaries deploy post-exploitation payloads.
