# Detection 037 — Security Event Log Cleared

## Objective

Detect when the Windows Security Event Log is explicitly cleared on a host.

Clearing event logs is a classic defense evasion tactic used by threat actors to erase evidence of malicious activities, including privilege escalation, lateral movement, credential dumping, and persistence installation. By wiping log records, adversaries impede digital forensics and incident response efforts. DET-037 monitors for Windows Security Event ID 1102 (or System Event ID 104), which is generated automatically by the Windows Event Log service whenever an audit log is cleared.

## MITRE ATT&CK

**Related Techniques:**
- **T1070.004** — Indicator Removal: File Deletion / Clear Windows Event Logs

Adversaries clear Windows Event Logs to hide operational artifacts, evade log-based SIEM detection mechanisms, and disrupt post-exploitation forensics.

## Windows / Sysmon Events

**Base Rule:** `63103` — Windows Security Event Log cleared (Event ID 1102: The audit log was cleared).

Relevant fields include:

- Event ID (`win.system.eventId`): `1102` (Security log cleared) or `104` (System log cleared via Eventlog source)
- Subject User Name (`win.eventdata.subjectUserName`): Account that requested the log clear action
- Subject Domain Name (`win.eventdata.subjectDomainName`): Domain/Workgroup of the performing user
- Subject User SID (`win.eventdata.subjectUserSid`): Security Identifier of the user account executing the log wipe
- Logon ID (`win.eventdata.subjectLogonId`): Session identifier associated with the user session

## Detection Logic

```text
Windows Event Log Service
        ↓
Event ID 1102 generated (Parent Rule 63103)
        ↓
Custom rule 100136 matches
        ↓
DET-037 alert generated (Level 15 - Critical / Maximum Severity)
```

The rule triggers when Windows Security Event ID 1102 (Audit log cleared) matches parent rule `63103`.

Clearing the Security Log is an extreme action in enterprise environments; therefore, any occurrence triggers a maximum-severity alert (Level 15) requiring immediate investigation.

## Wazuh Rule

```xml
<rule id="100136" level="15">
    <if_sid>63103</if_sid>

    <description>
        DET-037 - Windows Security Event Log was cleared
    </description>

    <mitre>
        <id>T1070.004</id>
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
| Detection ID | DET-037 |
| Wazuh Rule ID | 100136 |
| Severity | 15 (Critical / Maximum Severity) |
| Parent Rule ID | 63103 (Windows Event ID 1102 - Security Log Cleared) |
| Detection Type | Windows Security Event Audit |
| Event Source | Windows Security Event Log (Event ID 1102) |
| MITRE Techniques | T1070.004 |
| Category | Defense Evasion / Indicator Removal |

---

## Simulation

A log deletion simulation was conducted in the lab using Command Prompt (`wevtutil`), PowerShell (`Clear-EventLog`), and `Event Viewer`.

```text
Attacker / Compromised Administrator Account
        ↓
Executes log wiping command:
  > wevtutil cl Security
    OR
  > Clear-EventLog -LogName Security
        ↓
Windows Event Log service generates Security Event ID 1102
        ↓
Wazuh parent rule 63103 matches
        ↓
Custom rule 100136 matches
        ↓
DET-037 critical alert generated (Level 15) identifying performing user account
```

## Expected Alert

The expected Wazuh alert contains:

- **Detection:** `DET-037`
- **Rule ID:** `100136`
- **Severity:** `15`
- Description: `DET-037 - Windows Security Event Log was cleared`
- Subject User (`win.eventdata.subjectUserName`)
- Subject Domain (`win.eventdata.subjectDomainName`)
- Logon ID (`win.eventdata.subjectLogonId`)
- Timestamp

Example Alert Description Output:

```text
DET-037 - Windows Security Event Log was cleared
```

## Validation Result

**Status: VALIDATED**

Custom rule 100136 successfully generated Level 15 alerts immediately after running `wevtutil cl Security` or clearing logs manually from `eventvwr.msc`.

## Investigation Playbook

When DET-037 triggers, SOC analysts must immediately treat the host as potentially compromised until administrative necessity is proven.

### 1. Identify Performing User Account & Session Context

- **User Verification:** Check `win.eventdata.subjectUserName` and `win.eventdata.subjectLogonId`. Was this executed by a legitimate Administrator or a service/compromised user?
- **Logon Source:** Correlate the `subjectLogonId` with prior Event ID 4624 (Successful Logon) events to pinpoint the source IP, logon type (RDP, WinRM, local console), and remote hostname.

### 2. Check Command-Line History & Parent Process

- Query Sysmon Event ID 1 (Process Creation) around the time of the event for execution of:
  - `wevtutil.exe` (with parameters `cl Security`, `cl System`, `cl Application`)
  - `powershell.exe` / `pwsh.exe` executing `Clear-EventLog` or `Remove-EventLog`
  - Third-party log wiping utilities or custom scripts

### 3. Verify IT Authorization

- Contact system administrators or consult Change Management tickets to confirm if event log clearing was part of authorized maintenance, baseline image prep, or testing.

### 4. Determine Classification

Classify the event:

- **False Positive / Benign:** Rare instances of authorized sysadmin troubleshooting, VM template cloning/generalization (`sysprep`), or automated maintenance scripts.
- **True Positive:** Adversary wiping security logs to cover tracks following unauthorized access, privilege escalation, or data exfiltration.

## Response Playbook

### If activity is confirmed malicious

- **Isolate Endpoint Immediately:** Disconnect the host from the network to prevent further lateral movement or log tampering on adjacent systems.
- **Preserve Memory & Off-Host Logs:** Perform a RAM capture of the system before rebooting. Query centralized log servers / SIEM for historic logs forwarded prior to the clearing event.
- **Revoke Privileged Credentials:** Reset passwords and revoke active sessions for the user account identified in `win.eventdata.subjectUserName`.
- **Forensic Acquisition:** Conduct deep forensic analysis of disk artifacts ($MFT, $LogFile, USN Journal, Volume Shadow Copies) to recover erased events and reconstruct attacker activity.
- **Audit Domain Admin & Local Admin Groups:** Verify if new administrative accounts or persistent access mechanisms were created prior to the log wipe.

## False Positives

Common benign sources include:

- IT administrators preparing gold master disk images (e.g., Sysprep process).
- Routine testing of SIEM forwarding and alert triggering in lab environments.

## Tuning Considerations

DET-036 operates at **Maximum Severity (Level 15)** because log clearing is rarely part of standard operational workflows.

Tuning options:

- **Maintain Level 15 Severity:** Do not lower the severity of Event ID 1102 detections. Centralized SIEM forwarding should capture the event before local log clearing occurs.
- **Exclude Dedicated Build Systems (Optional):** If specific automated provisioning systems clean logs during automated VM image builds, apply strict hostname or user SID exclusions.
- **Monitor Complementary Events:** Pair with System Log Event ID 104 (`The System log file was cleared`) and PowerShell Event ID 4104 (Script Block Logging) to detect wiping across all event channels.

Tracking event log deletions ensures defense evasion techniques are flagged immediately before threat actors can erase operational footprints across the network.
