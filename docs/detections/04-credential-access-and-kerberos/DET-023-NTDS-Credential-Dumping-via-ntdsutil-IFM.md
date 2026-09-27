# Detection 023 — NTDS.dit Credential Dumping via ntdsutil IFM

## Objective

Detect execution of `ntdsutil.exe` using Install From Media (IFM) functionality, identifying potential Active Directory database (`ntds.dit`) extraction and credential dumping attempts.

The `ntds.dit` file on Windows Domain Controllers stores all Active Directory objects, including user accounts, group memberships, and password hashes (NTLM hashes and Kerberos keys). The legitimate Windows command-line tool `ntdsutil.exe` includes an Install From Media (`ifm`) feature designed to create backup snapshots of Active Directory for promotional deployment elsewhere. However, adversaries who obtain administrative privileges on a Domain Controller frequently abuse `ntdsutil.exe` with `ifm` commands (e.g., `create full c:\dump`) to dump the entire `ntds.dit` database along with the `SYSTEM` registry hive to extract all domain password hashes offline.

DET-023 monitors process creation events (specifically Sysmon Event ID 1 / Windows Event ID 4688 under parent rule 61603) for executions of `ntdsutil.exe` containing the `ifm` parameter.

## MITRE ATT&CK

**Related Sub-technique:** T1003.003 — OS Credential Dumping: NTDS

Adversaries may attempt to dump the Active Directory database (`ntds.dit`) to steal domain credentials.

DET-023 monitors `ntdsutil.exe` execution leveraging the `ifm` switch to identify offline domain database extractions.

## Windows / Sysmon Events

**Base Rule:** `61603` — Process Creation Event (Sysmon Event ID 1 / Windows Security Event ID 4688).

Relevant fields include:

- Original File Name (`win.eventdata.originalFileName`): `ntdsutil.exe`
- Executable Path (`win.eventdata.image`): Path of the binary executed
- Command Line (`win.eventdata.commandLine`): Execution flags containing `ifm`
- User (`win.eventdata.user`): Account executing the binary
- Parent Process (`win.eventdata.parentImage`): Parent process invoking `ntdsutil.exe`
- Process ID (`win.eventdata.processId`)

The `originalFileName` check ensures detection even if `ntdsutil.exe` is renamed by an attacker to bypass basic path-based filters.

## Detection Logic

```text
Process Creation Event (Rule 61603 / Sysmon Event 1)
        ↓
Check originalFileName (ntdsutil.exe)
        ↓
Check commandLine contains word boundary \bifm\b (case-insensitive)
        ↓
Custom rule 100122 matches
        ↓
DET-023 alert generated (Level 15 - Critical)
```

The rule evaluates process creation logs under parent rule `61603`.

The rule explicitly checks:

```text
win.eventdata.originalFileName matches ^ntdsutil\.exe$ (case-insensitive)
AND
win.eventdata.commandLine contains \bifm\b (case-insensitive)
```

By detecting the combination of `ntdsutil.exe` and the `ifm` parameter, custom rule 100122 catches unauthorized Active Directory database dumping attempts before offline hash extraction can take place.

## Wazuh Rule

```xml
<rule id="100122" level="15">
    <if_sid>61603</if_sid>

    <field name="win.eventdata.originalFileName" type="pcre2">(?i)^ntdsutil\.exe$</field>

    <field name="win.eventdata.commandLine" type="pcre2">(?i)\bifm\b</field>

    <description>
        DET-023 - Possible NTDS credential dumping via ntdsutil IFM: $(win.eventdata.image) executed with command $(win.eventdata.commandLine) by $(win.eventdata.user)
    </description>

    <mitre>
        <id>T1003.003</id>
    </mitre>

    <group>
        custom_detection_engineering,
        windows,
        credential_access,
        credential_dumping,
        ntds,
        attack.t1003.003
    </group>
</rule>
```

### Rule Details

| Field | Value |
|---|---|
| Detection ID | DET-023 |
| Wazuh Rule ID | 100122 |
| Severity | 15 (Critical) |
| Parent Rule ID | 61603 (Process Creation) |
| Detection Type | NTDS Database Dumping |
| Event Source | Sysmon Event ID 1 / Windows Security 4688 |
| Target Binary | `ntdsutil.exe` |
| Key Argument | `ifm` |
| MITRE Technique | T1003.003 |
| Category | Credential Access / NTDS |

---

## Simulation

An NTDS credential dumping attack was simulated in a domain environment.

```text
Attacker Host / Compromised Domain Controller
        ↓
Executes command: ntdsutil "ac i ntds" "ifm" "create full C:\Windows\Temp\NTDS" q q
        ↓
Windows/Sysmon generates Process Creation Event (Event ID 1 / 4688)
        ↓
Wazuh parent rule 61603 triggers
        ↓
Custom rule 100122 verifies originalFileName = ntdsutil.exe and commandLine matches \bifm\b
        ↓
DET-023 critical alert generated (Level 15)
```

## Expected Alert

The expected Wazuh alert contains:

- **Detection:** `DET-023`
- **Rule ID:** `100122`
- **Severity:** `15`
- Process Image (`win.eventdata.image`)
- Command Line (`win.eventdata.commandLine`)
- User (`win.eventdata.user`)
- Original File Name (`win.eventdata.originalFileName`)
- Timestamp

The alert description explicitly reports:

```text
DET-023 - Possible NTDS credential dumping via ntdsutil IFM: <image> executed with command <commandLine> by <user>
```

## Validation Result

**Status: VALIDATED**

Custom rule 100122 successfully intercepted process execution logs matching `ntdsutil.exe` running with the `ifm` switch, immediately escalating to a Critical Severity 15 alert.

## Investigation Playbook

When DET-023 triggers, immediate action is required as full domain compromise may be imminent.

### 1. Verify Execution Context & User Account

Review:

- **User:** (`win.eventdata.user`) — Did a standard Domain Admin execute this as part of a scheduled Active Directory deployment/maintenance, or was it an unfamiliar or compromised administrative account?
- **Host Location:** Was this command executed directly on a primary Domain Controller (DC) or an RODC (Read-Only Domain Controller)?

### 2. Inspect Target Output Directory

Analyze the `commandLine` argument:

- Determine where the dump files were saved (e.g., `create full C:\PerfLogs\`, `C:\Temp\`, `C:\Users\Public\`).
- Check if the output directory is hidden, temporary, or suspicious.

### 3. Check for Exfiltration Artifacts

Search for concurrent network activity:

- Look for large file transfers, web shell activity, or archiving operations (`7z.exe`, `rar.exe`, `zip`) involving the target dump folder.
- Check SMB, staging folders, or cloud storage connections.

### 4. Correlate Shadow Copy & Registry Access Activity

`ntdsutil` IFM automatically extracts the `SYSTEM` hive alongside `ntds.dit`:

- Search for Volume Shadow Copy creation logs (`vssadmin`, `WMI`, `powershell Get-WmiObject Win32_ShadowCopy`).
- Check registry export events (`reg save HKLM\SYSTEM`).

### 5. Determine Classification

Classify the event:

- **False Positive:** Authorized Domain Administrator preparing media for promoting a new Domain Controller via legitimate IFM process (should be pre-announced via Change Management).
- **True Positive:** Adversary extracting `ntds.dit` to offline-crack domain password hashes.

## Response Playbook

### If activity is confirmed malicious

- **Isolate Domain Controller / Host:** Immediately isolate the host from the network.
- **Terminate Dumping Operations:** Kill any active `ntdsutil.exe` or helper processes.
- **Delete Staged Artifacts:** Locate and securely erase the output directory containing `ntds.dit` and `SYSTEM` registry files to prevent exfiltration.
- **Initiate Enterprise-Wide Credential Reset:** 
  - Reset the `krbtgt` account password twice to invalidate all Active Directory Kerberos tickets.
  - Reset passwords for all Domain Admins and privileged accounts immediately.
- **Scope Blast Radius:** Inspect SIEM for concurrent suspicious logons across all domain hosts.

## False Positives

Common benign sources include:

- Legitimate Active Directory operations during child domain controller promotions using Install-From-Media techniques.
- Enterprise backup routines that explicitly invoke `ntdsutil` command scripts for system state backups.

## Tuning Considerations

DET-023 runs at **Critical Severity (Level 15)** because dumping `ntds.dit` grants total compromise of all domain user credentials.

Tuning options to minimize false alerts:

- **Change Management Integration:** Correlate execution alerts with scheduled maintenance windows for Domain Controller promotion tasks.
- **User/Hostname Filtering:** If specific automated backup software routinely runs `ntdsutil` via dedicated service accounts, restrict exclusions strictly to those specific service accounts and expected execution parameters.

Monitoring `ntdsutil.exe` IFM commands provides critical early detection against full Active Directory domain compromise.
