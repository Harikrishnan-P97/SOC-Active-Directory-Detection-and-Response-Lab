# Detection 036 — Startup Folder Persistence

## Objective

Detect file creation events within the Windows Startup folders (All Users or per-user profiles) on monitored endpoints.

The Windows Startup folder automatically executes shortcuts (`.lnk`), scripts (`.vbs`, `.bat`, `.ps1`), or executable binaries (`.exe`) whenever a user logs into the system or when the OS boots. Threat actors frequently exploit the Startup folder to establish persistence because it does not require administrative privileges (for user-specific Startup paths) and is reliable across reboot cycles. DET-036 leverages Sysmon File Creation monitoring to detect any process writing files into designated Windows Startup locations.

## MITRE ATT&CK

**Related Techniques:**
- **T1547.001** — Boot or Logon Autostart Execution: Registry Run Keys / Startup Folder

Adversaries add malicious binaries, scripts, or shortcut files to the Windows Startup folder to achieve automatic execution upon user authentication or system startup.

## Windows / Sysmon Events

**Base Rule:** `92204` — Sysmon Event ID 11 (FileCreated).

Relevant fields include:

- Target Filename (`win.eventdata.targetFilename`): Full path of the created file, matched against Startup directory regex: `(?i).*(ProgramData|Users\\[^\\]+\\AppData\\Roaming)\\Microsoft\\Windows\\Start Menu\\Programs\\StartUp.*`
- Image Path (`win.eventdata.image`): Path of the executable/process that created the file in the Startup folder
- Process ID (`win.eventdata.processId`): PID of the process executing the file creation
- User (`win.eventdata.user`): User identity under which the process ran

## Detection Logic

```text
Sysmon Event ID 11 (Rule 92204)
        ↓
Field win.eventdata.targetFilename matches Regex:
(?i).*(ProgramData|Users\\[^\\]+\\AppData\\Roaming)\\Microsoft\\Windows\\Start Menu\\Programs\\StartUp.*
        ↓
Custom rule 100135 matches
        ↓
DET-036 alert generated (Level 14 - High/Critical)
```

The rule triggers when Sysmon Event ID 11 (File Creation) matches parent rule `92204` AND the `targetFilename` path regex evaluates to true for either System-wide or User-specific Windows Startup directories:

- **All Users Startup Path:** `C:\ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp\`
- **User-Specific Startup Path:** `C:\Users\<Username>\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\StartUp\`

## Wazuh Rule

```xml
<rule id="100135" level="14">
    <if_sid>92204</if_sid>

    <field name="win.eventdata.targetFilename" type="pcre2">(?i).*(ProgramData|Users\\[^\\]+\\AppData\\Roaming)\\Microsoft\\Windows\\Start Menu\\Programs\\StartUp.*</field>

    <description>
        DET-036 - $(win.eventdata.image) created $(win.eventdata.targetFilename) in the Windows Startup folder
    </description>

    <mitre>
        <id>T1547.001</id>
    </mitre>

    <group>
        windows,
        sysmon,
        persistence,
        attack,
        custom_detection,
    </group>
</rule>
```

### Rule Details

| Field | Value |
|---|---|
| Detection ID | DET-036 |
| Wazuh Rule ID | 100135 |
| Severity | 14 (High / Critical) |
| Parent Rule ID | 92204 (Sysmon Event ID 11 - FileCreated) |
| Detection Type | File System Monitoring (Sysmon) |
| Event Source | Sysmon Log (Event ID 11) |
| Target Path | Windows Start Menu Programs Startup Directories |
| MITRE Techniques | T1547.001 |
| Category | Persistence / Boot or Logon Autostart Execution |

---

## Simulation

A Startup folder persistence simulation was performed in the laboratory environment using PowerShell and Command Prompt.

```text
Attacker Workstation / User Context
        ↓
Executes command to write a script/shortcut into the Startup folder:
  > New-Item -Path "$env:APPDATA\Microsoft\Windows\Start Menu\Programs\Startup\malicious.bat" -ItemType File -Value "powershell -enc..."
    OR
  > copy C:\Windows\Temp\payload.exe "C:\ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp\payload.exe"
        ↓
Sysmon records Event ID 11 (FileCreated) matching target path
        ↓
Wazuh parent rule 92204 matches
        ↓
Custom rule 100135 matches
        ↓
DET-036 critical-severity alert generated (Level 14) showing writing process and target file path
```

## Expected Alert

The expected Wazuh alert contains:

- **Detection:** `DET-036`
- **Rule ID:** `100135`
- **Severity:** `14`
- Description: `DET-036 - <IMAGE> created <TARGET_FILENAME> in the Windows Startup folder`
- Image (`win.eventdata.image`)
- Target Filename (`win.eventdata.targetFilename`)
- Timestamp

Example Alert Description Output:

```text
DET-036 - C:\Windows\System32\cmd.exe created C:\Users\user1\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\malicious.bat in the Windows Startup folder
```

## Validation Result

**Status: VALIDATED**

Custom rule 100135 successfully generated Level 14 alerts whenever files (executables, scripts, batch files, or shortcut files) were written to per-user or global Windows Startup folders.

## Investigation Playbook

When DET-036 triggers, SOC analysts must analyze the dropped file and the process responsible for writing it.

### 1. Analyze the Dropped File

- **File Type & Extension:** Is the file a shortcut (`.lnk`), executable (`.exe`), batch file (`.bat`/`.cmd`), script (`.vbs`/`.ps1`), or obfuscated configuration file?
- **File Content Inspection:** If the file is a text/script file, open and review the code for encoded commands or remote payload downloads. If it is a `.lnk` file, examine the target binary path and command-line arguments.
- **File Hash Analysis:** Compute the file's SHA256 hash and submit it to Threat Intelligence / VirusTotal.

### 2. Inspect the Creating Process

- **Process Lineage:** Check `win.eventdata.image`. Was the file dropped by a legitimate software installer (`msiexec.exe`), a web browser, PowerShell, CMD, or an unknown binary?
- **Parent Process Verification:** Trace back to the parent process using Sysmon Event ID 1 (Process Creation) to determine how the writing process was launched.

### 3. Determine Classification

Classify the event:

- **False Positive / Benign:** Legitimate software installation (e.g., Discord, Slack, Spotify, Teams) creating authorized startup shortcuts during installation.
- **True Positive:** Unauthorized file placement in the Startup folder designed to execute malicious code on login or boot.

## Response Playbook

### If activity is confirmed malicious

- **Delete Dropped File:** Remove the dropped executable, script, or shortcut from the Startup folder immediately:
  ```cmd
  del /f /q "C:\Users\<Username>\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\StartUp\<MaliciousFile>"
  ```
- **Terminate Parent/Child Processes:** Kill any active processes associated with the malicious payload.
- **Isolate Endpoint:** Network isolate the endpoint to contain potential remote C2 access.
- **Remediate Persistence:** Audit additional persistence mechanisms (Registry Run keys, Scheduled Tasks, Services).
- **Reset Credentials:** Reset passwords for the affected user account.

## False Positives

Common benign sources include:

- Software installers adding auto-start shortcuts during legitimate user-initiated installations.
- Enterprise management tools deploying auto-start utilities.

## Tuning Considerations

DET-036 operates at **Critical Severity (Level 14)** due to the high likelihood of persistent malware placement in Startup folders.

Tuning options:

- **Filter Whitelisted Installers:** Build child exclusion rules for trusted software installer binaries (e.g., signed setup executables running out of `C:\Program Files\`).
- **Correlate with Execution:** Pair file creation in Startup folders with Sysmon Event ID 1 (Process Creation) when the dropped file is subsequently executed upon reboot or user re-logon.

Monitoring the Windows Startup folder guarantees swift identification of autostart persistence mechanisms across all domain hosts.
