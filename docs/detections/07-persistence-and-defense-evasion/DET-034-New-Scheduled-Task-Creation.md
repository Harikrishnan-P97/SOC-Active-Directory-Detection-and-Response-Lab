# Detection 034 — New Scheduled Task Creation

## Objective

Detect the creation of a new scheduled task on monitored Windows endpoints.

Scheduled tasks allow administrative users and software packages to automate task execution at specific times or upon specific system events. Threat actors frequently leverage scheduled tasks to maintain persistent access across system reboots, execute payloads under elevated privileges, or schedule periodic C2 beaconing. DET-034 monitors Windows Task Scheduler event logs for newly registered tasks to catch unauthorized task creations.

## MITRE ATT&CK

**Related Techniques:**
- **T1053.005** — Scheduled Task/Job: Scheduled Task

Adversaries abuse the Windows Task Scheduler (`schtasks.exe` or PowerShell `TaskScheduler` modules) to create persistent background tasks executing malicious scripts, binaries, or LOLBins.

## Windows / Sysmon Events

**Base Rule:** `60228` — Windows Task Scheduler Event ID 4698 (A scheduled task was created).

Relevant fields include:

- Task Name (`win.eventdata.taskName`): Name of the newly registered scheduled task
- Task Content (`win.eventdata.taskContent`): XML definition containing action commands, execution triggers, and credentials
- User (`win.eventdata.subjectUserName` / `win.eventdata.user`): Account responsible for registering the task
- Client Process ID (`win.eventdata.clientProcessId`): PID of the process that created the scheduled task

## Detection Logic

```text
Windows Task Scheduler Event ID 4698 (Rule 60228)
        ↓
Custom rule 100133 matches
        ↓
DET-034 alert generated (Level 12 - High)
```

The rule triggers directly when Windows Security Event ID 4698 (Scheduled Task Created) matches parent rule `60228`.

Every scheduled task registration captured by the Windows Task Scheduler triggers this detection, capturing the task name dynamically in the alert description.

## Wazuh Rule

```xml
<rule id="100133" level="12">
    <if_sid>60228</if_sid>

    <description>
        DET-034 Scheduled Task Created - $(win.eventdata.taskName)
    </description>

    <group>
        custom_detection_engineering,
        custom_windows,
        persistence,
        scheduled_task,
        attack.t1053.005
    </group>

    <mitre>
        <id>T1053.005</id>
    </mitre>
</rule>
```

### Rule Details

| Field | Value |
|---|---|
| Detection ID | DET-034 |
| Wazuh Rule ID | 100133 |
| Severity | 12 (High) |
| Parent Rule ID | 60228 (Event ID 4698 - Scheduled Task Created) |
| Detection Type | Scheduled Task Registration |
| Event Source | Windows Security Log (Task Scheduler Event ID 4698) |
| Target Object | Windows Task Scheduler (`schtasks.exe` / COM API) |
| MITRE Techniques | T1053.005 |
| Category | Persistence / Execution |

---

## Simulation

A scheduled task creation simulation was performed in the laboratory environment using `schtasks.exe` and PowerShell.

```text
Attacker Workstation / Compromised User
        ↓
Executes command to register a persistent scheduled task:
  > schtasks /create /tn "UpdaterTask" /tr "C:\Windows\Temp\updater.exe" /sc daily /st 09:00
    OR
  > Register-ScheduledTask -TaskName "UpdaterTask" -Action (New-ScheduledTaskAction -Execute "C:\Windows\Temp\updater.exe")
        ↓
Task Scheduler service creates the XML definition in C:\Windows\System32\Tasks\
        ↓
Windows generates Security Event ID 4698
        ↓
Wazuh parent rule 60228 matches
        ↓
Custom rule 100133 matches
        ↓
DET-034 high-severity alert generated (Level 12) displaying task name "UpdaterTask"
```

## Expected Alert

The expected Wazuh alert contains:

- **Detection:** `DET-034`
- **Rule ID:** `100133`
- **Severity:** `12`
- Description: `DET-034 Scheduled Task Created - <TASK_NAME>`
- Task Name (`win.eventdata.taskName`)
- Subject User (`win.eventdata.subjectUserName`)
- Task Content XML (`win.eventdata.taskContent`)
- Timestamp

Example Alert Description Output:

```text
DET-034 Scheduled Task Created - \UpdaterTask
```

## Validation Result

**Status: VALIDATED**

Custom rule 100133 successfully generated Level 12 high-severity alerts whenever a new scheduled task was created via command line (`schtasks`), PowerShell, GUI (`taskschd.msc`), or API calls.

## Investigation Playbook

When DET-034 triggers, SOC analysts must inspect the task XML content and creator identity to evaluate potential malicious intent.

### 1. Analyze Task XML Action & Triggers

Inspect `win.eventdata.taskContent`:

- **Execution Command (`<Command>` & `<Arguments>`):** Is the command targeting a legitimate executable or calling PowerShell/CMD with obfuscated/encoded strings (`-enc`, `Invoke-Expression`)?
- **Suspicious Locations:** Is the executable located in temporary or unprivileged paths (`C:\Users\Public\`, `C:\Windows\Temp\`, `AppData`)?
- **Triggers (`<Triggers>`):** Does the task run on logon, system boot, or periodic intervals (e.g., every 5 minutes)?

### 2. Identify Creator & Context

- **Creating User:** Check `win.eventdata.subjectUserName`. Was the task registered by a normal user account, service account, or Domain Admin?
- **Creating Process:** Correlate `win.eventdata.clientProcessId` with Sysmon Event ID 1 to identify which process (`schtasks.exe`, PowerShell, installer) created the task.

### 3. Binary Verification & Hash Analysis

- Extract the target binary path from the task XML action, calculate its SHA256 file hash, and verify its digital signature.

### 4. Determine Classification

Classify the event:

- **False Positive / Benign:** Authorized application update tasks (e.g., Google Update, Adobe, Microsoft Edge, IT maintenance scripts).
- **True Positive:** Unauthorized scheduled task created for persistence, privilege escalation, or automated execution.

## Response Playbook

### If activity is confirmed malicious

- **Delete Scheduled Task:** Remove the scheduled task definition immediately:
  ```cmd
  schtasks /delete /tn "<TaskName>" /f
  ```
- **Isolate Endpoint:** Network isolate the compromised system to prevent remote payload downloads or C2 communication.
- **Terminate Malicious Processes:** Kill any active running instances spawned by the scheduled task.
- **Quarantine Payload:** Delete or quarantine binaries referenced in the task's `<Command>` definition.
- **Revoke Account Credentials:** Reset credentials for the user account identified in `win.eventdata.subjectUserName`.

## False Positives

Common benign sources include:

- Automated software updates (e.g., Chrome, Edge, Zoom, OneDrive).
- Enterprise management agents deploying maintenance or audit tasks.

## Tuning Considerations

DET-034 operates at **High Severity (Level 12)** because scheduled tasks are a dominant mechanism for persistence.

Tuning options:

- **Filter Approved Task Paths:** Create exclusion rules matching standard vendor task names (e.g., `\GoogleUpdateTaskMachineUA`) or trusted digital signatures.
- **Inspect Action Command Line:** Refine detection to trigger at higher severity specifically when scheduled task commands invoke script interpreters (`powershell.exe`, `cmd.exe`, `mshta.exe`, `wscript.exe`).
- **Monitor Task Modifications:** Pair DET-034 with Event ID 4702 (Scheduled Task Updated) to detect attackers altering pre-existing legitimate tasks.

Monitoring scheduled task creation ensures early identification of persistence mechanisms before scheduled payloads trigger.
