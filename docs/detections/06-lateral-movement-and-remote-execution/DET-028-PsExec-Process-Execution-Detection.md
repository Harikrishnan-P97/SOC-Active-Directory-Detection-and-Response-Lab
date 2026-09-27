# Detection 028 — PsExec Process Execution Detection

## Objective

Detect execution of the Sysinternals PsExec utility (or renamed variants ending in `psexec.exe` / `psexec64.exe`) on monitored Windows systems.

PsExec is a light-weight telnet-replacement that lets users execute processes on remote systems with full interactivity for console applications. While widely used by system administrators for legitimate remote management, it is heavily leveraged by threat actors and ransomware operators for lateral movement, remote command execution, and escalating privileges to `NT AUTHORITY\SYSTEM`. DET-028 monitors Sysmon Event ID 1 (Process Creation) events to catch PsExec binary execution.

## MITRE ATT&CK

**Related Techniques:**
- **T1021.002** — Remote Services: SMB/Windows Admin Shares
- **T1569.002** — System Services: Service Execution

Adversaries frequently utilize PsExec to execute malicious binaries or scripts across remote endpoints over SMB (TCP 445), often installing temporary services (`PSEXESVC.exe`) to run payloads under SYSTEM context.

## Windows / Sysmon Events

**Base Rule:** `sysmon_event1` — Sysmon Event ID 1 (Process Creation).

Relevant fields include:

- Image Path (`win.eventdata.image`): Target binary path checked via regular expression
- User (`win.eventdata.user`): Account initiating the PsExec process
- Command Line (`win.eventdata.commandLine`): Remote target system, credentials, and commands passed (e.g., `psexec.exe \\192.168.1.50 -u admin -p password cmd.exe`)
- Parent Image (`win.eventdata.parentImage`): Parent process launching PsExec (e.g., `cmd.exe`, `powershell.exe`, C2 framework binaries)
- Computer Name (`win.system.computer`): Source machine where PsExec is being launched

## Detection Logic

```text
Sysmon Process Creation Event (sysmon_event1 / Event ID 1)
        ↓
Regex Match on win.eventdata.image:
(?i)\\psexec(64)?\.exe$
        ↓
Custom rule 100127 matches
        ↓
DET-028 alert generated (Level 12 - High)
```

The rule triggers when a Sysmon Event ID 1 process creation event belongs to the `sysmon_event1` group.

It evaluates the image path using case-insensitive PCRE2 regular expression matching:

```regex
(?i)\\psexec(64)?\.exe$
```

This pattern matches standard executable names such as `psexec.exe` and `psexec64.exe` regardless of directory location.

## Wazuh Rule

```xml
<rule id="100127" level="12">

    <if_group>sysmon_event1</if_group>

    <field name="win.eventdata.image" type="pcre2">(?i)\\psexec(64)?\.exe$</field>

    <description>
        DET-028 PsExec Execution - $(win.eventdata.user)
    </description>

    <mitre>
        <id>T1021.002</id>
        <id>T1569.002</id>
    </mitre>

    <group>
        custom_windows,
        lateral_movement,
        psexec,
        attack.t1021.002,
        attack.t1569.002
    </group>

</rule>
```

### Rule Details

| Field | Value |
|---|---|
| Detection ID | DET-028 |
| Wazuh Rule ID | 100127 |
| Severity | 12 (High) |
| Parent Group | `sysmon_event1` (Sysmon Event ID 1) |
| Detection Type | Remote Execution / Lateral Movement |
| Event Source | Sysmon Event ID 1 (Process Creation) |
| Target Binary | `psexec.exe` / `psexec64.exe` |
| MITRE Techniques | T1021.002, T1569.002 |
| Category | Lateral Movement / Remote Execution |

---

## Simulation

A lateral movement simulation was performed in the lab environment using Sysinternals PsExec.

```text
Attacker Host / Compromised Admin Workstation (192.168.1.110)
        ↓
Executes command:
  > psexec64.exe \\192.168.1.120 -s cmd.exe
        ↓
Source Windows Host generates Sysmon Event ID 1 (Process Creation)
        ↓
Wazuh parent group sysmon_event1 matches
        ↓
Custom rule 100127 regex matches win.eventdata.image (psexec64.exe)
        ↓
DET-028 high-severity alert generated (Level 12) displaying account name
```

## Expected Alert

The expected Wazuh alert contains:

- **Detection:** `DET-028`
- **Rule ID:** `100127`
- **Severity:** `12`
- Description: `DET-028 PsExec Execution - <USER>`
- Executable Image Path (`win.eventdata.image`)
- Execution User (`win.eventdata.user`)
- Target Remote System / Command Line (`win.eventdata.commandLine`)
- Parent Image (`win.eventdata.parentImage`)
- Timestamp

Example Alert Description Output:

```text
DET-028 PsExec Execution - DOMAIN\admin_user
```

## Validation Result

**Status: VALIDATED**

Custom rule 100127 successfully generated Level 12 high-severity alerts upon execution of `psexec.exe` and `psexec64.exe`.

## Investigation Playbook

When DET-028 triggers, SOC analysts must rapidly determine if remote administrative activity is authorized or indicates active lateral movement.

### 1. Verify Administrative Authorization

Review:

- **Change Control / Support Tickets:** Confirm if a legitimate network administrator or IT helpdesk team member opened a maintenance ticket targeting the destination system.
- **Executing User Account:** (`win.eventdata.user`) — Check if the account belongs to authorized Domain Admins or an unexpected standard/service account.

### 2. Analyze Command Line Parameters

Inspect `win.eventdata.commandLine` for suspicious flags:

- `-s` (Executes process as `NT AUTHORITY\SYSTEM` — high risk for privilege escalation)
- `-u` / `-p` (Hardcoded credentials passed directly in command line)
- `-c` (Copies specified executable to remote system before execution)
- Remote execution targeting domain controllers or critical servers (e.g., `\\DC01`).

### 3. Inspect Destination System (Target Endpoint)

- Pivot to destination host logs and look for Sysmon Event ID 13/11 (Service creation) or Windows Security Event ID 7045 / Event ID 4697 for `PSEXESVC` installation.
- Verify what child processes were executed on the remote system by `PSEXESVC.exe` (e.g., `cmd.exe`, `powershell.exe`, ransomware binaries).

### 4. Determine Classification

Classify the event:

- **False Positive / Authorized:** Documented IT administrative task or authorized internal vulnerability assessment.
- **True Positive:** Unauthorized remote execution indicating lateral movement, C2 staging, or ransomware deployment.

## Response Playbook

### If activity is confirmed malicious

- **Isolate Systems:** Immediately disconnect both the source host running PsExec and the target destination system from the network.
- **Terminate PsExec & Remote Services:** Kill the running `psexec.exe` process on the source host and stop/delete `PSEXESVC` on the destination endpoint.
- **Revoke Compromised Credentials:** Immediately lock and reset passwords for compromised admin or service credentials used during execution.
- **Scan & Remediate Target Hosts:** Perform memory analysis and disk triage on target endpoints to locate dropped binaries, payloads, or scheduled tasks created during the PsExec session.
- **Block Unnecessary SMB Traffic:** Enforce internal firewall policies restricting SMB (TCP 445) traffic between non-server endpoints.

## False Positives

Common benign sources include:

- System administrators performing routine remote patch management or software deployment via PsExec scripts.
- Legacy IT management frameworks using PsExec for remote command execution.

## Tuning Considerations

DET-028 runs at **High Severity (Level 12)** due to the massive security risk associated with unmonitored PsExec execution.

Tuning options:

- **PE Header Supplementing:** Pair this rule with `originalFileName` checks (`PSEXEC.EXE`) to capture renamed executables (e.g., `rundll.exe` renamed from `psexec.exe`).
- **Whitelisting Authorized Admin Workstations:** If IT admins regularly use PsExec, restrict exclusions to specific source IP/workstation hostnames and verified IT accounts rather than disabling the rule entirely.
- **Enforce GPO Restrictions / AppLocker:** Restrict execution of PsExec binaries to approved administrative groups via AppLocker or Windows Defender Application Control (WDAC).

Monitoring PsExec execution provides essential defense against adversary lateral movement and remote payload staging.
