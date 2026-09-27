# Detection 030 — WinRM Remote Session Execution Detection

## Objective

Detect execution of the Windows Remote Management (WinRM) provider host process (`wsmprovhost.exe`) on monitored Windows endpoints.

WinRM is Microsoft's implementation of the WS-Management protocol, enabling administrators to manage systems remotely over HTTP (port 5985) or HTTPS (port 5986) using PowerShell Remoting or WinRM CLI. When a remote WinRM session or PowerShell remoting connection (`Enter-PSSession`, `Invoke-Command`) is established to a system, Windows spawns `wsmprovhost.exe` to host the session and execute commands on behalf of the remote user. Adversaries frequently leverage WinRM for stealthy lateral movement, living-off-the-land command execution, and remote host administration without dropping traditional binaries. DET-030 monitors process creation events to detect incoming WinRM executions.

## MITRE ATT&CK

**Related Techniques:**
- **T1021.006** — Remote Services: Windows Remote Management

Adversaries use WinRM to execute commands, run PowerShell scripts, and navigate laterally through an enterprise environment while bypassing traditional remote desktop monitoring tools.

## Windows / Sysmon Events

**Base Rule:** `61603` — Sysmon Event ID 1 (Process Creation).

Relevant fields include:

- Image Path (`win.eventdata.image`): Process binary path checked via regular expression
- User (`win.eventdata.user`): User account executing commands inside the WinRM session
- Process ID (`win.eventdata.processId`): PID assigned to `wsmprovhost.exe`
- Parent Image (`win.eventdata.parentImage`): Parent process launching `wsmprovhost.exe` (typically `svchost.exe`)
- Command Line (`win.eventdata.commandLine`): Process parameters and parameters passed during session initiation
- Computer Name (`win.system.computer`): Host receiving the incoming WinRM connection

## Detection Logic

```text
Sysmon Process Creation Event (Rule 61603 / Event ID 1)
        ↓
Regex Match on win.eventdata.image:
(?i).*\\wsmprovhost\.exe$
        ↓
Custom rule 100129 matches
        ↓
DET-030 alert generated (Level 12 - High)
```

The rule triggers when Sysmon Event ID 1 (Process Creation) matches parent rule `61603`.

It evaluates `win.eventdata.image` using case-insensitive PCRE2 regular expression matching:

```regex
(?i).*\\wsmprovhost\.exe$
```

This regular expression matches any process path ending in `wsmprovhost.exe` regardless of drive letter or path casing.

## Wazuh Rule

```xml
<rule id="100129" level="12">
    <if_sid>61603</if_sid>

    <field name="win.eventdata.image" type="pcre2">(?i).*\\wsmprovhost\.exe$</field>

    <description>
        DET-030 WinRM Remote Session - $(win.eventdata.user)
    </description>

    <group>
        custom_windows,
        lateral_movement,
        winrm,
        attack.t1021.006
    </group>

    <mitre>
        <id>T1021.006</id>
    </mitre>
</rule>
```

### Rule Details

| Field | Value |
|---|---|
| Detection ID | DET-030 |
| Wazuh Rule ID | 100129 |
| Severity | 12 (High) |
| Parent Rule ID | 61603 (Sysmon Event ID 1 - Process Creation) |
| Detection Type | WinRM Remote Execution |
| Event Source | Sysmon Event ID 1 |
| Target Process | `wsmprovhost.exe` |
| MITRE Techniques | T1021.006 |
| Category | Lateral Movement / Remote Services |

---

## Simulation

A WinRM lateral movement simulation was performed in the lab environment.

```text
Attacker Host / Admin Workstation
        ↓
Executes Remote PowerShell Session targeting Target Host :
  > Enter-PSSession -ComputerName 192.168.1.120 -Credential DOMAIN\admin
        ↓
Target Host accepts WinRM connection over TCP 5985/5986
        ↓
Target Host spawns wsmprovhost.exe under svchost.exe
        ↓
Sysmon Event ID 1 generated on Target Host
        ↓
Wazuh parent rule 61603 matches
        ↓
Custom rule 100129 matches regex (wsmprovhost.exe)
        ↓
DET-030 high-severity alert generated (Level 12) displaying execution user
```

## Expected Alert

The expected Wazuh alert contains:

- **Detection:** `DET-030`
- **Rule ID:** `100129`
- **Severity:** `12`
- Description: `DET-030 WinRM Remote Session - <USER>`
- Executable Image Path (`win.eventdata.image`)
- Execution User (`win.eventdata.user`)
- Parent Image Path (`win.eventdata.parentImage`)
- Command Line (`win.eventdata.commandLine`)
- Hostname (`win.system.computer`)
- Timestamp

Example Alert Description Output:

```text
DET-030 WinRM Remote Session - DOMAIN\admin_user
```

## Validation Result

**Status: VALIDATED**

Custom rule 100129 successfully generated Level 12 high-severity alerts whenever a remote PowerShell session or WinRM command execution spawned `wsmprovhost.exe`.

## Investigation Playbook

When DET-030 triggers, SOC analysts must rapidly determine if the remote WinRM connection stems from authorized IT administration or an adversary moving laterally.

### 1. Identify User Account & Origin

Review:

- **Executing User Account:** (`win.eventdata.user`) — Is the connection initiated by a known SysAdmin/Helpdesk account or an standard workstation user?
- **Correlate WinRM Logon Events:** Cross-reference Windows Event ID 4624 (Logon Type 3 - Network) around the same timestamp to extract the source IP address (`ipAddress`).

### 2. Inspect Child Processes

Examine child processes spawned under `wsmprovhost.exe`:

- Check Sysmon Event ID 1 where `parentImage` is `wsmprovhost.exe`.
- Look for execution of discovery commands (`whoami`, `net group`, `nltest`, `ipconfig`), privilege escalation tools, or PowerShell encoded commands (`powershell.exe -e ...`).

### 3. Verify Change Tickets & Administrative Activity

- Cross-check with IT operations tickets or automated management schedules (e.g., Ansible, PowerShell Universal, SCCM scripts).

### 4. Determine Classification

Classify the event:

- **False Positive / Benign:** Documented remote administration script, IT automation engine, or legitimate helpdesk support ticket.
- **True Positive:** Unauthorized WinRM remote session indicating interactive adversary lateral movement or living-off-the-land execution.

## Response Playbook

### If activity is confirmed malicious

- **Isolate Host:** Network isolate the compromised system receiving the WinRM session and the source IP host initiating the session.
- **Terminate WinRM Session:** Kill the active `wsmprovhost.exe` process tree on the target host (`taskkill /F /PID <PID>`).
- **Disable WinRM Service (If Necessary):** Stop the `WinRM` service (`net stop WinRM`) to block further incoming connections on target hosts.
- **Revoke Account Credentials:** Force password reset and terminate active Kerberos/NTLM tokens for the account specified in `win.eventdata.user`.
- **Harvest Artifacts:** Triage PowerShell Operational Logs (`Microsoft-Windows-PowerShell/Operational`, Event ID 4104) to review script blocks executed inside the WinRM session.

## False Positives

Common benign sources include:

- IT administrators using PowerShell remoting (`Enter-PSSession`, `Invoke-Command`) for remote system maintenance.
- Server management and automation platforms (e.g., Ansible, Octopus Deploy, Microsoft System Center) managing Windows hosts via WinRM.

## Tuning Considerations

DET-030 operates at **High Severity (Level 12)** to highlight remote PowerShell/WinRM sessions across the environment.

Tuning options:

- **Filter Approved Automation Servers:** If dedicated automation hosts (e.g., Ansible servers) run frequent tasks, create exclusion child rules matching authorized service accounts or source IPs.
- **Script Block Logging Correlation:** Pair DET-030 with PowerShell Event ID 4104 to automatically inspect commands executed inside the `wsmprovhost.exe` shell.
- **WinRM Hardening:** Restrict WinRM traffic via Windows Firewall GPO to allow connections only from dedicated administrative subnets/jump hosts.

Monitoring `wsmprovhost.exe` provides critical visibility into remote management protocols frequently abused for stealthy lateral movement.
