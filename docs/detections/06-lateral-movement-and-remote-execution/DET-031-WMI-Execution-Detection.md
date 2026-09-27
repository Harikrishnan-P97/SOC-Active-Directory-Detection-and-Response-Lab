# Detection 031 — WMI Remote Command Execution Detection

## Objective

Detect remote command execution originating from Windows Management Instrumentation (WMI) by monitoring critical binary executions spawned via the WMI provider host (`WmiPrvSE.exe`).

WMI is an administrative infrastructure built into Windows that enables remote monitoring, management, and script execution across network systems. Threat actors and post-exploitation frameworks (e.g., Impacket's `wmiexec`, Cobalt Strike, WMI persistence scripts) frequently leverage WMI (via DCOM/RPC on TCP 135 and dynamic RPC ports) to execute commands remotely without staging specialized binaries. DET-031 inspects process creation events originating from `WmiPrvSE.exe` and targets secondary execution binaries commonly used to run malicious commands, scripts, or LOLBins (Living off the Land Binaries).

## MITRE ATT&CK

**Related Techniques:**
- **T1047** — Windows Management Instrumentation

Adversaries use WMI to interact with local and remote systems to execute commands, gather system information, and deploy payloads stealthily under privileged system contexts.

## Windows / Sysmon Events

**Base Rule:** `92069` — Process Creation Event where parent process is WMI Provider Host (`WmiPrvSE.exe`).

Relevant fields include:

- Original File Name (`win.eventdata.originalFileName`): PE header original filename evaluated via regular expression
- User (`win.eventdata.user`): Account context under which the command executes
- Command Line (`win.eventdata.commandLine`): Full command and arguments passed to the spawned process
- Image Path (`win.eventdata.image`): Path of the process spawned by WMI
- Parent Process (`win.eventdata.parentImage`): `C:\Windows\System32\wbem\WmiPrvSE.exe`
- Computer Name (`win.system.computer`): Target host executing the WMI request

## Detection Logic

```text
Process Creation Event under WmiPrvSE.exe (Rule 92069)
        ↓
Regex Match on win.eventdata.originalFileName:
(?i)(Cmd\.EXE|RUNDLL32\.EXE|REGSVR32\.EXE|MSHTA\.EXE|CSCRIPT\.EXE|WSCRIPT\.EXE|CERTUTIL\.EXE|BITSADMIN\.EXE)
        ↓
Custom rule 100130 matches
        ↓
DET-031 alert generated (Level 12 - High)
```

The rule triggers when a process spawned by `WmiPrvSE.exe` matches parent rule `92069`.

It evaluates `win.eventdata.originalFileName` using case-insensitive PCRE2 regular expression matching:

```regex
(?i)(Cmd\.EXE|RUNDLL32\.EXE|REGSVR32\.EXE|MSHTA\.EXE|CSCRIPT\.EXE|WSCRIPT\.EXE|CERTUTIL\.EXE|BITSADMIN\.EXE)
```

By evaluating `originalFileName` rather than just the process image path, the detection captures cases where an attacker renames standard binaries (e.g., renaming `cmd.exe` to `update.exe`) to bypass basic image path filters.

## Wazuh Rule

```xml
<rule id="100130" level="12">

    <if_sid>92069</if_sid>

    <field name="win.eventdata.originalFileName" type="pcre2">(?i)(Cmd\.EXE|RUNDLL32\.EXE|REGSVR32\.EXE|MSHTA\.EXE|CSCRIPT\.EXE|WSCRIPT\.EXE|CERTUTIL\.EXE|BITSADMIN\.EXE)</field>

    <description>
        DET-031 WMI Remote Command Execution - $(win.eventdata.user)
    </description>

    <group>
        custom_windows,
        execution,
        wmi,
        attack.t1047
    </group>

    <mitre>
        <id>T1047</id>
    </mitre>

</rule>
```

### Rule Details

| Field | Value |
|---|---|
| Detection ID | DET-031 |
| Wazuh Rule ID | 100130 |
| Severity | 12 (High) |
| Parent Rule ID | 92069 (Child process of `WmiPrvSE.exe`) |
| Detection Type | WMI Remote Command Execution |
| Event Source | Sysmon Event ID 1 / Windows Security Event ID 4688 |
| Target Binaries | `Cmd.EXE`, `RUNDLL32.EXE`, `REGSVR32.EXE`, `MSHTA\.EXE`, `CSCRIPT.EXE`, `WSCRIPT.EXE`, `CERTUTIL.EXE`, `BITSADMIN.EXE` |
| MITRE Techniques | T1047 |
| Category | Execution / Lateral Movement |

---

## Simulation

A WMI remote execution simulation was performed in the lab environment using Impacket's `wmiexec`.

```text
Attacker Workstation (192.168.1.110)
        ↓
Executes wmiexec.py targeting Target Host (192.168.1.120):
  > wmiexec.py DOMAIN/admin:password@192.168.1.120 "cmd.exe /c ipconfig"
        ↓
Target Host receives RPC/DCOM request on TCP 135
        ↓
WmiPrvSE.exe spawns cmd.exe /c ipconfig > \\127.0.0.1\ADMIN$\...
        ↓
Target Host generates process creation log
        ↓
Wazuh parent rule 92069 matches (Parent: WmiPrvSE.exe)
        ↓
Custom rule 100130 matches originalFileName (Cmd.EXE)
        ↓
DET-031 high-severity alert generated (Level 12) showing executing user
```

## Expected Alert

The expected Wazuh alert contains:

- **Detection:** `DET-031`
- **Rule ID:** `100130`
- **Severity:** `12`
- Description: `DET-031 WMI Remote Command Execution - <USER>`
- Original File Name (`win.eventdata.originalFileName`)
- Executable Image Path (`win.eventdata.image`)
- Execution User (`win.eventdata.user`)
- Command Line (`win.eventdata.commandLine`)
- Parent Image Path (`win.eventdata.parentImage`)
- Timestamp

Example Alert Description Output:

```text
DET-031 WMI Remote Command Execution - DOMAIN\admin_user
```

## Validation Result

**Status: VALIDATED**

Custom rule 100130 successfully generated Level 12 high-severity alerts when `WmiPrvSE.exe` spawned monitored execution binaries such as `cmd.exe`, `rundll32.exe`, `cscript.exe`, and `certutil.exe`.

## Investigation Playbook

When DET-031 triggers, SOC analysts must quickly assess whether the WMI execution is an authorized administrative script or an attacker carrying out remote execution or lateral movement.

### 1. Analyze Command Line Parameters

Inspect `win.eventdata.commandLine` for indicators of malicious intent:

- Encoded commands, output redirection to admin shares (e.g., `> \\127.0.0.1\ADMIN$\...` typical of Impacket `wmiexec`), or staging files in `C:\Windows\Temp\`.
- Script execution flags with `cscript.exe`/`wscript.exe` loading unsigned `.vbs` or `.js` payloads.
- Abuse of `certutil.exe` (e.g., `-urlcache -split -f`) or `bitsadmin.exe` to download remote payloads.
- Proxy execution via `rundll32.exe` or `regsvr32.exe` invoking remote DLLs or `.sct` files (Squiblydoo).

### 2. Identify User & Source IP

- **User Account:** (`win.eventdata.user`) — Determine if the account is a Domain Admin, local Administrator, or service account.
- **Identify Source Host:** Pivot to Windows Security Event ID 4624 (Logon Type 3) or WMI Activity Operational logs (`Microsoft-Windows-WMI-Activity/Operational`, Event ID 5861) to find the client IP address (`ClientMachineId`) initiating the remote WMI call.

### 3. Check for Downstream Activity

- Look for child processes spawned by the target binary (e.g., `cmd.exe` spawning `powershell.exe` or reconnaissance tools like `whoami`, `net.exe`, `systeminfo`).

### 4. Determine Classification

Classify the event:

- **False Positive / Benign:** Authorized IT inventory software, SCCM management scripts, or enterprise monitoring agent using WMI.
- **True Positive:** Unauthorized WMI execution indicating lateral movement, C2 command execution, or defense evasion.

## Response Playbook

### If activity is confirmed malicious

- **Isolate Endpoint:** Instantly isolate the destination endpoint and the source host initiating the remote WMI connection.
- **Terminate Malicious Processes:** Kill `WmiPrvSE.exe` child process trees (`cmd.exe`, `rundll32.exe`, etc.) on the affected endpoint.
- **Revoke Account Credentials:** Force a password reset and revoke active Kerberos/NTLM sessions for the account listed in `win.eventdata.user`.
- **Collect & Triage Artifacts:** Inspect `C:\Windows\Temp\` and `ADMIN$` shares for temporary output files dropped during execution. Review `WMI-Activity/Operational` event logs for WMI namespace queries and bindings.
- **Block RPC/WMI Traffic:** Restrict RPC (TCP 135) and dynamic RPC ports via host-based firewalls to authorized jump boxes and deployment hosts.

## False Positives

Common benign sources include:

- System management frameworks (e.g., Microsoft SCCM, WMI-based inventory tools, PRTG Network Monitor) querying endpoints or launching administrative tasks.
- Backup and patch deployment tools executing maintenance VBScript or batch files via `WmiPrvSE.exe`.

## Tuning Considerations

DET-031 operates at **High Severity (Level 12)** due to WMI's high prevalence in post-exploitation and lateral movement activities.

Tuning options:

- **Filter Approved Service Accounts:** If legitimate monitoring agents (e.g., SCCM service accounts) generate frequent alerts, create targeted exclusion rules matching specific user accounts and command-line arguments.
- **PE Header Verification:** Rule 100130 already leverages `originalFileName` to mitigate evasion via binary renaming.
- **Harden WMI Permissions:** Restrict remote DCOM/WMI launch and activation permissions via GPO to authorized administrative groups only.

Monitoring child processes spawned by `WmiPrvSE.exe` provides crucial early detection of remote code execution and lateral movement across Windows networks.
