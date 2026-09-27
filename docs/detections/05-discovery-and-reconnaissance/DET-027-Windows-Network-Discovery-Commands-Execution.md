# Detection 027 — Windows Network Discovery Commands Execution

## Objective

Detect early-stage host and network discovery activity executed via standard native Windows utilities.

Adversaries, threat actors, and automated post-exploitation scripts frequently invoke native Windows command-line tools (Living-off-the-Land binaries or LotBins) immediately upon establishing initial access. Tools such as `ipconfig`, `arp`, `route`, `netstat`, `net view`, `whoami`, `nltest`, and `netsh` allow attackers to map local network configurations, active connections, routing tables, domain trusts, and account privileges without introducing external binaries. DET-027 monitors Sysmon Event ID 1 process creation events to flag the execution of these built-in discovery utilities.

## MITRE ATT&CK

**Related Techniques:**
- **T1016** — System Network Configuration Discovery
- **T1049** — System Network Connections Discovery

Native command-line tools are used during initial access and reconnaissance phases to gather actionable intelligence for subsequent lateral movement, privilege escalation, and network mapping.

## Windows / Sysmon Events

**Base Rule:** `61603` — Sysmon Event ID 1 (Process Creation) / Windows Process Audit Event.

Relevant fields include:

- Event ID (`win.system.eventID`): `1`
- Command Line (`win.eventdata.commandLine`): Process command-line string evaluated against targeted regex patterns
- Computer Name (`win.system.computer`): Host where the command was executed
- User (`win.eventdata.user`): Account executing the discovery command
- Parent Image (`win.eventdata.parentImage`): Parent process spawning the discovery tool (e.g., `cmd.exe`, `powershell.exe`, WMI, C2 agents)
- Image Path (`win.eventdata.image`): Path to the executed native Windows binary

## Detection Logic

```text
Sysmon Process Creation Event (Rule 61603 / Event ID 1)
        ↓
Regex Match on win.eventdata.commandLine:
(?i)(ipconfig|arp\s+-a|route\s+print|netstat|net\s+view|net\s+group|nslookup|hostname|whoami|ping|tracert|nltest|netsh)
        ↓
Custom rule 100126 matches
        ↓
DET-027 alert generated (Level 8 - Medium)
```

The rule evaluates Sysmon Event ID 1 process execution under parent rule `61603`.

It performs a case-insensitive PCRE2 regular expression match against command-line arguments:

```regex
(?i)(ipconfig|arp\s+-a|route\s+print|netstat|net\s+view|net\s+group|nslookup|hostname|whoami|ping|tracert|nltest|netsh)
```

This pattern catches high-risk discovery commands executed individually or as part of automated batch discovery scripts.

## Wazuh Rule

```xml
<rule id="100126" level="8">

    <if_sid>61603</if_sid>

    <field name="win.system.eventID">1</field>

    <field name="win.eventdata.commandLine" type="pcre2">(?i)(ipconfig|arp\s+-a|route\s+print|netstat|net\s+view|net\s+group|nslookup|hostname|whoami|ping|tracert|nltest|netsh)</field>

    <description>
        DET-027 Discovery Command on $(win.system.computer) by $(win.eventdata.user): $(win.eventdata.commandLine)
    </description>

    <group>
        custom_windows,
        discovery,
        network_discovery,
        attack.t1016,
        attack.t1049
    </group>

    <mitre>
        <id>T1016</id>
        <id>T1049</id>
    </mitre>

</rule>
```

### Rule Details

| Field | Value |
|---|---|
| Detection ID | DET-027 |
| Wazuh Rule ID | 100126 |
| Severity | 8 (Medium) |
| Parent Rule ID | 61603 (Sysmon Event ID 1) |
| Detection Type | Host & Network Discovery |
| Event Source | Sysmon Event ID 1 (Process Creation) |
| Target Pattern | Case-insensitive regex matching native discovery binaries |
| MITRE Techniques | T1016, T1049 |
| Category | Discovery / Network Reconnaissance |

---

## Simulation

A host discovery simulation was conducted on a monitored Windows endpoint.

```text
Attacker / Staged Shell on Target Host (192.168.1.115)
        ↓
Executes sequence:
  > whoami
  > ipconfig /all
  > route print
  > netstat -ano
  > nltest /dclocation:domain.local
        ↓
Target Windows Host generates Sysmon Event ID 1 events
        ↓
Wazuh parent rule 61603 matches
        ↓
Custom rule 100126 regex triggers on each command line match
        ↓
DET-027 alerts generated (Level 8) displaying computer, user, and commandLine
```

## Expected Alert

The expected Wazuh alert contains:

- **Detection:** `DET-027`
- **Rule ID:** `100126`
- **Severity:** `8`
- Dynamic Description: `DET-027 Discovery Command on <COMPUTER> by <USER>: <COMMAND_LINE>`
- Executable Image Path (`win.eventdata.image`)
- Execution User (`win.eventdata.user`)
- Parent Image (`win.eventdata.parentImage`)
- Timestamp

Example Alert Description Output:

```text
DET-027 Discovery Command on WIN-PC01 by DOMAIN\jdoe: ipconfig /all
```

## Validation Result

**Status: VALIDATED**

Custom rule 100126 successfully triggered Level 8 alerts across multiple native Windows discovery execution patterns.

## Investigation Playbook

When DET-027 triggers, SOC analysts must analyze the context to distinguish routine IT troubleshooting from adversary post-exploitation enumeration.

### 1. Evaluate Command Frequency & Clustering

Review:

- **Command Bursting:** Are multiple discovery commands executed rapidly within seconds or minutes? (e.g., `whoami` → `ipconfig` → `netstat` → `nltest`). Rapid sequential execution strongly indicates automated discovery scripts (e.g., enumeration phase of malware/C2 implants).
- **Single Utility Execution:** Isolated commands like `ping` or `hostname` often correlate with routine user or sysadmin troubleshooting.

### 2. Inspect Parent Process & User Context

Review:

- **Parent Process:** (`win.eventdata.parentImage`) — Is the binary spawned by interactive shells (`cmd.exe`, `powershell.exe`), web server processes (`w3wp.exe`), script hosts (`cscript.exe`, `wscript.exe`), or unknown/suspicious binaries?
- **User Account:** (`win.eventdata.user`) — Is the command run by a standard domain user, system account (`NT AUTHORITY\SYSTEM`), or service account?

### 3. Check Account & Machine History

Review:

- Determine if the executing user or host has recent alerts for initial access vectors (e.g., suspicious email attachments, web exploitation, external VPN logins).

### 4. Determine Classification

Classify the event:

- **False Positive / Benign:** Authorized IT administrator or support engineer performing active network diagnostics.
- **True Positive:** Unauthorized user or compromised process running reconnaissance commands to map internal topology.

## Response Playbook

### If activity is confirmed malicious

- **Isolate Endpoint:** Disconnect the target system from the network to halt ongoing discovery and prevent lateral propagation.
- **Identify & Terminate Parent C2/Process:** Identify the parent process or shell that spawned the discovery commands and terminate it immediately.
- **Revoke Compromised Credentials:** Lock the associated user account and reset credentials across active sessions.
- **Perform Forensic Triage:** Collect memory dumps, process execution trees, and recent file drops to identify initial access vectors and payload drop paths.
- **Audit Network Perimeter:** Verify if discovery commands revealed sensitive internal subnets and increase monitoring on adjacent endpoints.

## False Positives

Common benign sources include:

- IT support desk staff running diagnostic commands (`ping`, `ipconfig`, `tracert`) during network troubleshooting.
- Automated system management agents (e.g., SCCM, Datto, Kaseya, custom enterprise administrative scripts) periodically collecting network telemetry.

## Tuning Considerations

DET-027 operates at **Medium Severity (Level 8)** because individual commands like `whoami` or `ipconfig` are frequently used in normal administration.

Tuning options:

- **Exclude Verified Admin Management Agents:** Suppress alerts where parent processes originate from verified IT management software.
- **Create Correlation Rules:** Higher-severity composite rules can be implemented to escalate alert levels when multiple discovery commands (e.g., 3+ unique commands) execute within a short timeframe (e.g., 2 minutes).
- **Exclude Frequent Admin Users/Hosts:** Filter known network administrator workstations if diagnostic command volume creates notification fatigue.

Tracking native Windows discovery commands provides early visibility into adversary post-compromise activity before lateral movement occurs.
