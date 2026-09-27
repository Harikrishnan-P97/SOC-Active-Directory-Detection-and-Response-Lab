# Detection 026 — AdFind Active Directory Enumeration Tool Execution

## Objective

Detect execution of AdFind, a popular command-line tool frequently leveraged by adversaries and ransomware operators for Active Directory structure and trust enumeration.

AdFind is a legitimate command-line query utility for Active Directory. Due to its powerful filtering capabilities, speed, and standalone executable nature, it is heavily abused during the post-exploitation discovery phase by threat actors (e.g., FIN7, Ryuk, REvil, BlackCat) to map domain accounts, organizational units, subnets, trusts, and administrative groups. DET-026 inspects Windows process creation events to detect AdFind execution using binary PE header metadata (`originalFileName`).

## MITRE ATT&CK

**Related Techniques:**
- **T1087** — Account Discovery (Account Discovery: Domain Account)
- **T1069.002** — Permission Groups Discovery: Domain Groups
- **T1482** — Domain Trust Discovery

Adversaries routinely execute AdFind via batch scripts or automated C2 frameworks to query domain controllers and extract directory topology before launching ransomware or moving laterally.

## Windows / Sysmon Events

**Base Rule:** `61603` — Sysmon Event ID 1 (Process Creation) / Windows Process Audit Event.

Relevant fields include:

- Original File Name (`win.eventdata.originalFileName`): `AdFind.exe`
- Image Path (`win.eventdata.image`): Path of the binary being executed
- Command Line (`win.eventdata.commandLine`): Arguments passed (e.g., `adfind.exe -f "(objectcategory=person)"`, `adfind.exe -sc trustdmp`)
- User (`win.eventdata.user`): Account executing the command
- Parent Image (`win.eventdata.parentImage`): Parent process launching the binary (e.g., `cmd.exe`, `powershell.exe`, script runners)
- Process Hash (`win.eventdata.hashes`): Binary hashes (SHA256/MD5)

Inspecting `originalFileName` guarantees detection even if the binary is renamed (e.g., `discovery.exe` or `test.exe`).

## Detection Logic

```text
Sysmon Process Creation Event (Rule 61603 / Event ID 1)
        ↓
Check originalFileName equals "AdFind.exe"
        ↓
Custom rule 100125 matches
        ↓
DET-026 alert generated (Level 12 - High)
```

The rule evaluates process creation events under parent rule `61603`.

The rule explicitly checks:

```text
win.eventdata.originalFileName equals AdFind.exe
```

By leveraging internal PE file headers, custom rule 100125 accurately catches AdFind execution regardless of file path alterations or executable renaming.

## Wazuh Rule

```xml
<rule id="100125" level="12">

    <if_sid>61603</if_sid>

    <field name="win.eventdata.originalFileName">AdFind.exe</field>

    <description>
        DET-026 AdFind Active Directory Enumeration Tool Execution
    </description>

    <group>
        custom_windows,
        discovery,
        active_directory,
        adfind,
        attack.t087,
        attack.t1482,
        attack.t1069.002
    </group>

    <mitre>
        <id>T1087</id>
        <id>T1482</id>
        <id>T1069.002</id>
    </mitre>

</rule>
```

### Rule Details

| Field | Value |
|---|---|
| Detection ID | DET-026 |
| Wazuh Rule ID | 100125 |
| Severity | 12 (High) |
| Parent Rule ID | 61603 (Sysmon Event ID 1) |
| Detection Type | Active Directory Reconnaissance |
| Event Source | Sysmon Event ID 1 (Process Creation) |
| Target File | `AdFind.exe` (via PE Original File Name) |
| MITRE Techniques | T1087, T1482, T1069.002 |
| Category | Discovery / Active Directory Reconnaissance |

---

## Simulation

An Active Directory reconnaissance simulation was conducted in the lab environment using AdFind.

```text
Attacker Host / Compromised Endpoint (192.168.1.110)
        ↓
Executes: adfind.exe -f "(objectcategory=person)" -dn -gcb -sc trustdmp
        ↓
Target Windows Host generates Sysmon Event ID 1 (Process Creation)
        ↓
Wazuh parent rule 61603 triggers
        ↓
Custom rule 100125 matches PE header metadata (originalFileName = AdFind.exe)
        ↓
DET-026 high severity alert generated (Level 12)
```

## Expected Alert

The expected Wazuh alert contains:

- **Detection:** `DET-026`
- **Rule ID:** `100125`
- **Severity:** `12`
- Executable Image Path (`win.eventdata.image`)
- Original File Name (`win.eventdata.originalFileName = AdFind.exe`)
- Command Line (`win.eventdata.commandLine`)
- Execution User (`win.eventdata.user`)
- Timestamp

The alert description explicitly reports:

```text
DET-026 AdFind Active Directory Enumeration Tool Execution
```

## Validation Result

**Status: VALIDATED**

Custom rule 100125 successfully detected AdFind binary execution via internal PE metadata inspection, generating a Level 12 high-severity alert.

## Investigation Playbook

When DET-026 triggers, SOC analysts must immediately assess whether AdFind execution is part of an active intrusion campaign or an authorized administrative task.

### 1. Verify Activity Authorization

Review:

- **System Administration / Audit Schedule:** Check whether domain admins or security auditors have open change requests involving Active Directory queries.
- **Executing User Account:** (`win.eventdata.user`) — Is the command executed by a domain admin, service account, or standard endpoint user?

### 2. Analyze Command Line Flags

Inspect `win.eventdata.commandLine` for common adversary discovery flags:

- `-sc trustdmp` (Domain trust enumeration)
- `-f "(objectcategory=person)"` or `"(objectcategory=computer)"` (User and host enumeration)
- `-subnets -f` (Subnet mapping)
- `-gcb` (Global catalog queries)
- Scripted batch executions saving output to `.txt` or `.csv` files (e.g., `> ad_users.txt`).

### 3. Inspect Parent Process & Execution Path

Review:

- **Parent Image:** (`win.eventdata.parentImage`) — Was AdFind launched interactively (`cmd.exe`, `powershell.exe`) or spawned by a staging directory script (`C:\PerfLogs\`, `C:\Windows\Temp\`, `C:\Users\Public\`)?
- Spawning from unusual parent processes (e.g., WMI, PowerShell, scheduled tasks, C2 agent binaries) indicates active hands-on-keyboard activity.

### 4. Correlate with Network & LDAP Logs

- Check Domain Controller logs for sudden surges in LDAP search queries originating from the host machine within the same timeframe.

### 5. Determine Classification

Classify the event:

- **False Positive / Authorized:** Documented sysadmin script or penetration testing exercise.
- **True Positive:** Unauthorized reconnaissance indicating pre-ransomware staging or threat actor domain mapping.

## Response Playbook

### If activity is confirmed malicious

- **Isolate Endpoint:** Immediately disconnect the endpoint from the network to prevent further Active Directory scraping.
- **Terminate Process:** Terminate the running `AdFind.exe` process and its parent shell.
- **Revoke/Reset Credentials:** Reset credentials for the user account that ran the utility.
- **Identify Drop Location:** Locate and delete output text/CSV files generated by AdFind to prevent data exfiltration.
- **Scope Intrusion:** Conduct post-exploitation hunting on the isolated host for initial access vectors, lateral movement tools, and C2 implants.

## False Positives

Common benign sources include:

- Domain administrators performing legitimate LDAP management or directory troubleshooting via AdFind.
- Legacy IT automation scripts utilizing AdFind for batch reporting.

## Tuning Considerations

DET-026 runs at **High Severity (Level 12)** due to AdFind's high correlation with ransomware pre-execution activities.

Tuning options:

- **Exclude Authorized Admin Accounts:** Add exception conditions for authorized sysadmin accounts or dedicated management workstations if false positives occur during routine maintenance.
- **Combine with File Creation Auditing:** Create correlated rules monitoring for fast output file creation (`.txt` / `.csv`) alongside process execution.
- **Block Unsigned Binaries:** Enforce Application Control (AppLocker/WDAC) to block unauthorized execution of standalone utility binaries like AdFind across non-admin endpoints.

Monitoring AdFind provides vital early-warning signals to disrupt adversary domain enumeration before lateral movement or ransomware deployment occurs.
