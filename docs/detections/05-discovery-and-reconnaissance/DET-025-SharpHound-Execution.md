# Detection 025 — SharpHound / BloodHound Collector Execution

## Objective

Detect execution of the SharpHound collector tool used for Active Directory domain enumeration and mapping attack paths in BloodHound.

SharpHound is the C#-based data collector component of BloodHound, used by penetration testers and adversaries to gather extensive Active Directory (AD) data. It enumerates domain users, groups, sessions, computers, ACLs, trusts, and GPOs to discover attack paths toward domain dominance. DET-025 monitors Windows process execution events to flag instances where the collector executable runs, based on original file PE metadata.

## MITRE ATT&CK

**Related Techniques:**
- **T1087** — Account Discovery (Account Discovery: Domain Account)
- **T1069.002** — Permission Groups Discovery: Domain Groups
- **T1482** — Domain Trust Discovery

Adversaries use SharpHound to enumerate Active Directory structures, map privilege escalation routes, and identify high-value targets within the domain.

## Windows / Sysmon Events

**Base Rule:** `61603` — Sysmon Event ID 1 (Process Creation) / Windows Process Audit Event.

Relevant fields include:

- Original File Name (`win.eventdata.originalFileName`): `SharpHound.exe`
- Image Path (`win.eventdata.image`): Path of the binary being executed
- Command Line (`win.eventdata.commandLine`): Arguments passed during execution (e.g., `--CollectionMethods All`)
- User (`win.eventdata.user`): Account executing the collector tool
- Parent Image (`win.eventdata.parentImage`): Parent process launching the binary (e.g., `cmd.exe`, `powershell.exe`)
- Process Hash (`win.eventdata.hashes`): SHA256/MD5 hashes of the binary

Monitoring `originalFileName` catches execution even if the binary has been renamed (e.g., `update.exe` or `svchost.exe`).

## Detection Logic

```text
Sysmon Process Creation Event (Rule 61603 / Event ID 1)
        ↓
Check originalFileName matches "SharpHound.exe"
        ↓
Custom rule 100124 matches
        ↓
DET-025 alert generated (Level 10 - Medium/High)
```

The rule evaluates process creation events under parent rule `61603`.

The rule explicitly checks:

```text
win.eventdata.originalFileName equals SharpHound.exe
```

By inspecting the internal PE headers (`originalFileName`), custom rule 100124 reliably identifies SharpHound execution regardless of binary renaming attempts.

## Wazuh Rule

```xml
<rule id="100124" level="10">

    <if_sid>61603</if_sid>

    <field name="win.eventdata.originalFileName">SharpHound.exe</field>

    <description>
        DET-025 SharpHound / BloodHound Collector Execution
    </description>

    <group>
        custom_windows,
        discovery,
        bloodhound,
        sharphound,
        active_directory,
        attack.t1087,
        attack.t1482
    </group>

    <mitre>
        <id>T1087</id>
        <id>T1069.002</id>
        <id>T1482</id>
    </mitre>

</rule>
```

### Rule Details

| Field | Value |
|---|---|
| Detection ID | DET-025 |
| Wazuh Rule ID | 100124 |
| Severity | 10 (Medium / High) |
| Parent Rule ID | 61603 (Sysmon Event ID 1) |
| Detection Type | Reconnaissance / Active Directory Discovery |
| Event Source | Sysmon Event ID 1 (Process Creation) |
| Target File | `SharpHound.exe` (via PE Original File Name) |
| MITRE Techniques | T1087, T1069.002, T1482 |
| Category | Discovery / Reconnaissance |

---

## Simulation

A domain reconnaissance simulation was conducted in the lab environment using SharpHound.

```text
Attacker Host / Compromised Endpoint (192.168.1.105)
        ↓
Executes: SharpHound.exe --CollectionMethods All --ZipFileName bloodhound_data.zip
        ↓
Target Windows Host generates Sysmon Event ID 1 (Process Creation)
        ↓
Wazuh parent rule 61603 triggers
        ↓
Custom rule 100124 matches PE header metadata (originalFileName = SharpHound.exe)
        ↓
DET-025 alert generated (Level 10)
```

## Expected Alert

The expected Wazuh alert contains:

- **Detection:** `DET-025`
- **Rule ID:** `100124`
- **Severity:** `10`
- Executable Image Path (`win.eventdata.image`)
- Original File Name (`win.eventdata.originalFileName = SharpHound.exe`)
- Command Line (`win.eventdata.commandLine`)
- Execution User (`win.eventdata.user`)
- Timestamp

The alert description explicitly reports:

```text
DET-025 SharpHound / BloodHound Collector Execution
```

## Validation Result

**Status: VALIDATED**

Custom rule 100124 successfully identified the execution of SharpHound via PE header inspection, triggering a level 10 alert even when execution flags were customized.

## Investigation Playbook

When DET-025 triggers, SOC analysts must quickly assess whether an unauthorized entity or scheduled red team assessment is conducting AD mapping.

### 1. Verify Authorization & Assessment Schedules

Review:

- **Red Team / Audit Context:** Check internal ticketing and notification channels to determine if authorized penetration testing or security assessments are active.
- **User Account:** (`win.eventdata.user`) — Is the command executed by an administrative user, service account, or a standard enterprise workstation user?

### 2. Analyze Command Line & Output Artifacts

Review:

- **Command Line Arguments:** (`win.eventdata.commandLine`) — Look for collection flags such as `--CollectionMethods All`, `Dsession`, `Group`, `LoggedOn`, or `--ZipFileName`.
- **Output Files:** Check for local creation of `.json` or `.zip` files containing output collections (e.g., `*_BloodHound.zip`).

### 3. Check Parent Process & Execution Context

Review:

- **Parent Image:** (`win.eventdata.parentImage`) — Was it launched from `cmd.exe`, `powershell.exe`, an interactive shell, or an unusual service/C2 process?
- **Binary Path:** (`win.eventdata.image`) — Determine if the file was run from temp paths (`C:\Windows\Temp\`, `C:\Users\...\AppData\Local\Temp\`, `C:\PerfLogs\`).

### 4. Search for Correlated Network Reconnaissance

Correlate with LDAP / RPC network activity:

- SharpHound performs high-volume LDAP queries and RPC calls (SAMR, NetSessionEnum) to Domain Controllers and network endpoints.
- Check Domain Controller event logs for massive LDAP queries originating from the host within the same timeframe.

### 5. Determine Classification

Classify the event:

- **False Positive / Authorized:** Scheduled internal security audit or authorized Red Team simulation.
- **True Positive:** Unauthorized adversary performing active LDAP/AD enumeration to map lateral movement vectors.

## Response Playbook

### If activity is confirmed malicious

- **Isolate Endpoint:** Immediately isolate the compromised endpoint (`host/IP`) to cut off active LDAP enumeration and session scraping.
- **Kill Process & Remove Artifacts:** Terminate the SharpHound process and remove any generated `.zip` or `.json` output collections.
- **Revoke/Reset Credentials:** Reset credentials for the account that executed the tool and audit for any compromised sessions mapped during execution.
- **Analyze Initial Access Vector:** Investigate how the binary was dropped or executed on the host (e.g., web browser download, phishing delivery, remote code execution).
- **Monitor Domain Controllers:** Audit Domain Controller logs for unusual LDAP queries or follow-on privilege escalation attempts.

## False Positives

Common benign sources include:

- Authorized Blue Team / Defense audits mapping AD bloodhound paths for defensive remediation.
- Enterprise security software using embedded components derived from SharpHound libraries (rare).

## Tuning Considerations

DET-025 runs at **Medium/High Severity (Level 10)**.

Tuning options to minimize false alerts:

- **Exclude Authorized Audit Accounts/Hosts:** Filter alerts originating from approved security team service accounts or designated security jump boxes.
- **Combine with PowerShell Auditing:** Supplement this rule with PowerShell script block logging (Event ID 4104) to detect non-compiled PowerShell variants (`Invoke-BloodHound`).
- **LDAP Traffic Thresholds:** Implement behavioral rules on Network/DC logs to alert on sudden spikes in LDAP directory queries.

Tracking SharpHound execution ensures early detection of adversary reconnaissance before lateral movement attack paths can be exploited.
