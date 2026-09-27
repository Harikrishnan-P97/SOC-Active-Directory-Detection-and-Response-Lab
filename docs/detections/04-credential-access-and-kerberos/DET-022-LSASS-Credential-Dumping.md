# Detection 022 — LSASS Credential Dumping

## Objective

Detect process access attempts targeting `lsass.exe` (Local Security Authority Subsystem Service), identifying potential credential dumping activity within Windows endpoints.

The `lsass.exe` process manages user authentication and credentials, storing sensitive material such as Kerberos tickets, NTLM hashes, and cleartext passwords in system memory. Adversaries frequently attempt to read memory from `lsass.exe` using utilities like Mimikatz, ProcDump, ComSvcs.dll, or custom C2 tools to extract cached credentials for privilege escalation and lateral movement. DET-022 leverages Sysmon Event ID 10 (ProcessAccess) to flag applications attempting to open handles to `lsass.exe`.

## MITRE ATT&CK

**Related Sub-technique:** T1003.001 — OS Credential Dumping: LSASS Memory

Adversaries may attempt to access credentials stored in the LSASS process memory to obtain account secrets and impersonate users across the domain.

DET-022 monitors cross-process access requests targeting `lsass.exe` to catch memory extraction attempts.

## Windows / Sysmon Events

**Sysmon Event ID:** `10` — Process Access (ProcessAccess).

Relevant fields include:

- Source Image (`win.eventdata.sourceImage`): Path of the binary requesting process handle access
- Target Image (`win.eventdata.targetImage`): Path of the target binary (`lsass.exe`)
- Granted Access (`win.eventdata.grantedAccess`): Mask indicating requested rights (e.g., `0x1010`, `0x1F0FFF`, `0x1410`)
- Call Trace (`win.eventdata.callTrace`)
- Source Process ID (`win.eventdata.sourceProcessId`)
- Target Process ID (`win.eventdata.targetProcessId`)
- Source User (`win.eventdata.sourceUser`)

Access masks like `0x1010` (`PROCESS_VM_READ` | `PROCESS_QUERY_INFORMATION`) or `0x1F0FFF` (`PROCESS_ALL_ACCESS`) are common flags when memory dumping tools target LSASS.

## Detection Logic

```text
Sysmon Event 10 (ProcessAccess)
        ↓
Sysmon base group check (sysmon_event_10)
        ↓
Custom rule 100121 (TargetImage matches \lsass.exe)
        ↓
DET-022 alert (Level 12)
```

The rule evaluates process access logs under the `sysmon_event_10` group.

The rule explicitly evaluates:

```text
win.eventdata.targetImage ends with \lsass.exe (case-insensitive)
```

By tracking any non-standard process opening a handle to `lsass.exe`, custom rule 100121 detects potential memory access attempts used in credential harvesting.

## Wazuh Rule

```xml
<rule id="100121" level="12">
    <if_group>sysmon_event_10</if_group>

    <field name="win.eventdata.targetImage" type="pcre2">(?i)\lsass\.exe$</field>

    <description>DET-022 - Possible LSASS credential dumping: $(win.eventdata.sourceImage) accessed $(win.eventdata.targetImage) with access $(win.eventdata.grantedAccess)</description>

    <mitre>
        <id>T1003.001</id>
    </mitre>
    <group>
        custom_detection_engineering,
        windows,
        credential_access,
        lsass
    </group>
</rule>
```

### Rule Details

| Field | Value |
|---|---|
| Detection ID | DET-022 |
| Wazuh Rule ID | 100121 |
| Severity | 12 (High) |
| Parent Group | `sysmon_event_10` |
| Detection Type | LSASS Credential Dumping |
| Event Source | Sysmon Event ID 10 |
| Target Process | `\lsass.exe` |
| MITRE Technique | T1003.001 |
| Category | Credential Access / LSASS |

---

## Simulation

An LSASS credential dumping simulation was executed in the test lab using ProcDump and Mimikatz.

```text
Attacker Host / Workstation
        ↓
Executes command: procdump.exe -ma lsass.exe lsass.dmp
  OR runs Mimikatz: sekurlsa::logonpasswords
        ↓
Process opens handle to lsass.exe requesting memory read permissions
        ↓
Sysmon generates Event ID 10 (ProcessAccess to \lsass.exe)
        ↓
Wazuh sysmon_event_10 group matches
        ↓
Custom rule 100121 matches
        ↓
DET-022 alert generated (Level 12)
```

## Expected Alert

The expected Wazuh alert contains:

- **Detection:** `DET-022`
- **Rule ID:** `100121`
- **Severity:** `12`
- **Sysmon Event ID:** `10`
- Source Image (`sourceImage`)
- Target Image (`targetImage = C:\Windows\System32\lsass.exe`)
- Granted Access (`grantedAccess`)
- Source User (`sourceUser`)
- Timestamp

The alert description explicitly reports:

```text
DET-022 - Possible LSASS credential dumping: <sourceImage> accessed <targetImage> with access <grantedAccess>
```

## Validation Result

**Status: VALIDATED**

Custom rule 100121 successfully intercepted Sysmon Event 10 entries targeting `lsass.exe`, immediately raising a severity 12 alert upon handle access detection.

## Investigation Playbook

When DET-022 triggers, SOC analysts must verify whether the accessing application is a legitimate security agent or a credential theft utility.

### 1. Inspect Source Image and Path

Review:

- **Source Image:** (`win.eventdata.sourceImage`) — Is the accessing process a recognized binary (e.g., AV/EDR agent, `svchost.exe`, `csrss.exe`) or an unauthorized utility (`procdump.exe`, `mimikatz.exe`, `powershell.exe`, `rundll32.exe`)?
- Unsigned binaries running from `\AppData\`, `\Temp\`, or `\Downloads\` requesting LSASS access indicate high threat potential.

### 2. Evaluate Granted Access Mask

Review:

- **Granted Access:** (`win.eventdata.grantedAccess`)
  - `0x1010` or `0x1410`: Common for dumpers reading VM memory (`PROCESS_VM_READ`).
  - `0x1F0FFF`: Full access (`PROCESS_ALL_ACCESS`), highly indicative of malicious memory manipulation.

### 3. Analyze Call Trace

Inspect the `callTrace` field in Sysmon Event 10:

- Look for native DLLs like `dbghelp.dll`, `comsvcs.dll`, or `lsasrv.dll`. 
- `comsvcs.dll` combined with `rundll32.exe` (`MiniDump` function call) is a classic native LSASS dumping technique.

### 4. Check Parent Process & Command Line Context

Correlate with Sysmon Event 1 (Process Creation):

- Did `powershell.exe`, `cmd.exe`, or `rundll32.exe` spawn the source process?
- Check for command-line arguments involving dump paths (`lsass.dmp`, `out.dmp`).

### 5. Determine Classification

Classify the event:

- **False Positive:** Antivirus software, EDR agent, or system management tools (e.g., Task Manager creating a process dump manually for troubleshooting).
- **True Positive:** Credential dumping attack aiming to extract hashes and cleartext credentials.

## Response Playbook

### If activity is confirmed malicious

- **Isolate Host:** Immediately isolate the endpoint from the network via EDR/Wazuh response scripts.
- **Terminate Malicious Process:** Kill the source process (`sourceImage` / `sourceProcessId`).
- **Reset Compromised Credentials:** Force password resets for any accounts currently logged into the compromised machine (especially Domain Admins or Service Accounts).
- **Collect Dump Artifacts:** Search for created `.dmp` files on disk and remove them securely.
- **Scope Lateral Movement:** Search SIEM for successful logons (Event 4624) originating from this host to other endpoints.

## False Positives

Common benign sources include:

- Endpoint Protection Platforms (EPP / EDR agents) scanning LSASS memory for threats.
- Windows System processes (`csrss.exe`, `services.exe`, `wininit.exe`).
- IT Administrators generating memory dumps for debugging via Sysinternals tools or Task Manager.

## Tuning Considerations

DET-022 runs at **High Severity (Level 12)**.

Tuning options to minimize false alerts:

- **Whitelist Known Security Agents:** Exclude trusted, signed binaries (e.g., `MsMpEng.exe` for Windows Defender, EDR agent paths) by adding a child rule or field exclusions for `win.eventdata.sourceImage`.
- **Filter Specific Granted Access:** Focus high-level alerts on specific aggressive access masks (`0x1010`, `0x1F0FFF`, `0x1410`).

Monitoring handle creation against `lsass.exe` forms a vital defensive layer against credential theft.
