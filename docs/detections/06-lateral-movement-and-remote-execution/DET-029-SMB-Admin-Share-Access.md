# Detection 029 — SMB Admin Share Access

## Objective

Detect access to hidden administrative network shares (`ADMIN$` or `C$`) over Server Message Block (SMB).

Administrative shares are default network shares created by Windows NT-based operating systems to enable remote administration, patch management, and system maintenance. Adversaries and automated post-exploitation toolkits (e.g., PsExec, Impacket's `smbexec`/`psexec`, Cobalt Strike) routinely connect to `ADMIN$` or `C$` to stage payloads, drop binaries, and execute commands remotely during lateral movement. DET-029 monitors Windows SMB share access events to flag incoming connections targeting these sensitive administrative shares.

## MITRE ATT&CK

**Related Techniques:**
- **T1021.002** — Remote Services: SMB/Windows Admin Shares

Adversaries leverage administrative shares over SMB (TCP 445) to transfer files, execute code remotely under privileged contexts, and move laterally across domain-joined hosts.

## Windows / Sysmon Events

**Base Rule:** `67017` — Windows Security Event ID 5140 (A network share object was accessed).

Relevant fields include:

- Target Share Name (`win.eventdata.shareName`): Shared path accessed, evaluated via regular expression (e.g., `\\*\ADMIN$`, `\\*\C$`)
- Subject User Name (`win.eventdata.subjectUserName`): Account attempting SMB access
- Subject Domain Name (`win.eventdata.subjectDomainName`): Domain of the connecting account
- Source Address (`win.eventdata.ipAddress`): Source IP address initiating the SMB connection
- Source Port (`win.eventdata.ipPort`): Source TCP port of the connection

## Detection Logic

```text
Windows Event ID 5140 (Rule 67017 / Network Share Access)
        ↓
Regex Match on win.eventdata.shareName:
(ADMIN|C)\$
        ↓
Custom rule 100128 matches
        ↓
DET-029 alert generated (Level 12 - High)
```

The rule triggers when Windows Security Event ID 5140 (Network Share Access) matches parent rule `67017`.

It evaluates `win.eventdata.shareName` using PCRE2 regular expression matching:

```regex
(ADMIN|C)\$
```

This regular expression matches accesses to either the `ADMIN$` share (pointing to `C:\Windows`) or the `C$` default system drive share.

## Wazuh Rule

```xml
<rule id="100128" level="12">

    <if_sid>67017</if_sid>

    <field name="win.eventdata.shareName" type="pcre2">(ADMIN|C)\$</field>

    <description>
        DET-029 Administrative SMB Share Access - $(win.eventdata.subjectDomainName)\$(win.eventdata.subjectUserName)
    </description>

    <mitre>
        <id>T1021.002</id>
    </mitre>

    <group>
        custom_windows,
        lateral_movement,
        smb,
        attack.t1021.002
    </group>

</rule>
```

### Rule Details

| Field | Value |
|---|---|
| Detection ID | DET-029 |
| Wazuh Rule ID | 100128 |
| Severity | 12 (High) |
| Parent Rule ID | 67017 (Event ID 5140 - Network Share Object Access) |
| Detection Type | SMB Lateral Movement |
| Event Source | Windows Security Event ID 5140 |
| Target Shares | `ADMIN$` / `C$` |
| MITRE Techniques | T1021.002 |
| Category | Lateral Movement / Remote Access |

---

## Simulation

A lateral movement SMB share access simulation was performed in the lab environment.

```text
Attacker Workstation (192.168.1.110)
        ↓
Mounts remote administrative share on Target Host (192.168.1.120):
  > net use \\192.168.1.120\C$ /user:DOMAIN\admin password
        ↓
Target Windows Host generates Security Event ID 5140
        ↓
Wazuh parent rule 67017 matches
        ↓
Custom rule 100128 matches regex (C$)
        ↓
DET-029 high-severity alert generated (Level 12) showing connecting domain/user
```

## Expected Alert

The expected Wazuh alert contains:

- **Detection:** `DET-029`
- **Rule ID:** `100128`
- **Severity:** `12`
- Description: `DET-029 Administrative SMB Share Access - <DOMAIN>\<USER>`
- Target Share (`win.eventdata.shareName`)
- Source IP Address (`win.eventdata.ipAddress`)
- Subject User Name (`win.eventdata.subjectUserName`)
- Subject Domain Name (`win.eventdata.subjectDomainName`)
- Timestamp

Example Alert Description Output:

```text
DET-029 Administrative SMB Share Access - DOMAIN\admin_user
```

## Validation Result

**Status: VALIDATED**

Custom rule 100128 successfully generated Level 12 high-severity alerts upon incoming connections targeting `ADMIN$` and `C$` network shares.

## Investigation Playbook

When DET-029 triggers, SOC analysts must immediately assess whether the remote share access is part of an authorized IT administrative task or an active lateral movement attempt.

### 1. Verify Administrative Intent

Review:

- **Change Management / Support Schedule:** Check if an approved software deployment, vulnerability scan, or remote support session was scheduled for the target host.
- **Source IP Address:** (`win.eventdata.ipAddress`) — Is the connection originating from a known admin jump box, deployment server (e.g., SCCM), or an unmanaged workstation?

### 2. Inspect Correlated Remote Executions

Check logs on the target host for corresponding events immediately following share access:

- **Sysmon Event ID 11 (File Creation):** Look for new executables, DLLs, or batch scripts dropped into `C:\Windows\` or `C:\Windows\System32\`.
- **Windows Event ID 7045 / 4697 (Service Installation):** Check for temporary remote services registered right after share access (indicative of PsExec or Impacket).

### 3. Evaluate User Account Context

Review:

- **Account Type:** (`win.eventdata.subjectUserName`) — Is the connecting account a legitimate Domain Admin or a compromised local user/service account?

### 4. Determine Classification

Classify the event:

- **False Positive / Benign:** Authorized SCCM/EDR management deployment or documented IT administration.
- **True Positive:** Unauthorized remote SMB administrative share mounting indicating adversary staging or lateral movement.

## Response Playbook

### If activity is confirmed malicious

- **Isolate Endpoint:** Disconnect the target endpoint and source host from the network immediately to disrupt active SMB sessions and prevent payload delivery.
- **Revoke Compromised Credentials:** Lock the user account involved and force password resets across all active domain sessions.
- **Triage File Drops:** Inspect `C:\Windows\` and root directories for newly dropped binaries, scripts, or stage files and harvest IOCs.
- **Perform Forensic Memory Analysis:** Capture host memory to verify if payload execution occurred following SMB share access.
- **Restrict SMB Access:** Enforce host-based firewall policies restricting SMB (TCP 445) ingress to authorized administrative jump boxes only.

## False Positives

Common benign sources include:

- Enterprise software deployment tools (e.g., Microsoft SCCM, PDQ Deploy, vulnerability scanners) staging files remotely over `ADMIN$` or `C$`.
- Backup software accessing disk shares over network shares during scheduled backups.

## Tuning Considerations

DET-029 operates at **High Severity (Level 12)** due to the critical role SMB shares play in adversary lateral movement.

Tuning options:

- **Source IP Whitelisting:** If automated deployment servers generate persistent false positives, create exception rules filtering out approved source IP addresses (e.g., SCCM server IP).
- **Correlate with File Writes:** Pair Event ID 5140 with file creation events to escalate alerts specifically when files are written to `ADMIN$` or `C$`.
- **Disable Auto Admin Shares:** Where feasible, disable default administrative shares via Group Policy (`AutoShareWks` / `AutoShareServer`) on non-essential endpoints.

Monitoring administrative share access provides crucial early detection of remote staging and lateral movement across domain networks.
