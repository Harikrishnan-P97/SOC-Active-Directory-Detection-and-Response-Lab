# Detection 032 — Successful RDP Logon Detection

## Objective

Detect successful Remote Desktop Protocol (RDP) logons (Logon Type 10) on Windows endpoints.

RDP allows users to establish an interactive graphical desktop session over port TCP 3389. While RDP is a standard administrative tool, adversaries frequently leverage stolen credentials, compromised local accounts, or session hijacking to navigate enterprise environments laterally via RDP. DET-032 monitors successful Windows logon events specifically flagged with Logon Type 10 to establish visibility into remote interactive access.

## MITRE ATT&CK

**Related Techniques:**
- **T1021.001** — Remote Services: Remote Desktop Protocol

Adversaries use RDP to gain interactive GUI access to target endpoints, execute administrative actions, and move laterally across domain environments.

## Windows / Sysmon Events

**Base Rule:** `92651` — Windows Security Event ID 4624 (An account was successfully logged on).

Relevant fields include:

- Logon Type (`win.eventdata.logonType`): Identifies how the user logged on (`10` = RemoteInteractive / RDP)
- Target User Name (`win.eventdata.targetUserName`): Account that logged in
- Target Domain Name (`win.eventdata.targetDomainName`): Domain associated with the account
- Source IP Address (`win.eventdata.ipAddress`): IP address originating the RDP connection
- Workstation Name (`win.eventdata.workstationName`): Remote computer name initiating the request

## Detection Logic

```text
Windows Security Event ID 4624 (Rule 92651)
        ↓
Regex Match on win.eventdata.logonType:
^10$
        ↓
Custom rule 100131 matches
        ↓
DET-032 alert generated (Level 7 - Medium)
```

The rule triggers when Windows Security Event ID 4624 (Logon Success) matches parent rule `92651`.

It evaluates `win.eventdata.logonType` using PCRE2 regular expression matching:

```regex
^10$
```

This specifies Logon Type 10 (`RemoteInteractive`), which is generated exclusively when a user logs on remotely via Remote Desktop, Terminal Services, or Remote Assistance.

## Wazuh Rule

```xml
<rule id="100131" level="7">
    <if_sid>92651</if_sid>

    <field name="win.eventdata.logonType" type="pcre2">^10$</field>

    <description>
        DET-032 - Successful Remote Desktop (RDP) logon: $(win.eventdata.targetDomainName)\$(win.eventdata.targetUserName) from $(win.eventdata.ipAddress)
    </description>

    <mitre>
        <id>T1021.001</id>
    </mitre>

    <group>
        custom_detection_engineering,
        windows,
        lateral_movement,
        remote_access,
        rdp,
        authentication,
        attack.t1021.001
    </group>
</rule>
```

### Rule Details

| Field | Value |
|---|---|
| Detection ID | DET-032 |
| Wazuh Rule ID | 100131 |
| Severity | 7 (Medium) |
| Parent Rule ID | 92651 (Event ID 4624 - Successful Logon) |
| Detection Type | RDP Authentication |
| Event Source | Windows Security Event ID 4624 |
| Target Logon Type | Type 10 (RemoteInteractive / RDP) |
| MITRE Techniques | T1021.001 |
| Category | Lateral Movement / Remote Access |

---

## Simulation

An RDP authentication simulation was executed in the laboratory environment.

```text
Attacker Workstation / Remote Host (192.168.1.110)
        ↓
Initiates RDP Session to Target Host (192.168.1.120):
  > mstsc.exe /v:192.168.1.120
        ↓
Target Host accepts authentication credentials (DOMAIN\admin_user)
        ↓
Target Windows Host logs Event ID 4624 (Logon Type 10)
        ↓
Wazuh parent rule 92651 matches
        ↓
Custom rule 100131 matches logonType 10
        ↓
DET-032 medium-severity alert generated (Level 7) displaying target account & source IP
```

## Expected Alert

The expected Wazuh alert contains:

- **Detection:** `DET-032`
- **Rule ID:** `100131`
- **Severity:** `7`
- Description: `DET-032 - Successful Remote Desktop (RDP) logon: <DOMAIN>\<USER> from <IP_ADDRESS>`
- Logon Type (`win.eventdata.logonType`)
- Target User Name (`win.eventdata.targetUserName`)
- Target Domain Name (`win.eventdata.targetDomainName`)
- Source IP Address (`win.eventdata.ipAddress`)
- Timestamp

Example Alert Description Output:

```text
DET-032 - Successful Remote Desktop (RDP) logon: DOMAIN\admin_user from 192.168.1.110
```

## Validation Result

**Status: VALIDATED**

Custom rule 100131 successfully generated Level 7 medium-severity alerts for every successful inbound RDP session established across monitored Windows hosts.

## Investigation Playbook

When DET-032 triggers, SOC analysts should review the connection context to verify if the remote desktop session is authorized.

### 1. Verify Source IP & User

Review:

- **Source IP Address:** (`win.eventdata.ipAddress`) — Does the IP belong to an internal VPN pool, approved administrative jump host, or an unexpected network segment/external IP?
- **Target User Account:** (`win.eventdata.targetUserName`) — Is the logging-on user authorized to access the system via RDP?

### 2. Check Time & Behavior Context

- **Time of Day:** Was the logon initiated outside normal business/shift hours?
- **Volume / Anomaly:** Has this account previously logged onto this host via RDP, or is this first-time access?

### 3. Correlate Downstream Interactive Activity

Check process creation events (Sysmon ID 1 / Event ID 4688) under the new logon session:

- Look for immediate launch of administrative consoles (`mmc.exe`, `cmd.exe`, `powershell.exe`), credential harvesting utilities, or network scanning tools.

### 4. Determine Classification

Classify the event:

- **False Positive / Benign:** Authorized IT Administrator or user logging into their assigned machine/jump host.
- **True Positive:** Unauthorized RDP logon, compromised account abuse, or lateral movement via Remote Desktop.

## Response Playbook

### If activity is confirmed malicious

- **Disconnect RDP Session:** Terminate active RDP sessions for the user (`rwinsta <Session_ID>`).
- **Isolate Host:** Network isolate the compromised endpoint to prevent further interactive lateral movement.
- **Revoke Account Credentials:** Reset the user account password and terminate active sessions across Active Directory.
- **Collect Host Artifacts:** Review Terminal Services operational logs (`Microsoft-Windows-TerminalServices-LocalSessionManager/Operational`) for logon and reconnection event history.

## False Positives

Common benign sources include:

- IT support personnel using RDP for remote troubleshooting.
- System administrators accessing servers from jump boxes or VPN gateways.

## Tuning Considerations

DET-032 operates at **Medium Severity (Level 7)** because RDP logons occur regularly in Windows enterprise environments.

Tuning options:

- **Filter Jump Boxes:** Create child rules to lower severity or suppress alerts originating from authorized administrative jump servers.
- **Escalate External / Unexpected IPs:** Elevate alert severity if `win.eventdata.ipAddress` originates from non-internal IP subnets or unmanaged subnets.
- **Combine with Failed Logons:** Correlate DET-032 with prior RDP authentication failure alerts (Event ID 4625) to highlight potential brute-force or password-spray successes.

Monitoring successful RDP connections ensures visibility over remote interactive sessions across the enterprise.
