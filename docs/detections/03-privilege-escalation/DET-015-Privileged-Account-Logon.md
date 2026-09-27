# Detection 015 — Privileged Account Logon

## Objective

Detect interactive, network, or Remote Desktop Protocol (RDP) logons involving targeted highly privileged or administrative accounts, providing visibility into administrative session establishment and potential compromised credential usage.

Monitoring successful administrative authentication events is critical for Tier-0 asset defense and early detection of lateral movement. Adversaries possessing stolen administrative credentials frequently utilize standard authentication protocols (such as interactive desktop, SMB network shares, or Remote Desktop Services) to operate stealthily within target environments without triggering explicit brute-force or exploitation detections.

DET-015 logs high-value logon sessions to establish audit trails for administrative access, verify privileged access management (PAM) policy compliance, and detect unexpected remote administrative connections.

## MITRE ATT&CK

**Related Technique:** T1078 — Valid Accounts

Adversaries may obtain and leverage credentials of existing privileged accounts to access systems, move laterally, bypass access controls, and maintain persistent access across a domain or host environment.

DET-015 captures successful logon events for monitored high-privilege accounts (`Administrator`, `labadmin`, `testuser`) across Interactive, Network, and RDP logon types. Analysts must investigate the source IP address, target system context, logon timing, and session intent.

## Windows Events

**Event ID:** `4624` — An account was successfully logged on.

Relevant fields include:

- Target account name (`win.eventdata.targetUserName`)
- Logon type (`win.eventdata.logonType`):
  - **Type 2:** Interactive (local console / keyboard)
  - **Type 3:** Network (e.g., SMB share, IPC$, WinRM, network authentication)
  - **Type 10:** RemoteInteractive / RDP (Terminal Services / Remote Desktop)
- Source IP address (`win.eventdata.ipAddress`)
- Source workstation name (`win.eventdata.workstationName`)
- Logon Process Name (`win.eventdata.logonProcessName`)
- Authentication Package (`win.eventdata.authenticationPackageName`)
- Computer name / Domain Controller
- Timestamp

The **target username** identifies the privileged account logging in, while the **logon type** and **IP address** specify the access vector and origin.

## Detection Logic

```text
Windows Event 4624
        ↓
Wazuh base rule 60106
        ↓
Custom rule 100114
        ↓
DET-015 alert
```

The rule triggers on successful logon events processed under Wazuh base rule `60106`.

The rule explicitly requires regular expression matching across three parameters:

```text
win.system.eventID = 4624
win.eventdata.logonType = 2 | 3 | 10
win.eventdata.targetUserName = Administrator | labadmin | testuser
```

No time-window or thresholding is applied by DET-015; any matching logon event generates a level 10 alert.

## Wazuh Rule

```xml
<rule id="100114" level="10">
    <if_sid>60106</if_sid>

    <field name="win.system.eventID" type="pcre2">^4624$</field>
    <field name="win.eventdata.logonType" type="pcre2">^(2|3|10)$</field>
    <field name="win.eventdata.targetUserName" type="pcre2">^(Administrator|labadmin|testuser)$</field>

    <description>
        DET-015 - Privileged account logon detected: $(win.eventdata.targetUserName) from $(win.eventdata.ipAddress)
    </description>

    <mitre>
        <id>T1078</id>
    </mitre>

    <group>
        custom_detection_engineering,
        windows,
        authentication,
        privileged_access
    </group>
</rule>
```

### Rule Details

| Field | Value |
|---|---|
| Detection ID | DET-015 |
| Wazuh Rule ID | 100114 |
| Severity | 10 |
| Parent Rule | 60106 |
| Detection Type | Privileged Account Logon |
| Windows Event | 4624 |
| MITRE Technique | T1078 |
| Category | Authentication / Privileged Access |

---

## Simulation

A controlled privilege-authentication event was simulated in the lab environment by initiating an RDP session (Logon Type 10) or network access (Logon Type 3) using one of the monitored privileged accounts (`Administrator`, `labadmin`, or `testuser`).

```text
Source Workstation / IP Address
        ↓
Authenticates via RDP (Type 10) or Network (Type 3) as labadmin
        ↓
Windows generates Event 4624
        ↓
Wazuh base rule 60106 matches
        ↓
Custom rule 100114 matches
        ↓
DET-015 alert generated
```

## Expected Alert

The expected Wazuh alert contains:

- **Detection:** `DET-015`
- **Rule ID:** `100114`
- **Severity:** `10`
- **Windows Event:** `4624`
- Target account name (`Administrator`, `labadmin`, or `testuser`)
- Source IP Address
- Logon Type (`2`, `3`, or `10`)
- Computer / Host name
- Timestamp

The alert description explicitly reports:

```text
DET-015 - Privileged account logon detected: <targetUserName> from <ipAddress>
```

## Validation Result

**Status: VALIDATED**

The rule successfully identified Windows Event 4624 authentication telemetry matching specified high-privilege accounts across Logon Types 2, 3, and 10 via base rule `60106`, triggering custom alert 100114.

The detection provides real-time visibility into administrative logons and remote access vectors.

## Investigation Playbook

When DET-015 fires, analysts must determine if the privileged logon is part of authorized, routine maintenance or represents unauthorized credential usage.

### 1. Analyze logon parameters and source origin

Review:

- **Target Username:** (`Administrator`, `labadmin`, `testuser`)
- **Logon Type:** Interactive (`2`), Network (`3`), or RDP (`10`)
- **Source IP Address & Workstation Name:** Internal jump box, VPN subnet, DC, or external IP
- **Target Computer Name:** Endpoint, Server, or Domain Controller

Evaluate whether the source IP belongs to an authorized Privileged Access Workstation (PAW), IT jump box, or automated management server.

### 2. Verify change management and operational context

Check:

- Active IT Service Desk change tickets or emergency maintenance windows
- Shift schedules for systems administration personnel
- Remote access / PAM gateway session logs corresponding to the timestamp

Logons occurring outside standard business hours from non-PAW subnets require immediate scrutiny.

### 3. Review preceding authentication telemetry

Check for suspicious activity immediately preceding the successful logon:

- Multiple failed logon attempts (Event 4625) from the same source IP (brute-force or password spraying)
- Recent password resets (**DET-008**) or account status changes (**DET-009**, **DET-014**)

### 4. Audit execution telemetry within the session

Review post-logon host activity (Process Creation Event 4688 / Sysmon Event 1):

- Administrative CLI execution (`powershell.exe`, `cmd.exe`, `wmic.exe`, `psexec.exe`)
- Credential dumping or enumeration tools (`mimikatz`, `bloodhound`, `net.exe`)
- Security setting tampering, service creation, or firewall modifications

### 5. Determine classification

Classify the event:

- **Authorized Administrative Session:** Valid IT maintenance from an authorized PAW/Jump host with matching ticket.
- **Policy Violation:** IT personnel logging directly into servers from non-hardened endpoints instead of using PAM gateways.
- **Compromised Account / Adversarial Access:** Unauthorized authentication leveraging stolen valid credentials.

## Response Playbook

### If the activity is benign

- Confirm ticket authorization with the performing administrator.
- Ensure compliance with secure administrative access policies.
- Document ticket details in the SOC case notes.
- Close the alert as authorized administrative activity.

### If the activity violates policy (e.g., direct logon bypassing PAW)

- Notify the administrator and IT management of the compliance policy violation.
- Require session termination and reconnection via official PAM/Jump Box infrastructure.

### If compromise is suspected

- Terminate active logon sessions for the account on the target system.
- Immediately disable or lock out the compromised target account (`Administrator` / `labadmin`).
- Force a password reset across Active Directory or local SAM.
- Isolate both the source IP host (if internal) and target system via EDR.
- Review Active Directory logs across all Domain Controllers for lateral movement or persistence creation.
- Initiate the Incident Response Playbook.

## False Positives

Common benign sources include:

- Scheduled administrative scripts or backups operating under static local service credentials.
- Routine remote management by systems engineers via approved jump boxes.
- Automated vulnerability scanners or IT management software.

## Tuning Considerations

DET-014 operates at **medium-high severity (Level 10)**.

The current rule structure:

```text
Windows Event 4624 + Logon Types (2|3|10) + Target Users
        ↓
Wazuh rule 60106
        ↓
DET-015 / Rule 100114
```

Tuning options include:

- Expanding the regular expression to monitor newly provisioned administrative accounts or domain-specific admin groups.
- Filtering out trusted source IP addresses (e.g., dedicated PAWs or PAM gateways) to reduce noise.
- Elevating alert severity to Level 13 if Logon Type 3 or 10 originates from unknown or external IP ranges.
- Correlating with process creation events to flag logons that immediately launch command shells.

Tracking privileged account authentication ensures valid credentials cannot be used silently for undetected lateral movement.
