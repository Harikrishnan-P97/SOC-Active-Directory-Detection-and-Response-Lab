# Detection 041 — Windows Firewall Rule Added/Modified/Deleted

## Objective

Detect when a Windows Firewall exception rule is added, modified, or deleted on a Windows system.

Windows Defender Firewall controls inbound and outbound network traffic based on configured rules. Threat actors who gain administrative or SYSTEM access often modify local firewall rules to permit inbound Remote Desktop (RDP), command-and-control (C2) callback traffic, or lateral movement channels, or to block security software network traffic. DET-041 monitors Windows Security Event IDs 4946, 4947, and 4948 to ensure full visibility into host-based firewall policy changes.

## MITRE ATT&CK

**Related Techniques:**
- **T1562.004** — Impair Defenses: Disable or Modify System Firewall

Adversaries modify host firewall configurations using tools like `netsh advfirewall`, PowerShell (`New-NetFirewallRule`, `Set-NetFirewallRule`), or registry edits to open network ports or suppress defensive logging and blocking mechanisms.

## Windows / Sysmon Events

**Base Rule:** `60103` — Generic Windows Firewall / Audit Rule Event.

Relevant fields and trigger conditions include:

- Event ID (`win.system.eventID`): `4946`, `4947`, or `4948`
  - **Event ID 4946:** A change has been made to the Windows Firewall exception list (A rule was added).
  - **Event ID 4947:** A change has been made to the Windows Firewall exception list (A rule was modified).
  - **Event ID 4948:** A change has been made to the Windows Firewall exception list (A rule was deleted).
- Rule Name (`win.eventdata.ruleName`): Name of the modified or added firewall rule.
- Rule ID (`win.eventdata.ruleId`): Unique identifier for the firewall rule.

## Detection Logic

```text
Windows Security Log
        ↓
Event ID matches Regex: ^(4946|4947|4948)$ (Parent Rule 60103)
        ↓
Custom rule 100140 matches
        ↓
DET-041 alert generated (Level 7 - Medium Severity)
```

The rule triggers when Windows Security log events match parent rule `60103` AND `win.system.eventID` explicitly matches Event IDs `4946`, `4947`, or `4948`.

## Wazuh Rule

```xml
<rule id="100140" level="7">

    <if_sid>60103</if_sid>

    <field name="win.system.eventID" type="pcre2">^(4946|4947|4948)$</field>

    <description>
        DET-041 - Windows Firewall exception rule changed: $(win.eventdata.ruleName) (Event $(win.system.eventID))
    </description>

    <group>
        windows,
        defense_evasion,
        firewall_change,
        custom_detection_engineering,
        custom_detection
    </group>

    <mitre>
        <id>T1562.004</id>
    </mitre>

</rule>
```

### Rule Details

| Field | Value |
|---|---|
| Detection ID | DET-041 |
| Wazuh Rule ID | 100140 |
| Severity | 7 (Medium Severity) |
| Parent Rule ID | 60103 (Windows Firewall Event) |
| Detection Type | Windows Security Event Audit |
| Event Source | Windows Security Log |
| Targeted Event IDs | 4946, 4947, 4948 |
| MITRE Techniques | T1562.004 |
| Category | Defense Evasion / Firewall Modification |

---

## Simulation

A Windows Firewall modification simulation was conducted in the lab environment using `netsh` and PowerShell commands.

```text
Attacker / Compromised Administrator
        ↓
Executes command to open an inbound port:
  > netsh advfirewall firewall add rule name="Malicious_Inbound" dir=in action=allow protocol=TCP localport=4444
    OR
  > New-NetFirewallRule -DisplayName "Allow RDP Custom" -Direction Inbound -LocalPort 3389 -Protocol TCP -Action Allow
        ↓
Windows Security Log records Event ID 4946 (Rule Added)
        ↓
Wazuh parent rule 60103 matches
        ↓
Custom rule 100140 matches
        ↓
DET-041 alert generated (Level 7)
```

## Expected Alert

The expected Wazuh alert contains:

- **Detection:** `DET-041`
- **Rule ID:** `100140`
- **Severity:** `7`
- Description: `DET-041 - Windows Firewall exception rule changed: <RULE_NAME> (Event <EVENT_ID>)`
- Rule Name (`win.eventdata.ruleName`)
- Event ID (`win.system.eventID`)
- Timestamp

Example Alert Description Output:

```text
DET-041 - Windows Firewall exception rule changed: Malicious_Inbound (Event 4946)
```

## Validation Result

**Status: VALIDATED**

Custom rule 100140 successfully generated Level 7 alerts whenever firewall exception rules were created, updated, or removed using `netsh`, PowerShell, or GPO updates.

## Investigation Playbook

When DET-041 triggers, SOC analysts must verify whether the firewall rule modification was part of an approved administrative change or an attempt to bypass network filtering.

### 1. Analyze Event Details & Rule Intent

- **Action & Protocol:** Determine whether the rule allows inbound access to sensitive ports (e.g., 3389 RDP, 445 SMB, 5985/5986 WinRM, custom C2 ports) or blocks outbound connections for security agents.
- **Rule Name (`win.eventdata.ruleName`):** Look for suspicious or randomized rule names, or rules impersonating legitimate software (e.g., `Chrome Update`, `System`).

### 2. Identify Modifying Process & User Context

- Correlate the event timestamp with Sysmon Event ID 1 (Process Creation) to find the process responsible for the modification (`netsh.exe`, `powershell.exe`, or `mmc.exe`).
- Check the account context executing the command.

### 3. Verify IT / Change Management Approval

- Verify if system administrators were deploying firewall policies via Group Policy Objects (GPO) or authorized software installation.

### 4. Determine Classification

Classify the event:

- **False Positive / Benign:** Authorized software installation (e.g., VPN client, enterprise backup agent) or scheduled IT policy deployment via GPO.
- **True Positive:** Unauthorized firewall exception added by an adversary to facilitate lateral movement, remote access, or C2 traffic.

## Response Playbook

### If activity is confirmed malicious

- **Remove Malicious Firewall Rule:** Delete the added rule immediately:
  ```cmd
  netsh advfirewall firewall delete rule name="<RULE_NAME>"
  ```
- **Isolate Endpoint:** Isolate the host from the network to prevent remote access through the opened port.
- **Revoke Privileged Account Credentials:** Reset credentials for the user account used to perform the firewall modification.
- **Inspect Network Connections:** Review active socket connections (`netstat -ano` or Sysmon Event ID 3) to see if external connections were established over the modified port.

## False Positives

Common benign sources include:

- Automatic firewall rules created during legitimate software installations or updates.
- Centralized GPO firewall policy deployments across domain-joined machines.

## Tuning Considerations

DET-040/DET-041 operates at **Medium Severity (Level 7)**.

Tuning options:

- **Filter Benign GPO Rules:** If enterprise GPO updates generate excessive 4947/4946 events during routine refreshes, filter out specific known-good rule names or authorized service account execution paths.
- **Escalate Inbound Allow Rules:** Consider creating a higher-severity child rule (Level 10+) specifically when new inbound allow rules for sensitive management ports (3389, 5985, 445) are added outside of GPO execution.

Monitoring host firewall adjustments prevents adversaries from silently establishing persistent, unmonitored inbound or outbound network channels.
