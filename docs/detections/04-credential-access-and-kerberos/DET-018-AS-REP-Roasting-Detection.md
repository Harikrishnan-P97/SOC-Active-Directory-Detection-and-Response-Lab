# Detection 018 — AS-REP Roasting Detection

## Objective

Detect Kerberos Authentication Ticket (AS-REP / TGT) requests made without Kerberos Pre-Authentication, identifying potential AS-REP Roasting attacks against vulnerable Active Directory user accounts.

AS-REP Roasting is a credential access attack targeting user accounts configured with the "Do not require Kerberos preauthentication" flag (`DONT_REQ_PREAUTH` / `UF_DONT_REQUIRE_PREAUTH`). When an account has pre-authentication disabled, any unauthenticated attacker can send an Authentication Service Request (AS-REQ) to the Domain Controller for that user. The DC immediately returns an AS-REP response containing a Ticket Granting Ticket (TGT) encrypted with the target user's password hash. Attackers extract this encrypted material and attempt to crack the password offline without needing prior valid domain credentials or triggering logon failures.

DET-018 monitors domain controllers for Kerberos TGT requests where pre-authentication was explicitly bypassed (`preAuthType = 0`), capturing target accounts, client source IPs, and encryption types to detect exploitation attempts.

## MITRE ATT&CK

**Related Sub-technique:** T1558.004 — Steal or Acquire Kerberos Tickets: AS-REP Roasting

Adversaries with or without valid domain accounts may request AS-REP responses for target accounts that do not require Kerberos pre-authentication. The returned ticket payload can be cracked offline to recover cleartext user passwords, providing initial access or lateral privilege escalation.

DET-018 alerts directly when a TGT is issued without pre-authentication, enabling security teams to intercept credential harvesting attempts and remediate weak account configurations.

## Windows Events

**Event ID:** `4768` — A Kerberos authentication ticket (TGT) was requested.

Relevant fields include:

- Target Account Name (`win.eventdata.targetUserName`)
- Target SID (`win.eventdata.targetSid`)
- Pre-Authentication Type (`win.eventdata.preAuthType`):
  - `0`: Logged as `-` or `0` (No Pre-Authentication used / explicitly bypassed)
  - `2`: `PA-ENC-TIMESTAMP` (Standard Kerberos Pre-Authentication)
  - `15`: `PA-PK-AS-REQ` (Smart Card / PKINIT)
- Ticket Encryption Type (`win.eventdata.ticketEncryptionType`):
  - `0x17` (23): `RC4-HMAC` (commonly targeted for legacy hash cracking)
  - `0x12` (18): `AES256-CTS-HMAC-SHA1-96`
  - `0x11` (17): `AES128-CTS-HMAC-SHA1-96`
- Client IP Address (`win.eventdata.ipAddress`)
- Client Port (`win.eventdata.ipPort`)
- Ticket Options (`win.eventdata.ticketOptions`)
- Status / Result Code (`win.eventdata.status`): `0x0` (Success)
- Domain Controller Name
- Timestamp

The **targetUserName** identifies the vulnerable account whose TGT was retrieved, while **preAuthType = 0** explicitly signals pre-authentication bypass.

## Detection Logic

```text
Windows Event 4768
        ↓
Wazuh base rule 60103
        ↓
Custom rule 100117 (preAuthType == 0)
        ↓
DET-018 alert
```

The rule triggers on Kerberos authentication ticket request events processed under Wazuh base rule `60103`.

The rule explicitly matches two conditions:

```text
win.system.eventID = 4768
win.eventdata.preAuthType = 0
```

By filtering specifically for `preAuthType = 0`, custom rule 100117 isolates dangerous requests where Kerberos pre-authentication was skipped and generates a high-severity alert.

## Wazuh Rule

```xml
<rule id="100117" level="12">

    <if_sid>60103</if_sid>

    <field name="win.system.eventID">4768</field>

    <field name="win.eventdata.preAuthType">0</field>

    <description>
        DET-018 Possible AS-REP Roasting - Kerberos TGT Requested Without Preauthentication for $(win.eventdata.targetUserName)
    </description>

    <group>
        custom_windows,
        credential_access,
        kerberos,
        asreproasting,
        attack.t1558.004,
    </group>

    <mitre>
        <id>T1558.004</id>
    </mitre>

</rule>
```

### Rule Details

| Field | Value |
|---|---|
| Detection ID | DET-018 |
| Wazuh Rule ID | 100117 |
| Severity | 12 |
| Parent Rule | 60103 |
| Detection Type | AS-REP Roasting |
| Windows Event | 4768 |
| Pre-Auth Field | `preAuthType = 0` |
| MITRE Technique | T1558.004 |
| Category | Credential Access / Kerberos |

---

## Simulation

A controlled AS-REP Roasting attack was performed in the lab environment using offensive toolsets such as Rubeus (`Rubeus.exe asreproast`) or Impacket (`GetNPUsers.py`).

```text
Attacker Host / Workstation
        ↓
Executes GetNPUsers.py or Rubeus asreproast
        ↓
Requests TGT for user account with DONT_REQ_PREAUTH set
        ↓
Domain Controller issues Event 4768 with preAuthType = 0
        ↓
Wazuh base rule 60103 matches
        ↓
Custom rule 100117 matches (preAuthType = 0)
        ↓
DET-018 alert generated (Level 12)
```

## Expected Alert

The expected Wazuh alert contains:

- **Detection:** `DET-018`
- **Rule ID:** `100117`
- **Severity:** `12`
- **Windows Event:** `4768`
- Target Account Name (`targetUserName`)
- Pre-Auth Type (`preAuthType = 0`)
- Client IP Address (`ipAddress`)
- Ticket Encryption Type (`ticketEncryptionType`)
- Domain Controller name
- Timestamp

The alert description explicitly reports:

```text
DET-018 Possible AS-REP Roasting - Kerberos TGT Requested Without Preauthentication for <targetUserName>
```

## Validation Result

**Status: VALIDATED**

The rule successfully identified Windows Event 4768 requests with `preAuthType = 0` via base rule `60103` and generated custom alert 100117 at severity level 12.

The detection reliably captures pre-authentication bypass events on domain controllers, delivering immediate high-fidelity alerts for AS-REP Roasting.

## Investigation Playbook

When DET-018 fires, SOC analysts must rapidly assess whether the request represents legitimate legacy application behavior or an active credential harvesting campaign.

### 1. Analyze the target account configuration

Review:

- **Target User Account:** (`win.eventdata.targetUserName`) — Is the target a standard user, service account, or administrative identity?
- Active Directory Attributes: Check if the account has `DONT_REQ_PREAUTH` (`UF_DONT_REQUIRE_PREAUTH`) explicitly enabled in Active Directory.
- Password Age & Complexity: Has the target account's password been rotated recently, or is it legacy/static?

### 2. Evaluate requesting source IP and client details

Review:

- **Client IP Address:** (`win.eventdata.ipAddress`) — Does the IP trace back to an internal endpoint, external VPN gateway, or suspicious subnet?
- **Ticket Encryption Type:** (`win.eventdata.ticketEncryptionType`) — Was `0x17` (`RC4-HMAC`) requested? Attackers specifically target RC4 hashes for faster offline cracking in tools like Hashcat.

### 3. Query SIEM telemetry for reconnaissance or sweeps

Search domain logs surrounding the timestamp:

- Are there multiple Event 4768 entries with `preAuthType = 0` targeting different accounts from the same source IP?
- Automated scripts (e.g., `GetNPUsers.py`) query multiple domain accounts sequentially to collect all crackable hashes in one sweep.

### 4. Review endpoint execution (If source host is internal)

If the client host is an internal endpoint sending logs:

- Inspect Sysmon Event 1 / Windows 4688 process creation events around the time of the request.
- Look for process executions of `Rubeus.exe`, `python.exe` running Impacket tools, or suspicious PowerShell execution (`Get-ADUser -Filter 'DoNotRequirePreAuth -eq $true'`).

### 5. Determine classification

Classify the event:

- **Legacy System / Misconfiguration:** Rare legacy software system authenticating without pre-authentication due to outdated Kerberos stacks.
- **AS-REP Roasting Attack:** Unauthorized TGT request for pre-auth disabled accounts, indicating active credential harvesting.

## Response Playbook

### If the activity is benign / misconfiguration

- Consult identity administrators to verify why `DONT_REQ_PREAUTH` is configured on the target user.
- Enforce Kerberos Pre-Authentication on the account immediately if no technical dependency exists.
- Document ticket details and resolve the alert.

### If AS-REP Roasting / Adversarial activity is confirmed

- **Enable Pre-Authentication Immediately:** Remove the `DONT_REQ_PREAUTH` flag from the target account's UserAccountControl settings in Active Directory.
- **Force Password Reset:** Immediately reset the password of the target account (`targetUserName`) to a high-complexity (25+ characters) password to invalidate any stolen hash.
- **Isolate Source Host:** If the request originated from an internal workstation, disconnect the device from the network to stop ongoing attacks.
- **Audit Domain User Accounts:** Run a domain-wide audit for all accounts with `DONT_REQ_PREAUTH` enabled:
  ```powershell
  Get-ADUser -Filter {DoNotRequirePreAuth -eq $True} -Properties DoNotRequirePreAuth
  ```
- **Initiate Incident Response:** Follow organizational IR procedures to determine if initial access or secondary privilege escalation occurred.

## False Positives

Common benign causes include:

- Legacy operating systems or third-party appliances (e.g., older Unix/Linux Kerberos clients, legacy printers) that do not support pre-authentication standards.
- Misconfigured application service accounts left with `DONT_REQ_PREAUTH` enabled following historical migrations.

## Tuning Considerations

DET-018 operates at **high severity (Level 12)** due to the explicit threat posed by pre-authentication bypass.

Recommended tuning strategies include:

- **Exclude Known Legacy Service IPs:** If legacy hardware strictly requires `preAuthType = 0`, add exceptions filtering specific source IP addresses for known targets.
- **Correlate Encryption Downgrades:** Create a high-priority sub-rule raising severity to Level 13-14 when `preAuthType = 0` is combined with `ticketEncryptionType = 0x17` (RC4).
- **Proactive Remediation:** Rather than relying solely on alerts, enforce domain policies disallowing `DONT_REQ_PREAUTH` on non-essential user accounts.

Monitoring TGT requests without pre-authentication ensures immediate detection and remediation of one of the most straightforward privilege escalation vectors in Active Directory.
