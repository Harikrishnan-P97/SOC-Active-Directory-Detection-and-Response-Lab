# Detection 017 — Kerberos Service Ticket Request (Possible Kerberoasting)

## Objective

Detect Kerberos Service Ticket (TGS-REP) requests targeting Active Directory user accounts configured with Service Principal Names (SPNs), helping identify potential Kerberoasting attacks.

Kerberoasting is a post-exploitation technique where an authenticated domain user requests a Kerberos Ticket Granting Service (TGS) ticket for a user account associated with an SPN. Because TGS tickets are encrypted using the target account's password hash (typically RC4_HMAC_MD5 or AES), an attacker can extract the ticket from memory and attempt to crack the password offline without generating further domain logons or triggering account lockouts.

DET-017 monitors domain controllers for Kerberos Service Ticket requests, capturing the requesting user, target service/account, encryption types, and client IP addresses to identify suspicious ticket requests.

## MITRE ATT&CK

**Related Sub-technique:** T1558.003 — Steal or Acquire Kerberos Tickets: Kerberoasting

Adversaries may request Kerberos ticket-granting service (TGS) tickets for service accounts to crack their password hashes offline. This provides a path for privilege escalation, as service accounts frequently hold elevated rights (e.g., Domain Admins or local Administrator permissions) and often use weak, static passwords.

DET-017 alerts on individual TGS requests to establish visibility over Kerberos ticket activity. Analysts evaluate ticket parameters such as request volume, target account types, and ticket encryption methods.

## Windows Events

**Event ID:** `4769` — A Kerberos service ticket was requested.

Relevant fields include:

- Target Service Name (`win.eventdata.serviceName`)
- Target SID (`win.eventdata.serviceSid`)
- Account Name / Client Name (`win.eventdata.targetUserName`)
- Client IP Address (`win.eventdata.ipAddress`)
- Client Port (`win.eventdata.ipPort`)
- Ticket Encryption Type (`win.eventdata.ticketEncryptionType`):
  - `0x17` (23): `RC4-HMAC` (frequently targeted by attackers for legacy, weaker cracking complexity)
  - `0x12` (18): `AES256-CTS-HMAC-SHA1-96`
  - `0x11` (17): `AES128-CTS-HMAC-SHA1-96`
- Ticket Options (`win.eventdata.ticketOptions`)
- Failure Code (`win.eventdata.status`)
- Domain Controller Name
- Timestamp

The **target service name** indicates which service account's ticket was requested, while **targetUserName** and **ipAddress** identify the requesting user and source host.

## Detection Logic

```text
Windows Event 4769
        ↓
Wazuh base rule 60106
        ↓
Custom rule 100116
        ↓
DET-017 alert
```

The rule triggers on Kerberos service ticket request events processed under Wazuh base rule `60106`.

The rule explicitly matches:

```text
win.system.eventID = 4769
```

No additional field restriction or frequency thresholding is applied by DET-017 in this base state, creating an alert whenever a Kerberos TGS request event (4769) is processed by the parent rule `60106`.

## Wazuh Rule

```xml
<rule id="100116" level="10">

    <if_sid>60106</if_sid>

    <field name="win.system.eventID">4769</field>

    <description>
        DET-017 Kerberos Service Ticket Request (Possible Kerberoasting)
    </description>

    <group>
        custom_windows,
        credential_access,
        kerberos,
        kerberoasting,
        attack.t1558.003,
    </group>

    <mitre>
        <id>T1558.003</id>
    </mitre>

</rule>
```

### Rule Details

| Field | Value |
|---|---|
| Detection ID | DET-017 |
| Wazuh Rule ID | 100116 |
| Severity | 10 |
| Parent Rule | 60106 |
| Detection Type | Possible Kerberoasting |
| Windows Event | 4769 |
| MITRE Technique | T1558.003 |
| Category | Credential Access / Kerberos |

---

## Simulation

A controlled Kerberoasting activity was executed in the laboratory domain environment using tools such as Rubeus, Impacket (`GetUserSPNs.py`), or PowerShell (`Get-DomainUser -SPN`).

```text
Attacker Host / Domain Workstation
        ↓
Executes Rubeus.exe kerberoast or GetUserSPNs.py
        ↓
Requests TGS tickets for accounts with SPNs registered
        ↓
Domain Controller generates Event 4769
        ↓
Wazuh base rule 60106 matches
        ↓
Custom rule 100116 matches
        ↓
DET-017 alert generated
```

## Expected Alert

The expected Wazuh alert contains:

- **Detection:** `DET-017`
- **Rule ID:** `100116`
- **Severity:** `10`
- **Windows Event:** `4769`
- Target Service Name (`serviceName`)
- Client Account Name (`targetUserName`)
- Client IP Address (`ipAddress`)
- Ticket Encryption Type (`ticketEncryptionType`)
- Domain Controller name
- Timestamp

The alert description explicitly reports:

```text
DET-017 Kerberos Service Ticket Request (Possible Kerberoasting)
```

## Validation Result

**Status: VALIDATED**

The rule successfully identified Windows Event 4769 TGS ticket request telemetry via base rule `60106` and generated custom alert 100116.

The detection provides actionable visibility into Kerberos TGS requests across Active Directory domain controllers.

## Investigation Playbook

When DET-017 fires, analysts must evaluate whether the ticket request pattern reflects legitimate application service usage or automated credential harvesting (Kerberoasting).

### 1. Evaluate the requesting client identity and host

Review:

- **Client Username:** (`win.eventdata.targetUserName`) — Is the account an IT administrator, a service account, or a standard user?
- **Source IP Address:** (`win.eventdata.ipAddress`) — Does the IP map to an application server, developer workstation, or unexpected endpoint?
- **Target Service Name:** (`win.eventdata.serviceName`) — Is the requested SPN associated with a computer account (ends with `$`) or a user account?

Requests targeting **user accounts** (non-`$`) from non-application servers warrant heightened investigation.

### 2. Inspect ticket encryption type

Check `win.eventdata.ticketEncryptionType`:

- `0x17` (`RC4-HMAC`): Attackers frequently request RC4 tickets specifically because RC4 hashes are significantly easier to crack offline using GPUs (Hashcat/John the Ripper) compared to AES.
- `0x12` (`AES256`) / `0x11` (`AES128`): Standard modern default Kerberos encryption types.

A request for `0x17` (RC4) encryption against a user SPN—especially when the host supports AES—is a strong indicator of Kerberoasting (downgrade attack).

### 3. Check for anomalous request volumes (Sweeps)

Query SIEM / Wazuh logs for the source IP or client user over a 5-to-15 minute window:

- Are there multiple 4769 events requested in rapid succession for different service accounts?
- Automated tools (e.g., Rubeus, Invoke-Kerberoast) typically issue sequential or bulk TGS requests across all user SPNs in the domain.

### 4. Review host-level process telemetry

If the client host is monitored (Sysmon Event 1 / Windows 4688), inspect execution logs around the timestamp:

- Execution of `Rubeus.exe`, `PowerView.ps1`, `mimikatz.exe`, or custom assembly execution in PowerShell.
- Command-line flags containing `kerberoast`, `GetUserSPNs`, or `request`.

### 5. Determine classification

Classify the event:

- **Legitimate Application Access:** Normal TGS request issued by a standard user connecting to a legitimate database or web service (e.g., MSSQL service).
- **Misconfigured Application / Legacy Client:** System requesting legacy RC4 encryption due to outdated OS or baseline misconfigurations.
- **Kerberoasting Attack:** Multiple TGS requests for user SPNs (especially using `0x17` encryption) from an unauthorized endpoint.

## Response Playbook

### If the activity is benign

- Confirm valid service access with the user or application team.
- Ensure systems are configured to prefer AES encryption over RC4 (`0x17`).
- Document findings and close the alert.

### If Kerberoasting / Malicious activity is confirmed

- **Isolate the Source Host:** Disconnect the client endpoint from the network to prevent further reconnaissance or lateral movement.
- **Revoke / Reset Account Credentials:** Immediately reset the password of the requesting client account (if compromised).
- **Rotate Target Service Account Passwords:** Immediately reset the passwords of all requested target service accounts to strong, 25+ character complex passwords or migrate to Group Managed Service Accounts (gMSA).
- **Audit Domain SPNs:** Identify and review all user accounts configured with SPNs to ensure minimum privilege and robust password policies.
- **Initiate Incident Response:** Follow organizational IR protocols to investigate potential initial access vectors on the source host.

## False Positives

Common benign causes include:

- Standard user authentication to legitimate domain services (e.g., SQL Server, IIS web apps, SharePoint).
- Automated IT management systems or security scanners interacting with domain services.
- Legacy software clients requesting RC4-encrypted tickets due to un-negotiated Kerberos algorithms.

## Tuning Considerations

DET-017 operates at **medium-high severity (Level 10)**.

Because Event 4769 fires frequently in active enterprise environments, tuning is recommended to focus specifically on high-risk indicators:

- **Filter Computer Accounts:** Exclude service names ending in `$` (computer accounts), as standard Kerberoasting targets user-based SPNs.
- **Filter Encryption Type `0x17`:** Create a child rule specifically alerting on `win.eventdata.ticketEncryptionType = 0x17` (RC4) for non-computer accounts with elevated severity (Level 12+).
- **Implement Frequency Thresholding:** Build a thresholding rule (e.g., matching 5+ unique 4769 requests for user SPNs from the same source IP within 1 minute) to flag automated bulk Kerberoasting sweeps.

Monitoring Kerberos TGS requests ensures early detection of credential harvesting attempts against high-privilege service accounts.
