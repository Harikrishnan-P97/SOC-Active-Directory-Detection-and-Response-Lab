# Detection 021 — Silver Ticket Attack Detection

## Objective

Detect anomalous network logon events resulting from forged Kerberos Service Tickets (Silver Tickets), identifying localized service ticket manipulation within Active Directory environments.

Unlike a Golden Ticket attack (which targets the domain `krbtgt` account), a Silver Ticket attack occurs when an adversary compromises the password hash of a specific service account or computer account (e.g., `HOST/`, `CIFS/`, `MSSQL/`). Using this stolen service key, the attacker crafts a forged Kerberos Service Ticket (TGS) offline. 

Because the forged ticket is encrypted directly with the target service account's password hash, it bypasses interaction with the Domain Controller (KDC). When presented to the target service, the service decrypts the ticket, accepts the forged identity/privileges, and logs a local network authentication event (Event ID 4624, Logon Type 3) with distinct anomalous field artifacts—specifically a `NULL SID` (`S-1-0-0`) for the subject user.

## MITRE ATT&CK

**Related Sub-technique:** T1558.002 — Steal or Acquire Kerberos Tickets: Silver Ticket

Adversaries may forge Kerberos Service Tickets (TGS) using compromised service account hashes to obtain unauthorized access to targeted services, bypass Domain Controller logging, and maintain persistence.

DET-021 identifies forged Kerberos network logons by tracking explicit field anomalies generated during Silver Ticket authentication.

## Windows Events

**Event ID:** `4624` — An account was successfully logged on.

Relevant fields include:

- Logon Type (`win.eventdata.logonType`): `3` (Network Logon)
- Authentication Package Name (`win.eventdata.authenticationPackageName`): `Kerberos`
- Logon Process Name (`win.eventdata.logonProcessName`): `Kerberos`
- Subject User SID (`win.eventdata.subjectUserSid`): `S-1-0-0` (NULL SID)
- Target Account Name (`win.eventdata.targetUserName`): Non-machine account (`negate="yes" \$$`)
- Target Domain Name (`win.eventdata.targetDomainName`)
- Workstation Name (`win.eventdata.workstationName`)
- Source Network Address / IP (`win.eventdata.ipAddress`)
- Source Port (`win.eventdata.ipPort`)
- Key Length / Ticket Parameters

The key indicator is `subjectUserSid = S-1-0-0` paired with `logonType = 3` and `AuthenticationPackage = Kerberos`. In standard network authentications, the Subject User SID reflects the requesting entity or Local System. When presenting an offline-forged TGS directly to a endpoint/service, the Subject User SID defaults to `S-1-0-0`.

## Detection Logic

```text
Windows Event 4624 (Successful Network Logon)
        ↓
Wazuh base rule 92651
        ↓
Custom rule 100120 (LogonType == 3 AND AuthPackage == Kerberos AND SubjectUserSid == S-1-0-0 AND TargetUserName != *$)
        ↓
DET-021 alert (Level 14)
```

The rule monitors network authentication events processed under Wazuh base rule `92651`.

The rule explicitly evaluates:

```text
win.eventdata.authenticationPackageName = Kerberos
win.eventdata.logonProcessName = Kerberos
win.eventdata.logonType = 3
win.eventdata.subjectUserSid = S-1-0-0
win.eventdata.targetUserName != *$ (Excludes machine accounts)
```

By identifying Kerberos network logons (Type 3) where the Subject User SID is `S-1-0-0` and the user account is not a standard machine account ending in `$`, custom rule 100120 accurately isolates Silver Ticket exploitation.

## Wazuh Rule

```xml
<rule id="100120" level="14">

    <if_sid>92651</if_sid>

    <field name="win.eventdata.authenticationPackageName" type="pcre2">^Kerberos$</field>
    <field name="win.eventdata.logonProcessName" type="pcre2">^Kerberos$</field>
    <field name="win.eventdata.logonType" type="pcre2">^3$</field>
    <field name="win.eventdata.subjectUserSid" type="pcre2">^S-1-0-0$</field>
    <field name="win.eventdata.targetUserName" type="pcre2" negate="yes">\$$</field>

    <description>
        DET-021 - Possible Silver Ticket: forged Kerberos network logon by $(win.eventdata.targetDomainName)\$(win.eventdata.targetUserName) from $(win.eventdata.ipAddress)
    </description>

    <mitre>
        <id>T1558.002</id>
    </mitre>

    <group>
        custom_detection_engineering,
        windows,
        credential_access,
        kerberos,
        silver_ticket,
        authentication,
        attack.t1558.002
    </group>

</rule>
```

### Rule Details

| Field | Value |
|---|---|
| Detection ID | DET-021 |
| Wazuh Rule ID | 100120 |
| Severity | 14 (Critical) |
| Parent Rule | 92651 |
| Detection Type | Silver Ticket Activity |
| Windows Event | 4624 (Logon Type 3) |
| Subject User SID | `S-1-0-0` |
| MITRE Technique | T1558.002 |
| Category | Credential Access / Kerberos |

---

## Simulation

A Silver Ticket attack simulation was conducted using Mimikatz (`kerberos::golden /service:...`) to forge a ticket for a targeted service (e.g., `cifs`).

```text
Attacker Host / Workstation
        ↓
Extracts NTLM password hash of service/computer account (e.g., target server machine account)
        ↓
Forges TGS ticket offline using service account key (Mimikatz kerberos::golden /service:cifs ...)
        ↓
Injects ticket into session and accesses target host share (e.g., \TargetServer\c$)
        ↓
Target Server processes forged TGS without asking Domain Controller
        ↓
Target Server logs Event 4624 (Logon Type 3, SubjectUserSid = S-1-0-0, AuthPackage = Kerberos)
        ↓
Wazuh base rule 92651 matches
        ↓
Custom rule 100120 matches
        ↓
DET-021 alert generated (Level 14)
```

## Expected Alert

The expected Wazuh alert contains:

- **Detection:** `DET-021`
- **Rule ID:** `100120`
- **Severity:** `14`
- **Windows Event:** `4624`
- Target Account Name (`targetUserName`)
- Target Domain Name (`targetDomainName`)
- Subject User SID (`subjectUserSid = S-1-0-0`)
- Logon Type (`logonType = 3`)
- Authentication Package (`Kerberos`)
- Source IP Address (`ipAddress`)
- Target Hostname
- Timestamp

The alert description explicitly reports:

```text
DET-021 - Possible Silver Ticket: forged Kerberos network logon by <targetDomainName>\<targetUserName> from <ipAddress>
```

## Validation Result

**Status: VALIDATED**

Custom rule 100120 successfully matched Event 4624 network authentication entries containing `S-1-0-0` Subject User SIDs with Kerberos processing, generating a high-priority Severity 14 alert.

The rule successfully filtered out standard computer account authentications while catching forged user ticket presentations.

## Investigation Playbook

When DET-021 triggers, SOC analysts must act quickly to contain localized compromise of targeted servers or service accounts.

### 1. Verify source IP and destination target host

Review:

- **Source IP:** (`win.eventdata.ipAddress`) — Identify the originating system presenting the forged ticket.
- **Destination Host:** Determine which server processed the authentication request and which service was accessed (e.g., SMB/CIFS, SQL, WMI).

### 2. Inspect Target Account and User SID

Review:

- **Target Account:** (`win.eventdata.targetUserName`) — Is the account a Domain Admin or privileged account being impersonated?
- Query Domain Controller logs (Event 4769) to see if a matching TGS request exists for this user/IP around the same timeframe. **Lack of Event 4769 on the KDC strongly confirms a Silver Ticket.**

### 3. Identify the targeted service account

Identify which computer or service account hash was compromised to build the ticket:

- If accessing `cifs/SERVER01`, the target host's machine account (`SERVER01$`) password hash was likely dumped.
- If accessing `MSSQL/sql01.domain.com`, the SQL service account hash was likely compromised.

### 4. Check for post-exploitation activities

Inspect host monitoring logs (Sysmon/Windows Event Logs) on the target host for:

- Remote command execution (e.g., `psexec`, `wmiprvse.exe`, PowerShell remoting).
- File transfers or file modifications on sensitive network shares.
- Privileged operations or SAM database dumping.

### 5. Determine classification

Classify the event:

- **False Positive:** Rare custom legacy authentication bridge or misconfigured SSO proxy forging raw Kerberos structures.
- **Silver Ticket Attack:** Verified offline ticket injection using compromised service account credentials.

## Response Playbook

### If Silver Ticket Attack is confirmed

- **Isolate Affected Systems:** Immediately isolate both the originating IP host and the compromised target server from the network.
- **Reset Compromised Account Password TWICE:** 
  - If a service account key was used, reset the service account password **twice**.
  - If a machine account (`COMPUTER$`) key was used, reset the computer account password **twice** via PowerShell/Active Directory to force key rotation.
- **Evict Attacker Access:** Terminate active network sessions on the target host.
- **Perform Memory & Forensic Analysis:** Analyze target host memory to ensure no secondary persistence mechanisms (e.g., LSASS injection, scheduled tasks) were established.
- **Audit Service Account Privileges:** Re-evaluate rights granted to the targeted service account.

## False Positives

Common benign causes include:

- Specialized third-party Kerberos proxy services or non-standard single sign-on (SSO) gateways that construct raw Kerberos tickets.
- Legacy Unix/Linux Samba integrations performing raw Kerberos pass-through authentication without setting valid Subject SIDs.

## Tuning Considerations

DET-021 runs at **Critical Severity (Level 14)** due to the high confidence of the `S-1-0-0` artifact during Kerberos logon events.

Tuning options to minimize false alerts:

- **Whitelisting Specific IP Endpoints:** If legitimate SSO/Identity proxies generate this artifact, create strict source IP exclusions (`win.eventdata.ipAddress`).
- **Enforce PAC Validation:** Enable Kerberos KDC Validation of PAC (Privilege Attribute Certificate) signatures across Active Directory to prevent unverified tickets from being honored by services.

Detecting anomalous Subject SIDs during Kerberos network logons provides an exceptionally high-fidelity defense against Silver Ticket post-exploitation techniques.
