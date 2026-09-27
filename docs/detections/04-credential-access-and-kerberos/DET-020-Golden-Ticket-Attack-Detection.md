# Detection 020 — Golden Ticket Attack Detection

## Objective

Detect anomalous Kerberos Service Ticket (TGS-REQ / TGS-REP) requests using downgraded RC4-HMAC session key encryption, identifying potential Golden Ticket attacks within Active Directory environments.

A Golden Ticket attack is a post-exploitation technique where an adversary compromises the Active Directory domain `krbtgt` account hash. With this key, the attacker can forge custom Kerberos Ticket Granting Tickets (TGTs) offline. Because the forged TGT is signed with the valid `krbtgt` key, Domain Controllers accept it as legitimate without checking active sessions or account status. 

When presenting a forged Golden Ticket to request a service ticket (TGS), default forging tools (like Mimikatz) frequently negotiate session keys using legacy `RC4-HMAC` (`0x17`) encryption—even in modern domains where AES encryption (`0x12` / `0x11`) is standard. DET-020 monitors Kerberos service ticket requests (Event 4679) for RC4 session key encryption to catch forged TGT usage.

## MITRE ATT&CK

**Related Sub-technique:** T1558.001 — Steal or Acquire Kerberos Tickets: Golden Ticket

Adversaries may forge Kerberos Ticket Granting Tickets (TGT) using the domain `krbtgt` password hash to obtain unauthorized access to domain resources and maintain persistent administrator access.

DET-020 targets forged TGT exploitation by identifying anomalous session key encryption types associated with ticket request payloads.

## Windows Events

**Event ID:** `4769` — A Kerberos service ticket was requested.

Relevant fields include:

- Target Account Name (`win.eventdata.targetUserName`)
- Service Name (`win.eventdata.serviceName`)
- Service ID (`win.eventdata.serviceSid`)
- Ticket Options (`win.eventdata.ticketOptions`)
- Ticket Encryption Type (`win.eventdata.ticketEncryptionType`)
- Session Key Encryption Type (`win.eventdata.sessionKeyEncryptionType`): `0x17` (RC4-HMAC)
- Client IP Address (`win.eventdata.ipAddress`)
- Client Port (`win.eventdata.ipPort`)
- Status Code (`win.eventdata.status`): `0x0` (Success)
- Domain Controller Name
- Timestamp

The **sessionKeyEncryptionType = 0x17** explicitly indicates that the Kerberos session key was issued using RC4-HMAC encryption.

## Detection Logic

```text
Windows Event 4769
        ↓
Wazuh base rule 60103
        ↓
Custom rule 100119 (EventID == 4769 AND sessionKeyEncryptionType == 0x17)
        ↓
DET-020 alert (Level 12)
```

The rule triggers on Kerberos ticket service requests logged under Wazuh base rule `60103`.

The rule explicitly evaluates:

```text
win.system.eventID = 4769
win.eventdata.sessionKeyEncryptionType = 0x17
```

By isolating Event 4769 where `sessionKeyEncryptionType` is `0x17` (RC4-HMAC), custom rule 100119 detects ticket generation patterns indicative of Golden Ticket usage.

## Wazuh Rule

```xml
<rule id="100119" level="12">
    <if_sid>60103</if_sid>

    <field name="win.system.eventID">^4769$</field>
    <field name="win.eventdata.sessionKeyEncryptionType">^0x17$</field>

    <description>
        DET-020 - Possible Golden Ticket activity: Kerberos service ticket for $(win.eventdata.targetUserName) uses RC4 session encryption from $(win.eventdata.ipAddress)
    </description>

    <mitre>
        <id>T1558.001</id>
    </mitre>

    <group>
        custom_detection_engineering,
        windows,
        kerberos,
        credential_access,
        golden_ticket,
    </group>
</rule>
```

### Rule Details

| Field | Value |
|---|---|
| Detection ID | DET-020 |
| Wazuh Rule ID | 100119 |
| Severity | 12 (High) |
| Parent Rule | 60103 |
| Detection Type | Golden Ticket Activity |
| Windows Event | 4769 |
| Session Key Enc | `0x17` (RC4-HMAC) |
| MITRE Technique | T1558.001 |
| Category | Credential Access / Kerberos |

---

## Simulation

A Golden Ticket attack simulation was conducted in the lab using Mimikatz (`kerberos::golden`) and `kerberos::ptt` (Pass-the-Ticket).

```text
Attacker Host / Workstation
        ↓
Forges TGT using extracted krbtgt NTLM hash (Mimikatz kerberos::golden)
        ↓
Injects forged TGT into current logon session (kerberos::ptt)
        ↓
Requests Service Ticket (TGS) for target service (e.g., cifs/DC01)
        ↓
Domain Controller processes TGT, issues Event 4769 with sessionKeyEncryptionType = 0x17
        ↓
Wazuh base rule 60103 matches
        ↓
Custom rule 100119 matches
        ↓
DET-020 alert generated (Level 12)
```

## Expected Alert

The expected Wazuh alert contains:

- **Detection:** `DET-020`
- **Rule ID:** `100119`
- **Severity:** `12`
- **Windows Event:** `4769`
- Target Account Name (`targetUserName`)
- Service Name (`serviceName`)
- Session Key Encryption Type (`sessionKeyEncryptionType = 0x17`)
- Client IP Address (`ipAddress`)
- Domain Controller name
- Timestamp

The alert description explicitly reports:

```text
DET-020 - Possible Golden Ticket activity: Kerberos service ticket for <targetUserName> uses RC4 session encryption from <ipAddress>
```

## Validation Result

**Status: VALIDATED**

 custom rule 100119 successfully matched Windows Event 4768/4769 logs requesting service tickets via RC4 encryption, triggering a severity 12 alert.

The detection reliably captures Kerberos encryption downgrades indicative of forged Ticket Granting Tickets.

## Investigation Playbook

When DET-020 triggers, SOC analysts must immediately assess whether the RC4 session key request represents legacy operating system behavior or active ticket forgery.

### 1. Evaluate client IP address and host operating system

Review:

- **Client IP Address:** (`win.eventdata.ipAddress`) — Does the IP belong to a legacy Windows host (e.g., Server 2008/7) or a modern Windows 10/11/Server 2022 endpoint?
- Modern Windows operating systems negotiate AES (`0x12` / `0x11`) by default. RC4 requests from modern workstations are highly suspicious.

### 2. Inspect target user account and ticket attributes

Review:

- **Target User Name:** (`win.eventdata.targetUserName`) — Does the account exist in Active Directory? Golden Tickets often use fictitious user names or mismatched SIDs.
- **Service Name:** (`win.eventdata.serviceName`) — Is the client requesting access to sensitive infrastructure services (e.g., `krbtgt`, `cifs`, `HOST`, `RPCSS`)?
- Account SID vs. Ticket SID: Verify if the requested ticket lifetime or SID matches standard domain policy.

### 3. Check corresponding Event 4768 (TGT Request) logs

Query SIEM for matching Event 4768 logs from the same source IP:

- Legitimate session tickets (4769) are preceded by a valid TGT request (4768) on the DC within reasonable timeframes.
- If Event 4769 occurs **without a corresponding Event 4768 from the same IP**, the TGT was forged offline and injected directly.

### 4. Review host process activity (If client host is monitored)

If the originating endpoint sends Sysmon / Windows process logs:

- Inspect for memory manipulation tools (`mimikatz.exe`, `Rubeus.exe`, `psexec.exe`).
- Look for suspicious process injections into `lsass.exe` or command-line ticket injection syntax.

### 5. Determine classification

Classify the event:

- **Legacy Application / OS:** Third-party legacy application or outdated OS unable to support AES encryption.
- **Golden Ticket Attack:** Forged TGT presented to DC using default RC4 encryption parameters, indicating total domain compromise.

## Response Playbook

### If the activity is benign / legacy system

- Confirm legacy application constraints requiring RC4 session key negotiation.
- Document system IP/Hostname and create an operational exception or exclusion if necessary.

### If Golden Ticket Attack is confirmed

- **Initiate Tier-0 Compromise Protocol:** A confirmed Golden Ticket means the `krbtgt` account hash has been compromised. Treat as full Active Directory domain breach.
- **Isolate Source Host:** Immediately disconnect the source host (`ipAddress`) from the network.
- **Reset KRBTGT Password TWICE:** Follow Microsoft procedures to reset the domain `krbtgt` account password **two times consecutively** (allowing replication between resets) to invalidate all existing forged TGTs domain-wide.
- **Reset All Administrative Passwords:** Force password resets for Domain Admins, Enterprise Admins, and Service Accounts.
- **Evict Attacker Persistence:** Inspect Domain Controllers and Active Directory for secondary persistence (Skeleton Key, Malicious DCSync ACLs, unauthorized Admin accounts).

## False Positives

Common benign causes include:

- Legacy operating systems (Windows Server 2003/2008, Windows XP) authenticating within the domain.
- Third-party non-Windows Kerberos implementations (older Samba/Linux clients) configured exclusively for RC4-HMAC.

## Tuning Considerations

DET-020 runs at **High Severity (Level 12)**.

Tuning options to minimize false alerts:

- **Exclude Verified Legacy Host IPs:** Add IP-based filter exceptions for legacy appliances or older servers that cannot negotiate AES.
- **Disable RC4 Domain-Wide:** Disable RC4 encryption types in Kerberos policy via Group Policy (`Network security: Configure encryption types allowed for Kerberos`) to eliminate RC4 usage domain-wide.
- **Correlate Missing Event 4768:** Raise severity to Level 15 if Event 4769 with RC4 occurs without a matching Event 4768 TGT request.

Detecting Kerberos session key downgrades provides critical visibility against domain-level credential forgery.
