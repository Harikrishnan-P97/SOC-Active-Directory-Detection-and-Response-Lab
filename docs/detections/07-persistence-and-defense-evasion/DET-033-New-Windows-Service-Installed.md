# Detection 033 — New Windows Service Installed

## Objective

Detect the installation of a new Windows service on monitored host systems.

Adversaries frequently register malicious Windows services to establish persistent access across system reboots or to execute payloads with elevated privileges (often `NT AUTHORITY\SYSTEM`). DET-033 monitors Windows System event logs for service installation events to identify unauthorized service creations, malicious binary registrations, and persistence mechanisms.

## MITRE ATT&CK

**Related Techniques:**
- **T1543.003** — Create or Modify System Process: Windows Service

Adversaries abuse the Windows Service Control Manager (SCM) to create persistent services that automatically execute malicious binaries, scripts, or DLL payloads upon system boot or on demand.

## Windows / Sysmon Events

**Base Rule:** `61138` — Windows System Event ID 7045 (A service was installed in the system).

Relevant fields include:

- Service Name (`win.eventdata.serviceName`): Internal name of the newly installed service
- Service File Name / Path (`win.eventdata.imagePath`): Executable binary path and command-line arguments assigned to the service
- Service Type (`win.eventdata.serviceType`): Type of service (e.g., kernel driver, user-mode service)
- Start Type (`win.eventdata.startType`): Startup configuration (e.g., Auto Start, Demand Start, Disabled)
- Account Name (`win.eventdata.accountName`): Service execution context (e.g., `LocalSystem`, `LocalService`, or domain user account)
- User (`win.eventdata.subjectUserName` / `win.eventdata.user`): User account responsible for registering the service

## Detection Logic

```text
Windows System Event ID 7045 (Rule 61138)
        ↓
Custom rule 100132 matches
        ↓
DET-033 alert generated (Level 12 - High)
```

The rule triggers directly when Windows System Event ID 7045 (New Service Installed) matches parent rule `61138`.

Every new service installation captured by the Service Control Manager triggers this detection, capturing the service name dynamically in the alert description.

## Wazuh Rule

```xml
<rule id="100132" level="12">
    <if_sid>61138</if_sid>

    <description>
        DET-033 New Windows Service Installed - $(win.eventdata.serviceName)
    </description>

    <group>
        custom_detection_engineering,
        custom_windows,
        persistence,
        service_creation,
        attack.t1543.003
    </group>

    <mitre>
        <id>T1543.003</id>
    </mitre>
</rule>
```

### Rule Details

| Field | Value |
|---|---|
| Detection ID | DET-033 |
| Wazuh Rule ID | 100132 |
| Severity | 12 (High) |
| Parent Rule ID | 61138 (Windows Event ID 7045 - Service Installed) |
| Detection Type | Windows Service Installation |
| Event Source | Windows System Log (Event ID 7045) |
| Target Object | Windows Service Control Manager (SCM) |
| MITRE Techniques | T1543.003 |
| Category | Persistence / Defense Evasion |

---

## Simulation

A service creation simulation was performed in the laboratory environment using `sc.exe` and PowerShell.

```text
Attacker Workstation / Local Administrator
        ↓
Executes command to create a persistent service:
  > sc.exe create MaliciousService binPath= "C:\Windows\Temp\payload.exe" start= auto
    OR
  > New-Service -Name "MaliciousService" -BinaryPathName "C:\Windows\Temp\payload.exe" -StartupType Automatic
        ↓
Windows Service Control Manager registers the new service
        ↓
Windows generates System Event ID 7045
        ↓
Wazuh parent rule 61138 matches
        ↓
Custom rule 100132 matches
        ↓
DET-033 high-severity alert generated (Level 12) showing service name "MaliciousService"
```

## Expected Alert

The expected Wazuh alert contains:

- **Detection:** `DET-033`
- **Rule ID:** `100132`
- **Severity:** `12`
- Description: `DET-033 New Windows Service Installed - <SERVICE_NAME>`
- Service Name (`win.eventdata.serviceName`)
- Service File Path (`win.eventdata.imagePath`)
- Service Account (`win.eventdata.accountName`)
- Start Type (`win.eventdata.startType`)
- Timestamp

Example Alert Description Output:

```text
DET-033 New Windows Service Installed - MaliciousService
```

## Validation Result

**Status: VALIDATED**

Custom rule 100132 successfully generated Level 12 high-severity alerts whenever a new service was created via `sc.exe`, PowerShell, or third-party installers.

## Investigation Playbook

When DET-033 triggers, SOC analysts must evaluate the service configuration and binary path to determine legitimacy.

### 1. Analyze Binary Path & Parameters

Inspect `win.eventdata.imagePath`:

- **Path Location:** Is the executable located in standard system directories (`C:\Windows\System32\`, `C:\Program Files\`) or suspicious locations (`C:\Windows\Temp\`, `C:\Users\Public\`, `C:\AppData\`)?
- **Command Line Flags:** Does the path contain encoded command-line execution (e.g., `cmd.exe /c powershell -enc...` or `rundll32.exe`)?
- **Unusual File Extensions:** Is the service calling non-standard extensions, batch files (`.bat`/`.cmd`), or VBScripts (`.vbs`)?

### 2. Identify the Installing Account & Context

- **User Context:** Identify the account that initiated the installation. Was it installed during an active interactive session or remotely via WMI/PsExec?
- **Account Context:** Check `win.eventdata.accountName`. Does the service run under `LocalSystem` (`NT AUTHORITY\SYSTEM`), a service account, or a user domain account?

### 3. Binary Verification & Hash Analysis

- Locate the executable specified in `win.eventdata.imagePath` and compute its cryptographic file hashes (SHA256).
- Verify digital signatures and vendor authenticity.

### 4. Determine Classification

Classify the event:

- **False Positive / Benign:** Authorized software installation, driver update, or legitimate IT deployment (e.g., Google Update, VPN agents, software patches).
- **True Positive:** Unauthorized service creation used for persistence, privilege escalation, or lateral movement (e.g., Cobalt Strike `PsExec` services, ransomware persistence).

## Response Playbook

### If activity is confirmed malicious

- **Stop & Remove Service:** Stop the running service and delete the registry definition:
  ```cmd
  sc.exe stop <ServiceName>
  sc.exe delete <ServiceName>
  ```
- **Isolate Endpoint:** Network isolate the endpoint to contain potential C2 communication or lateral movement.
- **Quarantine Payload:** Delete or quarantine the executable binary referenced in `win.eventdata.imagePath`.
- **Revoke Credentials:** Reset passwords for any user or administrative accounts involved in creating the service.
- **Inspect Persistence:** Check Registry service locations (`HKLM\SYSTEM\CurrentControlSet\Services\<ServiceName>`) for residual artifacts or modifications.

## False Positives

Common benign sources include:

- Legitimate software installers, Windows updates, or security agent updates creating transient or permanent background services.
- IT administration tools deploying temporary maintenance agents.

## Tuning Considerations

DET-033 operates at **High Severity (Level 12)** because unauthorized service creation is a critical indicator of persistence and lateral movement.

Tuning options:

- **Filter Standard Software Installers:** If legitimate enterprise software deployments trigger frequent alerts, build child exclusion rules matching trusted binary paths and digital signatures.
- **Correlate with Parent Processes:** Pair service creation logs with Sysmon Event ID 1 (Process Creation) to trace the parent binary (`sc.exe`, `services.exe`, `powershell.exe`) that created the service.
- **Monitor Service Path Modifications:** Combine with registry monitoring to catch modifications to existing service `ImagePath` values (Service DLL hijacking / Service re-configuration).

Monitoring service creation provides essential defense coverage against persistent threat actors and privilege escalation tactics.
