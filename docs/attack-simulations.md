# Attack Simulations

This document describes the controlled attack simulations performed in the SOC Active Directory Detection Lab to validate the behavior of the 42 custom Wazuh detection rules.

The simulations were conducted in the isolated lab environment using `KALI`, `CLIENT01`, and `DC01` as appropriate for the technique being tested. Each simulation was designed to generate observable Windows or Sysmon telemetry and verify that the corresponding Wazuh detection logic generated the expected alert.

---

## 1. Simulation Methodology

The attack simulations followed a repeatable detection-validation workflow:

```text
Select Detection
      ↓
Identify ATT&CK Technique
      ↓
Generate Controlled Activity
      ↓
Verify Windows / Sysmon Telemetry
      ↓
Verify Wazuh Alert
      ↓
Validate Detection Rule
      ↓
Clean Up
      ↓
Document Result
```

### Simulation Principles

* Tests were performed inside the isolated SOC Active Directory Detection Lab.
* Activity was generated from `KALI`, `CLIENT01`, or `DC01` depending on the technique being simulated.
* Simulations were designed to reproduce controlled attacker-like behavior.
* Windows Security logs and Sysmon telemetry were used where applicable.
* Wazuh ingestion and custom detection rules were verified after activity generation.
* Temporary accounts, group memberships, scheduled tasks, services, firewall rules, and other test artifacts were removed after validation where applicable.
* The simulations were performed against the custom detection set covering `DET-001` through `DET-042`.
* Detection validation was based on the presence of the expected telemetry and corresponding Wazuh alert.

### Detection Validation Model

Each simulation was evaluated using the following chain:

```text
Attack Simulation
       ↓
Windows / Sysmon Event
       ↓
Wazuh Ingestion
       ↓
Parent Rule / Event Classification
       ↓
Custom Detection Rule
       ↓
Wazuh Alert
       ↓
Alert Verification
       ↓
Detection Status: VALIDATED
```

---

# 2. Authentication Attacks

Authentication simulations focused on failed authentication, brute-force behavior, successful interactive authentication, account lockout, and repeated authentication failures.

## DET-001 — Failed Authentication

**Activity:** Failed interactive login from `CLIENT01` using `CORP\jdoe`.

**Purpose:** Generate a Windows failed authentication event and verify the base failed-authentication detection.

**Detection:** `DET-001`

**Detection name:** Windows Failed Authentication

**Validation flow:**

```text
Failed Interactive Login
        ↓
Windows Failed Authentication Telemetry
        ↓
Wazuh Authentication Classification
        ↓
DET-001
        ↓
Wazuh Alert
```

**Result:** Validated.

---

## DET-002 — Brute Force Detection

**Activity:** Multiple failed interactive login attempts from `CLIENT01` against `CORP\jdoe`.

**Detection:** `DET-002`

**MITRE ATT&CK:** `T1110 — Brute Force`

The custom rule correlates multiple `DET-001` authentication failures for the same target username within the configured frequency/time window. The rule uses three matching events within 120 seconds.

**Result:** Validated.

---

## DET-003 — Successful Interactive Authentication

**Activity:** Successful interactive login from `CLIENT01` using `CORP\jdoe`.

**Detection:** `DET-003`

**MITRE ATT&CK:** `T1078 — Valid Accounts`

The rule monitors successful Windows logons with interactive-related logon types `2`, `7`, `10`, or `11`.

**Result:** Validated.

---

## DET-004 — Successful Login After Failed Attempts

**Activity:** Failed interactive authentication attempts followed by a successful interactive login from `CLIENT01` using `CORP\jdoe`.

**Detection:** `DET-004`

**MITRE ATT&CK:**

* `T1110 — Brute Force`
* `T1078 — Valid Accounts`

The detection correlates a successful login with preceding authentication failures for the same target account.

**Result:** Validated.

---

## DET-005 — Account Lock

**Activity:** Repeated failed interactive authentication from `CLIENT01` using `CORP\jdoe`, resulting in account lockout.

**Detection:** `DET-005`

**Result:** Validated.

---

## DET-006 — Multiple Authentication Failures From Same Source

**Activity:** Multiple failed interactive authentication attempts from `CLIENT01` using `CORP\jdoe`.

**Detection:** `DET-006`

**MITRE ATT&CK:** `T1110 — Brute Force`

The rule correlates six authentication failures from the same source IP within 180 seconds. The rule description identifies this as a password-spraying approximation.

**Result:** Validated.

---

# 3. Account and Privilege Attacks

Account and privilege simulations reproduced attacker-like account-management and privilege-escalation behavior after a hypothetical account compromise.

Test accounts were created or modified when required for the simulation. Temporary changes were cleaned up after detection validation.

## DET-007 — User Account Created

**Activity:** New user account creation from `DC01`.

**Scenario:** Simulated attacker activity following account compromise.

**MITRE ATT&CK:** `T1136 — Create Account`

The detection monitors Windows Event ID `4720`.

**Result:** Validated.

---

## DET-008 — Password Reset

**Activity:** Password reset performed from `DC01`.

**Scenario:** Simulated attacker activity following account compromise.

**MITRE ATT&CK:** `T1098 — Account Manipulation`

The detection monitors Windows Event ID `4724`.

**Result:** Validated.

---

## DET-009 — User Account Enabled

**Activity:** Disabled user account enabled from `DC01`.

**Scenario:** Simulated attacker activity following account compromise.

**MITRE ATT&CK:** `T1098 — Account Manipulation`

The detection monitors Windows Event ID `4722`.

**Result:** Validated.

---

## DET-010 — User Account Deleted

**Activity:** User account deleted from `DC01`.

**Scenario:** Simulated attacker activity following account compromise.

**MITRE ATT&CK:** `T1531 — Account Access Removal`

The detection monitors Windows Event ID `4726`.

**Result:** Validated.

---

## DET-011 — Added to Domain Admins

**Activity:** Test account added to the `Domain Admins` group from `DC01`.

**Scenario:** Simulated privilege escalation following account compromise.

**MITRE ATT&CK:** `T1098 — Account Manipulation`

The detection monitors Event ID `4728` and specifically identifies membership changes involving `Domain Admins`.

**Result:** Validated.

---

## DET-012 — Added to Enterprise Admins

**Activity:** Test account added to the `Enterprise Admins` group from `DC01`.

**MITRE ATT&CK:** `T1098 — Account Manipulation`

The detection monitors Event ID `4756` for `Enterprise Admins` membership changes.

**Result:** Validated.

---

## DET-013 — Added to Local Administrators

**Activity:** Test account added to the local `Administrators` group from `DC01`.

**MITRE ATT&CK:** `T1098 — Account Manipulation`

The detection monitors Event ID `4732`.

**Result:** Validated.

---

## DET-014 — Administrator Account Enabled

**Activity:** Built-in `Administrator` account enabled from `DC01`.

**MITRE ATT&CK:** `T1098 — Account Manipulation`

The detection identifies Event ID `4722` when the affected account is `Administrator`.

**Result:** Validated.

---

## DET-015 — Privileged Account Logon

**Activity:** Privileged account logon generating Windows Event ID `4624`.

**Relevant logon types:**

* `2` — Interactive
* `3` — Network
* `10` — Remote Interactive

**MITRE ATT&CK:** `T1078 — Valid Accounts`

The custom rule monitors successful `4624` events involving the configured privileged accounts.

**Result:** Validated.

---

## DET-016 — Active Directory Attribute Modification

**Activity:** Active Directory user attribute modified from `DC01`.

Example test:

```powershell
Set-ADUser jdoe -Description "DET-034-FRESH-TEST"
```

### Event Verification

```powershell
Get-WinEvent -FilterHashtable @{
    LogName='Security'
    Id=5136
    StartTime=(Get-Date).AddMinutes(-1)
} | Select-Object TimeCreated,Id,Message
```

### Cleanup

```powershell
Set-ADUser jdoe -Description $null
```

### Verification

```powershell
Get-ADUser jdoe -Properties Description |
Select-Object SamAccountName,Description
```

**MITRE ATT&CK:** `T1098 — Account Manipulation`

The detection monitors Active Directory object attribute modification telemetry and identifies the modified object, attribute, and modifying user.

**Result:** Validated.

---

# 4. Credential Attacks

Credential-access simulations covered Kerberos ticket abuse, directory replication, credential dumping, and NTLM-based authentication abuse.

## DET-017 — Kerberoasting

**Activity:** Kerberos service ticket requests generated from `KALI`.

```bash
GetUserSPNs.py corp.local/Administrator:'Password123' \
-dc-ip 10.10.10.20 \
-request
```

**Detection:** `DET-017`

**MITRE ATT&CK:** `T1558.003 — Kerberoasting`

The detection monitors Windows Event ID `4769`, representing Kerberos service ticket requests.

**Result:** Validated.

---

## DET-018 — AS-REP Roasting

**Activity:** AS-REP request generated from `KALI`.

```bash
GetNPUsers.py corp.local/svc_asrep \
-dc-ip 10.10.10.20 \
-no-pass
```

**MITRE ATT&CK:** `T1558.004 — AS-REP Roasting`

The detection monitors Event ID `4768` where Kerberos preauthentication is absent (`preAuthType=0`).

**Result:** Validated.

---

## DET-019 — DCSync

**Activity:** Directory replication request generated from `KALI`.

```bash
secretsdump.py corp.local/Administrator:'Password123'@10.10.10.20
```

**MITRE ATT&CK:** `T1003.006 — DCSync`

The detection identifies Event ID `4662` directory replication activity with the configured access mask.

**Result:** Validated.

---

## DET-020 — Golden Ticket

**Activity:** Forged Kerberos Golden Ticket generated from `KALI` using the `krbtgt` secret.

The simulation included:

1. Obtaining the `krbtgt` secret.
2. Creating a forged Kerberos ticket.
3. Loading the ticket into the Kerberos credential cache.
4. Verifying the ticket using `klist`.
5. Performing remote authentication against `DC01`.

**MITRE ATT&CK:** `T1558.001 — Golden Ticket`

The Wazuh rule monitors Kerberos service-ticket activity associated with RC4 session encryption as the configured Golden Ticket detection signal.

**Result:** Validated.

---

## DET-021 — Silver Ticket

**Activity:** Forged service ticket generated from `KALI` for the HTTP service.

The simulation included:

1. Creating the forged service ticket.
2. Loading the ticket into `KRB5CCNAME`.
3. Verifying the Kerberos cache using `klist`.
4. Triggering authentication against the IIS service.
5. Reviewing Windows Security Event ID `4624`.
6. Removing the temporary ticket cache.

**MITRE ATT&CK:** `T1558.002 — Silver Ticket`

The custom detection identifies suspicious Kerberos network logon characteristics associated with forged service-ticket activity.

**Result:** Validated.

---

## DET-022 — LSASS Credential Dumping

**Activity:** Controlled LSASS access attempt from `CLIENT01` with administrative privileges.

The simulation:

1. Obtained the LSASS process ID.
2. Attempted to open LSASS using Windows API calls.
3. Requested `PROCESS_QUERY_INFORMATION` and `PROCESS_VM_READ`.
4. Verified whether LSASS could be accessed.

The detection relies on Sysmon process-access telemetry targeting `lsass.exe`.

**MITRE ATT&CK:** `T1003.001 — LSASS Memory`

**Result:** Validated.

---

## DET-023 — NTDS.dit Credential Dumping

**Activity:** NTDS IFM operation performed on `DC01`.

```powershell
Start-Process C:\Windows\System32\ntdsutil.exe `
    -ArgumentList "ifm" `
    -Wait
```

**MITRE ATT&CK:** `T1003.003 — NTDS`

The detection identifies `ntdsutil.exe` execution with the `ifm` command.

**Result:** Validated.

---

## DET-024 — Pass-the-Hash

**Activity:** NTLM authentication using a password hash from `KALI`.

```bash
wmiexec.py -hashes :58a478135a93ac3bf058a5ea0e8fdb71 \
'CORP/jdoe@10.10.10.20'
```

**MITRE ATT&CK:** `T1550.002 — Pass the Hash`

The detection identifies the configured NTLM network-logon pattern for the test account.

**Result:** Validated.

---

# 5. Discovery

Discovery simulations reproduced post-compromise reconnaissance from `CLIENT01`.

## DET-025 — SharpHound / BloodHound

**Activity:** SharpHound/BloodHound collector executed from `CLIENT01`.

**Scenario:** Simulated attacker reconnaissance following compromise.

**MITRE ATT&CK:**

* `T1087 — Account Discovery`
* `T1069.002 — Permission Groups Discovery: Domain Groups`
* `T1482 — Domain Trust Discovery`

The detection identifies `SharpHound.exe` execution through Windows process telemetry.

**Result:** Validated.

---

## DET-026 — AdFind

**Activity:** AdFind executed from `CLIENT01`.

**Scenario:** Simulated Active Directory enumeration following compromise.

**MITRE ATT&CK:**

* `T1087 — Account Discovery`
* `T1482 — Domain Trust Discovery`
* `T1069.002 — Permission Groups Discovery: Domain Groups`

The detection identifies `AdFind.exe` execution.

**Result:** Validated.

---

## DET-027 — Windows Network Discovery

**Activity:** Network and host discovery commands executed from `CLIENT01`.

Examples:

```cmd
ipconfig.exe /all
arp.exe -a
nslookup.exe dc01.corp.local
net.exe view
```

Additional commands included network and host discovery utilities such as `route`, `netstat`, `net group`, `hostname`, `whoami`, `ping`, `tracert`, and `nltest`.

**MITRE ATT&CK:**

* `T1016 — System Network Configuration Discovery`
* `T1049 — System Network Connections Discovery`

The detection uses Sysmon process-creation telemetry and command-line matching for the configured discovery commands.

**Result:** Validated.

---

# 6. Lateral Movement and Remote Execution

The lateral-movement simulations tested common Windows remote-execution and remote-access mechanisms.

## DET-028 — PsExec

**Activity:** PsExec execution from `CLIENT01`.

**MITRE ATT&CK:**

* `T1021.002 — SMB/Windows Admin Shares`
* `T1569.002 — System Services: Service Execution`

The detection identifies PsExec process execution through Sysmon telemetry.

**Result:** Validated.

---

## DET-029 — SMB Administrative Share

**Activity:** Administrative SMB share access.

**MITRE ATT&CK:** `T1021.002 — SMB/Windows Admin Shares`

The detection monitors access to administrative shares such as `ADMIN$` and `C$`.

**Result:** Validated.

---

## DET-030 — WinRM

**Activity:** Remote PowerShell session established against `DC01`.

From `KALI`:

```bash
evil-winrm -i 10.10.10.20 \
-u labadmin \
-p Password123
```

From `CLIENT01`:

```powershell
Enter-PSSession -ComputerName DC01 \
-Credential CORP\labadmin
```

**MITRE ATT&CK:** `T1021.006 — Windows Remote Management`

The detection identifies `wsmprovhost.exe` execution associated with WinRM remote sessions.

**Result:** Validated.

---

## DET-031 — WMI

**Activity:** WMI-based remote execution.

From `KALI`:

```bash
wmiexec.py CORP/labadmin:'Password123'@10.10.10.30
```

From `CLIENT01`:

```powershell
Invoke-WmiMethod `
    -Class Win32_Process `
    -Name Create `
    -ArgumentList "cmd.exe /c whoami"
```

**MITRE ATT&CK:** `T1047 — Windows Management Instrumentation`

The detection identifies WMI-related execution through the configured parent event and executable indicators.

**Result:** Validated.

---

## DET-032 — RDP

**Activity:** Remote Desktop authentication to `DC01` from `KALI`.

```bash
xfreerdp /v:DC01.corp.local \
/u:CORP\\Administrator \
/cert:ignore
```

**MITRE ATT&CK:** `T1021.001 — Remote Services: RDP`

The detection identifies successful Remote Desktop logons using Windows logon type `10`.

**Result:** Validated.

---

# 7. Persistence and Defense Evasion

## DET-033 — Windows Service Creation

**Activity:** A new Windows service was created as a controlled persistence simulation.

**MITRE ATT&CK:** `T1543.003 — Create or Modify System Process: Windows Service`

The detection monitors the configured Windows service installation telemetry.

**Result:** Validated.

---

## DET-034 — Scheduled Task

**Activity:** Scheduled task created from `CLIENT01`.

```cmd
schtasks /create /tn "SOC-Test-ScheduledTask" ^
/tr "cmd.exe /c whoami" ^
/sc once /st 23:59 /f
```

### Cleanup

```cmd
schtasks /delete /tn "SOC-Test-ScheduledTask" /f
```

**MITRE ATT&CK:** `T1053.005 — Scheduled Task/Job: Scheduled Task`

The detection identifies scheduled-task creation telemetry.

**Result:** Validated.

---

## DET-035 — Group Policy Modification

**Activity:** Controlled modification of the `Default Domain Policy`.

```powershell
Import-Module GroupPolicy

Set-GPRegistryValue `
    -Name "Default Domain Policy" `
    -Key "HKLM\Software\SOCLab" `
    -ValueName "TestValue" `
    -Type String `
    -Value "DetectionTest"
```

### Cleanup

```powershell
Import-Module GroupPolicy

Remove-GPRegistryValue `
    -Name "Default Domain Policy" `
    -Key "HKLM\Software\SOCLab" `
    -Value "TestValue"
```

**MITRE ATT&CK:** `T1484.001 — Domain or Tenant Policy Modification: Group Policy Modification`

The detection identifies modifications to `groupPolicyContainer` objects.

**Result:** Validated.

---

## DET-036 — Startup Folder Persistence

**Activity:** Controlled file creation in the Windows Startup folder.

```powershell
Copy-Item `
    C:\Windows\System32\notepad.exe `
    "$env:APPDATA\Microsoft\Windows\Start Menu\Programs\Startup\Updater.exe"
```

### Cleanup

```powershell
Remove-Item `
    "$env:APPDATA\Microsoft\Windows\Start Menu\Programs\Startup\Updater.exe" `
    -Force
```

**MITRE ATT&CK:** `T1547.001 — Registry Run Keys / Startup Folder`

The detection monitors Sysmon file-creation telemetry targeting Windows Startup-folder paths.

**Result:** Validated.

---

## DET-037 — Security Event Log Cleared

**Activity:** Windows Security event log cleared from `CLIENT01` with administrative privileges.

```cmd
wevtutil cl Security
```

**MITRE ATT&CK:** `T1070.004 — Indicator Removal: File Deletion`

The detection identifies Windows Security Event Log clearing activity.

**Result:** Validated.

---

## DET-038 — Audit Policy Modification

**Activity:** Windows Logon auditing disabled from `CLIENT01`.

```cmd
auditpol /set /subcategory:"Logon" /success:disable
```

### Cleanup

```cmd
auditpol /set /subcategory:"Logon" /success:enable
```

**MITRE ATT&CK:** `T1562.002 — Impair Defenses: Disable Windows Event Logging`

The detection identifies Windows audit-policy modification activity.

**Result:** Validated.

---

## DET-039 — Windows Defender Tampering

**Activity:** Controlled Defender configuration change from `CLIENT01`.

```powershell
Set-MpPreference -PUAProtection Enabled
```

### Cleanup

```powershell
Set-MpPreference -PUAProtection Disabled
```

**MITRE ATT&CK:** `T1562.001 — Impair Defenses: Disable or Modify Tools`

The custom detection monitors Defender events `5001`, `5007`, and `5013`.

**Result:** Validated.

---

## DET-040 — Suspicious PowerShell

**Activity:** PowerShell execution using `ExecutionPolicy Bypass` from `CLIENT01`.

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass `
-Command "Write-Output 'DET042-VALIDATED-TEST'"
```

**MITRE ATT&CK:** `T1059.001 — PowerShell`

The detection identifies PowerShell execution containing the configured `-ExecutionPolicy Bypass` pattern.

> **Validation note:** The test command contains the string `DET042-VALIDATED-TEST`, while the detection being tested is `DET-040`. This string was retained as part of the recorded test activity.

**Result:** Validated.

---

# 8. Impact

## DET-041 — Windows Firewall Rule Modification

**Activity:** Windows Firewall rule created, modified, and deleted from `CLIENT01`.

### Create Firewall Rule

```powershell
New-NetFirewallRule `
    -DisplayName "SOC-DET041-Test-59999" `
    -Direction Inbound `
    -Action Allow `
    -Protocol TCP `
    -LocalPort 59999
```

### Modify Firewall Rule

```powershell
Set-NetFirewallRule `
    -DisplayName "SOC-DET041-Test-59999" `
    -Action Block
```

### Remove Firewall Rule

```powershell
Remove-NetFirewallRule `
    -DisplayName "SOC-DET041-Test-59999"
```

### Verification

```powershell
Get-NetFirewallRule -DisplayName "SOC-DET041*" |
Format-Table DisplayName, Enabled, Direction, Action, Profile
```

### Cleanup

```powershell
Get-NetFirewallRule -DisplayName "SOC-DET041*" |
Remove-NetFirewallRule
```

**Telemetry:**

* `4946` — Firewall rule added
* `4947` — Firewall rule modified
* `4948` — Firewall rule deleted

**MITRE ATT&CK:** `T1562.004 — Impair Defenses: Disable or Modify System Firewall`

The custom rule explicitly monitors Events `4946`, `4947`, and `4948`.

**Result:** Validated.

> **Classification note:** This simulation is documented under the project's planned Impact section, while the corresponding Wazuh rule categorizes the activity as defense evasion/firewall modification.

---

## DET-042 — Windows Security-Enabled Group Deletion

**Activity:** Temporary security-enabled Active Directory group created and then deleted from `DC01`.

### Create Test Group

```powershell
New-ADGroup `
    -Name "DET-Test-Delete-Group" `
    -SamAccountName "DET-Test-Delete-Group" `
    -GroupCategory Security `
    -GroupScope Global
```

### Verify Group

```powershell
Get-ADGroup "DET-Test-Delete-Group"
```

### Delete Group

```powershell
Remove-ADGroup "DET-Test-Delete-Group" -Confirm:$false
```

**MITRE ATT&CK:** `T1531 — Account Access Removal`

The detection monitors security-enabled group deletion events `4730`, `4734`, and `4758`.

**Result:** Validated.

---

# 9. Detection Validation

The final validation stage confirmed that simulated activity was visible in the telemetry pipeline and produced the expected custom Wazuh detection.

```text
Attack Simulation
       ↓
Windows / Sysmon Event
       ↓
Wazuh Ingestion
       ↓
Parent Rule / Event Classification
       ↓
Custom Rule
       ↓
Wazuh Alert
       ↓
Alert Verification
       ↓
Detection Status: VALIDATED
```

## Wazuh Data Sources

The validation process used the following Wazuh indices:

```text
wazuh-archives-4.x-*
```

Used to review raw or archived telemetry.

```text
wazuh-alerts-4.x-*
```

Used to verify generated Wazuh detection alerts.

The validation process therefore checked both the underlying telemetry and the resulting detection alert rather than relying solely on the presence of an alert.

---

# 10. Detection Validation Summary

| ID      | Detection                              | Simulation Source | Primary Telemetry / Signal  | MITRE ATT&CK            | Status    |
| ------- | -------------------------------------- | ----------------- | --------------------------- | ----------------------- | --------- |
| DET-001 | Failed Authentication                  | CLIENT01          | Windows authentication      | —                       | Validated |
| DET-002 | Brute Force                            | CLIENT01          | Authentication failures     | T1110                   | Validated |
| DET-003 | Successful Interactive Authentication  | CLIENT01          | 4624                        | T1078                   | Validated |
| DET-004 | Successful Login After Failed Attempts | CLIENT01          | Authentication correlation  | T1110, T1078            | Validated |
| DET-005 | Account Lock                           | CLIENT01          | Account lockout             | —                       | Validated |
| DET-006 | Multiple Authentication Failures       | CLIENT01          | Authentication correlation  | T1110                   | Validated |
| DET-007 | User Account Created                   | DC01              | 4720                        | T1136                   | Validated |
| DET-008 | Password Reset                         | DC01              | 4724                        | T1098                   | Validated |
| DET-009 | User Account Enabled                   | DC01              | 4722                        | T1098                   | Validated |
| DET-010 | User Account Deleted                   | DC01              | 4726                        | T1531                   | Validated |
| DET-011 | Domain Admin Membership                | DC01              | 4728                        | T1098                   | Validated |
| DET-012 | Enterprise Admin Membership            | DC01              | 4756                        | T1098                   | Validated |
| DET-013 | Local Administrator Membership         | DC01              | 4732                        | T1098                   | Validated |
| DET-014 | Administrator Enabled                  | DC01              | 4722                        | T1098                   | Validated |
| DET-015 | Privileged Account Logon               | DC01              | 4624                        | T1078                   | Validated |
| DET-016 | AD Attribute Modification              | DC01              | 5136                        | T1098                   | Validated |
| DET-017 | Kerberoasting                          | KALI              | 4769                        | T1558.003               | Validated |
| DET-018 | AS-REP Roasting                        | KALI              | 4768                        | T1558.004               | Validated |
| DET-019 | DCSync                                 | KALI              | 4662                        | T1003.006               | Validated |
| DET-020 | Golden Ticket                          | KALI              | Kerberos ticket activity    | T1558.001               | Validated |
| DET-021 | Silver Ticket                          | KALI              | 4624 / Kerberos             | T1558.002               | Validated |
| DET-022 | LSASS Credential Dumping               | CLIENT01          | Sysmon process access       | T1003.001               | Validated |
| DET-023 | NTDS.dit / IFM                         | DC01              | Process / command telemetry | T1003.003               | Validated |
| DET-024 | Pass-the-Hash                          | KALI              | NTLM network logon          | T1550.002               | Validated |
| DET-025 | SharpHound / BloodHound                | CLIENT01          | Process creation            | T1087, T1069.002, T1482 | Validated |
| DET-026 | AdFind                                 | CLIENT01          | Process creation            | T1087, T1482, T1069.002 | Validated |
| DET-027 | Network Discovery                      | CLIENT01          | Sysmon process creation     | T1016, T1049            | Validated |
| DET-028 | PsExec                                 | CLIENT01          | Sysmon process creation     | T1021.002, T1569.002    | Validated |
| DET-029 | SMB Admin Share                        | CLIENT01          | SMB share access            | T1021.002               | Validated |
| DET-030 | WinRM                                  | KALI / CLIENT01   | `wsmprovhost.exe`           | T1021.006               | Validated |
| DET-031 | WMI                                    | KALI / CLIENT01   | WMI execution               | T1047                   | Validated |
| DET-032 | RDP                                    | KALI              | 4624 / Logon Type 10        | T1021.001               | Validated |
| DET-033 | Windows Service                        | Windows host      | Service installation        | T1543.003               | Validated |
| DET-034 | Scheduled Task                         | CLIENT01          | Scheduled task creation     | T1053.005               | Validated |
| DET-035 | GPO Modification                       | DC01              | AD/GPO modification         | T1484.001               | Validated |
| DET-036 | Startup Persistence                    | CLIENT01          | Sysmon file creation        | T1547.001               | Validated |
| DET-037 | Security Event Log Cleared             | CLIENT01          | Security log clear          | T1070.004               | Validated |
| DET-038 | Audit Policy Modification              | CLIENT01          | Audit policy change         | T1562.002               | Validated |
| DET-039 | Defender Tampering                     | CLIENT01          | Defender events             | T1562.001               | Validated |
| DET-040 | Suspicious PowerShell                  | CLIENT01          | Sysmon PowerShell telemetry | T1059.001               | Validated |
| DET-041 | Firewall Modification                  | CLIENT01          | 4946/4947/4948              | T1562.004               | Validated |
| DET-042 | Security-Enabled Group Deletion        | DC01              | 4730/4734/4758              | T1531                   | Validated |

---

# 11. Cleanup and Test Hygiene

Where simulations modified the lab environment, cleanup was performed after validation.

Examples included:

* Removing temporary user accounts.
* Restoring modified account attributes.
* Removing temporary group memberships.
* Removing temporary Active Directory groups.
* Deleting scheduled tasks.
* Removing temporary services.
* Removing Startup-folder test files.
* Restoring Windows audit-policy settings.
* Restoring Defender configuration.
* Removing temporary firewall rules.
* Removing temporary Kerberos ticket caches.

Cleanup ensured that temporary detection-validation artifacts did not remain in the lab environment after testing.

---

# 12. Validation Outcome

The attack simulation process was used to validate the complete detection pipeline across the 42 custom detections:

```text
Controlled Attack Activity
          ↓
Windows / Sysmon Telemetry
          ↓
Wazuh Collection
          ↓
Event Classification
          ↓
Custom Detection Logic
          ↓
Wazuh Alert
          ↓
SOC Validation
```

All `DET-001` through `DET-042` simulations were recorded as validated during the detection-engineering testing process.

The simulations demonstrate that the lab's detection engineering workflow connects controlled attacker activity with observable endpoint/domain telemetry and corresponding Wazuh detection logic.
