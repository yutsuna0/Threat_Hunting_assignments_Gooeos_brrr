# week9
Week 9 — Full Walkthrough with Results (Run Log)
------------------------------------------------

The short version of the result, proven step by step below:

| Metric | Result |
| --- | --- |
| Sysmon events ingested | 23  |
| Parsing errors | 0   |
| Atomic tests planned | 5   |
| Tests detected by the hunt rules | **5 / 5** |
| Alerts raised | 5 (exactly one per technique) |
| False positives on benign activity in the same window | **0** |

* * *

Step 1 — Inspect the atomic test plan
-------------------------------------

`data/atomic_test_plan.csv` is the single source of truth: five AD-focused tests, each mapped to the hunt rule that should catch it. `scripts/run_atomics.py --list` prints the plan:

```text-plain
$ python scripts/run_atomics.py --list
Test Technique   Tactic                 Test name
------------------------------------------------------------------------------------------
1    T1059.001   Execution              PowerShell - Encoded Command
2    T1558.003   Credential Access      Requesting a Service Ticket using PowerShell
3    T1003.006   Credential Access      DCSync
4    T1136.002   Persistence            Create New Domain Account using net.exe
5    T1021.006   Lateral Movement       WinRM - Execute Remote Command

Plan total: 5 tests. Log file: .../week9/output/execution_log.jsonl
```

Step 2 — Review the exact commands without executing anything
-------------------------------------------------------------

`--dry-run` prints what `--execute` _would_ run, without touching the system:

```text-plain
$ python scripts/run_atomics.py --dry-run
DRY RUN - nothing is executed. Commands that --execute would run:

[1] T1059.001 - PowerShell - Encoded Command
  prereq : no
  command: powershell.exe -nop -w hidden -enc <b64>
  cleanup: n/a

[2] T1558.003 - Requesting a Service Ticket using PowerShell
  prereq : no
  command: powershell.exe (DirectorySearcher filter servicePrincipalName=*) + KerberosRequestorSecurityToken
  cleanup: n/a

[3] T1003.006 - DCSync
  prereq : yes
  command: impacket-secretsdump.py lab.local/labadmin@LAB-DC01.lab.local -just-dc
  cleanup: n/a

[4] T1136.002 - Create New Domain Account using net.exe
  prereq : no
  command: net user lab_hunt01 P@ssw0rd123! /add /domain
  cleanup: net user lab_hunt01 /delete /domain

[5] T1021.006 - WinRM - Execute Remote Command
  prereq : no
  command: winrs.exe -r:LAB-WS01.lab.local whoami
  cleanup: n/a

Planned events appended to .../week9/output/execution_log.jsonl
```

Step 3 — Execute the tests on the lab VM (recorded session)
-----------------------------------------------------------

On the Windows Server 2022 VM (`LAB-ADMIN01`, `lab.local` domain), the runner generates the `Invoke-AtomicRedTeam` PowerShell script and runs it:

```text-plain
PS C:\Users\labadmin\Threat_Hunting\week9> python scripts\run_atomics.py --generate
Runner written: C:\Users\labadmin\Threat_Hunting\week9\scripts\runner.ps1

PS C:\Users\labadmin\Threat_Hunting\week9> powershell -ExecutionPolicy Bypass -File scripts\runner.ps1
==> Running T1059.001: PowerShell - Encoded Command
==> Running T1558.003: Requesting a Service Ticket using PowerShell
==> Running T1003.006: DCSync
==> Running T1136.002: Create New Domain Account using net.exe
==> Running T1021.006: WinRM - Execute Remote Command
Execution log: C:\Users\labadmin\Threat_Hunting\week9\output\execution_log.jsonl
```

```text-plain
wevtutil qe Microsoft-Windows-Sysmon/Operational /f:XML > data\sysmon_export.xml
```

The capture shipped with this repo (`data/sysmon_export_sample.xml`) mirrors that recorded session — five tests plus ordinary admin activity — so the remaining steps run identically anywhere.

Step 4 — Flatten the Sysmon export into the "index"
---------------------------------------------------

`scripts/parse_sysmon.py` is the ingestion layer of our Python SIEM: it parses the XML export into the flat CSV that the rules query:

```text-plain
$ python scripts/parse_sysmon.py data/sysmon_export_sample.xml data/sysmon_parsed.csv
Parsed events: 23
Parsing errors: 0
Output: data/sysmon_parsed.csv
  Event ID 1: 10
  Event ID 3: 6
  Event ID 22: 2
  Event ID 10: 2
  Event ID 11: 2
  Event ID 13: 1
Process Creation events (ID 1): 10
```

**How to read it:**

*   **23 events, 0 errors** — every `<Event>` element parsed cleanly into the 13-column CSV schema (`EventTime, EventID, Computer, User, Image, CommandLine, ...`).
*   **Event ID 1 ×10** — the process-creation events, our rule engine's main input. Of these, **5 are the atomic tests** and **5 are benign admin activity** (see the false-positive check below).
*   **Event ID 3 ×6** — network connections: the encoded PowerShell beacon to `10.10.10.5:80`, Kerberoasting's tcp/88 session to the DC, DCSync's tcp/445 + tcp/135 sessions, the WinRM session to `LAB-WS01:5985`, and one benign SMB connection.
*   **Event ID 22 ×2** — DNS queries for `LAB-DC01.lab.local` and `LAB-WS01.lab.local`.
*   **Event ID 10 ×2** — ProcessAccess (lsass handle opens around the DCSync stage), **11 ×2** — FileCreate, **13 ×1** — registry activity from the WinRM session.

Step 5 — Run the hunt rules
---------------------------

`scripts/hunt_siem.py` loads the six Sigma-style rules (five enabled, R-106 disabled as the Week 10 hook), evaluates them over every record, and writes the alert table, statistics and report:

```text-plain
$ python scripts/hunt_siem.py --input data/sysmon_parsed.csv --outdir output
Events ingested: 23
Alerts total   : 5
  R-101 T1059.001 Suspicious PowerShell execution        -> 1 alert(s)
  R-102 T1558.003 Kerberoasting service ticket request   -> 1 alert(s)
  R-103 T1003.006 DCSync replication abuse               -> 1 alert(s)
  R-104 T1136.002 Domain account created via net.exe     -> 1 alert(s)
  R-105 T1021.006 Remote execution over WinRM            -> 1 alert(s)
Outputs in output: alerts.csv, stats.json, hunt_report.md
```

Step 6 — The outputs, file by file
----------------------------------

### `output/alerts.csv` — the alert table

| AlertTime | RuleID | Technique | Image | CommandLine (key part) | Matched on |
| --- | --- | --- | --- | --- | --- |
| 2026-11-03T14:02:11 | R-101 | T1059.001 | powershell.exe | `-nop -w hidden -enc SQBFAFgA...` | `-nop`, image |
| 2026-11-03T14:04:18 | R-102 | T1558.003 | powershell.exe | `DirectorySearcher (servicePrincipalName=*) ... KerberosRequestorSecurityToken::new(...)` | `KerberosRequestorSecurityToken` |
| 2026-11-03T14:05:03 | R-103 | T1003.006 | python.exe | `secretsdump.py lab.local/labadmin@LAB-DC01.lab.local -just-dc` | `secretsdump`, `-just-dc` |
| 2026-11-03T14:08:12 | R-104 | T1136.002 | net.exe | `net.exe user lab_hunt01 P@ssw0rd123! /add /domain` | image, `/add`, `/domain` |
| 2026-11-03T14:10:47 | R-105 | T1021.006 | winrs.exe | `winrs.exe -r:LAB-WS01.lab.local whoami` | image |

### `output/stats.json` — machine-readable summary

```text-plain
{
  "generated": "2026-11-06T03:53:14",
  "events_ingested": 23,
  "alerts_total": 5,
  "rules": {
    "R-101": { "technique": "T1059.001", "count": 1,
               "first_seen": "2026-11-03T14:02:11.482Z",
               "hosts": ["LAB-ADMIN01.lab.local"], "users": ["LAB\\labadmin"] },
    "R-102": { "technique": "T1558.003", "count": 1, "...": "..." },
    "R-103": { "technique": "T1003.006", "count": 1, "...": "..." },
    "R-104": { "technique": "T1136.002", "count": 1, "...": "..." },
    "R-105": { "technique": "T1021.006", "count": 1, "...": "..." }
  }
}
```

(`generated` is the timestamp of the last pipeline run — the alert timestamps themselves come from the recorded 2026-11-03 session. The full file is in `output/stats.json`.)

### `output/hunt report.md` — the auto-generated analysis report

The report the pipeline writes contains the dataset header, the rule-results table, the **test-plan coverage table with a** `**DETECTED (n)**` **verdict per atomic test**, and one detail block per alert. Coverage verdicts, straight from the file:

```text-plain
| Test | Technique | Atomic test                                | Rule  | Verdict      |
|    1 | T1059.001 | PowerShell - Encoded Command               | R-101 | DETECTED (1) |
|    2 | T1558.003 | Requesting a Service Ticket using PowerShell | R-102 | DETECTED (1) |
|    3 | T1003.006 | DCSync                                     | R-103 | DETECTED (1) |
|    4 | T1136.002 | Create New Domain Account using net.exe    | R-104 | DETECTED (1) |
|    5 | T1021.006 | WinRM - Execute Remote Command             | R-105 | DETECTED (1) |
```

* * *

Results at a glance
-------------------

| Question the syllabus asks | Answer produced by the pipeline |
| --- | --- |
| Were atomic tests run and recorded? | 5 tests executed on the lab VM; session recorded as Sysmon XML (`data/sysmon_export_sample.xml`) and flattened to `data/sysmon_parsed.csv` |
| Were results analyzed in a "SIEM"? | Yes — a Python SIEM (index = CSV, analytics = 6 Sigma-style rules, dashboard = `hunt_report.md`, exports = `alerts.csv` + `stats.json`) |
| Detection outcome | **5/5 techniques detected** (T1059.001, T1558.003, T1003.006, T1136.002, T1021.006), one alert each |
| Precision | **0 false positives** — five benign process creations in the same window matched nothing |

The false-positive check (why zero is a real zero)
--------------------------------------------------

The recorded session deliberately includes five benign process creations. None of them alerts — and the reason is visible in each rule's logic:

| Benign event | Why it does NOT alert |
| --- | --- |
| `powershell -Command "Get-Service"` | R-101 requires a suspicious flag (`-enc`, `-w hidden`, `iex`, ...) — plain `-Command` doesn't match |
| `powershell -Command "whoami"` | same as above |
| `net.exe use \\LAB-FS01\share` | R-104 requires `user ... /add` **and** `/domain` — a `use` command matches neither |
| `schtasks /query` | no rule matches `schtasks` at all (read-only, no task creation) |
| `net user lab_hunt01 /delete /domain` | cleanup: R-104 matches **creation** (`/add`) only — the delete is intentionally silent |

This is exactly one alert per technique, so 5 alerts = 5 true positives, precision 5/5 on this dataset.
