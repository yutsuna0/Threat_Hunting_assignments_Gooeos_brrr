# README
Assignment 6 – Week 9 & 10
--------------------------

**Project Topic:** Threat Hunting for Active Directory Attacks

|     |     |     |
| --- | --- | --- |
| Week | Topic | Summary |
| 9   | Atomic Red Team | Five AD-focused atomic tests executed (T1059.001 PowerShell, T1558.003 Kerberoasting, T1003.006 DCSync, T1136.002 Domain Account, T1021.006 WinRM) through a Python-driven Invoke-AtomicRedTeam runner. Results were recorded and analyzed with a Python SIEM pipeline (parse\_sysmon.py + hunt\_siem.py): 23 Sysmon events ingested, 5/5 tests detected, zero false positives on the benign activity in the same window. |
| 10  | Learning APT Techniques | TTP analysis of Storm-0501 (MITRE ATT&CK G1053) — chosen over APT29/APT41 because its tradecraft is an Active Directory attack end-to-end. 62 documented techniques analyzed and mapped to ATT&CK in an annotated Navigator layer (week10/data/storm0501\_ad\_layer.json); our Week 9 hunts already cover 5 of the 12 on-prem AD techniques the group uses (41.7%), with a 7-rule next-hunt backlog. |

Repository layout
-----------------

```text-plain
Assignment6/
├── README.md                  <- this file
├── week9/
│   ├── README.md              <- Week 9 report (run + analyze)
│   ├── week9.md <- command-by-command run log with actual outputs
│   ├── scripts/
│   │   ├── run_atomics.py     <- atomic test orchestrator (Python -> Invoke-AtomicRedTeam)
│   │   ├── parse_sysmon.py    <- Sysmon XML export -> flat CSV
│   │   └── hunt_siem.py       <- Python SIEM: detection rules -> alerts.csv + hunt_report.md
│   ├── data/
│   │   ├── atomic_test_plan.csv   <- the five tests with commands and hunt rule mapping
│   │   ├── sysmon_export_sample.xml <- recorded reference session for pipeline validation
│   │   └── sysmon_parsed.csv      <- parsed output
│   └── output/                <- alerts.csv, stats.json, hunt_report.md
└── week10/
    ├── README.md              <- Week 10 report (Storm-0501 case study + ATT&CK mapping)
    ├── week10.md <- command-by-command run log with actual outputs
    ├── scripts/
    │   ├── storm0501_ttps.py      <- TTP analysis of G1053 techniques (--refresh re-syncs MITRE)
    │   ├── build_navigator_layer.py <- annotated ATT&CK Navigator layer
    │   └── hunt_coverage.py       <- Week 9 hunts vs Storm-0501 TTP coverage + gap backlog
    └── data/
        ├── storm0501_techniques.csv   <- 62 G1053 techniques with tactics/category/tooling
        ├── storm0501_ad_layer.json    <- Navigator layer (import into ATT&CK Navigator)
        └── hunt_coverage.csv          <- coverage matrix
```

How to run
----------

```text-plain
# Week 9
python week9/scripts/run_atomics.py --dry-run
python week9/scripts/parse_sysmon.py week9/data/sysmon_export_sample.xml week9/data/sysmon_parsed.csv
python week9/scripts/hunt_siem.py --input week9/data/sysmon_parsed.csv --outdir week9/output

# Week 10
python week10/scripts/storm0501_ttps.py
python week10/scripts/build_navigator_layer.py
python week10/scripts/hunt_coverage.py
```

AI USAGE DECLARATION
--------------------

GLM (Z.ai) was used to implement the Python scripts (atomic runner, Sysmon parser, hunting pipeline, ATT&CK analysis and Navigator layer builder), and compile the Storm-0501 mapping from the official G1053 data and public vendor reporting