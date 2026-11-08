# week10
Week 10 – Full Walkthrough with Results
---------------------------------------

The short version of the result, proven step by step below:

| Metric | Result |
| --- | --- |
| Storm-0501 (G1053) documented techniques analyzed | 62 (28 sub-techniques, 34 base) |
| Techniques targeting identity infrastructure | 31 of 62 (**50.0%**) |
| On-prem AD techniques (= our hunting scope) | 12 (19.4%) |
| Local dataset vs official MITRE layer | **62 / 62 in sync** |
| Navigator layer techniques annotated | 62 / 62 |
| Week 9 hunts that map into G1053 tradecraft | 3 direct + 2 via documented tooling |
| Coverage of the on-prem AD scope | **5 of 12 (41.7%)** |
| Gap backlog with concrete next-hunt proposals | 7 hunts (9 technique IDs incl. 2 parents) |

* * *

Step 1 – TTP analysis of Storm-0501 (G1053)
-------------------------------------------

`scripts/storm0501_ttps.py` reads `data/storm0501_techniques.csv` – the 62 techniques from the official ATT&CK group layer, each annotated by us with a tactic list, an operational category (AD / Cloud / Host / Impact / ...) and the observed tooling. The default run prints the full analytical summary:

```text-plain
$ python scripts/storm0501_ttps.py
Storm-0501 (MITRE ATT&CK G1053, v1.0, created 2025-10-19)
Documented techniques: 62 (28 sub-techniques, 34 base techniques)

Tactic distribution (a technique can span several tactics):
  Defense Evasion             16  ################
  Discovery                   12  ############
  Persistence                 12  ############
  Credential Access           10  ##########
  Privilege Escalation         7  #######
  Lateral Movement             6  ######
  Execution                    5  #####
  Impact                       4  ####
  Resource Development         4  ####
  Initial Access               3  ###
  Exfiltration                 2  ##
  Command and Control          2  ##
  Collection                   1  #

Operational categories (our mapping for the AD attack topic):
  Host tradecraft                         20  (32.3%)
  Cloud pivot (Entra ID / Azure)          19  (30.6%)
  AD / on-prem identity                   12  (19.4%)
  Impact / extortion & exfiltration        6  (9.7%)
  Resource development                     4  (6.5%)
  Initial access                           1  (1.6%)

On-premises AD techniques (core of our hunting topic) (12 techniques):
  T1087       Account Discovery
  T1087.002   Account Discovery: Domain Account  [tools: ADRecon.ps1 (obfuscated obfs.ps1 / recon.ps1)]
  T1110       Brute Force
  T1059.001   Command and Scripting Interpreter: PowerShell  [tools: PowerShell; Evil-WinRM sessions]
  T1555.005   Credentials from Password Stores: Password Managers  [tools: Find-KeePassConfig.ps1]
  T1484       Domain or Tenant Policy Modification
  T1484.001   Domain or Tenant Policy Modification: Group Policy Modification  [tools: GPO distribution]
  T1482       Domain Trust Discovery  [tools: nltest.exe]
  T1003       OS Credential Dumping  [tools: Impacket SecretsDump]
  T1003.006   OS Credential Dumping: DCSync  [tools: Impacket secretsdump.py / Mimikatz lsadump::dcsync]
  T1021.006   Remote Services: Windows Remote Management  [tools: Evil-WinRM]
  T1053.005   Scheduled Task/Job: Scheduled Task  [tools: GPO-registered task 'SysUpdate']
```

**How to read it – this single output answers the syllabus question "what are the group's TTPs":**

*   **62 documented techniques** across 13 tactics; the heavyweights are Defense Evasion (16) and Discovery (12) – typical of a ransomware operation that needs to neutralize protection and learn the estate before striking.
*   **The identity-centric share is the headline for our topic:** 12 on-prem AD + 19 cloud-identity/Entra-Azure techniques = 31 of 62 = **50.0% of the arsenal targets identity infrastructure**. Storm-0501 is not "an AD group" by marketing – it is one by ATT&CK arithmetic.
*   **The 12 AD techniques define our hunting scope** (the last table). Five of them are exactly what Week 9 tested: PowerShell (T1059.001), DCSync (T1003.006), WinRM (T1021.006) – direct; Kerberoasting and domain-account creation via the group's documented Impacket/Net tooling.

The same script slices the dataset without writing any new file:

```text-plain
$ python scripts/storm0501_ttps.py --category AD
$ python scripts/storm0501_ttps.py --category Cloud
$ python scripts/storm0501_ttps.py --tactic "Credential Access"
```

Step 2 – Prove the dataset is current against MITRE
---------------------------------------------------

`--refresh` downloads the **live official Navigator layer** from attack.mitre.org and diffs the technique IDs against our CSV:

```text-plain
$ python scripts/storm0501_ttps.py --refresh
Fetching https://attack.mitre.org/groups/G1053/G1053-enterprise-layer.json ...
Live layer: 62 techniques | local CSV: 62
Local CSV is in sync with the official layer.
```

Step 3 – Map the TTPs to ATT&CK
-------------------------------

`scripts/build_navigator_layer.py` converts the CSV into `data/storm0501_ad_layer.json`, a Navigator-ready layer where **every one of the 62 techniques is annotated** with a score that encodes its role in the AD attack chain and a comment naming the observed tooling:

```text-plain
$ python scripts/build_navigator_layer.py
Layer written: ../week10/data/storm0501_ad_layer.json
Techniques annotated: 62
   20 pts  Host tradecraft                        x20
   40 pts  Cloud pivot (Entra ID / Azure)         x19
   60 pts  AD / on-prem identity                  x12
   80 pts  Impact / extortion & exfiltration      x6
    5 pts  Resource development                   x4
   30 pts  Initial access                         x1
```

**The scoring scheme**:

| Score | Color | Meaning |
| --- | --- | --- |
| 60  | red | AD / on-prem identity – our hunting priority |
| 40  | orange | Cloud pivot (Entra ID / Azure) – second stage of the chain |
| 80  | dark red | Impact / extortion & exfiltration — the end goal |
| 30  | yellow | Initial access — chain start |
| 20  | blue | Host tradecraft — supporting activity |
| 10 / 5 | grey | C2 & remote access / resource development |

`scripts/hunt_coverage.py` cross-references the Week 9 test plan against the 62 G1053 techniques and writes the coverage matrix `data/hunt_coverage.csv`:

```text-plain
$ python scripts/hunt_coverage.py
==========================================================================
Week 9 hunt suite -> Storm-0501 (G1053) coverage
==========================================================================
  R-101  T1059.001   direct G1053 technique
  R-102  T1558.003   via Impacket (S0357) - Steal or Forge Kerberos Tickets: Kerberoasting
  R-103  T1003.006   direct G1053 technique
  R-104  T1136.002   via Net (S0039) - Create Account: Domain Account
  R-105  T1021.006   direct G1053 technique

G1053 documented techniques : 62
Covered directly            : 3 (4.8% of all techniques)
Covered via software links  : 2
On-prem AD techniques (our scope): 12
AD techniques covered directly   : 3 (25.0%)
AD techniques covered incl. tooling: 5 (41.7%)

AD gap backlog (9 techniques without a hunt):
  T1087       Account Discovery
              next hunt: Hunt the sub-technique instead: T1087.002 (ADRecon) plus generic account-enumeration PowerShell.
  T1087.002   Account Discovery: Domain Account
              next hunt: Alert on ADRecon/SharpView images and obfuscated recon.ps1 file drops (Sysmon 1/11).
  T1110       Brute Force
              next hunt: Detect Kerberos pre-auth failure bursts (Security 4768 with 0x12) per source host.
  T1555.005   Credentials from Password Stores: Password Managers
              next hunt: Alert on processes opening Keepass config/database files (Sysmon 11 on *.kdbx, Find-KeePassConfig).
  T1484       Domain or Tenant Policy Modification
              next hunt: Hunt the sub-techniques: T1484.001 (GPO edits) and T1484.002 (federated-domain backdoor).
  T1484.001   Domain or Tenant Policy Modification: Group Policy Modification
              next hunt: Monitor GPO edits on security products (Directory Services 5136 with gPCUserExtensionNames changes).
  T1482       Domain Trust Discovery
              next hunt: Alert on nltest.exe /domain_trusts /all_trusts command lines (Sysmon 1).
  T1003       OS Credential Dumping
              next hunt: Alert on Impacket SecretsDump argument patterns beyond DCSync: SAM, SECURITY saves.
  T1053.005   Scheduled Task/Job: Scheduled Task
              next hunt: Alert on scheduled task creation via GPO (Security 4698 with 'SysUpdate'-like names, unknown authors).

Matrix written: .../week10/data/hunt_coverage.csv
```

**How to read it — the numbers behind the headline "41.7%":**

*   **3 direct** (T1059.001, T1003.006, T1021.006): techniques Storm-0501 itself uses, and our rules hunt them by name.
*   **2 via software links** (T1558.003, T1136.002): not group-level rows in G1053, but the group is documented to use **Impacket (S0357)** and **Net (S0039)** — software entries that carry those techniques, so a hunt on the technique still covers the group's behavior.
*   **Scope, not vanity, drives the percentage.** "3 of 62 = 4.8%" looks tiny but is misleading: our project hunts _on-prem AD_, not the group's cloud stage. Within the declared scope — the 12 on-prem AD techniques — we cover **5 of 12 (41.7%)** counting direct + tooling coverage (3 direct = 25.0% strictly).
*   **The gap backlog is 9 technique IDs but 7 concrete hunts:** T1087 and T1484 are parent techniques whose hunts _are_ their sub-techniques (T1087.002, T1484.001/002), so the seven actionable proposals are: ADRecon file drops, Kerberos pre-auth failure bursts (4768/0x12), Keepass theft (`*.kdbx`), GPO edits on security products (DS 5136), `nltest /domain_trusts`, non-DCSync SecretsDump patterns, and GPO-registered task creation (4698, "SysUpdate"-like names).
*   The written matrix (`data/hunt_coverage.csv`) has one row per Week 9 hunt: `R-103,DCSync,T1003.006,OS Credential Dumping: DCSync,direct G1053 technique,AD / on-prem identity` and so on.