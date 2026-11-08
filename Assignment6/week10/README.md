# README
Week 10 – Learning APT Techniques: Storm-0501 (G1053)
-----------------------------------------------------

**Group selection:** **Storm-0501 (MITRE ATT&CK G1053)**   
Storm-0501's entire operation is an Active Directory attack: it compromises on-prem AD, then pivots through the Entra Connect sync infrastructure into Entra ID and Azure

Group Profile
-------------

| Field | Value |
| --- | --- |
| MITRE ID | G1053 (v1.0, created 2025-10-19) |
| Aliases | Storm-0501 (Microsoft) |
| Motivation | Financially motivated – ransomware and extortion |
| Active since | 2021 (first observed attacking US school districts with Sabbath ransomware) |
| RaaS affiliations | Sabbath, Hive, BlackCat, Hunters International, LockBit 3.0, Embargo |
| Signature capability | Hybrid-cloud ransomware: on-prem AD compromise → Entra ID/Azure takeover → data destruction and extortion without classic endpoint encryption |
| Primary sources | Microsoft Threat Intelligence blogs (2024-09-26, 2025-08-27), Avertium Sabbath analysis (2022), "Kitten.gif" Sabbath affiliate research (2021); MITRE ATT&CK G1053 |

The 2025 Hybrid-Cloud Attack Chain (Case Study)
-----------------------------------------------

Condensed from Microsoft Threat Intelligence's August 2025 report on a real multi-subsidiary enterprise attack (multiple AD domains joined by trusts, several Entra tenants synced through Entra Connect servers):

| #   | Stage | ATT&CK technique |
| --- | --- | --- |
| 1   | Move laterally with Evil-WinRM over WinRM | T1021.006 |
| 2   | Probe endpoint protection (`sc query sense`, `sc query windefend`) to target unmonitored hosts | T1518.001 |
| 3   | Host discovery (`quser.exe`, `net.exe`, `systeminfo`, `tasklist.exe`) | T1082, T1057 |
| 4   | DCSync against the on-prem domain | T1003.006 |
| 5   | Pivot through a compromised Entra Connect Sync server (tunnel, not EDR-onboarded) | T1021.007 |
| 6   | Extract the **DSA account**; enumerate the tenant with AzureHound | T1078.004, T1087.004, T1580, T1526 |
| 7   | Cross-domain lateral movement to a second Entra Connect server; repeat tenant enumeration | T1021.007 |
| 8   | Find a synced non-human account holding Global Administrator, without MFA; reset its on-prem password so Entra Connect (PHS) syncs it to the cloud | T1098.001 |
| 9   | Sign in as that Global Admin, **register own MFA method**; satisfy a hybrid-join Conditional Access rule by hopping to a hybrid-joined server | T1556.009, T1078.004 |
| 10  | `elevateAccess/action` → User Access Administrator over all subscriptions; `roleAssignments/write` → Owner | T1098.003 |
| 11  | Federated-domain backdoor with AADInternals – sign in as almost any user via forged SAML tokens | T1484.002 |
| 12  | Expose Azure Storage accounts publicly (`storageAccounts/write`) and steal access keys (`listkeys/action`) | T1530, T1552.004 |
| 13  | Exfiltrate with AzCopy to attacker infrastructure | T1567.002, T1537 |
| 14  | Mass-delete snapshots, restore points, storage accounts, backup vaults; delete resource locks and immutability policies | T1490, T1578.003, T1485 |
| 15  | Cloud-encrypt what survived via a new Key Vault customer-managed key and storage encryption scopes, then delete the key | T1555.006, T1486 |
| 16  | Extortion over Microsoft Teams; double extortion on leak sites | T1657 |

TTP Analysis
------------

`scripts/storm0501_ttps.py` analyzes `data/storm0501_techniques.csv`, which was built from the official ATT&CK G1053 layer and verified against it

Documented techniques: 62 (28 sub-techniques, 34 base techniques).

Tactic distribution (a technique can span several tactics):

| Tactic | Count |     | Tactic | Count |
| --- | --- | --- | --- | --- |
| Defense Evasion | 16  |     | Execution | 5   |
| Discovery | 12  |     | Impact | 4   |
| Persistence | 12  |     | Resource Development | 4   |
| Credential Access | 10  |     | Initial Access | 3   |
| Privilege Escalation | 7   |     | Exfiltration | 2   |
| Lateral Movement | 6   |     | Command and Control | 2   |
|     |     |     | Collection | 1   |

Operational categories – our mapping of each technique to its role in the AD attack chain:

| Category | Count | Share |
| --- | --- | --- |
| Host tradecraft | 20  | 32.3% |
| Cloud pivot (Entra ID / Azure) | 19  | 30.6% |
| AD / on-prem identity | 12  | 19.4% |
| Impact / extortion & exfiltration | 6   | 9.7% |
| Resource development | 4   | 6.5% |
| Initial access | 1   | 1.6% |

31 of 62 techniques (50.0%) target identity infrastructure -- on-prem AD or the Entra/Azure identity plane. The on-prem AD subset, which defines our hunting scope:

| Technique | Name | Observed tooling |
| --- | --- | --- |
| T1087 / T1087.002 | Account Discovery: Domain Account | ADRecon.ps1 (obfuscated `obfs.ps1` / `recon.ps1`) |
| T1059.001 | PowerShell | PowerShell one-liners; Evil-WinRM sessions |
| T1110 | Brute Force | credential brute force |
| T1482 | Domain Trust Discovery | `nltest.exe` |
| T1003 / T1003.006 | OS Credential Dumping / DCSync | Impacket SecretsDump; Mimikatz `lsadump::dcsync` |
| T1484 / T1484.001 | Group Policy Modification | GPO distribution to tamper with security products |
| T1555.005 | Password Managers | `Find-KeePassConfig.ps1` (Keepass theft) |
| T1021.006 | Windows Remote Management | Evil-WinRM |
| T1053.005 | Scheduled Task | GPO-registered task **"**SysUpdate**"** (Embargo delivery) |

Mapping to MITRE ATT&CK – Navigator Layer
-----------------------------------------

`scripts/build_navigator_layer.py` converts the technique table into `data/storm0501_ad_layer.json`, an annotated Navigator layer. Every technique carries a score encoding its role in the chain and a comment with the observed tooling:

| Score | Color | Meaning |
| --- | --- | --- |
| 60  | red | AD / on-prem identity — our hunting priority |
| 40  | orange | Cloud pivot (Entra ID / Azure) |
| 80  | dark red | Impact / extortion & exfiltration |
| 30  | yellow | Initial access |
| 20  | blue | Host tradecraft |
| 10 / 5 | grey | C2 & remote access / Resource development |

To view: open [https://mitre-attack.github.io/attack-navigator/](https://mitre-attack.github.io/attack-navigator/) → _Open Existing Layer_ → select `week10/data/storm0501_ad_layer.json`. The layer keeps the official G1053 v1.0 technique set, so it stays comparable with `Assignment2/assets/G1053-enterprise-layer.json` from Week 4 while adding our hunt-oriented annotations.

Tooling Observed
----------------

| Tool | ATT&CK software | Role for Storm-0501 |
| --- | --- | --- |
| AADInternals | S0677 | Federated-domain backdoor, token forging, tenant reconnaissance |
| Cobalt Strike | S0154 | C2 (Beacon with `license_id 666`), Themida-packed, launched via regsvr32/rundll32 |
| Embargo | S1247 | Ransomware payload delivered through the GPO "SysUpdate" task |
| Impacket | S0357 | SecretsDump/DCSync, Kerberoasting, remote execution |
| Net | S0039 | Account/group discovery, domain account creation |

References
----------

*   [https://attack.mitre.org/groups/G1053/](https://attack.mitre.org/groups/G1053/) — Storm-0501 group page (techniques, software, layer)
*   Microsoft Threat Intelligence. (2025, August 27). _Storm-0501's evolving techniques lead to cloud-based ransomware._ [https://www.microsoft.com/en-us/security/blog/2025/08/27/storm-0501s-evolving-techniques-lead-to-cloud-based-ransomware](https://www.microsoft.com/en-us/security/blog/2025/08/27/storm-0501s-evolving-techniques-lead-to-cloud-based-ransomware)
*   Microsoft Threat Intelligence. (2024, September 26). _Storm-0501: Ransomware attacks expanding to hybrid cloud environments._ [https://www.microsoft.com/en-us/security/blog/2024/09/26/storm-0501-ransomware-attacks-expanding-to-hybrid-cloud-environments](https://www.microsoft.com/en-us/security/blog/2024/09/26/storm-0501-ransomware-attacks-expanding-to-hybrid-cloud-environments)
*   Avertium. (2022, January 11). _An In-Depth Look at Ransomware Gang, Sabbath_ (cited by ATT&CK G1053 for the group's origins)
*   McLellan, T., Schondorfer, B. (2021, November 29). _Kitten.gif: Meet the Sabbath Ransomware Affiliate Program, Again_ (cited by ATT&CK G1053 for ADRecon/GPO/Impacket tradecraft)
*   [https://mitre-attack.github.io/attack-navigator/](https://mitre-attack.github.io/attack-navigator/) — ATT&CK Navigator (layer import)
*   `Assignment2/assets/G1053-enterprise-layer.json` — our Week 4 baseline layer for the same group