# README
Week 8 – Adversary Emulation Plan
---------------------------------

**Project Topic:** Threat Hunting for Active Directory Attacks

This covers the syllabus task for Week 8: developing an adversary emulation plan covering initial access, persistence, and data exfiltration, documented using ATT&CK techniques

Summary
-------

This plan is built around HackTheBox's _Forest_ machine, executed end-to-end using common AD tools. Ten stages, reconnaissance through Domain Admin access via pass-the-hash, were actually performed and are documented with real commands and output in `Forest.md`

|     |     |
| --- | --- |
| Stage | Technique |
| 1\. Reconnaissance | T1595 (Active Scanning) |
| 2\. Discovery | T1087.002 (Domain Account) |
| 3\. AS-REP Roasting | T1558.004 (AS-REP Roasting) |
| 4\. Password Cracking | T1110.002 (Password Cracking) |
| 5\. Initial Foothold (WinRM) | T1021.006 (Remote Services: Windows Remote Management) |
| 6\. Discovery (BloodHound) | T1069.002 (Permission Groups Discovery: Domain Groups) |
| 7\. Privilege Escalation (Group Membership) | T1098 (Account Manipulation) |
| 8\. Privilege Escalation (ACL/DCSync grant) | T1098 (Account Manipulation) |
| 9\. Credential Access | T1003.006 (OS Credential Dumping: DCSync) |
| 10\. Pass the Hash | T1550.002 (Use Alternate Authentication Material: Pass the Hash) |
| 11\. Persistence (Domain Account Creation) | T1136.002 (Create Account: Domain Account) |

AI Usage Declaration
--------------------

Claude (Sonnet 5) was used to map the actual recorded attack path to ATT&CK techniques and structure the emulation plan, including the planned extension stages
